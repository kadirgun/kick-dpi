use log::{error, info};
use std::sync::Mutex;
use tauri::Manager;
use windivert::{prelude::WinDivertFlags, ShutdownHandle, WinDivert};

use super::strategies::{
    FakePacketStrategy, FakeSniStrategy, IpFragStrategy, OverlapStrategy, ShuffleStrategy,
    SniSplitStrategy, TcpFragmentStrategy, WrongChecksumStrategy,
};

fn tls_payload(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() || (bytes[0] >> 4) != 4 {
        return None;
    }
    let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
    if bytes.len() <= ip_header_len + 20 {
        return None;
    }
    let tcp_header_len = ((bytes[ip_header_len + 12] >> 4) * 4) as usize;
    let payload_start = ip_header_len + tcp_header_len;
    if bytes.len() < payload_start + 6 {
        return None;
    }
    Some(&bytes[payload_start..])
}

/// Returns true if the packet is a TLS ClientHello (regardless of SNI/ECH).
fn is_client_hello(bytes: &[u8]) -> bool {
    tls_payload(bytes)
        .map(|payload| {
            payload.len() >= 6
                && payload[0] == 0x16  // TLS Handshake record
                && payload[1] == 0x03  // TLS version major
                && payload[5] == 0x01 // Handshake type: ClientHello
        })
        .unwrap_or(false)
}

fn extract_sni(bytes: &[u8]) -> Option<String> {
    let payload = tls_payload(bytes)?;

    // Check TLS Record header (0x16 0x03)
    if payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }

    let handshake = &payload[5..];
    if handshake.len() < 38 {
        return None;
    }
    if handshake[0] != 0x01 {
        return None;
    } // Only ClientHello

    let mut pos = 38; // After Random (32) + Protocol Version (2) + Handshake Type(1) + Handshake Len(3) = 38 bytes

    // Skip Session ID
    if pos >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    // Skip Cipher Suites
    if pos + 1 >= handshake.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Skip Compression Methods
    if pos >= handshake.len() {
        return None;
    }
    let compression_methods_len = handshake[pos] as usize;
    pos += 1 + compression_methods_len;

    // Read Extensions Length
    if pos + 1 >= handshake.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > handshake.len() {
        return None;
    }

    // Parse Extensions
    while pos + 3 < extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI
            let ext_data = &handshake[pos..pos + ext_len];
            if ext_data.len() >= 5 {
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if 5 + name_len <= ext_data.len() {
                    if let Ok(sni) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                        return Some(sni.to_string());
                    }
                }
            }
        }
        pos += ext_len;
    }

    None
}

static SNI_SHUTDOWN: Mutex<Option<ShutdownHandle>> = Mutex::new(None);

pub(super) fn stop_listener() {
    if let Ok(mut guard) = SNI_SHUTDOWN.lock() {
        if let Some(sh) = guard.take() {
            let _ = sh.shutdown();
        }
    }
}

/// Blocking recv/reinject loop.
pub(super) fn run_listener(filter: &str, app_handle: tauri::AppHandle) {
    let buf_size = app_handle
        .state::<crate::state::AppState>()
        .settings_snapshot()
        .app
        .performance
        .packet_buffer_size;
    let handle = match WinDivert::network(filter, 0, WinDivertFlags::default()) {
        Ok(h) => {
            info!("[sni] WinDivert handle opened (filter: {filter})");
            if let Ok(mut guard) = SNI_SHUTDOWN.lock() {
                *guard = Some(h.shutdown_handle());
            }
            h
        }
        Err(e) => {
            error!("[sni] Failed to open WinDivert handle: {e}");
            return;
        }
    };

    let mut buf = vec![0u8; buf_size];

    info!("[sni] listener loop started");

    loop {
        match handle.recv(&mut buf) {
            Ok(packet) => {
                let packet = packet.into_owned();
                let bytes = packet.data.as_ref();

                if should_drop_udp_443(bytes, &app_handle) {
                    info!("[sni] dropping UDP 443 packet for matching rule");
                    continue;
                }

                let mutated_packets = if is_client_hello(bytes) {
                    use crate::{packet_key::ConnectionKey, state::AppState};

                    let state = app_handle.state::<AppState>();
                    let sni = extract_sni(bytes);

                    let packet_path = ConnectionKey::from_raw(bytes).and_then(|key| {
                        let pid = state.pid_for_connection_or_local_port(&key)?;
                        state.path_for_pid(pid)
                    });

                    let should_apply = state
                        .settings_snapshot()
                        .sni_enabled_for(sni.as_deref().unwrap_or(""), packet_path.as_deref());

                    if !should_apply {
                        info!(
                            "[sni] no rule matched: sni={:?} path={:?}",
                            sni, packet_path
                        );
                        vec![packet]
                    } else {
                        info!(
                            "[sni] ClientHello matched: sni={:?} path={:?}",
                            sni, packet_path
                        );
                        state.inc_sni();

                        let app_settings = state.settings_snapshot().app;
                        let strats = &app_settings.sni.strategies;
                        let params = &app_settings.strategy_params;

                        let mut packets = vec![packet];

                        if strats.get("WrongChecksum").copied().unwrap_or(true) {
                            let s = WrongChecksumStrategy {
                                decoy_ttl: params.wrong_checksum_decoy_ttl as u8,
                            };
                            packets = packets.into_iter().flat_map(|p| s.process(p)).collect();
                        }
                        if strats.get("FakeSni").copied().unwrap_or(true) {
                            let s = FakeSniStrategy {
                                decoy_ttl: params.fake_sni_decoy_ttl as u8,
                            };
                            packets = packets.into_iter().flat_map(|p| s.process(p)).collect();
                        }
                        if strats.get("Overlap").copied().unwrap_or(true) {
                            let s = OverlapStrategy {
                                decoy_ttl: params.overlap_decoy_ttl as u8,
                            };
                            packets = packets.into_iter().flat_map(|p| s.process(p)).collect();
                        }
                        if strats.get("IpFrag").copied().unwrap_or(true) {
                            let s = IpFragStrategy {
                                first_frag_payload_bytes: params.ip_frag_first_payload_bytes
                                    as usize,
                            };
                            packets = packets.into_iter().flat_map(|p| s.process(p)).collect();
                        }
                        if strats.get("SniSplit").copied().unwrap_or(true) {
                            packets = packets
                                .into_iter()
                                .flat_map(|p| SniSplitStrategy.process(p))
                                .collect();
                        }
                        if strats.get("TcpFragment").copied().unwrap_or(true) {
                            let s = TcpFragmentStrategy::default();
                            packets = packets.into_iter().flat_map(|p| s.process(p)).collect();
                        }
                        if strats.get("FakePacket").copied().unwrap_or(true) {
                            let s = FakePacketStrategy::default();
                            packets = packets.into_iter().flat_map(|p| s.process(p)).collect();
                        }
                        if strats.get("Shuffle").copied().unwrap_or(true) {
                            packets = ShuffleStrategy.process_batch(packets);
                        }
                        packets
                    }
                } else {
                    vec![packet]
                };

                fn should_drop_udp_443(bytes: &[u8], app_handle: &tauri::AppHandle) -> bool {
                    use crate::{
                        packet_key::{ConnectionKey, TransportProtocol},
                        state::AppState,
                    };

                    let Some(key) = ConnectionKey::from_raw(bytes) else {
                        return false;
                    };

                    if key.protocol != TransportProtocol::Udp {
                        return false;
                    }

                    let state = app_handle.state::<AppState>();
                    let packet_path = state
                        .pid_for_connection_or_local_port(&key)
                        .and_then(|pid| state.path_for_pid(pid));

                    state
                        .settings_snapshot()
                        .sni_enabled_for("", packet_path.as_deref())
                }
                for mut mp in mutated_packets {
                    // Reinject the packet into the network stack
                    if let Err(e) = handle.send(&mut mp) {
                        error!("[sni] failed to send packet: {e}");
                    }
                }
            }
            Err(e) => {
                error!("[sni] recv error: {e}");
            }
        }
    }
}
