use log::{error, info};
use std::sync::Mutex;
use windivert::{prelude::WinDivertFlags, ShutdownHandle, WinDivert};

use super::strategies::{
    FakePacketStrategy, FakeSniStrategy, IpFragStrategy, OverlapStrategy, ShuffleStrategy,
    SniSplitStrategy, TcpFragmentStrategy, WrongChecksumStrategy,
};

fn extract_sni(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || (bytes[0] >> 4) != 4 {
        return None;
    }

    let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
    if bytes.len() <= ip_header_len + 20 {
        return None; // not enough for TCP
    }

    let tcp_header_len = ((bytes[ip_header_len + 12] >> 4) * 4) as usize;
    let payload_start = ip_header_len + tcp_header_len;

    if bytes.len() < payload_start + 43 {
        return None;
    }

    let payload = &bytes[payload_start..];

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
pub(super) fn run_listener(filter: &str) {
    let wrong_checksum = WrongChecksumStrategy::default();
    let fake_sni = FakeSniStrategy::default();
    let overlap = OverlapStrategy::default();
    let ip_frag = IpFragStrategy::default();
    let sni_split = SniSplitStrategy;
    let tcp_fragment = TcpFragmentStrategy::default();
    let fake_packet = FakePacketStrategy::default();
    let shuffle = ShuffleStrategy;
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

    let mut buf = vec![0u8; 65_535];

    info!("[sni] listener loop started");

    loop {
        match handle.recv(&mut buf) {
            Ok(packet) => {
                let packet = packet.into_owned();
                let bytes = packet.data.as_ref();

                let mutated_packets = if let Some(sni) = extract_sni(bytes) {
                    info!("[sni] SNI Packet: {}", sni);
                    let packets = wrong_checksum.process(packet);
                    let packets: Vec<_> = packets
                        .into_iter()
                        .flat_map(|p| fake_sni.process(p))
                        .collect();
                    let packets: Vec<_> = packets
                        .into_iter()
                        .flat_map(|p| overlap.process(p))
                        .collect();
                    let packets: Vec<_> = packets
                        .into_iter()
                        .flat_map(|p| ip_frag.process(p))
                        .collect();
                    let packets: Vec<_> = packets
                        .into_iter()
                        .flat_map(|p| sni_split.process(p))
                        .collect();
                    let packets: Vec<_> = packets
                        .into_iter()
                        .flat_map(|p| tcp_fragment.process(p))
                        .collect();
                    let packets: Vec<_> = packets
                        .into_iter()
                        .flat_map(|p| fake_packet.process(p))
                        .collect();
                    shuffle.process_batch(packets)
                } else {
                    vec![packet]
                };

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
