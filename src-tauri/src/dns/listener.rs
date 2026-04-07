use log::{error, info};
use std::sync::{Arc, Mutex};
use tauri::Manager;
use windivert::{
    address::WinDivertAddress, layer::NetworkLayer, packet::WinDivertPacket,
    prelude::WinDivertFlags, ShutdownHandle, WinDivert,
};
use windivert_sys::ChecksumFlags;

use super::{doh, forge, parse};

// WinDivert filter: outgoing UDP packets destined for port 53
const DNS_FILTER: &str = "udp.DstPort == 53 and outbound";

static DNS_SHUTDOWN: Mutex<Option<ShutdownHandle>> = Mutex::new(None);

pub fn stop_dns_listener() {
    if let Ok(mut guard) = DNS_SHUTDOWN.lock() {
        if let Some(sh) = guard.take() {
            let _ = sh.shutdown();
        }
    }
}

pub fn start_dns_listener(app_handle: tauri::AppHandle) {
    std::thread::Builder::new()
        .name("windivert-dns".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(move || run_dns_listener(app_handle))
        .expect("failed to spawn DNS listener thread");
}

fn run_dns_listener(app_handle: tauri::AppHandle) {
    let client = Arc::new(doh::build_client());

    let handle = match WinDivert::network(DNS_FILTER, 1, WinDivertFlags::default()) {
        Ok(h) => {
            info!("[dns] WinDivert handle opened (filter: {DNS_FILTER})");
            let handle = Arc::new(h);
            if let Ok(mut guard) = DNS_SHUTDOWN.lock() {
                *guard = Some(handle.shutdown_handle());
            }
            handle
        }
        Err(e) => {
            error!("[dns] Failed to open WinDivert handle: {e}");
            return;
        }
    };

    let buf_size = app_handle
        .state::<crate::state::AppState>()
        .settings_snapshot()
        .app
        .performance
        .dns_buffer_size;
    let mut buf = vec![0u8; buf_size];

    info!("[dns] listener loop started");

    loop {
        match handle.recv(&mut buf) {
            Ok(packet) => {
                let packet = packet.into_owned();
                let bytes = packet.data.as_ref().to_vec();
                let addr = packet.address;

                let client = Arc::clone(&client);
                let handle = Arc::clone(&handle);
                let app_handle = app_handle.clone();

                // Spawn an async task so the recv loop is never blocked by
                // the outgoing HTTP request to the DoH server.
                tauri::async_runtime::spawn(async move {
                    handle_dns_packet(&handle, &client, bytes, addr, &app_handle).await;
                });
            }
            Err(e) => {
                error!("[dns] recv error: {e}");
            }
        }
    }
}

async fn handle_dns_packet(
    handle: &WinDivert<NetworkLayer>,
    client: &reqwest::Client,
    raw: Vec<u8>,
    addr: WinDivertAddress<NetworkLayer>,
    app_handle: &tauri::AppHandle,
) {
    // Locate the start of the UDP payload (= raw DNS message)
    let ip_ihl = match raw.first() {
        Some(b) if (b >> 4) == 4 => ((b & 0x0F) * 4) as usize,
        _ => return,
    };

    if raw.len() < ip_ihl + 8 {
        return;
    }

    let udp_payload_len = u16::from_be_bytes([raw[ip_ihl + 4], raw[ip_ihl + 5]]) as usize - 8;
    let dns_start = ip_ihl + 8;
    let dns_end = dns_start + udp_payload_len;

    if dns_end > raw.len() {
        // Malformed packet — let it through rather than silently dropping
        reinject_original(handle, raw, addr);
        return;
    }

    let dns_wire = &raw[dns_start..dns_end];

    let query = match parse::parse_query(dns_wire) {
        Some(q) => q,
        None => {
            // Not a parseable query (could be a response or unusual format)
            reinject_original(handle, raw, addr);
            return;
        }
    };

    {
        use crate::{packet_key::ConnectionKey, state::AppState};

        let state = app_handle.state::<AppState>();
        let packet_path = ConnectionKey::from_raw(&raw).and_then(|key| {
            let pid = state.pid_for_connection_or_local_port(&key)?;
            state.path_for_pid(pid)
        });

        if !state
            .settings_snapshot()
            .dns_enabled_for(&query.name, packet_path.as_deref())
        {
            reinject_original(handle, raw, addr);
            return;
        }

        info!("[dns] {} QTYPE={}", query.name, query.qtype);

        state.inc_dns();
    }

    // Always let the original query reach the real DNS server immediately.
    // This guarantees DNS resolution works even if DoH is slow or fails.
    reinject_original(handle, raw.clone(), addr.clone());

    // Also try DoH — if it responds before the real DNS answer arrives, the
    // OS receives a correct (unblocked) answer first.
    let (doh_url, doh_timeout_ms) = {
        use crate::state::AppState;
        let settings = app_handle.state::<AppState>().settings_snapshot();
        let dns = &settings.app.dns;
        (
            doh::provider_url(&dns.provider, dns.custom_url.as_deref()),
            dns.timeout_ms,
        )
    };
    let doh_response = match doh::query_doh(client, &query.wire, &doh_url, doh_timeout_ms).await {
        Ok(r) => r,
        Err(e) => {
            error!("[dns] DoH request failed for {}: {e}", query.name);
            return; // original already reinjected above
        }
    };

    let forged = match forge::forge_dns_response(&raw, &doh_response) {
        Some(p) => p,
        None => {
            error!("[dns] Failed to forge response for {}", query.name);
            return;
        }
    };

    // Build an inbound-flagged packet so the OS delivers it to the waiting socket
    let mut inbound_addr = addr;
    inbound_addr.set_outbound(false);

    let mut reply: WinDivertPacket<'static, NetworkLayer> = WinDivertPacket {
        address: inbound_addr,
        data: std::borrow::Cow::Owned(forged),
    };

    let _ = reply.recalculate_checksums(ChecksumFlags::new());

    if let Err(e) = handle.send(&mut reply) {
        error!("[dns] Failed to inject DoH reply: {e}");
    }
}

/// Reinjection helper — forwards the original packet unchanged when we cannot
/// (or should not) replace it with a DoH response.
fn reinject_original(
    handle: &WinDivert<NetworkLayer>,
    raw: Vec<u8>,
    addr: WinDivertAddress<NetworkLayer>,
) {
    let mut pkt: WinDivertPacket<'static, NetworkLayer> = WinDivertPacket {
        address: addr,
        data: std::borrow::Cow::Owned(raw),
    };
    if let Err(e) = handle.send(&mut pkt) {
        error!("[dns] Failed to reinject original DNS packet: {e}");
    }
}
