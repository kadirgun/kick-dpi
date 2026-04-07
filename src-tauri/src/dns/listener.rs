use log::{error, info};
use std::sync::Arc;
use windivert::{
    address::WinDivertAddress, layer::NetworkLayer, packet::WinDivertPacket,
    prelude::WinDivertFlags, WinDivert,
};
use windivert_sys::ChecksumFlags;

use super::{doh, forge, parse};

// WinDivert filter: outgoing UDP packets destined for port 53
const DNS_FILTER: &str = "udp.DstPort == 53 and outbound";

pub fn start_dns_listener() {
    std::thread::Builder::new()
        .name("windivert-dns".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(run_dns_listener)
        .expect("failed to spawn DNS listener thread");
}

fn run_dns_listener() {
    let client = Arc::new(doh::build_client());

    let handle = match WinDivert::network(DNS_FILTER, 1, WinDivertFlags::default()) {
        Ok(h) => {
            info!("[dns] WinDivert handle opened (filter: {DNS_FILTER})");
            Arc::new(h)
        }
        Err(e) => {
            error!("[dns] Failed to open WinDivert handle: {e}");
            return;
        }
    };

    let mut buf = vec![0u8; 65_535];

    info!("[dns] listener loop started");

    loop {
        match handle.recv(&mut buf) {
            Ok(packet) => {
                let packet = packet.into_owned();
                let bytes = packet.data.as_ref().to_vec();
                let addr = packet.address;

                let client = Arc::clone(&client);
                let handle = Arc::clone(&handle);

                // Spawn an async task so the recv loop is never blocked by
                // the outgoing HTTP request to the DoH server.
                tauri::async_runtime::spawn(async move {
                    handle_dns_packet(&handle, &client, bytes, addr).await;
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

    info!("[dns] {} QTYPE={}", query.name, query.qtype);

    let doh_response = match doh::query_doh(client, &query.wire).await {
        Ok(r) => r,
        Err(e) => {
            error!("[dns] DoH request failed for {}: {e}", query.name);
            // Fall back: let the original query reach the system DNS
            reinject_original(handle, raw, addr);
            return;
        }
    };

    let forged = match forge::forge_dns_response(&raw, &doh_response) {
        Some(p) => p,
        None => {
            error!("[dns] Failed to forge response for {}", query.name);
            reinject_original(handle, raw, addr);
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

    // The original outgoing query is simply dropped (not reinjected) so the
    // real DNS server never receives it.
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
