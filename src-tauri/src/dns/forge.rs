/// Forges an IPv4/UDP packet that looks like the DNS server's reply coming
/// back to the original querying process.
///
/// Takes:
/// - `original`: the raw bytes of the outgoing DNS query packet (IP + UDP + DNS)
/// - `dns_response`: the raw DNS wire-format response received from the DoH server
///
/// Returns the forged inbound packet bytes ready for WinDivert injection with
/// the INBOUND flag set.
pub fn forge_dns_response(original: &[u8], dns_response: &[u8]) -> Option<Vec<u8>> {
    // --- Parse original query IP header ---
    if original.is_empty() || (original[0] >> 4) != 4 {
        return None;
    }

    let ip_ihl = ((original[0] & 0x0F) * 4) as usize;
    if original.len() < ip_ihl + 8 {
        return None; // need at least UDP header
    }

    // Src/Dst IP from original query
    let src_ip = &original[12..16]; // querier IP  (becomes dst in reply)
    let dst_ip = &original[16..20]; // DNS server IP (becomes src in reply)

    // Src/Dst port from original UDP header
    let src_port = u16::from_be_bytes([original[ip_ihl], original[ip_ihl + 1]]); // querier port
    let udp_dst_port = u16::from_be_bytes([original[ip_ihl + 2], original[ip_ihl + 3]]); // should be 53

    // The forged reply:  src = DNS server (dst_ip:53), dst = querier (src_ip:src_port)
    let udp_len = (8 + dns_response.len()) as u16;
    let ip_total = ip_ihl + 8 + dns_response.len();

    let mut pkt = Vec::with_capacity(ip_total);

    // --- IPv4 header (20 bytes, no options) ---
    pkt.push(0x45); // version=4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&(ip_total as u16).to_be_bytes()); // total length
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // flags=DF, frag offset=0
    pkt.push(64); // TTL
    pkt.push(17); // protocol = UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder (WinDivert recalculates)
    pkt.extend_from_slice(dst_ip); // src IP = original dst (DNS server)
    pkt.extend_from_slice(src_ip); // dst IP = original src (querier)

    // --- UDP header (8 bytes) ---
    pkt.extend_from_slice(&udp_dst_port.to_be_bytes()); // src port = 53
    pkt.extend_from_slice(&src_port.to_be_bytes()); // dst port = querier's ephemeral port
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder

    // --- DNS response payload ---
    pkt.extend_from_slice(dns_response);

    Some(pkt)
}
