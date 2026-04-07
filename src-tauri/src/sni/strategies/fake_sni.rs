use crate::sni::packet::RawPacket;

/// Injects a syntactically valid TLS ClientHello before the real one, but with
/// the SNI hostname replaced by random ASCII characters of the same length.
/// The decoy has a low TTL so it is dropped before reaching the server, but
/// stateful DPI engines read it first and associate the connection with the
/// wrong (fake) domain — causing their state machine to misclassify or ignore
/// the subsequent real traffic.
pub struct FakeSniStrategy {
    pub decoy_ttl: u8,
}

impl Default for FakeSniStrategy {
    fn default() -> Self {
        Self { decoy_ttl: 4 }
    }
}

impl FakeSniStrategy {
    pub fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        let bytes = packet.data.as_ref();

        // IPv4 only
        if bytes.is_empty() || (bytes[0] >> 4) != 4 {
            return vec![packet];
        }

        let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
        if bytes.len() <= ip_header_len + 20 {
            return vec![packet];
        }

        let tcp_header_len = ((bytes[ip_header_len + 12] >> 4) * 4) as usize;
        let payload_start = ip_header_len + tcp_header_len;

        // Must be a TLS ClientHello
        if bytes.len() < payload_start + 6
            || bytes[payload_start] != 0x16
            || bytes[payload_start + 1] != 0x03
            || bytes[payload_start + 5] != 0x01
        {
            return vec![packet];
        }

        // Find the SNI hostname range inside the payload
        let tcp_payload = &bytes[payload_start..];
        let (sni_start, sni_len) = match find_sni_range(tcp_payload) {
            Some(r) => r,
            None => return vec![packet],
        };

        // Absolute offsets from packet start
        let abs_sni_start = payload_start + sni_start;
        let abs_sni_end = abs_sni_start + sni_len;

        if abs_sni_end > bytes.len() {
            return vec![packet];
        }

        let mut decoy = packet.clone();
        {
            let d = decoy.data.to_mut();

            // Set low TTL so the packet dies before reaching the server
            d[8] = self.decoy_ttl;

            // Replace the SNI hostname bytes with deterministic-looking but
            // invalid ASCII (repeating 'x' shifted by position — cheap, no RNG needed)
            for (i, b) in d[abs_sni_start..abs_sni_end].iter_mut().enumerate() {
                *b = b'a' + (i % 26) as u8;
            }
        }

        let _ = decoy.recalculate_checksums(windivert_sys::ChecksumFlags::new());

        // Decoy first, then the real packet
        vec![decoy, packet]
    }
}

/// Returns `(sni_hostname_offset_in_payload, sni_hostname_len)`.
/// Parses TLS record → Handshake → ClientHello → Extensions → SNI extension.
fn find_sni_range(payload: &[u8]) -> Option<(usize, usize)> {
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }

    let handshake = &payload[5..];
    if handshake.len() < 38 || handshake[0] != 0x01 {
        return None;
    }

    let mut pos = 38usize;

    // Skip Session ID
    if pos >= handshake.len() {
        return None;
    }
    pos += 1 + handshake[pos] as usize;

    // Skip Cipher Suites
    if pos + 1 >= handshake.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Skip Compression Methods
    if pos >= handshake.len() {
        return None;
    }
    pos += 1 + handshake[pos] as usize;

    // Extensions
    if pos + 1 >= handshake.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > handshake.len() {
        return None;
    }

    while pos + 3 < ext_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension: list_len(2) + name_type(1) + name_len(2) + hostname
            let ext_data = &handshake[pos..pos + elen];
            if ext_data.len() >= 5 {
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if 5 + name_len <= ext_data.len() {
                    // offset from payload start: 5 (record hdr) + pos + 5 (sni hdr)
                    let hostname_offset = 5 + pos + 5;
                    return Some((hostname_offset, name_len));
                }
            }
        }
        pos += elen;
    }

    None
}
