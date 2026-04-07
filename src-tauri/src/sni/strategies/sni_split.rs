use crate::sni::packet::RawPacket;

/// Splits the TLS ClientHello SNI hostname field across two TCP packets so that
/// SNI-based filters cannot read the complete hostname from a single segment.
pub struct SniSplitStrategy;

impl SniSplitStrategy {
    pub fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        let mut chunk1 = packet.clone();

        let (split_offset, payload_start, original_len, ip_header_len) = {
            let bytes = chunk1.data.as_ref();
            if bytes.is_empty() || (bytes[0] >> 4) != 4 {
                return vec![packet]; // limit to IPv4
            }

            let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
            if bytes.len() < ip_header_len + 20 {
                return vec![packet];
            }
            let tcp_header_len = ((bytes[ip_header_len + 12] >> 4) * 4) as usize;
            let payload_start = ip_header_len + tcp_header_len;
            if bytes.len() < payload_start {
                return vec![packet];
            }

            let tcp_payload = &bytes[payload_start..];
            let offset = match find_sni_middle_offset(tcp_payload) {
                Some(off) => payload_start + off,
                None => return vec![packet],
            };

            if offset <= payload_start || offset >= bytes.len() {
                return vec![packet];
            }

            (offset, payload_start, bytes.len(), ip_header_len)
        };

        // Mutate chunk1
        {
            let bytes1 = chunk1.data.to_mut();
            let new_total_len = split_offset;

            // Hack for IPv4 only (offset 2)
            bytes1[2..4].copy_from_slice(&(new_total_len as u16).to_be_bytes());

            // TCP Flags
            let flags_offset = ip_header_len + 13;
            bytes1[flags_offset] &= 0xF7; // Clear PSH

            bytes1.truncate(split_offset);
        }
        let _ = chunk1.recalculate_checksums(windivert_sys::ChecksumFlags::new());

        // Mutate chunk2
        let mut chunk2 = packet.clone();
        {
            let bytes2 = chunk2.data.to_mut();

            let tcp_start = ip_header_len;

            let mut seq_bytes = [0u8; 4];
            seq_bytes.copy_from_slice(&bytes2[tcp_start + 4..tcp_start + 8]);
            let new_seq = u32::from_be_bytes(seq_bytes) + (split_offset - payload_start) as u32;
            bytes2[tcp_start + 4..tcp_start + 8].copy_from_slice(&new_seq.to_be_bytes());

            let flags_offset = tcp_start + 13;
            bytes2[flags_offset] &= 0xF7;
            if (bytes2[flags_offset] & 0x10) != 0 {
                // it's an ACK
                bytes2[flags_offset] |= 0x10;
            }

            let chunk2_payload_len = original_len - split_offset;
            let chunk2_total_len = payload_start + chunk2_payload_len;
            bytes2[2..4].copy_from_slice(&(chunk2_total_len as u16).to_be_bytes());

            // shift payload
            bytes2.copy_within(split_offset..original_len, payload_start);
            bytes2.truncate(payload_start + chunk2_payload_len);
        }
        let _ = chunk2.recalculate_checksums(windivert_sys::ChecksumFlags::new());

        vec![chunk1, chunk2]
    }
}

fn find_sni_middle_offset(payload: &[u8]) -> Option<usize> {
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != 0x16 {
        return None;
    }
    if payload[1] != 0x03 || (payload[2] != 0x01 && payload[2] != 0x03) {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }

    let handshake_data = &payload[5..];
    if handshake_data.len() < 1 + 3 + 2 + 32 {
        return None;
    }
    if handshake_data[0] != 0x01 {
        return None;
    }

    let mut pos = 38;
    if pos >= handshake_data.len() {
        return None;
    }
    let session_id_len = handshake_data[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 1 >= handshake_data.len() {
        return None;
    }
    let cipher_suites_len =
        u16::from_be_bytes([handshake_data[pos], handshake_data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= handshake_data.len() {
        return None;
    }
    let compression_methods_len = handshake_data[pos] as usize;
    pos += 1 + compression_methods_len;

    if pos + 1 >= handshake_data.len() {
        return None;
    }
    let extensions_len =
        u16::from_be_bytes([handshake_data[pos], handshake_data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > handshake_data.len() {
        return None;
    }

    while pos + 3 < extensions_end {
        let ext_type = u16::from_be_bytes([handshake_data[pos], handshake_data[pos + 1]]);
        let ext_len =
            u16::from_be_bytes([handshake_data[pos + 2], handshake_data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            return parse_sni_extension(&handshake_data[pos..pos + ext_len], 5 + pos);
        }
        pos += ext_len;
    }
    None
}

fn parse_sni_extension(ext_data: &[u8], base_offset: usize) -> Option<usize> {
    if ext_data.len() < 2 {
        return None;
    }
    let sni_list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    if ext_data.len() < 2 + sni_list_len {
        return None;
    }

    let mut pos = 2;
    if pos >= ext_data.len() {
        return None;
    }
    let _name_type = ext_data[pos];
    pos += 1;

    if pos + 1 >= ext_data.len() {
        return None;
    }
    let name_len = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]) as usize;
    pos += 2;

    if pos + name_len > ext_data.len() {
        return None;
    }

    let hostname_offset = base_offset + pos;
    Some(hostname_offset + (name_len / 2))
}
