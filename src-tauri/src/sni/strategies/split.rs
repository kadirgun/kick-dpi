use super::tls_offsets::{parse_tls, TlsInfo};
use crate::sni::packet::RawPacket;

/// Splits the ClientHello TCP payload at protocol-aware positions so no single
/// segment carries the complete SNI hostname. Position markers follow the
/// zapret syntax: `1`, `sniext`, `sniext+N`, `host`, `host+N`, `midsld`,
/// `sld`, `endsld`, or a plain number. Türk Telekom's DPI is defeated with
/// `1,sniext+1` (verified community preset).
pub struct SplitStrategy {
    pub positions: Vec<String>,
}

impl Default for SplitStrategy {
    fn default() -> Self {
        Self {
            positions: vec!["1".to_string(), "sniext+1".to_string()],
        }
    }
}

impl SplitStrategy {
    pub fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        let bytes = packet.data.as_ref();

        if bytes.is_empty() || (bytes[0] >> 4) != 4 {
            return vec![packet];
        }

        let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
        if bytes.len() < ip_header_len + 20 {
            return vec![packet];
        }

        let tcp_header_len = ((bytes[ip_header_len + 12] >> 4) * 4) as usize;
        let payload_start = ip_header_len + tcp_header_len;
        let payload_len = bytes.len().saturating_sub(payload_start);
        if payload_len < 6 {
            return vec![packet];
        }

        let tls_info = parse_tls(&bytes[payload_start..]);
        let splits = resolve_positions(&self.positions, payload_len, tls_info.as_ref());
        if splits.is_empty() {
            return vec![packet];
        }

        build_fragments(packet, ip_header_len, payload_start, payload_len, &splits)
    }
}

/// Resolves position markers into sorted, unique, payload-relative split
/// offsets. Invalid markers are ignored; out-of-range markers are clamped.
pub fn resolve_positions(
    positions: &[String],
    payload_len: usize,
    tls_info: Option<&TlsInfo>,
) -> Vec<usize> {
    let mut offsets: Vec<usize> = Vec::new();

    for marker in positions {
        let marker = marker.trim();
        if marker.is_empty() {
            continue;
        }

        let (name, add) = match marker.find('+') {
            Some(i) => {
                let add = marker[i + 1..].trim().parse::<usize>().unwrap_or(0);
                (&marker[..i], add)
            }
            None => (marker, 0),
        };

        let base = if name == "sniext" {
            tls_info.and_then(|t| t.sniext)
        } else if name == "host" {
            tls_info.and_then(|t| t.host)
        } else if name == "sld" {
            tls_info.and_then(|t| t.sld)
        } else if name == "endsld" {
            tls_info.and_then(|t| match t.sld {
                Some(s) => Some(s + t.sld_len_marker()),
                None => None,
            })
        } else if name == "midsld" {
            tls_info.and_then(|t| t.midsld())
        } else {
            name.parse::<usize>().ok()
        };

        if let Some(base) = base {
            let offset = base + add;
            if offset > 0 && offset < payload_len {
                offsets.push(offset);
            }
        }
    }

    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

impl TlsInfo {
    /// Length of the SLD region (last two labels) from `sld` to hostname end.
    pub fn sld_len_marker(&self) -> usize {
        match (self.host, self.sld) {
            (Some(h), Some(s)) => (h + self.host_len).saturating_sub(s),
            _ => 0,
        }
    }

    /// Middle of the SLD region ("middle of second-level domain").
    pub fn midsld(&self) -> Option<usize> {
        self.sld.map(|s| s + self.sld_len_marker() / 2)
    }
}

/// Builds one TCP packet per payload window between split offsets.
/// Sequence numbers advance correctly; PSH is cleared on all but the last
/// fragment; checksums are recalculated.
pub fn build_fragments(
    packet: RawPacket,
    ip_header_len: usize,
    payload_start: usize,
    payload_len: usize,
    splits: &[usize],
) -> Vec<RawPacket> {
    let bytes = packet.data.as_ref();
    let base_seq = u32::from_be_bytes(
        bytes[ip_header_len + 4..ip_header_len + 8]
            .try_into()
            .unwrap(),
    );
    let original_flags = bytes[ip_header_len + 13];

    let mut boundaries: Vec<usize> = vec![0];
    boundaries.extend_from_slice(splits);
    boundaries.push(payload_len);

    let mut chunks = Vec::with_capacity(boundaries.len() - 1);

    for window in boundaries.windows(2) {
        let start = window[0];
        let end = window[1];
        let is_last = end == payload_len;

        let mut chunk = packet.clone();
        {
            let b = chunk.data.to_mut();

            let seq = base_seq.wrapping_add(start as u32);
            b[ip_header_len + 4..ip_header_len + 8].copy_from_slice(&seq.to_be_bytes());

            let flags_offset = ip_header_len + 13;
            if is_last {
                b[flags_offset] = original_flags;
            } else {
                b[flags_offset] = original_flags & 0xF7; // clear PSH
            }

            let chunk_payload_start = payload_start + start;
            let chunk_payload_end = payload_start + end;
            b.copy_within(chunk_payload_start..chunk_payload_end, payload_start);
            let new_total = payload_start + (end - start);
            b.truncate(new_total);
            b[2..4].copy_from_slice(&(new_total as u16).to_be_bytes());
        }

        let _ = chunk.recalculate_checksums(windivert_sys::ChecksumFlags::new());
        chunks.push(chunk);
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_positions_split_payload() {
        // payload_len = 8, splits at 2 and 5 → chunks [0..2], [2..5], [5..8]
        let mut b = vec![0u8; 40 + 8];
        b[0] = 0x45;
        b[20 + 12] = (5 << 4) as u8;
        b[20 + 13] = 0x18; // PSH|ACK
        let packet = unsafe { crate::sni::packet::RawPacket::new(b) };

        let frags = build_fragments(packet, 20, 40, 8, &[2, 5]);
        assert_eq!(frags.len(), 3);

        let psh_bit = 0x08;
        assert_eq!(frags[0].data.as_ref()[20 + 13] & psh_bit, 0);
        assert_eq!(frags[1].data.as_ref()[20 + 13] & psh_bit, 0);
        assert_eq!(frags[2].data.as_ref()[20 + 13] & psh_bit, psh_bit);
        assert_eq!(frags[0].data.as_ref()[2..4], [0, 42]); // IP(20)+TCP(20)+2 payload
    }
}
