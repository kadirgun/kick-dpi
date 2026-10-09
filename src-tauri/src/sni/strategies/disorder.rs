use super::split::{build_fragments, resolve_positions};
use super::tls_offsets::parse_tls;
use crate::sni::packet::RawPacket;

/// Multi-disorder: fragments the ClientHello at the configured positions and
/// sends the fragments OUT OF ORDER (last first). The server's TCP stack
/// reassembles out-of-order segments normally, while DPI engines that do not
/// buffer out-of-window data fail to see the complete hostname.
pub struct DisorderStrategy {
    pub positions: Vec<String>,
}

impl Default for DisorderStrategy {
    fn default() -> Self {
        Self {
            positions: vec!["midsld".to_string()],
        }
    }
}

impl DisorderStrategy {
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

        let mut fragments =
            build_fragments(packet, ip_header_len, payload_start, payload_len, &splits);
        if fragments.len() < 2 {
            return fragments;
        }

        fragments.reverse();
        fragments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_with_payload(payload: &[u8]) -> RawPacket {
        let mut b = vec![0u8; 40];
        b[0] = 0x45;
        b[20 + 12] = (5 << 4) as u8;
        b[20 + 13] = 0x18;
        b.extend_from_slice(payload);
        unsafe { crate::sni::packet::RawPacket::new(b) }
    }

    #[test]
    fn reverses_fragment_order() {
        let payload = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00, 0x00];
        let out = DisorderStrategy {
            positions: vec!["2".into()],
        }
        .process(packet_with_payload(&payload));

        assert_eq!(out.len(), 2);
        // Out of order: fragment covering [2..8] first, [0..2] second.
        let first_payload = &out[0].data.as_ref()[40..];
        let second_payload = &out[1].data.as_ref()[40..];
        assert_eq!(first_payload, &payload[2..]);
        assert_eq!(second_payload, &payload[..2]);
    }
}
