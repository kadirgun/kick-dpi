use crate::sni::packet::RawPacket;

/// Sends 1..N copies of the real ClientHello BEFORE it, with "fooling" markers
/// that make them harmless to the server but readable by the DPI appliance:
/// - `badsum`: IP and TCP checksums overwritten with garbage (server drops at
///   NIC), plus a low TTL as a second guard;
/// - `badseq`: TCP sequence shifted by a configurable delta so the server
///   discards it as out-of-window, checksums kept valid so DPI parses it.
///
/// This is the zapret `--dpi-desync=fake` primitive that empirically works
/// against Türk Telekom's DPI (fake-first + badsum + ttl 3-4). The DPI engine
/// locks onto the first-seen ClientHello and, if it matches a decoy, never
/// inspects the real one that follows.
pub struct FakeTlsFirstStrategy {
    pub decoy_ttl: u8,
    /// Number of decoy copies sent before the real packet (1-255).
    pub repeats: u8,
    /// "badsum" or "badseq".
    pub fooling: String,
    /// TCP sequence delta applied by the badseq fooling mode (typically negative).
    pub badseq_delta: i32,
}

impl Default for FakeTlsFirstStrategy {
    fn default() -> Self {
        Self {
            decoy_ttl: 4,
            repeats: 6,
            fooling: "badsum".to_string(),
            badseq_delta: -10000,
        }
    }
}

impl FakeTlsFirstStrategy {
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

        // Only inject before TLS records (ClientHello is gated by the listener)
        if bytes.len() < payload_start + 2
            || bytes[payload_start] != 0x16
            || bytes[payload_start + 1] != 0x03
        {
            return vec![packet];
        }

        let repeats = self.repeats.max(1);
        let mut out = Vec::with_capacity(repeats as usize + 1);

        for _ in 0..repeats {
            let mut decoy = packet.clone();
            {
                let d = decoy.data.to_mut();

                // Low TTL: the decoy dies long before reaching the server.
                d[8] = self.decoy_ttl;

                if self.fooling == "badseq" {
                    let seq_offset = ip_header_len + 4;
                    let seq = u32::from_be_bytes(d[seq_offset..seq_offset + 4].try_into().unwrap());
                    let new_seq = (seq as i64 + self.badseq_delta as i64) as u32;
                    d[seq_offset..seq_offset + 4].copy_from_slice(&new_seq.to_be_bytes());
                    // Valid checksums so DPI accepts the packet as genuine.
                    let _ = decoy.recalculate_checksums(windivert_sys::ChecksumFlags::new());
                } else {
                    // badsum: garbage IP + TCP checksums; server drops the packet,
                    // DPI engines that skip checksum validation still parse it.
                    let tcp_checksum_offset = ip_header_len + 16;
                    d[tcp_checksum_offset] = 0xDE;
                    d[tcp_checksum_offset + 1] = 0xAD;
                    d[10] = 0xDE;
                    d[11] = 0xAD;
                }
            }
            out.push(decoy);
        }

        // Decoys first, real ClientHello last
        out.push(packet);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls_packet() -> RawPacket {
        // IPv4 (20) + TCP (20) headers, then an 8-byte TLS record payload.
        let mut b = vec![0u8; 20 + 20];
        b[0] = 0x45; // IPv4, IHL 5
        b[8] = 64; // TTL
        b[12..16].copy_from_slice(&[10, 0, 0, 1]);
        b[16..20].copy_from_slice(&[93, 184, 216, 34]);
        b[20 + 12] = (5 << 4) as u8; // TCP data offset 20
        let tls = [0x16u8, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00];
        b.extend_from_slice(&tls);
        // Test helper: address is zeroed (from_raw is crate-private)
        unsafe { crate::sni::packet::RawPacket::new(b) }
    }

    #[test]
    fn emits_repeats_decoys_then_real() {
        let s = FakeTlsFirstStrategy {
            decoy_ttl: 4,
            repeats: 3,
            fooling: "badsum".into(),
            badseq_delta: -10000,
        };
        let out = s.process(tls_packet());
        assert_eq!(out.len(), 4);

        for decoy in &out[..3] {
            assert_eq!(decoy.data.as_ref()[8], 4); // TTL
            let tcp_checksum = &decoy.data.as_ref()[20 + 16..20 + 18];
            assert_eq!(tcp_checksum, &[0xDE, 0xAD]);
        }

        let real = out.last().unwrap();
        assert_eq!(real.data.as_ref()[8], 64); // untouched TTL
    }

    #[test]
    fn badseq_shifts_sequence_with_valid_checksums() {
        let s = FakeTlsFirstStrategy {
            decoy_ttl: 4,
            repeats: 2,
            fooling: "badseq".into(),
            badseq_delta: -10000,
        };
        let original = tls_packet();
        let base_seq = u32::from_be_bytes(original.data.as_ref()[24..28].try_into().unwrap());
        let out = s.process(original);
        assert_eq!(out.len(), 3);

        let decoy_seq = u32::from_be_bytes(out[0].data.as_ref()[24..28].try_into().unwrap());
        let expected = (base_seq as i64 - 10000) as u32;
        assert_eq!(decoy_seq, expected);
        assert_ne!(out[0].data.as_ref()[8], 64);
        // checksums were recalculated, not 0xDEAD
        assert_ne!(&out[0].data.as_ref()[20 + 16..20 + 18], &[0xDE, 0xAD]);
    }
}
