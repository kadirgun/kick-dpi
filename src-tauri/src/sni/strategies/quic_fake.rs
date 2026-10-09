use crate::sni::packet::RawPacket;

/// Sends copies of the outbound QUIC Initial packet (UDP/443, long header)
/// BEFORE the original with fooling markers: a randomized SCID and a garbage
/// UDP checksum, so the server never receives them but the DPI appliance sees
/// plausible Initials first. Zapret-equivalent of `--filter-udp=443
/// --dpi-desync=fake --dpi-desync-repeats=N` ( Türk Telekom verified: repeats 6-11).
///
/// The returned vector contains ONLY decoys; the caller drops the original
/// packet (same semantic as the block mode: QUIC traffic is killed so the
/// client falls back to TCP, but the DPI engine is fed decoy state first).
pub struct QuicFakeStrategy {
    pub decoy_ttl: u8,
    /// Number of decoy Initials sent per captured Initial (1-255).
    pub repeats: u8,
}

impl Default for QuicFakeStrategy {
    fn default() -> Self {
        Self { decoy_ttl: 4, repeats: 6 }
    }
}

impl QuicFakeStrategy {
    pub fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        let bytes = packet.data.as_ref();

        if bytes.is_empty() || (bytes[0] >> 4) != 4 {
            return vec![];
        }

        let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
        if bytes.len() < ip_header_len + 8 {
            return vec![];
        }

        // UDP payload start = QUIC header start
        let quic_start = ip_header_len + 8;

        // Long header required for Initial; short-header packets have no CIDs
        // to spoof and are useless as decoys.
        if !is_quic_initial(&bytes[quic_start..]) {
            return vec![];
        }

        let scid_range = match scid_range(&bytes[quic_start..]) {
            Some(r) => (quic_start + r.0, quic_start + r.1),
            None => return vec![],
        };

        let repeats = self.repeats.max(1);
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ (bytes.len() as u64))
            .unwrap_or(0xdeadbeef);

        let mut out = Vec::with_capacity(repeats as usize);
        for _ in 0..repeats {
            let mut decoy = packet.clone();
            {
                let d = decoy.data.to_mut();

                // Low TTL so the decoy dies before reaching the server.
                d[8] = self.decoy_ttl;

                // Randomize SCID bytes (same length) so the DPI sees a
                // different connection identity than the real one.
                for i in scid_range.0..scid_range.1 {
                    seed = seed
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    d[i] = (seed >> 33) as u8;
                }

                // Garbage UDP checksum — server drops even if TTL survived.
                let udp_checksum_offset = ip_header_len + 6;
                d[udp_checksum_offset] = 0xDE;
                d[udp_checksum_offset + 1] = 0xAD;
            }
            out.push(decoy);
        }

        out
    }
}

/// True if the packet bytes at `quic` start with a long header whose version
/// is non-zero (i.e. a QUIC Initial — the first packets of every connection).
pub fn is_quic_initial(quic: &[u8]) -> bool {
    if quic.len() < 6 {
        return false;
    }
    // Long header bit + version != 0 (0 = version negotiation, not Initial)
    (quic[0] & 0x80) != 0 && u32::from_be_bytes(quic[1..5].try_into().unwrap()) != 0
}

/// Returns `(start, end)` of the SCID field within the QUIC header, if present.
fn scid_range(quic: &[u8]) -> Option<(usize, usize)> {
    if quic.len() < 6 {
        return None;
    }
    let dcid_len = quic[5] as usize;
    let scid_len_pos = 6 + dcid_len;
    if scid_len_pos >= quic.len() {
        return None;
    }
    let scid_len = quic[scid_len_pos] as usize;
    let start = scid_len_pos + 1;
    if start + scid_len > quic.len() || scid_len == 0 {
        return None;
    }
    Some((start, start + scid_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quic_packet(scid_len: usize) -> RawPacket {
        let mut quic = vec![0xc0u8]; // long header
        quic.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version 1
        quic.push(8); // DCID len
        quic.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // DCID
        quic.push(scid_len as u8); // SCID len
        quic.extend_from_slice(&vec![0xAA; scid_len]);
        quic.extend_from_slice(&vec![0; 1200 - quic.len()]);

        let mut b = vec![0x45u8, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 1, 2, 3, 4];
        b.extend_from_slice(&54321u16.to_be_bytes()); // src port
        b.extend_from_slice(&443u16.to_be_bytes()); // dst port
        b.extend_from_slice(&((8 + quic.len()) as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0]); // checksum placeholder
        b.extend_from_slice(&quic);

        unsafe { crate::sni::packet::RawPacket::new(b) }
    }

    #[test]
    fn emits_decoys_without_original() {
        let s = QuicFakeStrategy { decoy_ttl: 4, repeats: 6 };
        let packet = quic_packet(16);
        let out = s.process(packet);

        assert_eq!(out.len(), 6);
        for decoy in &out {
            assert_eq!(decoy.data.as_ref()[8], 4); // TTL
            // UDP checksum garbage
            assert_eq!(&decoy.data.as_ref()[20 + 6..20 + 8], &[0xDE, 0xAD]);
        }
    }

    #[test]
    fn short_header_packets_get_no_decoy() {
        let mut packet = quic_packet(16);
        {
            let b = packet.data.to_mut();
            b[20 + 8] = 0x40; // short header (long bit cleared)
        }
        let out = QuicFakeStrategy::default().process(packet);
        assert!(out.is_empty());
    }

    #[test]
    fn zero_scid_gets_no_decoy() {
        let packet = quic_packet(0);
        let out = QuicFakeStrategy::default().process(packet);
        assert!(out.is_empty());
    }
}
