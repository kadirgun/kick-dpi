use crate::sni::packet::RawPacket;

/// Classic TCP overlap attack. Injects a decoy segment covering the SAME TCP
/// sequence range as the real packet but with garbage payload. Some DPI engines
/// accept the first arriving segment for a given sequence range; the server's
/// TCP stack typically handles retransmits correctly and uses the later (real)
/// segment. Net result: DPI reassembles noise while the server sees the truth.
///
/// The decoy has a low TTL so it is unlikely to reach the server, but even if
/// it does, the real segment arriving later will replace it in the server's
/// receive buffer (last-writer-wins reassembly behavior on many OSes).
pub struct OverlapStrategy {
    pub decoy_ttl: u8,
}

impl Default for OverlapStrategy {
    fn default() -> Self {
        Self { decoy_ttl: 4 }
    }
}

impl OverlapStrategy {
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

        // Only target TLS records
        if bytes.len() < payload_start + 2
            || bytes[payload_start] != 0x16
            || bytes[payload_start + 1] != 0x03
        {
            return vec![packet];
        }

        let payload_len = bytes.len() - payload_start;
        if payload_len == 0 {
            return vec![packet];
        }

        let mut decoy = packet.clone();
        {
            let d = decoy.data.to_mut();

            // Low TTL
            d[8] = self.decoy_ttl;

            // Same sequence number as the real packet — this is the overlap.
            // The payload bytes are overwritten with a repeating 0xFF pattern so
            // DPI sees an unparseable record while keeping the same byte count.
            for b in d[payload_start..].iter_mut() {
                *b = 0xFF;
            }
        }

        // Recalculate checksums so the decoy is a structurally valid IP/TCP packet
        // (only the application layer is garbage). This maximizes the chance that
        // the DPI engine accepts and parses it.
        let _ = decoy.recalculate_checksums(windivert_sys::ChecksumFlags::new());

        // Decoy first — it races to the DPI engine while the real packet follows
        vec![decoy, packet]
    }
}
