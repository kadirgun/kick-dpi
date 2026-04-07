use crate::sni::packet::RawPacket;

/// Injects a crafted decoy packet before the real one. The decoy has a low TTL
/// so it reaches the DPI appliance but expires before reaching the server,
/// confusing stateful inspection engines.
pub struct FakePacketStrategy {
    #[allow(dead_code)]
    pub decoy_ttl: u8,
}

impl Default for FakePacketStrategy {
    fn default() -> Self {
        Self { decoy_ttl: 4 } // common low TTL for decoys
    }
}

impl FakePacketStrategy {
    pub fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        // Only fire if it's HTTPS (we can rely on the BPF filter, but let's double check)
        // If it has payload: TLS ClientHello is the most important to decoy.
        let bytes = packet.data.as_ref();
        if bytes.is_empty() || (bytes[0] >> 4) != 4 {
            return vec![packet]; // not IPv4
        }

        let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
        if bytes.len() <= ip_header_len + 20 {
            return vec![packet]; // no payload
        }

        // TLS ClientHello starts with 0x16 0x03
        let tcp_header_len = ((bytes[ip_header_len + 12] >> 4) * 4) as usize;
        let payload_start = ip_header_len + tcp_header_len;

        if bytes.len() < payload_start + 2
            || bytes[payload_start] != 0x16
            || bytes[payload_start + 1] != 0x03
        {
            return vec![packet];
        }

        let mut decoy = packet.clone();
        let mut trailing_decoy = packet.clone();

        for d in [decoy.data.to_mut(), trailing_decoy.data.to_mut()] {
            // Set the IPv4 TTL to decoy_ttl
            d[8] = self.decoy_ttl;
            // Corrupt the TLS Content Type so DPI sees invalid data
            if d.len() > payload_start {
                d[payload_start] ^= 0x42;
            }
        }

        // Recalculate checksums for both decoys
        let _ = decoy.recalculate_checksums(windivert_sys::ChecksumFlags::new());
        let _ = trailing_decoy.recalculate_checksums(windivert_sys::ChecksumFlags::new());

        // [sahte, gercek, sahte] — DPI motoru once fake gorur, gercegi anlamaz, sonra fake gorur
        vec![decoy, packet, trailing_decoy]
    }
}
