use crate::sni::packet::RawPacket;

/// Sends a clone of the packet with a deliberately invalid TCP checksum before
/// the real one. The destination server's OS drops it (checksum mismatch), but
/// many DPI appliances skip checksum validation and parse the payload — reading
/// the corrupted / misleading data and building wrong connection state.
pub struct WrongChecksumStrategy {
    pub decoy_ttl: u8,
}

impl Default for WrongChecksumStrategy {
    fn default() -> Self {
        Self { decoy_ttl: 4 }
    }
}

impl WrongChecksumStrategy {
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

        // Only inject for TLS records
        if bytes.len() < payload_start + 2
            || bytes[payload_start] != 0x16
            || bytes[payload_start + 1] != 0x03
        {
            return vec![packet];
        }

        let mut decoy = packet.clone();
        {
            let d = decoy.data.to_mut();

            // Low TTL — server OS drops it even if checksum were valid
            d[8] = self.decoy_ttl;

            // Write an obviously invalid TCP checksum (0xDEAD) at TCP checksum offset
            let tcp_checksum_offset = ip_header_len + 16;
            if d.len() > tcp_checksum_offset + 1 {
                d[tcp_checksum_offset] = 0xDE;
                d[tcp_checksum_offset + 1] = 0xAD;
            }

            // Also invalidate IP checksum
            let ip_checksum_offset = 10;
            if d.len() > ip_checksum_offset + 1 {
                d[ip_checksum_offset] = 0xDE;
                d[ip_checksum_offset + 1] = 0xAD;
            }
            // Intentionally NOT calling recalculate_checksums — we want bad checksums
        }

        vec![decoy, packet]
    }
}
