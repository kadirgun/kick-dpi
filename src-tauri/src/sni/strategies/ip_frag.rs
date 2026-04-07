use crate::sni::packet::RawPacket;

/// Splits the packet at the IP layer using IP fragmentation (RFC 791).
/// Sets the "More Fragments" flag and Fragment Offset in the IP header so the
/// payload is split into two IP fragments. Many DPI devices do not perform IP
/// reassembly and inspect each fragment in isolation, missing the full TLS record.
///
/// Note: IPv4 fragmentation only. The IP header is modified in-place; TCP and
/// upper-layer checksums remain as-is (the receiver's IP stack reassembles
/// before passing to TCP, so the TCP checksum over the full payload is valid).
pub struct IpFragStrategy {
    /// How many bytes of the IP payload to put in the first fragment.
    /// Must be a multiple of 8 (IP fragment offset unit).
    pub first_frag_payload_bytes: usize,
}

impl Default for IpFragStrategy {
    fn default() -> Self {
        // 8 bytes in first fragment — just enough to split the TCP header
        // from the payload, or any sensible power-of-8 split point.
        Self {
            first_frag_payload_bytes: 8,
        }
    }
}

impl IpFragStrategy {
    pub fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        let bytes = packet.data.as_ref();

        if bytes.is_empty() || (bytes[0] >> 4) != 4 {
            return vec![packet];
        }

        let ip_header_len = ((bytes[0] & 0x0F) * 4) as usize;
        if bytes.len() < ip_header_len + 20 {
            return vec![packet];
        }

        // Don't fragment already-fragmented packets
        let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
        let df_bit = (flags_frag >> 14) & 1;
        if df_bit != 0 {
            return vec![packet]; // DF flag set — cannot fragment
        }

        let ip_payload_len = bytes.len() - ip_header_len;
        let split = self
            .first_frag_payload_bytes
            .min(ip_payload_len.saturating_sub(8));
        // Must be multiple of 8
        let split = (split / 8) * 8;
        if split == 0 || split >= ip_payload_len {
            return vec![packet];
        }

        // Read IP header fields we need
        let identification = u16::from_be_bytes([bytes[4], bytes[5]]);

        // --- Fragment 1 ---
        let mut frag1 = packet.clone();
        {
            let d = frag1.data.to_mut();

            // Total length = ip_header_len + split
            let frag1_total = ip_header_len + split;
            d[2..4].copy_from_slice(&(frag1_total as u16).to_be_bytes());

            // Flags: MF=1 (More Fragments), fragment offset = 0
            // Bits: [Reserved=0][DF=0][MF=1] | offset (13 bits) = 0
            d[6] = 0x20; // MF bit set, offset high byte = 0
            d[7] = 0x00;

            d.truncate(frag1_total);
        }
        // Recalculate only IP checksum (TCP checksum spans the full reassembled datagram)
        let _ = frag1.recalculate_checksums(windivert_sys::ChecksumFlags::new().set_no_tcp());

        // --- Fragment 2 ---
        let mut frag2 = packet.clone();
        {
            let d = frag2.data.to_mut();

            let frag2_payload_len = ip_payload_len - split;
            let frag2_total = ip_header_len + frag2_payload_len;

            // Total length
            d[2..4].copy_from_slice(&(frag2_total as u16).to_be_bytes());

            // Identification (same as frag1 so receiver reassembles them)
            d[4..6].copy_from_slice(&identification.to_be_bytes());

            // Flags: MF=0, fragment offset = split / 8
            let offset_units = (split / 8) as u16;
            let flags_offset_field = offset_units; // MF=0, DF=0
            d[6..8].copy_from_slice(&flags_offset_field.to_be_bytes());

            // Shift the second fragment's payload to right after the IP header
            d.copy_within(
                ip_header_len + split..ip_header_len + ip_payload_len,
                ip_header_len,
            );
            d.truncate(frag2_total);
        }
        let _ = frag2.recalculate_checksums(windivert_sys::ChecksumFlags::new().set_no_tcp());

        vec![frag1, frag2]
    }
}
