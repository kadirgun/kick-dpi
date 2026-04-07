use crate::sni::packet::RawPacket;

/// Splits the TCP payload into multiple small segments to prevent DPI devices
/// from reassembling the full TLS ClientHello before inspecting it.
pub struct TcpFragmentStrategy {
    /// Payload bytes per chunk. Smaller values produce more fragments.
    pub chunk_size: usize,
}

impl Default for TcpFragmentStrategy {
    fn default() -> Self {
        Self { chunk_size: 2 }
    }
}

impl TcpFragmentStrategy {
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
        let total_len = bytes.len();
        let payload_len = total_len.saturating_sub(payload_start);

        if payload_len <= self.chunk_size {
            return vec![packet];
        }

        // Read original TCP sequence number once
        let base_seq = u32::from_be_bytes(
            bytes[ip_header_len + 4..ip_header_len + 8]
                .try_into()
                .unwrap(),
        );

        let original_flags = bytes[ip_header_len + 13];

        let mut chunks: Vec<RawPacket> = Vec::new();
        let mut offset = 0usize; // offset into payload

        while offset < payload_len {
            let end = (offset + self.chunk_size).min(payload_len);
            let is_last = end == payload_len;

            let mut chunk = packet.clone();
            {
                let b = chunk.data.to_mut();

                // Update TCP sequence number
                let seq = base_seq.wrapping_add(offset as u32);
                b[ip_header_len + 4..ip_header_len + 8].copy_from_slice(&seq.to_be_bytes());

                // Update TCP flags: clear PSH on non-last chunks
                let flags_offset = ip_header_len + 13;
                if is_last {
                    b[flags_offset] = original_flags;
                } else {
                    b[flags_offset] = original_flags & 0xF7; // clear PSH
                }

                // Move the chunk payload to right after headers, truncate
                let chunk_payload_start = payload_start + offset;
                let chunk_payload_end = payload_start + end;
                b.copy_within(chunk_payload_start..chunk_payload_end, payload_start);
                let new_total = payload_start + (end - offset);
                b.truncate(new_total);

                // Update IPv4 total length
                b[2..4].copy_from_slice(&(new_total as u16).to_be_bytes());
            }

            let _ = chunk.recalculate_checksums(windivert_sys::ChecksumFlags::new());
            chunks.push(chunk);

            offset = end;
        }

        chunks
    }
}
