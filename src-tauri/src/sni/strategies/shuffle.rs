use crate::sni::packet::RawPacket;

/// Randomly reorders the entire packet batch produced by previous strategies.
/// By shuffling injection order, DPI engines cannot rely on sequential packet
/// arrival to reconstruct the TLS ClientHello.
///
/// Uses a time-seeded LCG (Fisher-Yates) — no external crate needed.
pub struct ShuffleStrategy;

impl ShuffleStrategy {
    pub fn process_batch(&self, mut packets: Vec<RawPacket>) -> Vec<RawPacket> {
        if packets.len() > 1 {
            let n = packets.len();
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0xdeadbeef);
            let mut rng = seed;
            for i in (1..n).rev() {
                // Knuth multiplicative LCG step
                rng = rng
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let j = (rng >> 33) as usize % (i + 1);
                packets.swap(i, j);
            }
        }
        packets
    }
}
