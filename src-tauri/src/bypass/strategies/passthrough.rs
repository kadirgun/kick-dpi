use crate::bypass::{packet::RawPacket, strategy::Strategy};

/// Transparent pass-through — reinjects the packet unchanged.
/// Used as the baseline to verify the pipeline plumbing is correct.
pub struct PassthroughStrategy;

impl Strategy for PassthroughStrategy {
    fn name(&self) -> &'static str {
        "passthrough"
    }

    fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        vec![packet]
    }
}
