use crate::bypass::{packet::RawPacket, strategy::Strategy};

/// Splits the TLS ClientHello SNI hostname field across two TCP packets so that
/// SNI-based filters cannot read the complete hostname from a single segment.
///
/// Not yet implemented — currently a transparent pass-through.
pub struct SniSplitStrategy;

impl Strategy for SniSplitStrategy {
    fn name(&self) -> &'static str {
        "sni_split"
    }

    fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        vec![packet]
    }
}
