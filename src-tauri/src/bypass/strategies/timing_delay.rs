use crate::bypass::{packet::RawPacket, strategy::Strategy};

/// Inserts a configurable inter-chunk delay between fragmented packet pieces.
/// Intended to be used in combination with `TcpFragmentStrategy` or
/// `SniSplitStrategy` to further confuse stateful DPI reassembly timers.
///
/// Not yet implemented — currently a transparent pass-through.
pub struct TimingDelayStrategy;

impl Strategy for TimingDelayStrategy {
    fn name(&self) -> &'static str {
        "timing_delay"
    }

    fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        vec![packet]
    }
}
