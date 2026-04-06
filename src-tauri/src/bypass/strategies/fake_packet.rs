use crate::bypass::{packet::RawPacket, strategy::Strategy};

/// Injects a crafted decoy packet before the real one. The decoy has a low TTL
/// so it reaches the DPI appliance but expires before reaching the server,
/// confusing stateful inspection engines.
///
/// Not yet implemented — currently a transparent pass-through.
pub struct FakePacketStrategy;

impl Strategy for FakePacketStrategy {
    fn name(&self) -> &'static str {
        "fake_packet"
    }

    fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        vec![packet]
    }
}
