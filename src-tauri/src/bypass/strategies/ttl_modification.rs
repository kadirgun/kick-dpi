use crate::bypass::{packet::RawPacket, strategy::Strategy};

/// Manipulates the IP TTL value so that a decoy packet reaches the DPI device
/// but expires before reaching the destination server. Works on network
/// topologies where the hop count to the DPI appliance is known.
///
/// Not yet implemented — currently a transparent pass-through.
pub struct TtlModificationStrategy;

impl Strategy for TtlModificationStrategy {
    fn name(&self) -> &'static str {
        "ttl_modification"
    }

    fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        vec![packet]
    }
}
