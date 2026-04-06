use crate::bypass::{packet::RawPacket, strategy::Strategy};

/// Splits the TCP payload into multiple smaller segments to prevent DPI devices
/// from reassembling the full TLS ClientHello before inspecting it.
///
/// Not yet implemented — currently a transparent pass-through.
pub struct TcpFragmentStrategy;

impl Strategy for TcpFragmentStrategy {
    fn name(&self) -> &'static str {
        "tcp_fragment"
    }

    fn process(&self, packet: RawPacket) -> Vec<RawPacket> {
        vec![packet]
    }
}
