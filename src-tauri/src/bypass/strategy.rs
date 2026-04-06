use super::packet::RawPacket;

/// A single bypass strategy. Takes ownership of a packet and returns zero or
/// more packets that should be (re-)injected into the network stack.
///
/// Returning `vec![packet]` is a transparent no-op pass-through.
/// Returning an empty vec drops the packet.
/// Returning multiple packets injects each of them.
pub trait Strategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn process(&self, packet: RawPacket) -> Vec<RawPacket>;
}

/// Chains multiple strategies sequentially: the output packets of strategy N
/// are fed individually into strategy N+1. Starts from a single captured packet
/// and may produce 0..N packets to reinject.
pub struct StrategyPipeline {
    strategies: Vec<Box<dyn Strategy>>,
}

impl StrategyPipeline {
    pub fn new(strategies: Vec<Box<dyn Strategy>>) -> Self {
        Self { strategies }
    }

    /// Run the full pipeline on one captured packet.
    pub fn run(&self, packet: RawPacket) -> Vec<RawPacket> {
        let mut current = vec![packet];
        for strategy in &self.strategies {
            current = current
                .into_iter()
                .flat_map(|p| strategy.process(p))
                .collect();
        }
        current
    }
}
