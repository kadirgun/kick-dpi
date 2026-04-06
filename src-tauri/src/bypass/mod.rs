pub mod packet;
pub mod strategies;
pub mod strategy;

mod listener;
pub mod setup;

pub use strategy::StrategyPipeline;

use strategies::{
    FakePacketStrategy, PassthroughStrategy, SniSplitStrategy, TcpFragmentStrategy,
    TimingDelayStrategy, TtlModificationStrategy,
};

const FILTER: &str = "tcp.DstPort == 443 and tcp.PayloadLength > 0";

/// Build the default strategy pipeline used at startup.
/// All strategies are currently no-ops; replace their bodies as each is
/// implemented.
pub fn default_pipeline() -> StrategyPipeline {
    StrategyPipeline::new(vec![
        Box::new(PassthroughStrategy),
        Box::new(TcpFragmentStrategy),
        Box::new(SniSplitStrategy),
        Box::new(FakePacketStrategy),
        Box::new(TimingDelayStrategy),
        Box::new(TtlModificationStrategy),
    ])
}

/// Open the WinDivert handle and spawn the blocking listener thread.
///
/// # Stack size
/// WinDivert's initialisation (which triggers SCM / kernel driver calls) and
/// its internal `recv`/helper subroutines heavily utilize the stack. The Windows
/// default 1 MB stack size leads to `STATUS_STACK_OVERFLOW` (0xc00000fd). We
/// must spawn a distinct thread configured with a much larger stack (32MB).
pub fn start_listener(pipeline: StrategyPipeline) {
    std::thread::Builder::new()
        .name("windivert-listener".into())
        .spawn(move || listener::run_listener(pipeline, FILTER))
        .expect("failed to spawn WinDivert listener thread");
}
