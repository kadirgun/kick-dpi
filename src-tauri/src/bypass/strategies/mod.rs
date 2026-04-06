mod tcp_fragmentation;
mod tcp_inter_chunk_delay;
mod tcp_rst_blocking;
mod tcp_sni_splitting;
mod tcp_window_size;

pub use tcp_fragmentation::TcpFragmentationStrategy;
pub use tcp_inter_chunk_delay::TcpInterChunkDelayStrategy;
pub use tcp_rst_blocking::TcpRstBlockingStrategy;
pub use tcp_sni_splitting::TcpSniSplittingStrategy;
pub use tcp_window_size::TcpWindowSizeStrategy;

use super::strategy::BypassStrategy;

pub fn default_strategies() -> Vec<Box<dyn BypassStrategy>> {
    vec![
        Box::new(TcpWindowSizeStrategy::default()),
        Box::new(TcpSniSplittingStrategy::default()),
        Box::new(TcpFragmentationStrategy::default()),
        Box::new(TcpRstBlockingStrategy::default()),
        Box::new(TcpInterChunkDelayStrategy::default()),
    ]
}
