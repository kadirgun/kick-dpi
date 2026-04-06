use super::super::context::BypassContext;
use super::super::strategy::BypassStrategy;

#[derive(Debug, Default)]
pub struct TcpRstBlockingStrategy;

impl BypassStrategy for TcpRstBlockingStrategy {
    fn name(&self) -> &'static str {
        "tcp_rst_blocking"
    }
}
