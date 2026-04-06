use super::super::context::BypassContext;
use super::super::strategy::{BeforeSendFuture, BypassStrategy};
use std::time::Duration;

#[derive(Debug)]
pub struct TcpInterChunkDelayStrategy {
    delay: Duration,
    has_sent_chunk: bool,
}

impl TcpInterChunkDelayStrategy {
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            has_sent_chunk: false,
        }
    }
}

impl Default for TcpInterChunkDelayStrategy {
    fn default() -> Self {
        Self::new(Duration::from_millis(20))
    }
}

impl BypassStrategy for TcpInterChunkDelayStrategy {
    fn name(&self) -> &'static str {
        "tcp_inter_chunk_delay"
    }

    fn before_send(&mut self, _context: &mut BypassContext, _data: &[u8]) -> BeforeSendFuture {
        if self.has_sent_chunk {
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
            })
        } else {
            self.has_sent_chunk = true;
            Box::pin(async {})
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn build_context() -> BypassContext {
        BypassContext::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443)),
        )
    }

    #[test]
    fn waits_after_the_first_chunk() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                let mut strategy = TcpInterChunkDelayStrategy::default();
                let mut context = build_context();

                strategy.before_send(&mut context, b"first").await;

                let second_send = strategy.before_send(&mut context, b"second");
                let handle = tokio::spawn(second_send);

                tokio::task::yield_now().await;
                tokio::time::advance(Duration::from_millis(24)).await;
                assert!(!handle.is_finished());

                tokio::time::advance(Duration::from_millis(1)).await;
                handle.await.unwrap();
            });
    }
}
