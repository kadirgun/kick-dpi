use super::context::BypassContext;
use super::strategy::{BeforeSendFuture, BypassStrategy};
use tokio::net::TcpStream;

pub struct BypassPipeline {
    strategies: Vec<Box<dyn BypassStrategy>>,
}

impl BypassPipeline {
    pub fn new(strategies: Vec<Box<dyn BypassStrategy>>) -> Self {
        Self { strategies }
    }

    pub fn empty() -> Self {
        Self {
            strategies: Vec::new(),
        }
    }

    pub fn push(&mut self, strategy: Box<dyn BypassStrategy>) {
        self.strategies.push(strategy);
    }

    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }

    pub fn strategy_names(&self) -> Vec<&'static str> {
        self.strategies
            .iter()
            .map(|strategy| strategy.name())
            .collect()
    }

    pub fn on_connect(
        &mut self,
        context: &mut BypassContext,
        client: &TcpStream,
        upstream: &TcpStream,
    ) {
        for strategy in &mut self.strategies {
            strategy.on_connect(context, client, upstream);
        }
    }

    pub fn on_tls_start(
        &mut self,
        context: &mut BypassContext,
        client: &TcpStream,
        upstream: &TcpStream,
    ) {
        for strategy in &mut self.strategies {
            strategy.on_tls_start(context, client, upstream);
        }
    }

    pub fn before_send(
        &mut self,
        context: &mut BypassContext,
        data: &[u8],
    ) -> Vec<BeforeSendFuture> {
        self.strategies
            .iter_mut()
            .map(|strategy| strategy.before_send(context, data))
            .collect()
    }

    pub fn process_sni(&mut self, context: &mut BypassContext, data: &[u8]) -> Vec<Vec<u8>> {
        let mut chunks = vec![data.to_vec()];

        for strategy in &mut self.strategies {
            let mut next_chunks = Vec::new();
            for chunk in chunks {
                next_chunks.extend(strategy.process_sni(context, &chunk));
            }
            chunks = next_chunks;
        }

        chunks
    }

    pub fn on_client_data(&mut self, context: &mut BypassContext, data: &[u8]) -> Vec<Vec<u8>> {
        let mut chunks = vec![data.to_vec()];

        for strategy in &mut self.strategies {
            let mut next_chunks = Vec::new();
            for chunk in chunks {
                next_chunks.extend(strategy.on_client_data(context, &chunk));
            }
            chunks = next_chunks;
        }

        chunks
    }

    pub fn on_server_data(&mut self, context: &mut BypassContext, data: &[u8]) {
        for strategy in &mut self.strategies {
            strategy.on_server_data(context, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::context::BypassContext;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::{Arc, Mutex};

    struct RecordingStrategy {
        name: &'static str,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordingStrategy {
        fn new(name: &'static str, calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { name, calls }
        }
    }

    impl BypassStrategy for RecordingStrategy {
        fn name(&self) -> &'static str {
            self.name
        }

        fn before_send(
            &mut self,
            _context: &mut BypassContext,
            _data: &[u8],
        ) -> BeforeSendFuture {
            self.calls.lock().unwrap().push(self.name);
            Box::pin(async {})
        }
    }

    fn build_context() -> BypassContext {
        BypassContext::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443)),
        )
    }

    #[test]
    fn before_send_runs_strategies_in_order() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let calls = Arc::new(Mutex::new(Vec::new()));
                let mut pipeline = BypassPipeline::new(vec![
                    Box::new(RecordingStrategy::new("first", Arc::clone(&calls))),
                    Box::new(RecordingStrategy::new("second", Arc::clone(&calls))),
                ]);
                let mut context = build_context();

                let futures = pipeline.before_send(&mut context, b"payload");
                for future in futures {
                    future.await;
                }

                let calls = calls.lock().unwrap();
                assert_eq!(calls.as_slice(), ["first", "second"]);
            });
    }
}

impl Default for BypassPipeline {
    fn default() -> Self {
        Self::new(super::strategies::default_strategies())
    }
}
