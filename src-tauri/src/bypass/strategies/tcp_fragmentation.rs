use super::super::context::BypassContext;
use super::super::strategy::BypassStrategy;

#[derive(Debug, Default)]
pub struct TcpFragmentationStrategy;

impl BypassStrategy for TcpFragmentationStrategy {
    fn name(&self) -> &'static str {
        "tcp_fragmentation"
    }

    fn on_connect(
        &mut self,
        _context: &mut BypassContext,
        client: &tokio::net::TcpStream,
        _upstream: &tokio::net::TcpStream,
    ) {
        client.set_nodelay(true).ok();
    }

    fn on_client_data(&mut self, context: &mut BypassContext, data: &[u8]) -> Vec<Vec<u8>> {
        // Only fragment initial packets from the client
        if context.client_bytes() == 0 && data.len() > 5 {
            // Check if it looks like a TLS Handshake (0x16)
            if data[0] == 0x16 {
                // Fragment: Split the first 3 bytes (Record Type + Version)
                // from the rest of the ClientHello to evade DPI signature matching.
                let (first, second) = data.split_at(3);
                return vec![first.to_vec(), second.to_vec()];
            }
        }
        vec![data.to_vec()]
    }

    fn on_tls_start(
        &mut self,
        _context: &mut BypassContext,
        client: &tokio::net::TcpStream,
        _upstream: &tokio::net::TcpStream,
    ) {
        client.set_nodelay(false).ok();
    }
}
