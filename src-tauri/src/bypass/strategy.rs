use super::context::BypassContext;
use std::future::Future;
use std::pin::Pin;
use tokio::net::TcpStream;

pub type BeforeSendFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub trait BypassStrategy: Send {
    fn name(&self) -> &'static str;

    fn before_send(&mut self, _context: &mut BypassContext, _data: &[u8]) -> BeforeSendFuture {
        Box::pin(async {})
    }

    fn on_connect(
        &mut self,
        _context: &mut BypassContext,
        _client: &TcpStream,
        _upstream: &TcpStream,
    ) {
    }

    fn on_tls_start(
        &mut self,
        _context: &mut BypassContext,
        _client: &TcpStream,
        _upstream: &TcpStream,
    ) {
    }

    fn process_sni(&mut self, _context: &mut BypassContext, data: &[u8]) -> Vec<Vec<u8>> {
        vec![data.to_vec()]
    }

    fn on_client_data(&mut self, _context: &mut BypassContext, data: &[u8]) -> Vec<Vec<u8>> {
        vec![data.to_vec()]
    }

    fn on_server_data(&mut self, _context: &mut BypassContext, _data: &[u8]) {}
}
