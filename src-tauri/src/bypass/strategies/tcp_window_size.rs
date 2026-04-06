use super::super::context::BypassContext;
use super::super::strategy::BypassStrategy;
use std::io;
use tokio::net::TcpStream;

use socket2::SockRef;

const SMALL_WINDOW_SIZE: usize = 64;

#[derive(Debug, Default)]
pub struct TcpWindowSizeStrategy {
    client_recv_buffer_size: Option<usize>,
    upstream_recv_buffer_size: Option<usize>,
}

impl TcpWindowSizeStrategy {
    fn tune_window_size(stream: &TcpStream, size: usize) -> io::Result<usize> {
        let socket = SockRef::from(stream);
        let original_size = socket.recv_buffer_size()?;
        socket.set_recv_buffer_size(size)?;
        Ok(original_size)
    }

    fn restore_window_size(stream: &TcpStream, size: usize) -> io::Result<()> {
        SockRef::from(stream).set_recv_buffer_size(size)
    }
}

impl BypassStrategy for TcpWindowSizeStrategy {
    fn name(&self) -> &'static str {
        "tcp_window_size"
    }

    fn on_connect(
        &mut self,
        _context: &mut BypassContext,
        client: &TcpStream,
        upstream: &TcpStream,
    ) {
        if self.client_recv_buffer_size.is_none() {
            match Self::tune_window_size(client, SMALL_WINDOW_SIZE) {
                Ok(original_size) => self.client_recv_buffer_size = Some(original_size),
                Err(error) => {
                    log::warn!("tcp_window_size: failed to tune client socket: {}", error)
                }
            }
        }

        if self.upstream_recv_buffer_size.is_none() {
            match Self::tune_window_size(upstream, SMALL_WINDOW_SIZE) {
                Ok(original_size) => self.upstream_recv_buffer_size = Some(original_size),
                Err(error) => {
                    log::warn!("tcp_window_size: failed to tune upstream socket: {}", error)
                }
            }
        }
    }

    fn on_tls_start(
        &mut self,
        _context: &mut BypassContext,
        client: &TcpStream,
        upstream: &TcpStream,
    ) {
        if let Some(original_size) = self.client_recv_buffer_size.take() {
            if let Err(error) = Self::restore_window_size(client, original_size) {
                log::warn!(
                    "tcp_window_size: failed to restore client socket: {}",
                    error
                );
            }
        }

        if let Some(original_size) = self.upstream_recv_buffer_size.take() {
            if let Err(error) = Self::restore_window_size(upstream, original_size) {
                log::warn!(
                    "tcp_window_size: failed to restore upstream socket: {}",
                    error
                );
            }
        }
    }
}
