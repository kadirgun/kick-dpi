use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct BypassContext {
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
    server_name: Option<String>,
    client_hello_seen: bool,
    client_bytes: usize,
    server_bytes: usize,
}

impl BypassContext {
    pub fn new(peer_addr: SocketAddr, target_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            target_addr,
            server_name: None,
            client_hello_seen: false,
            client_bytes: 0,
            server_bytes: 0,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    pub fn set_server_name(&mut self, server_name: impl Into<String>) {
        self.server_name = Some(server_name.into());
    }

    pub fn clear_server_name(&mut self) {
        self.server_name = None;
    }

    pub fn mark_client_hello_seen(&mut self) {
        self.client_hello_seen = true;
    }

    pub fn client_hello_seen(&self) -> bool {
        self.client_hello_seen
    }

    pub fn record_client_bytes(&mut self, bytes: usize) {
        self.client_bytes = self.client_bytes.saturating_add(bytes);
    }

    pub fn record_server_bytes(&mut self, bytes: usize) {
        self.server_bytes = self.server_bytes.saturating_add(bytes);
    }

    pub fn client_bytes(&self) -> usize {
        self.client_bytes
    }

    pub fn server_bytes(&self) -> usize {
        self.server_bytes
    }
}
