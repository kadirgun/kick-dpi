use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    sync::RwLock,
};

use crate::{
    packet_key::{ConnectionKey, TransportProtocol},
    settings::Settings,
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub path: String,
}

#[derive(Default)]
pub struct AppState {
    pub dns_count: AtomicU64,
    pub sni_count: AtomicU64,
    pub settings: RwLock<Settings>,
    pub connections: RwLock<HashMap<ConnectionKey, u32>>,
    pub process_paths: RwLock<HashMap<u32, String>>,
}

impl AppState {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings: RwLock::new(settings),
            ..Self::default()
        }
    }

    pub fn inc_dns(&self) {
        self.dns_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_sni(&self) {
        self.sni_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn settings_snapshot(&self) -> Settings {
        self.settings.read().unwrap().clone()
    }

    pub fn replace_settings(&self, settings: Settings) {
        *self.settings.write().unwrap() = settings;
    }

    pub fn record_connection(&self, key: ConnectionKey, pid: u32) {
        self.connections.write().unwrap().insert(key, pid);
    }

    pub fn remove_connection(&self, key: &ConnectionKey) {
        self.connections.write().unwrap().remove(key);
    }

    pub fn pid_for_connection(&self, key: &ConnectionKey) -> Option<u32> {
        self.connections.read().unwrap().get(key).copied()
    }

    pub fn pid_for_local_port(&self, protocol: TransportProtocol, local_port: u16) -> Option<u32> {
        self.connections
            .read()
            .unwrap()
            .iter()
            .find(|(key, _)| key.protocol == protocol && key.local_port == local_port)
            .map(|(_, pid)| *pid)
    }

    pub fn pid_for_connection_or_local_port(&self, key: &ConnectionKey) -> Option<u32> {
        self.pid_for_connection(key)
            .or_else(|| self.pid_for_local_port(key.protocol, key.local_port))
    }

    pub fn replace_process_paths(&self, paths: HashMap<u32, String>) {
        *self.process_paths.write().unwrap() = paths;
    }

    pub fn path_for_pid(&self, pid: u32) -> Option<String> {
        if let Some(path) = self.process_paths.read().unwrap().get(&pid).cloned() {
            return Some(path);
        }
        // Cache miss: query directly on-demand (handles short-lived subprocesses
        // and processes spawned between refresh cycles)
        crate::process_cache::query_process_path(pid)
    }

    pub fn processes_snapshot(&self) -> Vec<ProcessEntry> {
        let mut processes: Vec<_> = self
            .process_paths
            .read()
            .unwrap()
            .iter()
            .map(|(pid, path)| ProcessEntry {
                pid: *pid,
                path: path.clone(),
            })
            .collect();

        processes.sort_by_key(|entry| entry.pid);
        processes
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::packet_key::TransportProtocol;

    use super::{AppState, ConnectionKey};

    fn udp_key(
        local_address: &str,
        local_port: u16,
        remote_address: &str,
        remote_port: u16,
    ) -> ConnectionKey {
        ConnectionKey {
            protocol: TransportProtocol::Udp,
            local_address: local_address.parse::<IpAddr>().unwrap(),
            local_port,
            remote_address: remote_address.parse::<IpAddr>().unwrap(),
            remote_port,
        }
    }

    #[test]
    fn pid_resolution_falls_back_to_local_port() {
        let state = AppState::default();
        state.record_connection(udp_key("127.0.0.1", 50000, "1.1.1.1", 443), 4242);

        let lookup = udp_key("127.0.0.1", 50000, "8.8.8.8", 443);

        assert_eq!(state.pid_for_connection_or_local_port(&lookup), Some(4242));
    }
}
