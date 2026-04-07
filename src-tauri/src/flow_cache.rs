use std::{sync::Mutex, thread, time::Duration};

use log::{error, info};
use tauri::Manager;
use windivert::{
    prelude::{WinDivertEvent, WinDivertFlags},
    ShutdownHandle, WinDivert,
};

use crate::{packet_key::ConnectionKey, state::AppState};

static FLOW_SHUTDOWN: Mutex<Option<ShutdownHandle>> = Mutex::new(None);

#[allow(dead_code)]
pub fn stop_flow_listener() {
    if let Ok(mut guard) = FLOW_SHUTDOWN.lock() {
        if let Some(sh) = guard.take() {
            let _ = sh.shutdown();
        }
    }
}

pub fn start_flow_listener(app_handle: tauri::AppHandle) {
    thread::Builder::new()
        .name("windivert-flow-cache".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || run_flow_listener(app_handle))
        .expect("failed to spawn flow cache thread");
}

fn run_flow_listener(app_handle: tauri::AppHandle) {
    let handle = match WinDivert::flow("true", 0, WinDivertFlags::default()) {
        Ok(handle) => {
            info!("[flow] WinDivert handle opened");
            if let Ok(mut guard) = FLOW_SHUTDOWN.lock() {
                *guard = Some(handle.shutdown_handle());
            }
            handle
        }
        Err(e) => {
            error!("[flow] Failed to open WinDivert handle: {e}");
            return;
        }
    };

    loop {
        match handle.recv() {
            Ok(packet) => {
                let addr = packet.address;
                let state = app_handle.state::<AppState>();

                match addr.event() {
                    WinDivertEvent::FlowEstablished => {
                        let key = ConnectionKey {
                            protocol: if addr.protocol() == 6 {
                                crate::packet_key::TransportProtocol::Tcp
                            } else {
                                crate::packet_key::TransportProtocol::Udp
                            },
                            local_address: addr.local_address(),
                            local_port: addr.local_port(),
                            remote_address: addr.remote_address(),
                            remote_port: addr.remote_port(),
                        };

                        state.record_connection(key, addr.process_id());
                    }
                    WinDivertEvent::FlowDeleted => {
                        let key = ConnectionKey {
                            protocol: if addr.protocol() == 6 {
                                crate::packet_key::TransportProtocol::Tcp
                            } else {
                                crate::packet_key::TransportProtocol::Udp
                            },
                            local_address: addr.local_address(),
                            local_port: addr.local_port(),
                            remote_address: addr.remote_address(),
                            remote_port: addr.remote_port(),
                        };

                        state.remove_connection(&key);
                    }
                    _ => {}
                }
            }
            Err(e) => {
                error!("[flow] recv error: {e}");
                let sleep_ms = app_handle
                    .state::<AppState>()
                    .settings_snapshot()
                    .app
                    .performance
                    .flow_cache_sleep_ms as u64;
                thread::sleep(Duration::from_millis(sleep_ms));
            }
        }
    }
}
