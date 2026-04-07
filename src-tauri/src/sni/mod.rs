pub mod packet;
pub mod strategies;

mod listener;

const FILTER: &str =
    "(tcp.DstPort == 443 and tcp.PayloadLength > 0) or (udp.DstPort == 443 and outbound)";

pub fn start_listener(app_handle: tauri::AppHandle) {
    std::thread::Builder::new()
        .name("windivert-listener".into())
        .spawn(move || listener::run_listener(FILTER, app_handle))
        .expect("failed to spawn WinDivert listener thread");
}

pub fn stop_listener() {
    listener::stop_listener();
}
