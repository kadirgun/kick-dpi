pub(crate) mod bypass;
pub(crate) mod dns;
mod proxy;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let proxy_controller = proxy::ProxyController::start(proxy::default_bind_addr());
            log::info!("Starting SOCKS5 proxy at {}", proxy_controller.bind_addr());
            app.manage(proxy_controller);

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
