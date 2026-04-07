use tauri::Manager;

pub(crate) mod connection_reset;
pub(crate) mod dns;
pub(crate) mod flow_cache;
pub(crate) mod packet_key;
pub(crate) mod process_cache;
pub(crate) mod settings;
pub(crate) mod setup;
pub(crate) mod sni;
pub(crate) mod state;

#[tauri::command]
fn stop_dns_listener() {
    dns::stop_dns_listener();
}

#[tauri::command]
fn stop_sni_listener() {
    sni::stop_listener();
}

#[tauri::command]
fn get_settings(app: tauri::AppHandle) -> Result<settings::Settings, String> {
    settings::load_settings(&app)
}

#[tauri::command]
fn set_settings(app: tauri::AppHandle, settings: settings::Settings) -> Result<(), String> {
    settings::save_settings(&app, &settings)?;
    let app_state = app.state::<state::AppState>();
    let old_settings = app_state.settings_snapshot();
    app_state.replace_settings(settings.clone());

    #[cfg(windows)]
    {
        // Reset open connections for rules that are new or had their paths changed
        let changed_rules: Vec<&settings::Rule> = settings
            .rules
            .iter()
            .filter(|new_rule| {
                !old_settings
                    .rules
                    .iter()
                    .any(|old_rule| old_rule.id == new_rule.id && old_rule.paths == new_rule.paths)
            })
            .collect();

        connection_reset::reset_connections_for_rules(&changed_rules, &app_state);
    }

    Ok(())
}

#[tauri::command]
fn reset_connections_for_rule_ids(
    app: tauri::AppHandle,
    rule_ids: Vec<String>,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let app_state = app.state::<state::AppState>();
        let current_settings = app_state.settings_snapshot();
        let matched_rules: Vec<&settings::Rule> = current_settings
            .rules
            .iter()
            .filter(|r| rule_ids.contains(&r.id))
            .collect();
        connection_reset::reset_connections_for_rules(&matched_rules, &app_state);
    }
    Ok(())
}

#[tauri::command]
fn get_dns_packets(state: tauri::State<'_, state::AppState>) -> u64 {
    state.dns_count.load(std::sync::atomic::Ordering::Relaxed)
}

#[tauri::command]
fn get_sni_packets(state: tauri::State<'_, state::AppState>) -> u64 {
    state.sni_count.load(std::sync::atomic::Ordering::Relaxed)
}

#[tauri::command]
fn get_processes(state: tauri::State<'_, state::AppState>) -> Vec<state::ProcessEntry> {
    state.processes_snapshot()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let _ = app
                .get_webview_window("main")
                .expect("no main window")
                .set_focus();
        }))
        .setup(|app| {
            let app_handle = app.handle().clone();
            let loaded_settings = settings::load_settings(&app_handle).unwrap_or_default();
            app.manage(state::AppState::new(loaded_settings));

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            #[cfg(windows)]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    setup::ensure_windivert().await;
                    flow_cache::start_flow_listener(handle.clone());
                    process_cache::start_process_cache(handle.clone());
                    sni::start_listener(handle.clone());
                    dns::start_dns_listener(handle);
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            stop_dns_listener,
            stop_sni_listener,
            get_settings,
            set_settings,
            reset_connections_for_rule_ids,
            get_dns_packets,
            get_sni_packets,
            get_processes,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
