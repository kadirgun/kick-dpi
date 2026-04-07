use std::{collections::HashMap, sync::Mutex, thread, time::Duration};

use log::{error, info};
use tauri::Manager;
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::CloseHandle,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
};

use crate::state::AppState;

static PROCESS_REFRESH_STOP: Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>> =
    Mutex::new(None);

pub fn start_process_cache(app_handle: tauri::AppHandle) {
    let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Ok(mut guard) = PROCESS_REFRESH_STOP.lock() {
        *guard = Some(stop_flag.clone());
    }

    thread::Builder::new()
        .name("process-cache-refresh".into())
        .spawn(move || run_process_cache(app_handle, stop_flag))
        .expect("failed to spawn process cache thread");
}

#[allow(dead_code)]
pub fn stop_process_cache() {
    if let Ok(mut guard) = PROCESS_REFRESH_STOP.lock() {
        if let Some(flag) = guard.take() {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

fn run_process_cache(
    app_handle: tauri::AppHandle,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    info!("[process-cache] refresh loop started");

    while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
        match refresh_process_paths(&app_handle) {
            Ok(paths) => {
                app_handle.state::<AppState>().replace_process_paths(paths);
            }
            Err(e) => {
                error!("[process-cache] refresh failed: {e}");
            }
        }

        for _ in 0..50 {
            if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn refresh_process_paths(_app_handle: &tauri::AppHandle) -> Result<HashMap<u32, String>, String> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| e.to_string())?;

    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut paths = HashMap::new();
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();

    while has_entry {
        let pid = entry.th32ProcessID;
        if let Some(path) = process_path(pid) {
            paths.insert(pid, path);
        }

        has_entry = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }

    let _ = unsafe { CloseHandle(snapshot) };
    Ok(paths)
}

pub fn query_process_path(pid: u32) -> Option<String> {
    process_path(pid)
}

fn process_path(pid: u32) -> Option<String> {
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(e) => {
            log::debug!("[process-cache] OpenProcess failed pid={pid}: {e}");
            return None;
        }
    };

    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;

    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };

    let _ = unsafe { CloseHandle(handle) };

    match result {
        Ok(()) => Some(String::from_utf16_lossy(&buf[..len as usize])),
        Err(e) => {
            log::debug!("[process-cache] QueryFullProcessImageNameW failed pid={pid}: {e}");
            None
        }
    }
}
