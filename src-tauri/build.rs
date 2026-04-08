use std::io::Read;
use std::path::PathBuf;
use tauri_build::WindowsAttributes;

const WINDIVERT_URL: &str =
    "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

fn download_windivert(target_dir: &PathBuf) {
    let dll_path = target_dir.join("WinDivert.dll");
    let sys_path = target_dir.join("WinDivert64.sys");

    if dll_path.exists() && sys_path.exists() {
        return;
    }

    std::fs::create_dir_all(target_dir).expect("Failed to create target directory");

    let response = reqwest::blocking::get(WINDIVERT_URL).expect("Failed to download WinDivert ZIP");
    let bytes = response.bytes().expect("Failed to read response");

    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).expect("Failed to open ZIP archive");

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let entry_name = entry.name().to_string();

        // Extract only x64 .dll and .sys files
        let is_x64 = entry_name.contains("x64/") || entry_name.contains("x64\\");
        let is_target_ext = entry_name.ends_with(".dll") || entry_name.ends_with(".sys");

        if is_x64 && is_target_ext {
            let file_name = std::path::Path::new(&entry_name)
                .file_name()
                .unwrap()
                .to_owned();

            let out_path = target_dir.join(&file_name);

            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .expect("Failed to read file from archive");
            std::fs::write(&out_path, &buf).expect("Failed to write file to target directory");
        }
    }
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("failed to derive target directory from OUT_DIR")
        .to_path_buf();

    download_windivert(&target_dir);

    // Check whether this is a development build (for npm run tauri dev)
    let is_dev = std::env::var("DEP_TAURI_DEV").unwrap_or_default() == "true";

    if !is_dev {
        // Apply custom Windows manifest
        let mut windows = WindowsAttributes::new();
        windows = windows.app_manifest(include_str!("manifest.xml"));

        let attrs = tauri_build::Attributes::new().windows_attributes(windows);

        tauri_build::try_build(attrs).expect("build script failed");
    } else {
        tauri_build::build();
    }
}
