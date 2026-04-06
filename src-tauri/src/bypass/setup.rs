use log::{error, info};
use std::env;
use std::fs::File;
use std::io::Cursor;

const WINDIVERT_URL: &str = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

pub async fn ensure_windivert() {
    let dll_path = std::path::PathBuf::from("WinDivert.dll");
    let sys_path = std::path::PathBuf::from("WinDivert64.sys");

    if dll_path.exists() && sys_path.exists() {
        info!("[setup] WinDivert binaries already exist, skipping download.");
        return;
    }

    info!("[setup] WinDivert binaries not found. Downloading from {}", WINDIVERT_URL);

    match reqwest::get(WINDIVERT_URL).await {
        Ok(response) => {
            if response.status().is_success() {
                match response.bytes().await {
                    Ok(bytes) => {
                        if let Err(e) = extract_windivert(bytes.as_ref(), &dll_path, &sys_path) {
                            error!("[setup] Failed to extract WinDivert: {}", e);
                        } else {
                            info!("[setup] WinDivert downloaded and extracted successfully.");
                        }
                    }
                    Err(e) => error!("[setup] Failed to read response body: {}", e),
                }
            } else {
                error!("[setup] Download failed with status: {}", response.status());
            }
        }
        Err(e) => {
            error!("[setup] Failed to download WinDivert: {}", e);
        }
    }
}

fn extract_windivert(
    zip_bytes: &[u8],
    dll_path: &std::path::PathBuf,
    sys_path: &std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();

        if name.ends_with("x64/WinDivert.dll") {
            let mut out_file = File::create(dll_path)?;
            std::io::copy(&mut file, &mut out_file)?;
            info!("[setup] Extracted {:?}", dll_path);
        } else if name.ends_with("x64/WinDivert64.sys") {
            let mut out_file = File::create(sys_path)?;
            std::io::copy(&mut file, &mut out_file)?;
            info!("[setup] Extracted {:?}", sys_path);
        }
    }

    Ok(())
}

