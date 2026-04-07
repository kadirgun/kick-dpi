use tauri_build::WindowsAttributes;

fn main() {
    // Development build mi kontrol et (npm run tauri dev için)
    let is_dev = std::env::var("DEP_TAURI_DEV").unwrap_or_default() == "true";

    if !is_dev {
        // Windows için özel manifest uygula
        let mut windows = WindowsAttributes::new();
        windows = windows.app_manifest(include_str!("manifest.xml")); // Dosyadan yükle

        let attrs = tauri_build::Attributes::new().windows_attributes(windows);

        tauri_build::try_build(attrs).expect("build script failed");
    } else {
        // Development'ta varsayılan manifest'i kullan
        tauri_build::build();
    }
}
