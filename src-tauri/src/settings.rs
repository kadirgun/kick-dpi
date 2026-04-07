use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tauri_plugin_store::StoreExt;

const SETTINGS_STORE_FILE: &str = "settings.json";
const SETTINGS_KEY: &str = "settings";

// Global app settings (non-rule-based)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub dns: DnsSettings,
    pub sni: SniSettings,
    pub strategy_params: StrategySettings,
    pub performance: PerformanceSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(default = "default_dns_provider")]
    pub provider: String, // "Cloudflare" | "Quad9" | "NextDNS" | "Custom"
    pub custom_url: Option<String>,
    #[serde(default = "default_dns_timeout")]
    pub timeout_ms: u32,
    #[serde(default)]
    pub fallback_enabled: bool,
    #[serde(default)]
    pub fallback_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniSettings {
    #[serde(default = "default_strategies")]
    pub strategies: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategySettings {
    #[serde(default = "default_ttl")]
    pub wrong_checksum_decoy_ttl: u32,
    #[serde(default = "default_ttl")]
    pub fake_sni_decoy_ttl: u32,
    #[serde(default = "default_ttl")]
    pub overlap_decoy_ttl: u32,
    #[serde(default = "default_ip_frag_bytes")]
    pub ip_frag_first_payload_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    #[serde(default = "default_process_cache_refresh")]
    pub process_cache_refresh_ms: u32,
    #[serde(default = "default_flow_cache_sleep")]
    pub flow_cache_sleep_ms: u32,
    #[serde(default = "default_packet_buffer_size")]
    pub packet_buffer_size: usize,
    #[serde(default = "default_connection_reset_buffer")]
    pub connection_reset_buffer_kb: usize,
    #[serde(default = "default_dns_buffer_size")]
    pub dns_buffer_size: usize,
    #[serde(default = "default_sni_buffer_size")]
    pub sni_buffer_size: usize,
}

// Default functions
fn default_dns_provider() -> String {
    "Cloudflare".to_string()
}

fn default_dns_timeout() -> u32 {
    2000
}

fn default_ttl() -> u32 {
    4
}

fn default_ip_frag_bytes() -> u32 {
    8
}

fn default_process_cache_refresh() -> u32 {
    5000 // 50 * 100ms
}

fn default_flow_cache_sleep() -> u32 {
    50
}

fn default_packet_buffer_size() -> usize {
    65535
}

fn default_connection_reset_buffer() -> usize {
    4
}

fn default_dns_buffer_size() -> usize {
    65535
}

fn default_sni_buffer_size() -> usize {
    65535
}

fn default_strategies() -> HashMap<String, bool> {
    let mut map = HashMap::new();
    map.insert("WrongChecksum".to_string(), true);
    map.insert("FakeSni".to_string(), true);
    map.insert("Overlap".to_string(), true);
    map.insert("IpFrag".to_string(), true);
    map.insert("SniSplit".to_string(), true);
    map.insert("TcpFragment".to_string(), true);
    map.insert("FakePacket".to_string(), true);
    map.insert("Shuffle".to_string(), true);
    map
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            dns: DnsSettings::default(),
            sni: SniSettings::default(),
            strategy_params: StrategySettings::default(),
            performance: PerformanceSettings::default(),
        }
    }
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            provider: default_dns_provider(),
            custom_url: None,
            timeout_ms: default_dns_timeout(),
            fallback_enabled: false,
            fallback_servers: vec![],
        }
    }
}

impl Default for SniSettings {
    fn default() -> Self {
        Self {
            strategies: default_strategies(),
        }
    }
}

impl Default for StrategySettings {
    fn default() -> Self {
        Self {
            wrong_checksum_decoy_ttl: default_ttl(),
            fake_sni_decoy_ttl: default_ttl(),
            overlap_decoy_ttl: default_ttl(),
            ip_frag_first_payload_bytes: default_ip_frag_bytes(),
        }
    }
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            process_cache_refresh_ms: default_process_cache_refresh(),
            flow_cache_sleep_ms: default_flow_cache_sleep(),
            packet_buffer_size: default_packet_buffer_size(),
            connection_reset_buffer_kb: default_connection_reset_buffer(),
            dns_buffer_size: default_dns_buffer_size(),
            sni_buffer_size: default_sni_buffer_size(),
        }
    }
}

// Legacy Settings struct for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub app: AppSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub hosts: Vec<String>,
    pub paths: Vec<String>,
    pub dns_enabled: bool,
    pub sni_enabled: bool,
}

impl Settings {
    pub fn dns_enabled_for(&self, host: &str, path: Option<&str>) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.dns_enabled && rule.matches(host, path))
    }

    pub fn sni_enabled_for(&self, host: &str, path: Option<&str>) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.sni_enabled && rule.matches(host, path))
    }
}

impl Rule {
    pub fn matches(&self, host: &str, path: Option<&str>) -> bool {
        if let Some(path) = path {
            if self.paths.iter().any(|pattern| matches_path(pattern, path)) {
                return true;
            }
        }

        if self.hosts.is_empty() {
            return false;
        }

        self.hosts.iter().any(|pattern| matches_host(pattern, host))
    }

    pub fn path_matches(&self, path: &str) -> bool {
        self.paths.iter().any(|pattern| matches_path(pattern, path))
    }
}

pub fn load_settings(app: &tauri::AppHandle) -> Result<Settings, String> {
    let store = app.store(SETTINGS_STORE_FILE).map_err(|e| e.to_string())?;

    if let Some(value) = store.get(SETTINGS_KEY) {
        serde_json::from_value(value).map_err(|e| e.to_string())
    } else {
        let settings = Settings::default();
        store.set(
            SETTINGS_KEY,
            serde_json::to_value(&settings).map_err(|e| e.to_string())?,
        );
        store.save().map_err(|e| e.to_string())?;
        Ok(settings)
    }
}

pub fn save_settings(app: &tauri::AppHandle, settings: &Settings) -> Result<(), String> {
    let store = app.store(SETTINGS_STORE_FILE).map_err(|e| e.to_string())?;
    store.set(
        SETTINGS_KEY,
        serde_json::to_value(settings).map_err(|e| e.to_string())?,
    );
    store.save().map_err(|e| e.to_string())
}

fn matches_host(pattern: &str, value: &str) -> bool {
    let pattern = normalize_host(pattern);
    let value = normalize_host(value);

    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return value.ends_with(suffix)
            && value.len() > suffix.len()
            && value.as_bytes()[value.len() - suffix.len() - 1] == b'.';
    }

    wildcard_match(&pattern, &value)
}

fn matches_path(pattern: &str, value: &str) -> bool {
    wildcard_match(&normalize_path(pattern), &normalize_path(value))
}

fn normalize_host(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_path(value: &str) -> String {
    value.trim().replace('/', "\\").to_ascii_lowercase()
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == value {
        return true;
    }

    if pattern == "*" {
        return true;
    }

    let segments: Vec<&str> = pattern.split('*').collect();
    if segments.len() == 1 {
        return pattern == value;
    }

    let mut remainder = value;
    let mut first_segment = true;

    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            continue;
        }

        let is_last = index == segments.len() - 1;
        if first_segment && !pattern.starts_with('*') {
            if !remainder.starts_with(segment) {
                return false;
            }
            remainder = &remainder[segment.len()..];
        } else if is_last && !pattern.ends_with('*') {
            if !remainder.ends_with(segment) {
                return false;
            }
        } else if let Some(position) = remainder.find(segment) {
            remainder = &remainder[position + segment.len()..];
        } else {
            return false;
        }

        first_segment = false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::{matches_host, matches_path, Rule};

    #[test]
    fn matches_windows_style_path_glob() {
        assert!(matches_path(
            r"C:\Users\kadir\AppData\Local\Discord\*\Discord.exe",
            r"c:\users\kadir\appdata\local\discord\app-1\Discord.exe",
        ));
        assert!(!matches_path(
            r"C:\Users\kadir\AppData\Local\Discord\*\Discord.exe",
            r"C:\Users\kadir\AppData\Local\Discord\Discord.exe",
        ));
    }

    #[test]
    fn matches_host_wildcard() {
        assert!(matches_host("*.discordapp.com", "canary.discordapp.com"));
        assert!(matches_host("*.discordapp.com", "ptb.discordapp.com"));
        assert!(!matches_host("*.discordapp.com", "discordapp.com"));
    }

    #[test]
    fn path_only_rule_matches_path_without_host_fallback() {
        let rule = Rule {
            id: "test".into(),
            name: "Discord".into(),
            hosts: vec![],
            paths: vec![r"C:\Users\kadir\AppData\Local\Discord\*\Discord.exe".into()],
            dns_enabled: true,
            sni_enabled: true,
        };

        assert!(rule.matches(
            "",
            Some(r"c:\users\kadir\appdata\local\discord\app-1\discord.exe")
        ));
        assert!(!rule.matches("", None));
        assert!(!rule.matches(
            "",
            Some(r"c:\users\kadir\appdata\local\discord\discord.exe")
        ));
    }
}
