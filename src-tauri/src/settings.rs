use serde::{Deserialize, Serialize};
use tauri_plugin_store::StoreExt;

const SETTINGS_STORE_FILE: &str = "settings.json";
const SETTINGS_KEY: &str = "settings";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    pub rules: Vec<Rule>,
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
