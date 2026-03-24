use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub settings: Settings,
    pub watch: Vec<WatchEntry>,
    #[serde(default)]
    pub rule: Vec<RuleEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    #[serde(default)]
    pub default_action: DefaultAction,
    #[serde(default = "default_timeout")]
    pub prompt_timeout: u64,
    #[serde(default)]
    pub prompt_method: PromptMethod,
    #[serde(default)]
    pub restore_on_stop: bool,
    #[serde(default = "default_log_dest")]
    pub log_destination: String,
}

fn default_timeout() -> u64 {
    30
}

fn default_log_dest() -> String {
    "stdout".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PromptMethod {
    #[default]
    Terminal,
    Gui,
    Notification,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WatchEntry {
    pub path: String,
    #[serde(default)]
    pub default_action: Option<DefaultAction>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleEntry {
    pub file: String,
    pub binary: String,
    pub action: RuleAction,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

impl Config {
    /// Load from ~/.config/cred-guard/config.toml, expanding ~ in all paths.
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path();
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read config at {}: {}", path.display(), e))?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Append a new rule to the config file on disk.
    pub fn append_rule(entry: &RuleEntry) -> anyhow::Result<()> {
        use fs2::FileExt;
        use std::io::Write;

        let path = config_path();
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)?;
        file.lock_exclusive()?;

        let rule_toml = toml::to_string(entry)?;
        let mut writer = std::io::BufWriter::new(&file);
        writeln!(writer, "\n[[rule]]")?;
        write!(writer, "{rule_toml}")?;

        file.unlock()?;
        Ok(())
    }

    /// Expand ~ to the real user's home directory (respects SUDO_USER).
    pub fn expand_path(path: &str) -> PathBuf {
        if let Some(rest) = path.strip_prefix("~/") {
            let home = std::env::var("SUDO_USER")
                .ok()
                .and_then(|u| home_for_user(&u))
                .or_else(dirs::home_dir);
            if let Some(home) = home {
                return home.join(rest);
            }
        }
        PathBuf::from(path)
    }

    /// Resolved watch paths with ~ expanded.
    pub fn watched_paths(&self) -> Vec<PathBuf> {
        self.watch
            .iter()
            .map(|w| Self::expand_path(&w.path))
            .collect()
    }
}

fn config_path() -> PathBuf {
    // Use SUDO_USER's home when running under sudo, so we find the
    // real user's config rather than root's.
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if let Some(home) = home_for_user(&sudo_user) {
            return home
                .join(".config")
                .join("cred-guard")
                .join("config.toml");
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("cred-guard")
        .join("config.toml")
}

/// Resolve another user's home directory via the password database.
fn home_for_user(username: &str) -> Option<PathBuf> {
    use std::ffi::CString;
    let name = CString::new(username).ok()?;
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    Some(PathBuf::from(dir.to_string_lossy().into_owned()))
}
