use crate::policy::rule::Access;
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

#[derive(Debug, Deserialize, Serialize, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
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
    // TODO: per-file default override is parsed but NOT yet honored — the
    // policy engine only uses the global settings.default_action. Wire this
    // through PolicyEngine::evaluate (keyed by watched file) before documenting
    // it as functional.
    #[allow(dead_code)]
    #[serde(default)]
    pub default_action: Option<DefaultAction>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleEntry {
    pub file: String,
    pub binary: String,
    pub action: RuleAction,
    /// Direction the rule authorizes. Absent in legacy configs → `read`, so
    /// every previously-written rule keeps its read-only meaning.
    #[serde(default, skip_serializing_if = "access_is_read")]
    pub access: Access,
    /// sha256 of the binary when the rule was captured (binary-identity pin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// macOS code-signing identity captured with the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// For interpreter rules, the pinned script path (narrows the interpreter
    /// to a specific program).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
}

fn access_is_read(access: &Access) -> bool {
    *access == Access::Read
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

impl Config {
    /// Load from ~/.config/file-guard/config.toml, expanding ~ in all paths.
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
        let file = std::fs::OpenOptions::new().append(true).open(&path)?;
        file.lock_exclusive()?;

        let rule_toml = toml::to_string(entry)?;
        let mut writer = std::io::BufWriter::new(&file);
        writeln!(writer, "\n[[rule]]")?;
        write!(writer, "{rule_toml}")?;

        file.unlock()?;
        Ok(())
    }

    /// Expand a leading `~/` to the watched user's home directory.
    ///
    /// When file-guard runs as a privileged system daemon it is *not* the
    /// owner of the credentials it guards, so `~` must resolve to the target
    /// user's home, not root's. Resolution order: `FILE_GUARD_USER`, then
    /// `SUDO_USER`, then the running user's home.
    pub fn expand_path(path: &str) -> PathBuf {
        if let Some(rest) = path.strip_prefix("~/")
            && let Some(home) = target_home()
        {
            return home.join(rest);
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
    // Explicit override wins — the systemd unit points this at
    // /etc/file-guard/config.toml so the root daemon reads the operator's
    // config rather than /root/.config.
    if let Ok(path) = std::env::var("FILE_GUARD_CONFIG") {
        return PathBuf::from(path);
    }
    if let Some(home) = target_home() {
        return home.join(".config").join("file-guard").join("config.toml");
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("file-guard")
        .join("config.toml")
}

/// The home directory of the user whose credentials are being guarded.
/// `FILE_GUARD_USER` (explicit) > `SUDO_USER` > the running user.
fn target_home() -> Option<PathBuf> {
    std::env::var("FILE_GUARD_USER")
        .ok()
        .and_then(|u| home_for_user(&u))
        .or_else(|| {
            std::env::var("SUDO_USER")
                .ok()
                .and_then(|u| home_for_user(&u))
        })
        .or_else(dirs::home_dir)
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

/// Resolve a username to its uid via the password database.
fn uid_for_user(username: &str) -> Option<u32> {
    use std::ffi::CString;
    let name = CString::new(username).ok()?;
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    Some(unsafe { (*pw).pw_uid })
}

/// The uid of the guarded user — the account the prompt agent runs as.
/// `FILE_GUARD_USER` > `SUDO_USER` > the running user.
pub fn target_uid() -> u32 {
    std::env::var("FILE_GUARD_USER")
        .ok()
        .and_then(|u| uid_for_user(&u))
        .or_else(|| {
            std::env::var("SUDO_USER")
                .ok()
                .and_then(|u| uid_for_user(&u))
        })
        .unwrap_or_else(|| unsafe { libc::getuid() })
}

/// Canonical path of the daemon↔agent socket. Both ends resolve it identically.
///
/// In production the NixOS module sets `FILE_GUARD_AGENT_SOCKET` to a path
/// inside a root-owned directory on both units, so the socket name cannot be
/// hijacked. The dev fallback lives in the user's runtime dir and is NOT
/// hardened against same-uid impersonation.
pub fn agent_socket_path() -> PathBuf {
    if let Some(explicit) = std::env::var_os("FILE_GUARD_AGENT_SOCKET") {
        return PathBuf::from(explicit);
    }
    // The root daemon connects to the guarded user's agent, which lives in that
    // user's runtime dir — resolve it from FILE_GUARD_USER (via target_uid()),
    // since root's own XDG_RUNTIME_DIR is the wrong place.
    if unsafe { libc::geteuid() == 0 } {
        return PathBuf::from(format!("/run/user/{}/file-guard-agent.sock", target_uid()));
    }
    // A user-mode agent/daemon: its own runtime dir.
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("file-guard-agent.sock");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/file-guard-agent.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings_watch_rule() {
        let toml = r#"
[settings]
default_action = "deny"

[[watch]]
path = "~/.aws/credentials"

[[rule]]
file = "~/.aws/credentials"
binary = "/usr/bin/aws"
action = "allow"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.watch.len(), 1);
        assert_eq!(config.rule.len(), 1);
        assert_eq!(config.settings.default_action, DefaultAction::Deny);
        assert_eq!(config.settings.prompt_timeout, 30); // serde default
        assert_eq!(config.rule[0].action, RuleAction::Allow);
    }

    #[test]
    fn expand_path_leaves_absolute_paths_untouched() {
        assert_eq!(
            Config::expand_path("/etc/file-guard/config.toml"),
            PathBuf::from("/etc/file-guard/config.toml"),
        );
    }

    #[test]
    fn legacy_rule_defaults_to_unpinned_read() {
        // A rule written before direction/pinning existed must keep working.
        let toml = r#"
[settings]
[[watch]]
path = "~/.aws/credentials"
[[rule]]
file = "~/.aws/credentials"
binary = "/usr/bin/aws"
action = "allow"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.rule[0].access, Access::Read);
        assert!(config.rule[0].sha256.is_none());
        assert!(config.rule[0].signature.is_none());
    }

    #[test]
    fn write_rule_with_pin_round_trips() {
        let entry = RuleEntry {
            file: "/home/a/.config/x".into(),
            binary: "/usr/bin/x".into(),
            action: RuleAction::Allow,
            access: Access::Write,
            sha256: Some("deadbeef".into()),
            signature: None,
            script: None,
        };
        let serialized = toml::to_string(&entry).unwrap();
        assert!(serialized.contains("access = \"write\""));
        assert!(serialized.contains("sha256 = \"deadbeef\""));
        assert!(!serialized.contains("signature"));

        let back: RuleEntry = toml::from_str(&serialized).unwrap();
        assert_eq!(back.access, Access::Write);
        assert_eq!(back.sha256.as_deref(), Some("deadbeef"));
    }
}
