use crate::policy::rule::Access;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub settings: Settings,
    #[serde(default)]
    pub watch: Vec<WatchEntry>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    /// Per-file override of `settings.default_action`, applied when a prompt
    /// times out or the agent is unreachable for this file.
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
    /// sha256 of the pinned script's contents (interpreter rules only). Catches
    /// in-place tampering on distros where the script path is stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_sha256: Option<String>,
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
    /// Load the daemon's config (see `config_path` for resolution order),
    /// expanding ~ in all paths.
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path();
        let contents = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "no config found at {}. If the daemon should be running, check \
                 `systemctl status file-guard`; otherwise point FILE_GUARD_CONFIG \
                 at your config.",
                path.display()
            ),
            std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                "config at {} is not readable by this user; re-run with sudo \
                 (e.g. `sudo file-guard rules`).",
                path.display()
            ),
            _ => anyhow::anyhow!("failed to read config at {}: {e}", path.display()),
        })?;
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

    /// Remove the `[[rule]]` at `index` (0-based, matching `rule` order) from the
    /// config file, preserving the rest of the file's comments and formatting.
    /// Returns the removed entry's `(binary, file)` for reporting.
    pub fn remove_rule_at(index: usize) -> anyhow::Result<(String, String)> {
        use fs2::FileExt;
        use std::io::{Seek, Write};

        let path = config_path();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        file.lock_exclusive()?;

        let mut contents = String::new();
        std::io::Read::read_to_string(&mut file, &mut contents)?;
        let mut doc = contents.parse::<toml_edit::DocumentMut>()?;

        let rules = doc
            .get_mut("rule")
            .and_then(|i| i.as_array_of_tables_mut())
            .ok_or_else(|| anyhow::anyhow!("no [[rule]] entries in {}", path.display()))?;

        if index >= rules.len() {
            anyhow::bail!(
                "rule index {} out of range (have {} rule(s))",
                index,
                rules.len()
            );
        }

        let removed = rules.get(index).unwrap();
        let report = (
            removed
                .get("binary")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
            removed
                .get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
        );
        rules.remove(index);

        let rendered = doc.to_string();
        file.set_len(0)?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(rendered.as_bytes())?;

        file.unlock()?;
        Ok(report)
    }

    /// Reconcile the declarative seed into the daemon-managed live config:
    /// `[settings]` and `[[watch]]` are taken from the seed (the operator's
    /// source of truth, e.g. a Nix-store path), while learned `[[rule]]`
    /// ("allow always") entries already in the live file are preserved. No-op
    /// unless `FILE_GUARD_SEED_CONFIG` is set.
    ///
    /// This lets declarative changes apply on daemon restart without the
    /// operator hand-deleting the live file, while never losing captured rules.
    /// The live file is written world-readable (0644) - it holds only access
    /// policy, no secrets - so the guarded user can run read-only `status` /
    /// `rules` / `log` without sudo.
    pub fn reconcile_seed() -> anyhow::Result<()> {
        let Some(seed_path) = std::env::var_os("FILE_GUARD_SEED_CONFIG") else {
            return Ok(());
        };
        let seed_path = PathBuf::from(seed_path);
        let live_path = config_path();

        let seed: Config = std::fs::read_to_string(&seed_path)
            .map_err(|e| anyhow::anyhow!("failed to read seed config {}: {e}", seed_path.display()))
            .and_then(|s| Ok(toml::from_str(&s)?))?;

        // Preserve learned rules from the live file. If it exists but cannot be
        // parsed, abort rather than silently dropping captured rules.
        let rule = match std::fs::read_to_string(&live_path) {
            Ok(contents) => {
                parse_live_config(&contents)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "live config {} is corrupt ({e}); refusing to overwrite it and \
                             lose learned rules - fix or remove it manually",
                            live_path.display()
                        )
                    })?
                    .rule
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                anyhow::bail!("failed to read live config {}: {e}", live_path.display())
            }
        };

        let merged = Config {
            settings: seed.settings,
            watch: seed.watch,
            rule,
        };
        write_atomic(&live_path, &toml::to_string(&merged)?)
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

pub fn config_path() -> PathBuf {
    // Explicit override wins - the systemd unit points this at
    // /var/lib/file-guard/config.toml so the root daemon reads the operator's
    // config rather than /root/.config.
    if let Ok(path) = std::env::var("FILE_GUARD_CONFIG") {
        return PathBuf::from(path);
    }
    // A separate CLI invocation (`file-guard rules`, `status`, …) has no
    // FILE_GUARD_CONFIG, so follow the path the running daemon published. This
    // makes the CLI act on the daemon's actual config instead of guessing
    // ~/.config, regardless of where the operator put it.
    if let Some(path) = published_config_path() {
        return path;
    }
    if let Some(home) = target_home() {
        return home.join(".config").join("file-guard").join("config.toml");
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("file-guard")
        .join("config.toml")
}

/// Path of the runtime pointer file in which a running daemon records its
/// resolved config path, written beside the PID file in the root-owned
/// rendezvous dir. Mirrors `pid_file_path`'s root-vs-user split (the dev,
/// user-mode daemon publishes into its own runtime dir).
pub fn runtime_config_pointer_path() -> PathBuf {
    if unsafe { libc::geteuid() == 0 } {
        return PathBuf::from("/run/file-guard/config");
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("file-guard").join("config");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/file-guard/config"))
}

/// The config path a running daemon has published, if any. Checks the system
/// daemon's location first, then a dev (user-mode) daemon's runtime dir. The
/// pointer holds only a path (no secrets) and is world-readable, so an
/// unprivileged CLI can locate the config even when the config itself is
/// root-only (a read then fails with a clear "re-run with sudo").
fn published_config_path() -> Option<PathBuf> {
    let user_runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })))
        .join("file-guard")
        .join("config");
    for candidate in [PathBuf::from("/run/file-guard/config"), user_runtime] {
        if let Ok(contents) = std::fs::read_to_string(&candidate) {
            let path = PathBuf::from(contents.trim());
            if !path.as_os_str().is_empty() {
                return Some(path);
            }
        }
    }
    None
}

fn parse_live_config(contents: &str) -> Result<Config, toml::de::Error> {
    match toml::from_str(contents) {
        Ok(config) => Ok(config),
        Err(err) => {
            let Some(repaired) = remove_legacy_empty_rule_array(contents) else {
                return Err(err);
            };
            toml::from_str(&repaired).map_err(|_| err)
        }
    }
}

fn remove_legacy_empty_rule_array(contents: &str) -> Option<String> {
    if !contents.lines().any(|line| line.trim() == "[[rule]]") {
        return None;
    }

    let mut removed = false;
    let repaired = contents
        .lines()
        .filter(|line| {
            if !removed && line.trim() == "rule = []" {
                removed = true;
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    removed.then(|| format!("{repaired}\n"))
}

/// Atomically write `contents` to `path` (temp file + rename) with mode 0644.
/// The crash-safe rename means a reader never sees a half-written config.
fn write_atomic(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path {} has no parent", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("toml.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(contents.as_bytes())?;
    file.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    drop(file);
    std::fs::rename(&tmp, path)?;
    Ok(())
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

/// The uid of the guarded user - the account the prompt agent runs as.
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

/// Path of the daemon's PID file, used by `file-guard stop` and `status` to
/// find a running daemon. `FILE_GUARD_PID_FILE` > `/run/file-guard/daemon.pid`
/// (root) > the user's runtime dir.
pub fn pid_file_path() -> PathBuf {
    if let Some(explicit) = std::env::var_os("FILE_GUARD_PID_FILE") {
        return PathBuf::from(explicit);
    }
    if unsafe { libc::geteuid() == 0 } {
        return PathBuf::from("/run/file-guard/daemon.pid");
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("file-guard").join("daemon.pid");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/file-guard/daemon.pid"))
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
    // user's runtime dir - resolve it from FILE_GUARD_USER (via target_uid()),
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
    fn settings_only_config_defaults_to_no_watches() {
        let config: Config = toml::from_str(
            r#"
[settings]
default_action = "deny"
"#,
        )
        .unwrap();

        assert!(config.watch.is_empty());
        assert!(config.rule.is_empty());
    }

    #[test]
    fn reconcile_seed_applies_seed_and_preserves_learned_rules() {
        let dir = std::env::temp_dir().join(format!("fg-reconcile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seed = dir.join("seed.toml");
        let live = dir.join("live.toml");
        std::fs::write(
            &seed,
            "[settings]\ndefault_action = \"deny\"\n\
             [[watch]]\npath = \"~/.config/new/creds\"\n",
        )
        .unwrap();
        // Live file has stale settings/watch plus a learned rule to preserve.
        std::fs::write(
            &live,
            "[settings]\ndefault_action = \"allow\"\n\
             [[watch]]\npath = \"~/.config/OLD/creds\"\n\
             [[rule]]\nfile = \"~/.config/new/creds\"\n\
             binary = \"/usr/bin/x\"\naction = \"allow\"\n",
        )
        .unwrap();

        // SAFETY: set/remove process env around a self-contained reconcile; no
        // other test reads these vars.
        unsafe {
            std::env::set_var("FILE_GUARD_SEED_CONFIG", &seed);
            std::env::set_var("FILE_GUARD_CONFIG", &live);
        }
        Config::reconcile_seed().unwrap();
        unsafe {
            std::env::remove_var("FILE_GUARD_SEED_CONFIG");
            std::env::remove_var("FILE_GUARD_CONFIG");
        }

        let merged: Config = toml::from_str(&std::fs::read_to_string(&live).unwrap()).unwrap();
        // Seed's settings + watches win.
        assert_eq!(merged.settings.default_action, DefaultAction::Deny);
        assert_eq!(merged.watch.len(), 1);
        assert_eq!(merged.watch[0].path, "~/.config/new/creds");
        // Learned rule survives.
        assert_eq!(merged.rule.len(), 1);
        assert_eq!(merged.rule[0].binary, "/usr/bin/x");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_rules_are_not_serialized() {
        let config = Config {
            settings: Settings {
                default_action: DefaultAction::Deny,
                prompt_timeout: default_timeout(),
                prompt_method: PromptMethod::Gui,
                restore_on_stop: true,
                log_destination: default_log_dest(),
            },
            watch: vec![WatchEntry {
                path: "~/.config/gcloud/credentials.db".into(),
                default_action: None,
            }],
            rule: Vec::new(),
        };

        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("rule = []"));
        assert!(!serialized.contains("[[rule]]"));
    }

    #[test]
    fn live_config_accepts_legacy_empty_rule_array_before_rule_tables() {
        let toml = r#"
rule = []

[settings]
default_action = "deny"

[[watch]]
path = "~/.config/gcloud/credentials.db"

[[rule]]
file = "~/.config/gcloud/credentials.db"
binary = "/usr/bin/gcloud"
action = "allow"
"#;
        assert!(toml::from_str::<Config>(toml).is_err());

        let config = parse_live_config(toml).unwrap();
        assert_eq!(config.rule.len(), 1);
        assert_eq!(config.rule[0].binary, "/usr/bin/gcloud");
    }

    #[test]
    fn legacy_empty_rule_array_repair_is_not_applied_without_rule_tables() {
        let toml = r#"
rule = []

[settings]
default_action = "deny"
"#;
        assert!(remove_legacy_empty_rule_array(toml).is_none());
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
            script_sha256: None,
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
