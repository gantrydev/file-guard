use crate::policy::rule::Access;
use serde::{Deserialize, Deserializer, Serialize};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn validate_env_path(var: &str, value: &OsStr) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        anyhow::bail!("${} must be an absolute path, got: {}", var, path.display());
    }
    let components: Vec<_> = path.components().collect();
    if components.len() > 64 {
        anyhow::bail!(
            "${} path is suspiciously deep ({} components)",
            var,
            components.len()
        );
    }
    Ok(path)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub settings: Settings,
    #[serde(default)]
    pub watch: Vec<WatchEntry>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule: Vec<RuleEntry>,
}

#[derive(Debug, Serialize)]
pub struct Settings {
    #[serde(default)]
    pub default_action: DefaultAction,
    #[serde(default = "default_timeout")]
    pub prompt_timeout: u64,
    #[serde(default)]
    pub prompt_method: PromptMethod,
    /// Fire a desktop notification alongside every prompt, even for
    /// `log_only` (which otherwise has no visible feedback). On Linux
    /// this calls `notify-send` from the user's session agent.
    pub notify: bool,
    #[serde(default)]
    pub restore_on_stop: bool,
    #[serde(default = "default_log_dest")]
    pub log_destination: String,
}

#[derive(Deserialize)]
struct SettingsInput {
    #[serde(default)]
    default_action: DefaultAction,
    #[serde(default = "default_timeout")]
    prompt_timeout: u64,
    #[serde(default)]
    prompt_method: PromptMethodInput,
    #[serde(default)]
    notify: Option<bool>,
    #[serde(default)]
    restore_on_stop: bool,
    #[serde(default = "default_log_dest")]
    log_destination: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PromptMethodInput {
    #[default]
    Terminal,
    Gui,
    LogOnly,
    Notification,
}

impl<'de> Deserialize<'de> for Settings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = SettingsInput::deserialize(deserializer)?;
        let legacy_notification = matches!(input.prompt_method, PromptMethodInput::Notification);
        let prompt_method = match input.prompt_method {
            PromptMethodInput::Terminal => PromptMethod::Terminal,
            PromptMethodInput::Gui => PromptMethod::Gui,
            PromptMethodInput::LogOnly | PromptMethodInput::Notification => PromptMethod::LogOnly,
        };

        Ok(Self {
            default_action: input.default_action,
            prompt_timeout: input.prompt_timeout,
            prompt_method,
            notify: input.notify.unwrap_or(legacy_notification),
            restore_on_stop: input.restore_on_stop,
            log_destination: input.log_destination,
        })
    }
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
#[serde(rename_all = "snake_case")]
pub enum PromptMethod {
    #[default]
    Terminal,
    Gui,
    /// Log-only: no interactive prompt. Falls back to `default_action` after
    /// the configured prompt timeout. If `notify` is set, a desktop
    /// notification is also fired.
    LogOnly,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WatchEntry {
    pub path: String,
    /// Per-file override of `settings.default_action`, applied when a prompt
    /// times out or the agent is unreachable for this file.
    #[serde(default)]
    pub default_action: Option<DefaultAction>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
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
    /// Legacy field retained so older rule files continue to round-trip.
    /// Ignored by the Linux policy engine.
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

#[derive(Deserialize, Serialize)]
struct RulesDocument {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rule: Vec<RuleEntry>,
}

pub fn parse_rules_document(contents: &str) -> anyhow::Result<Vec<RuleEntry>> {
    Ok(toml::from_str::<RulesDocument>(contents)?.rule)
}

pub fn serialize_rules_document(rules: Vec<RuleEntry>) -> anyhow::Result<String> {
    Ok(toml::to_string(&RulesDocument { rule: rules })?)
}

impl Config {
    /// Load the daemon's config (see `config_path` for resolution order),
    /// expanding ~ in all paths.
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path()?;
        let contents = read_operator_config(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "no config found at {}. If the daemon should be running, check \
                 `systemctl status file-guard`; otherwise point FILE_GUARD_CONFIG \
                 at your config.",
                path.display()
            ),
            std::io::ErrorKind::PermissionDenied if unsafe { libc::geteuid() } != 0 => {
                anyhow::anyhow!(
                    "config at {} is not readable by this user; re-run with sudo \
                 (e.g. `sudo file-guard rules`).",
                    path.display()
                )
            }
            _ => anyhow::anyhow!("failed to read config at {}: {e}", path.display()),
        })?;
        let config = parse_live_config(&contents)?;
        Ok(config)
    }

    /// Copy the operator-owned declarative seed to the live config path. A
    /// caller-provided migration runs before replacement so rules captured by
    /// older versions can be committed to the learned-rule database first.
    /// An existing live file keeps its ownership and permissions. A newly
    /// created file is mode 0644 because it contains policy, not credentials.
    pub fn reconcile_seed(
        migrate_rules: impl FnOnce(Vec<RuleEntry>, Vec<RuleEntry>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let Some(seed_path) = std::env::var_os("FILE_GUARD_SEED_CONFIG") else {
            return Ok(());
        };
        let seed_path = validate_env_path("FILE_GUARD_SEED_CONFIG", &seed_path)?;
        let live_path = config_path()?;

        let seed = read_operator_config(&seed_path).map_err(|e| {
            anyhow::anyhow!("failed to read seed config {}: {e}", seed_path.display())
        })?;
        let seed_config = parse_live_config(&seed).map_err(|error| {
            anyhow::anyhow!("seed config {} is invalid: {error}", seed_path.display())
        })?;
        update_config(&live_path, true, |current| {
            let previous_rules = current
                .map(parse_live_config)
                .transpose()
                .map_err(|error| {
                    anyhow::anyhow!(
                        "live config {} is invalid; refusing to replace it before legacy-rule migration: {error}",
                        live_path.display()
                    )
                })?
                .map(|config| config.rule)
                .unwrap_or_default();
            migrate_rules(previous_rules, seed_config.rule)?;
            Ok((seed, ()))
        })
    }

    /// Expand a leading `~/` to the watched user's home directory.
    ///
    /// When file-guard runs as a privileged system daemon it is *not* the
    /// owner of the credentials it guards, so `~` must resolve to the target
    /// user's home, not root's. Resolution order: `FILE_GUARD_USER`, then
    /// `SUDO_USER`, then the running user's home.
    pub fn expand_path(path: &str) -> anyhow::Result<PathBuf> {
        if let Some(rest) = path.strip_prefix("~/")
            && let Some(home) = target_home()?
        {
            return Ok(home.join(rest));
        }
        Ok(PathBuf::from(path))
    }

    /// Resolved watch paths with ~ expanded.
    pub fn watched_paths(&self) -> anyhow::Result<Vec<PathBuf>> {
        self.watch
            .iter()
            .map(|w| Self::expand_path(&w.path))
            .collect()
    }
}

pub fn config_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("FILE_GUARD_CONFIG") {
        return validate_env_path("FILE_GUARD_CONFIG", &path);
    }
    if let Some(path) = published_config_path() {
        return Ok(path);
    }
    if let Some(home) = target_home()? {
        return Ok(home.join(".config").join("file-guard").join("config.toml"));
    }
    Ok(dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("file-guard")
        .join("config.toml"))
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

pub fn control_socket_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("FILE_GUARD_CONTROL_SOCKET") {
        return validate_env_path("FILE_GUARD_CONTROL_SOCKET", &path);
    }
    if unsafe { libc::geteuid() == 0 } {
        return Ok(PathBuf::from("/run/file-guard/control.sock"));
    }
    user_control_socket_path()
}

pub fn control_socket_client_paths() -> anyhow::Result<Vec<PathBuf>> {
    if let Some(path) = std::env::var_os("FILE_GUARD_CONTROL_SOCKET") {
        return Ok(vec![validate_env_path("FILE_GUARD_CONTROL_SOCKET", &path)?]);
    }
    let system = PathBuf::from("/run/file-guard/control.sock");
    if unsafe { libc::geteuid() == 0 } {
        return Ok(vec![system]);
    }
    Ok(default_client_control_sockets(user_control_socket_path()?))
}

fn default_client_control_sockets(user: PathBuf) -> Vec<PathBuf> {
    vec![PathBuf::from("/run/file-guard/control.sock"), user]
}

fn user_control_socket_path() -> anyhow::Result<PathBuf> {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(validate_env_path("XDG_RUNTIME_DIR", &runtime)?.join("file-guard-control.sock"));
    }
    let uid = unsafe { libc::getuid() };
    Ok(PathBuf::from(format!(
        "/run/user/{uid}/file-guard-control.sock"
    )))
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
            if path.is_absolute() {
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

fn read_operator_config(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("config path must be absolute: {}", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("config path {} has no parent", path.display()),
        )
    })?;
    crate::secure_file::validate_trusted_directory(parent)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "config {} must be a regular file owned by root or uid {effective_uid}, and must not be writable by group or others",
                path.display()
            ),
        ));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
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

fn update_config<T>(
    path: &Path,
    allow_missing: bool,
    update: impl FnOnce(Option<&str>) -> anyhow::Result<(String, T)>,
) -> anyhow::Result<T> {
    let _lock = lock_config(path)?;
    let current = match read_config_for_update(path) {
        Ok(value) => Some(value),
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let (rendered, result) = update(current.as_ref().map(|(contents, _)| contents.as_str()))?;
    if current
        .as_ref()
        .is_some_and(|(contents, _)| contents == &rendered)
    {
        return Ok(result);
    }
    write_atomic(
        path,
        &rendered,
        current.as_ref().map(|(_, metadata)| metadata),
    )?;
    Ok(result)
}

fn lock_config(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path {} has no parent", path.display()))?;
    crate::secure_file::ensure_trusted_directory(parent, 0o700)?;

    let lock_path = config_lock_path(path)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|error| anyhow::anyhow!("opening config lock {}: {error}", lock_path.display()))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        anyhow::bail!(
            "config lock {} must be a regular file owned by uid {}",
            lock_path.display(),
            unsafe { libc::geteuid() }
        );
    }
    if metadata.mode() & 0o7777 != 0o600 {
        lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(lock)
}

fn config_lock_path(path: &Path) -> anyhow::Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("config path {} has no file name", path.display()))?
        .to_os_string();
    name.push(".lock");
    Ok(path.with_file_name(name))
}

fn read_config_for_update(path: &Path) -> std::io::Result<(String, std::fs::Metadata)> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "config {} must be a singly-linked regular file owned by uid {} and not writable by group or others",
                path.display(),
                unsafe { libc::geteuid() }
            ),
        ));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok((contents, metadata))
}

fn write_atomic(
    path: &Path,
    contents: &str,
    expected: Option<&std::fs::Metadata>,
) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path {} has no parent", path.display()))?;
    let mut name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("config path {} has no file name", path.display()))?
        .to_os_string();
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = path.with_file_name(name);
    let result = (|| -> anyhow::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp)?;

        if let Some(metadata) = expected {
            let actual = file.metadata()?;
            if actual.uid() != metadata.uid() || actual.gid() != metadata.gid() {
                let rc = unsafe {
                    libc::fchown(
                        file.as_raw_fd(),
                        metadata.uid() as libc::uid_t,
                        metadata.gid() as libc::gid_t,
                    )
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            file.set_permissions(std::fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
        } else {
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }

        file.write_all(contents.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
        verify_config_target(path, expected)?;
        std::fs::rename(&tmp, path)?;

        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)?
            .sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn verify_config_target(path: &Path, expected: Option<&std::fs::Metadata>) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    match (expected, std::fs::symlink_metadata(path)) {
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        (None, Ok(_)) => anyhow::bail!("config {} appeared during update", path.display()),
        (None, Err(error)) => Err(error.into()),
        (Some(expected), Ok(actual))
            if actual.is_file()
                && actual.dev() == expected.dev()
                && actual.ino() == expected.ino()
                && actual.ctime() == expected.ctime()
                && actual.ctime_nsec() == expected.ctime_nsec()
                && actual.len() == expected.len() =>
        {
            Ok(())
        }
        (Some(_), Ok(_)) => anyhow::bail!("config {} changed during update", path.display()),
        (Some(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("config {} disappeared during update", path.display())
        }
        (Some(_), Err(error)) => Err(error.into()),
    }
}

#[derive(Clone)]
struct UserRecord {
    uid: u32,
    gid: u32,
    home: PathBuf,
}

fn target_user() -> anyhow::Result<Option<UserRecord>> {
    for variable in ["FILE_GUARD_USER", "SUDO_USER"] {
        if let Some(name) = std::env::var_os(variable) {
            return lookup_user(&name)?.map(Some).ok_or_else(|| {
                anyhow::anyhow!(
                    "${variable} names an unknown user: {}",
                    name.to_string_lossy()
                )
            });
        }
    }
    Ok(None)
}

fn lookup_user(name: &OsStr) -> anyhow::Result<Option<UserRecord>> {
    use std::os::unix::ffi::OsStrExt;

    let name = std::ffi::CString::new(name.as_bytes())?;
    let mut buffer_len = 16 * 1024;
    loop {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_len];
        let status = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer_len < 1024 * 1024 {
            buffer_len *= 2;
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status).into());
        }
        if result.is_null() {
            return Ok(None);
        }
        let record = unsafe { record.assume_init() };
        let home = unsafe { std::ffi::CStr::from_ptr(record.pw_dir) };
        return Ok(Some(UserRecord {
            uid: record.pw_uid,
            gid: record.pw_gid,
            home: PathBuf::from(OsStr::from_bytes(home.to_bytes())),
        }));
    }
}

fn target_home() -> anyhow::Result<Option<PathBuf>> {
    Ok(target_user()?.map(|user| user.home).or_else(dirs::home_dir))
}

pub fn target_identity() -> anyhow::Result<(u32, u32)> {
    Ok(target_user()?.map_or_else(
        || (unsafe { libc::getuid() }, unsafe { libc::getgid() }),
        |user| (user.uid, user.gid),
    ))
}

/// Path of the daemon's PID file, used by `file-guard stop` and `status` to
/// find a running daemon. `FILE_GUARD_PID_FILE` > `/run/file-guard/daemon.pid`
/// (root) > the user's runtime dir.
pub fn pid_file_path() -> anyhow::Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("FILE_GUARD_PID_FILE") {
        return validate_env_path("FILE_GUARD_PID_FILE", &explicit);
    }
    if unsafe { libc::geteuid() == 0 } {
        return Ok(PathBuf::from("/run/file-guard/daemon.pid"));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime).join("file-guard").join("daemon.pid"));
    }
    let uid = unsafe { libc::getuid() };
    Ok(PathBuf::from(format!(
        "/run/user/{uid}/file-guard/daemon.pid"
    )))
}

/// Canonical path of the daemon↔agent socket. Both ends resolve it identically.
///
/// In production the NixOS module sets `FILE_GUARD_AGENT_SOCKET` to a path
/// inside a root-owned directory on both units, so the socket name cannot be
/// hijacked. The dev fallback lives in the user's runtime dir and is NOT
/// hardened against same-uid impersonation.
pub fn agent_socket_path() -> anyhow::Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("FILE_GUARD_AGENT_SOCKET") {
        return validate_env_path("FILE_GUARD_AGENT_SOCKET", &explicit);
    }
    if unsafe { libc::geteuid() == 0 } {
        let (target_uid, _) = target_identity()?;
        return Ok(PathBuf::from(format!(
            "/run/user/{}/file-guard-agent.sock",
            target_uid
        )));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime).join("file-guard-agent.sock"));
    }
    let uid = unsafe { libc::getuid() };
    Ok(PathBuf::from(format!(
        "/run/user/{uid}/file-guard-agent.sock"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    fn temp_config() -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "file-guard-config-{}-{}.toml",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn remove_temp_config(path: &Path) {
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(config_lock_path(path).unwrap()).unwrap();
    }

    fn pinned_rule(hash: &str) -> RuleEntry {
        RuleEntry {
            file: "/home/a/.config/x".into(),
            binary: "/usr/bin/x".into(),
            action: RuleAction::Allow,
            access: Access::Any,
            sha256: Some(hash.into()),
            signature: None,
            script: None,
            script_sha256: None,
        }
    }

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
    fn legacy_notification_method_keeps_notifications_enabled() {
        let config: Config = toml::from_str(
            r#"
[settings]
prompt_method = "notification"
"#,
        )
        .unwrap();

        assert_eq!(config.settings.prompt_method, PromptMethod::LogOnly);
        assert!(config.settings.notify);

        let serialized = toml::to_string(&config).unwrap();
        assert!(serialized.contains("prompt_method = \"log_only\""));
        assert!(serialized.contains("notify = true"));
    }

    #[test]
    fn log_only_defaults_to_no_desktop_notification() {
        let config: Config = toml::from_str(
            r#"
[settings]
prompt_method = "log_only"
"#,
        )
        .unwrap();

        assert_eq!(config.settings.prompt_method, PromptMethod::LogOnly);
        assert!(!config.settings.notify);
    }

    #[test]
    fn reconcile_seed_replaces_the_complete_declarative_config() {
        let dir = std::env::temp_dir().join(format!("fg-reconcile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seed = dir.join("seed.toml");
        let live = dir.join("live.toml");
        std::fs::write(
            &seed,
            "[settings]\ndefault_action = \"deny\"\n\
             [[watch]]\npath = \"~/.config/new/creds\"\n\
             [[rule]]\nfile = \"~/.config/new/creds\"\n\
             binary = \"/usr/bin/new\"\naction = \"allow\"\n",
        )
        .unwrap();
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
        let migrated = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = Arc::clone(&migrated);
        Config::reconcile_seed(move |previous, declarative| {
            *captured.lock().unwrap() = previous
                .into_iter()
                .filter(|rule| !declarative.contains(rule))
                .collect();
            Ok(())
        })
        .unwrap();
        unsafe {
            std::env::remove_var("FILE_GUARD_SEED_CONFIG");
            std::env::remove_var("FILE_GUARD_CONFIG");
        }

        let merged: Config = toml::from_str(&std::fs::read_to_string(&live).unwrap()).unwrap();
        assert_eq!(merged.settings.default_action, DefaultAction::Deny);
        assert_eq!(merged.watch.len(), 1);
        assert_eq!(merged.watch[0].path, "~/.config/new/creds");
        assert_eq!(merged.rule.len(), 1);
        assert_eq!(merged.rule[0].binary, "/usr/bin/new");
        assert_eq!(migrated.lock().unwrap().len(), 1);
        assert_eq!(migrated.lock().unwrap()[0].binary, "/usr/bin/x");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_rules_are_not_serialized() {
        let config = Config {
            settings: Settings {
                default_action: DefaultAction::Deny,
                prompt_timeout: default_timeout(),
                prompt_method: PromptMethod::Gui,
                notify: false,
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
            Config::expand_path("/etc/file-guard/config.toml").unwrap(),
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

    #[test]
    fn rules_document_round_trips_without_settings() {
        let rule = pinned_rule("hash");
        let exported = serialize_rules_document(vec![rule.clone()]).unwrap();

        assert!(!exported.contains("[settings]"));
        assert_eq!(parse_rules_document(&exported).unwrap(), vec![rule]);
    }

    #[test]
    fn concurrent_config_updates_are_linearized_by_the_sidecar_lock() {
        let path = temp_config();
        std::fs::write(&path, "[settings]\n").unwrap();
        let writers = 16;
        let barrier = Arc::new(Barrier::new(writers));
        let mut threads = Vec::new();
        for writer in 0..writers {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let rule = pinned_rule(&format!("hash-{writer}"));
                barrier.wait();
                update_config(&path, false, |current| {
                    let mut config = parse_live_config(current.unwrap())?;
                    config.rule.push(rule);
                    Ok((toml::to_string(&config)?, ()))
                })
                .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let config: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(config.rule.len(), writers);
        remove_temp_config(&path);
    }

    #[test]
    fn atomic_config_update_preserves_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path = temp_config();
        std::fs::write(&path, "[settings]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        update_config(&path, false, |current| {
            Ok((format!("{}\n# updated\n", current.unwrap()), ()))
        })
        .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
        remove_temp_config(&path);
    }

    #[test]
    fn operator_config_rejects_symlinks_and_writable_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let target = temp_config();
        let link = temp_config();
        std::fs::write(&target, "[settings]\n").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_operator_config(&link).is_err());
        std::fs::remove_file(&link).unwrap();

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_operator_config(&target).is_err());
        std::fs::remove_file(target).unwrap();
    }

    #[test]
    fn unprivileged_clients_prefer_the_system_control_socket() {
        assert_eq!(
            default_client_control_sockets(PathBuf::from("/run/user/1000/local.sock")),
            vec![
                PathBuf::from("/run/file-guard/control.sock"),
                PathBuf::from("/run/user/1000/local.sock")
            ]
        );
    }
}
