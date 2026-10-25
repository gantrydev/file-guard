use crate::config::Config;
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

pub fn load() -> anyhow::Result<Config> {
    let path = config_path()?;
    let contents = read_operator_config(&path).map_err(|e| {
        let message = match e.kind() {
            std::io::ErrorKind::NotFound => format!(
                "no config found at {}. If the daemon should be running, check \
             `systemctl status file-guard`; otherwise point FILE_GUARD_CONFIG \
             at your config.",
                path.display()
            ),
            std::io::ErrorKind::PermissionDenied if rustix::process::geteuid().as_raw() != 0 => {
                format!(
                    "config at {} is not readable by this user; re-run with sudo \
             (e.g. `sudo file-guard rules`).",
                    path.display()
                )
            }
            _ => format!("failed to read config at {}: {e}", path.display()),
        };
        anyhow::Error::new(e).context(message)
    })?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

/// Expand a leading `~/` to the watched user's home directory.
///
/// When file-guard runs as a privileged system daemon it is not the owner of
/// the credentials it guards, so `~` must resolve to the target user's home,
/// not root's. Resolution order: `FILE_GUARD_USER`, then `SUDO_USER`, then the
/// running user's home.
pub fn expand_path(path: &str) -> anyhow::Result<PathBuf> {
    expand_file_path(Path::new(path))
}

pub fn expand_file_path(path: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(rest) = path.strip_prefix("~")
        && let Some(home) = target_home()?
    {
        return Ok(home.join(rest));
    }
    Ok(path.to_path_buf())
}

pub fn watched_paths(config: &Config) -> anyhow::Result<Vec<PathBuf>> {
    config.watch.iter().map(|w| expand_path(&w.path)).collect()
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
    if rustix::process::geteuid().is_root() {
        return PathBuf::from("/run/file-guard/config");
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("file-guard").join("config");
    }
    let uid = rustix::process::getuid().as_raw();
    PathBuf::from(format!("/run/user/{uid}/file-guard/config"))
}

pub fn control_socket_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("FILE_GUARD_CONTROL_SOCKET") {
        return validate_env_path("FILE_GUARD_CONTROL_SOCKET", &path);
    }
    if rustix::process::geteuid().is_root() {
        return Ok(PathBuf::from("/run/file-guard/control.sock"));
    }
    user_control_socket_path()
}

pub fn control_socket_client_paths() -> anyhow::Result<Vec<PathBuf>> {
    if let Some(path) = std::env::var_os("FILE_GUARD_CONTROL_SOCKET") {
        return Ok(vec![validate_env_path("FILE_GUARD_CONTROL_SOCKET", &path)?]);
    }
    let system = PathBuf::from("/run/file-guard/control.sock");
    if rustix::process::geteuid().is_root() {
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
    let uid = rustix::process::getuid().as_raw();
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
        .unwrap_or_else(|| {
            PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()))
        })
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
    let effective_uid = rustix::process::geteuid().as_raw();
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

fn target_user() -> anyhow::Result<Option<nix::unistd::User>> {
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

fn lookup_user(name: &OsStr) -> anyhow::Result<Option<nix::unistd::User>> {
    let name = name
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("user name must be valid UTF-8"))?;
    Ok(nix::unistd::User::from_name(name)?)
}

fn target_home() -> anyhow::Result<Option<PathBuf>> {
    Ok(target_user()?.map(|user| user.dir).or_else(dirs::home_dir))
}

pub fn target_identity() -> anyhow::Result<(u32, u32)> {
    Ok(target_user()?.map_or_else(
        || {
            (
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
            )
        },
        |user| (user.uid.as_raw(), user.gid.as_raw()),
    ))
}

/// Path of the daemon's PID file, used by `file-guard stop` and `status` to
/// find a running daemon. `FILE_GUARD_PID_FILE` > `/run/file-guard/daemon.pid`
/// (root) > the user's runtime dir.
pub fn pid_file_path() -> anyhow::Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("FILE_GUARD_PID_FILE") {
        return validate_env_path("FILE_GUARD_PID_FILE", &explicit);
    }
    if rustix::process::geteuid().is_root() {
        return Ok(PathBuf::from("/run/file-guard/daemon.pid"));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime).join("file-guard").join("daemon.pid"));
    }
    let uid = rustix::process::getuid().as_raw();
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
    if rustix::process::geteuid().is_root() {
        let (target_uid, _) = target_identity()?;
        return Ok(PathBuf::from(format!(
            "/run/user/{}/file-guard-agent.sock",
            target_uid
        )));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime).join("file-guard-agent.sock"));
    }
    let uid = rustix::process::getuid().as_raw();
    Ok(PathBuf::from(format!(
        "/run/user/{uid}/file-guard-agent.sock"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_lookup_preserves_account_identity_and_home() {
        let expected = nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .unwrap();
        let actual = lookup_user(OsStr::new(&expected.name)).unwrap().unwrap();
        assert_eq!(
            (actual.uid, actual.gid, actual.dir),
            (expected.uid, expected.gid, expected.dir)
        );
        assert!(
            lookup_user(OsStr::new("file-guard-test-missing-account"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn expand_path_leaves_absolute_paths_untouched() {
        assert_eq!(
            expand_path("/etc/file-guard/config.toml").unwrap(),
            PathBuf::from("/etc/file-guard/config.toml"),
        );
    }

    #[test]
    fn cli_path_expansion_preserves_non_utf8_names() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(OsStr::from_bytes(b"/tmp/credential-\xff"));
        assert_eq!(expand_file_path(path).unwrap(), path);
        let relative = Path::new(OsStr::from_bytes(b"credential-\xff"));
        assert_eq!(expand_file_path(relative).unwrap(), relative);
    }

    #[test]
    fn operator_config_rejects_symlinks_and_writable_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = crate::testing::temp_dir("config");
        let target = directory.path().join("config.toml");
        let link = directory.path().join("link.toml");
        std::fs::write(&target, "[settings]\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(read_operator_config(&target).unwrap(), "[settings]\n");
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
