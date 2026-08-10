//! Out-of-process control of a running daemon: `stop`, `status`, and `log`.
//! These run as a separate short-lived `file-guard` invocation and locate the
//! daemon via its PID file and the audit log via the config.

use crate::config::{self, Config};
use crate::logging;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonIdentity {
    pid: u32,
    start_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonProcess {
    Verified(DaemonIdentity),
    Unverified(DaemonIdentity),
}

impl DaemonProcess {
    fn identity(self) -> DaemonIdentity {
        match self {
            Self::Verified(identity) | Self::Unverified(identity) => identity,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityState {
    Verified,
    Unverified,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessProbe {
    Alive,
    Missing,
    Unknown,
}

/// PID of the running daemon, or `None` if none is running. Checks this
/// context's PID path first, then the system daemon's well-known location, so a
/// guarded (non-root) user - whose context resolves to its own runtime dir -
/// still sees the root daemon at `/run/file-guard/daemon.pid`.
pub fn running_pid() -> anyhow::Result<Option<u32>> {
    Ok(running_process()?.map(|process| process.identity().pid))
}

fn running_process() -> anyhow::Result<Option<DaemonProcess>> {
    let primary = config::pid_file_path()?;
    if let Some(process) = process_from(&primary) {
        return Ok(Some(process));
    }
    let system = PathBuf::from("/run/file-guard/daemon.pid");
    if system != primary {
        return Ok(process_from(&system));
    }
    Ok(None)
}

fn process_from(path: &Path) -> Option<DaemonProcess> {
    let identity = std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| parse_daemon_identity(&contents))?;
    match classify_identity(identity) {
        IdentityState::Verified => Some(DaemonProcess::Verified(identity)),
        IdentityState::Unverified => Some(DaemonProcess::Unverified(identity)),
        IdentityState::Stale => {
            let _ = std::fs::remove_file(path);
            None
        }
    }
}

fn parse_daemon_identity(contents: &str) -> Option<DaemonIdentity> {
    let mut fields = contents.split_whitespace();
    let identity = DaemonIdentity {
        pid: fields.next()?.parse().ok()?,
        start_time: fields.next()?.parse().ok()?,
    };
    if fields.next().is_some() || identity.pid == 0 || i32::try_from(identity.pid).is_err() {
        return None;
    }
    Some(identity)
}

fn identity_alive(identity: DaemonIdentity) -> bool {
    crate::process::start_time(identity.pid).ok() == Some(identity.start_time)
}

fn classify_identity(identity: DaemonIdentity) -> IdentityState {
    match crate::process::start_time(identity.pid) {
        Ok(start_time) if start_time == identity.start_time => IdentityState::Verified,
        Ok(_) => IdentityState::Stale,
        Err(_) => classify_unreadable_identity(probe_process(identity.pid)),
    }
}

fn classify_unreadable_identity(probe: ProcessProbe) -> IdentityState {
    match probe {
        ProcessProbe::Missing => IdentityState::Stale,
        ProcessProbe::Alive | ProcessProbe::Unknown => IdentityState::Unverified,
    }
}

fn probe_process(pid: u32) -> ProcessProbe {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return ProcessProbe::Missing;
    };
    if unsafe { libc::kill(pid, 0) } == 0 {
        return ProcessProbe::Alive;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => ProcessProbe::Alive,
        Some(libc::ESRCH) => ProcessProbe::Missing,
        _ => ProcessProbe::Unknown,
    }
}

/// Send SIGTERM to the running daemon and wait for it to exit (and run its
/// unmount path). Errors if no daemon is running.
pub fn stop() -> anyhow::Result<()> {
    let pid_path = config::pid_file_path()?;
    let Some(process) = running_process()? else {
        anyhow::bail!(
            "no running daemon found (no matching process identity at {}). \
             Under systemd use `systemctl stop file-guard`.",
            pid_path.display()
        );
    };
    let identity = match process {
        DaemonProcess::Verified(identity) => identity,
        DaemonProcess::Unverified(identity) => anyhow::bail!(
            "daemon pid {} exists, but its process identity is hidden; \
             re-run with sufficient privilege or use `sudo systemctl stop file-guard`",
            identity.pid
        ),
    };
    let pid = identity.pid;

    #[cfg(target_os = "linux")]
    let maybe_process = signal_linux_daemon(identity)?;
    #[cfg(not(target_os = "linux"))]
    signal_daemon(identity)?;

    println!("sent SIGTERM to file-guard (pid {pid}); waiting for unmount…");

    #[cfg(target_os = "linux")]
    if let Some(process) = maybe_process {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};

        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        let mut descriptor = [PollFd::new(&process, PollFlags::IN)];
        for _ in 0..150 {
            match poll(&mut descriptor, Some(&timeout)) {
                Ok(0) => {}
                Ok(_) => {
                    println!("stopped");
                    return Ok(());
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "failed waiting for daemon (pid {pid}): {error}"
                    ));
                }
            }
        }
        anyhow::bail!("daemon (pid {pid}) did not exit within 15s")
    }

    // pidfd-free polling path (pre-5.1 Linux fallback + all non-Linux).
    for _ in 0..150 {
        if !identity_alive(identity) {
            println!("stopped");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("daemon (pid {pid}) did not exit within 15s");
}

#[cfg(target_os = "linux")]
fn signal_linux_daemon(identity: DaemonIdentity) -> anyhow::Result<Option<rustix::fd::OwnedFd>> {
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

    let raw_pid = i32::try_from(identity.pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| anyhow::anyhow!("invalid daemon pid {}", identity.pid))?;
    match pidfd_open(raw_pid, PidfdFlags::empty()) {
        Ok(process) => {
            if !identity_alive(identity) {
                anyhow::bail!(
                    "daemon pid {} was recycled before it could be signaled",
                    identity.pid
                )
            }
            pidfd_send_signal(&process, Signal::TERM).map_err(|error| {
                let error = std::io::Error::from_raw_os_error(error.raw_os_error());
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    anyhow::anyhow!(
                        "cannot signal daemon (pid {}): it runs as another user. \
                         Use `sudo systemctl stop file-guard`.",
                        identity.pid
                    )
                } else {
                    anyhow::anyhow!("failed to signal daemon (pid {}): {error}", identity.pid)
                }
            })?;
            Ok(Some(process))
        }
        Err(rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL) => {
            // Pre-5.1 kernel: pidfd_open not available. Fall back to kill()
            // after re-verifying the start-time identity to guard against
            // PID recycling.
            if !identity_alive(identity) {
                anyhow::bail!(
                    "daemon pid {} was recycled before it could be signaled",
                    identity.pid
                )
            }
            let pid = identity.pid as libc::pid_t;
            if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    anyhow::bail!(
                        "cannot signal daemon (pid {}): it runs as another user. \
                         Use `sudo systemctl stop file-guard`.",
                        identity.pid
                    )
                }
                anyhow::bail!("failed to signal daemon (pid {}): {error}", identity.pid)
            }
            tracing::info!(
                "pidfd_open unavailable (kernel < 5.1); signaled via kill(), \
                 falling back to sleep-based polling"
            );
            Ok(None)
        }
        Err(error) => {
            let error = std::io::Error::from_raw_os_error(error.raw_os_error());
            Err(anyhow::anyhow!(
                "pidfd_open for pid {}: {error}",
                identity.pid
            ))
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_daemon(identity: DaemonIdentity) -> anyhow::Result<()> {
    if !identity_alive(identity) {
        anyhow::bail!("daemon pid {} was recycled", identity.pid)
    }
    if unsafe { libc::kill(identity.pid as libc::pid_t, libc::SIGTERM) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow::bail!(
            "cannot signal daemon (pid {}): it runs as another user. \
             Use `sudo systemctl stop file-guard`.",
            identity.pid
        );
    }
    Err(anyhow::anyhow!(
        "failed to signal daemon (pid {}): {error}",
        identity.pid
    ))
}

/// Print daemon state, each watched file's mount status, and recent accesses.
pub fn status(config: &Config) -> anyhow::Result<()> {
    match running_pid()? {
        Some(pid) => println!("daemon:  running (pid {pid})"),
        None => println!("daemon:  not running"),
    }

    let mounts = fuse_mounts();
    println!("\nwatched files:");
    if config.watch.is_empty() {
        println!("  (none configured)");
    }
    for path in config.watched_paths()? {
        let state = if mounts.contains(&path) {
            "mounted"
        } else {
            "not mounted"
        };
        println!("  [{state:>11}]  {}", path.display());
    }

    let log_dest = config.settings.log_destination.trim();
    println!("\nrecent access (audit log: {log_dest}):");
    if matches!(log_dest, "" | "stdout" | "journal") {
        println!("  (audit log goes to the journal; set log_destination to a file path)");
    } else {
        let entries = logging::read_recent(&Config::expand_path(log_dest)?, 10);
        if entries.is_empty() {
            println!("  (no entries)");
        }
        for e in entries {
            println!("  {e}");
        }
    }
    Ok(())
}

/// Print the audit log, optionally following it. `n` bounds the initial tail.
pub fn tail_log(config: &Config, n: usize, follow: bool) -> anyhow::Result<()> {
    let dest = config.settings.log_destination.trim();
    if matches!(dest, "" | "stdout" | "journal") {
        anyhow::bail!(
            "audit log is not written to a file (log_destination = \"{dest}\"); \
             it goes to the daemon's journal - try `journalctl -u file-guard`. \
             Set log_destination to a path to enable `file-guard log`."
        );
    }
    let path = Config::expand_path(dest)?;

    let initial = logging::read_recent_batch(&path, n)?;
    for entry in initial.entries {
        println!("{entry}");
    }
    if !follow {
        return Ok(());
    }

    let mut cursor = initial.cursor;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        loop {
            let batch = logging::read_new(&path, &mut cursor, MAX_LOG_READ_BYTES)?;
            if !batch.advanced {
                break;
            }
            for entry in batch.entries {
                println!("{entry}");
            }
        }
    }
}

const MAX_LOG_READ_BYTES: usize = 16 * 1024 * 1024;

/// Whether `path` is currently served by a live file-guard FUSE mount. Used by
/// `restore` to refuse acting underneath a mount the daemon still owns.
pub fn is_fuse_mount(path: &Path) -> bool {
    fuse_mounts().iter().any(|m| m == path)
}

/// Mount points currently served by a file-guard FUSE mount, from
/// `/proc/self/mountinfo`. Empty on platforms without it.
fn fuse_mounts() -> Vec<PathBuf> {
    let Ok(contents) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    contents.lines().filter_map(parse_mountinfo_line).collect()
}

/// A mountinfo line yields a path iff it is a `file-guard` FUSE mount.
/// Format: `<fields…> <mountpoint at idx 4> … - <fstype> <source> <superopts>`.
fn parse_mountinfo_line(line: &str) -> Option<PathBuf> {
    let (left, right) = line.split_once(" - ")?;
    let left_fields: Vec<&str> = left.split(' ').collect();
    let mountpoint = left_fields.get(4)?;
    let mut right_fields = right.split(' ');
    let fstype = right_fields.next()?;
    let source = right_fields.next()?;
    let file_guard_source = source == "file-guard"
        || source.strip_prefix("file-guard:").is_some_and(|token| {
            token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
    if fstype.starts_with("fuse") && file_guard_source {
        Some(PathBuf::from(unescape_mountinfo(mountpoint)))
    } else {
        None
    }
}

/// mountinfo octal-escapes space/tab/newline/backslash in paths.
fn unescape_mountinfo(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_record_requires_pid_and_start_time() {
        assert_eq!(
            parse_daemon_identity("123 456\n"),
            Some(DaemonIdentity {
                pid: 123,
                start_time: 456,
            })
        );
        assert_eq!(parse_daemon_identity("123\n"), None);
        assert_eq!(parse_daemon_identity("0 456\n"), None);
        assert_eq!(parse_daemon_identity("123 456 extra\n"), None);
        assert_eq!(parse_daemon_identity("4294967295 456\n"), None);
    }

    #[test]
    fn inaccessible_live_identity_is_reported_without_becoming_signalable() {
        assert_eq!(
            classify_unreadable_identity(ProcessProbe::Alive),
            IdentityState::Unverified
        );
        assert_eq!(
            classify_unreadable_identity(ProcessProbe::Unknown),
            IdentityState::Unverified
        );
        assert_eq!(
            classify_unreadable_identity(ProcessProbe::Missing),
            IdentityState::Stale
        );
    }

    #[test]
    fn process_identity_rejects_a_recycled_start_time() {
        let pid = std::process::id();
        let start_time = crate::process::start_time(pid).unwrap();
        assert!(identity_alive(DaemonIdentity { pid, start_time }));
        assert!(!identity_alive(DaemonIdentity {
            pid,
            start_time: start_time.wrapping_add(1),
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_refuses_a_mismatched_process_identity() {
        let pid = std::process::id();
        let start_time = crate::process::start_time(pid).unwrap().wrapping_add(1);
        let error = signal_linux_daemon(DaemonIdentity { pid, start_time }).unwrap_err();
        assert!(error.to_string().contains("recycled"));
    }

    #[test]
    fn detects_file_guard_fuse_mount() {
        let line = "40 35 0:44 / /home/a/.aws/credentials rw,nosuid,nodev,relatime \
                    shared:1 - fuse file-guard rw,user_id=0,group_id=0";
        assert_eq!(
            parse_mountinfo_line(line),
            Some(PathBuf::from("/home/a/.aws/credentials"))
        );
    }

    #[test]
    fn detects_tokenized_file_guard_fuse_mount() {
        let line = "40 35 0:44 / /home/a/.aws/credentials rw,nosuid,nodev,relatime \
                    shared:1 - fuse file-guard:00112233445566778899aabbccddeeff rw,user_id=0";
        assert_eq!(
            parse_mountinfo_line(line),
            Some(PathBuf::from("/home/a/.aws/credentials"))
        );
    }

    #[test]
    fn ignores_other_mounts() {
        let ext4 = "23 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw";
        let other_fuse = "40 35 0:44 / /mnt rw - fuse sshfs rw";
        assert_eq!(parse_mountinfo_line(ext4), None);
        assert_eq!(parse_mountinfo_line(other_fuse), None);
    }

    #[test]
    fn unescapes_spaces_in_mountpoint() {
        let line = "40 35 0:44 / /home/a/My\\040Secrets rw - fuse file-guard rw";
        assert_eq!(
            parse_mountinfo_line(line),
            Some(PathBuf::from("/home/a/My Secrets"))
        );
    }
}
