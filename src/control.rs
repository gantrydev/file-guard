//! Out-of-process control of a running daemon: `stop`, `status`, and `log`.
//! These run as a separate short-lived `file-guard` invocation and locate the
//! daemon via its PID file and the audit log via the config.

use crate::config::{self, Config};
use crate::logging;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// PID of the running daemon, or `None` if there is no PID file or the recorded
/// process is gone (in which case a stale PID file is cleaned up).
pub fn running_pid() -> Option<u32> {
    let path = config::pid_file_path();
    let pid: u32 = std::fs::read_to_string(&path).ok()?.trim().parse().ok()?;
    if pid_alive(pid) {
        Some(pid)
    } else {
        let _ = std::fs::remove_file(&path);
        None
    }
}

/// Whether `pid` is a live process (signal 0 probes existence without delivery).
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Send SIGTERM to the running daemon and wait for it to exit (and run its
/// unmount path). Errors if no daemon is running.
pub fn stop() -> anyhow::Result<()> {
    let Some(pid) = running_pid() else {
        anyhow::bail!(
            "no running daemon found (no live PID file at {}). \
             Under systemd use `systemctl stop file-guard`.",
            config::pid_file_path().display()
        );
    };

    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error())
            .map_err(|e| anyhow::anyhow!("failed to signal daemon (pid {pid}): {e}"));
    }
    println!("sent SIGTERM to file-guard (pid {pid}); waiting for unmount…");

    for _ in 0..150 {
        if !pid_alive(pid) {
            println!("stopped");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("daemon (pid {pid}) did not exit within 15s");
}

/// Print daemon state, each watched file's mount status, and recent accesses.
pub fn status(config: &Config) -> anyhow::Result<()> {
    match running_pid() {
        Some(pid) => println!("daemon:  running (pid {pid})"),
        None => println!("daemon:  not running"),
    }

    let mounts = fuse_mounts();
    println!("\nwatched files:");
    if config.watch.is_empty() {
        println!("  (none configured)");
    }
    for path in config.watched_paths() {
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
        let entries = logging::read_recent(&Config::expand_path(log_dest), 10);
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
    let path = Config::expand_path(dest);

    for entry in logging::read_recent(&path, n) {
        println!("{entry}");
    }
    if !follow {
        return Ok(());
    }

    // Poll for growth and print newly-appended entries.
    let mut offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let len = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if len < offset {
            offset = 0; // truncated/rotated - restart from the top
        }
        if len > offset {
            for entry in read_from(&path, offset) {
                println!("{entry}");
            }
            offset = len;
        }
    }
}

/// Parse audit entries appended after byte `offset`.
fn read_from(path: &Path, offset: u64) -> Vec<logging::AccessLogEntry> {
    use std::io::{Read, Seek};
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    if f.seek(std::io::SeekFrom::Start(offset)).is_err() {
        return Vec::new();
    }
    let mut buf = String::new();
    if f.read_to_string(&mut buf).is_err() {
        return Vec::new();
    }
    buf.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
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
    if fstype.starts_with("fuse") && source == "file-guard" {
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
    fn detects_file_guard_fuse_mount() {
        let line = "40 35 0:44 / /home/a/.aws/credentials rw,nosuid,nodev,relatime \
                    shared:1 - fuse file-guard rw,user_id=0,group_id=0";
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
