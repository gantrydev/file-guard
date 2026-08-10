use std::path::PathBuf;

pub fn binary_path(pid: u32) -> anyhow::Result<PathBuf> {
    let proc_path = format!("/proc/{pid}/exe");
    std::fs::read_link(&proc_path)
        .map_err(|e| anyhow::anyhow!("readlink {proc_path} failed for pid {pid}: {e}"))
}

pub fn start_time(pid: u32) -> anyhow::Result<u64> {
    let me = procfs::process::Process::new(pid as i32)
        .map_err(|e| anyhow::anyhow!("opening /proc/{pid}: {e}"))?;
    let stat = me
        .stat()
        .map_err(|e| anyhow::anyhow!("reading /proc/{pid}/stat: {e}"))?;
    // starttime is in clock ticks since boot; convert to nanosecond epoch
    // approximation by scaling to seconds via sysconf(_SC_CLK_TCK) then nanos.
    let ticks = stat.starttime;
    let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if clock_ticks_per_sec <= 0 {
        anyhow::bail!("sysconf(_SC_CLK_TCK) returned invalid value");
    }
    Ok(ticks * 1_000_000_000 / clock_ticks_per_sec as u64)
}

/// The process's argv, from `/proc/<pid>/cmdline` (NUL-separated).
pub fn cmdline(pid: u32) -> anyhow::Result<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|e| anyhow::anyhow!("read /proc/{pid}/cmdline: {e}"))?;
    Ok(raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// Read the immediate parent's identity from `/proc`.
pub fn parent_info(pid: u32) -> Option<(u32, String, Option<PathBuf>)> {
    let process = procfs::process::Process::new(pid as i32).ok()?;
    let ppid = u32::try_from(process.stat().ok()?.ppid).ok()?;
    if ppid == 0 {
        return None;
    }
    let parent = procfs::process::Process::new(ppid as i32).ok()?;
    let name = parent.stat().ok()?.comm;
    let binary_path = binary_path(ppid).ok();
    Some((ppid, name, binary_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_info_labels_the_parent_process() {
        let expected_pid = unsafe { libc::getppid() } as u32;
        let expected_name = procfs::process::Process::new(expected_pid as i32)
            .unwrap()
            .stat()
            .unwrap()
            .comm;

        let (pid, name, _) = parent_info(std::process::id()).unwrap();

        assert_eq!(pid, expected_pid);
        assert_eq!(name, expected_name);
    }
}
