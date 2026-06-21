use std::path::PathBuf;

pub fn binary_path(pid: u32) -> anyhow::Result<PathBuf> {
    let proc_path = format!("/proc/{pid}/exe");
    let resolved = std::fs::read_link(&proc_path)
        .map_err(|e| anyhow::anyhow!("readlink {proc_path} failed for pid {pid}: {e}"))?;

    Ok(resolved)
}

pub fn start_time(pid: u32) -> anyhow::Result<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat_contents = std::fs::read_to_string(&stat_path)
        .map_err(|e| anyhow::anyhow!("failed to read {stat_path}: {e}"))?;

    let close_paren_offset = stat_contents
        .rfind(')')
        .ok_or_else(|| anyhow::anyhow!("malformed /proc/{pid}/stat: no closing paren"))?;

    let fields_after_comm = &stat_contents[close_paren_offset + 2..];
    let fields: Vec<&str> = fields_after_comm.split_whitespace().collect();
    let starttime_field_index = 19;
    let starttime_raw = fields
        .get(starttime_field_index)
        .ok_or_else(|| anyhow::anyhow!("missing starttime field in /proc/{pid}/stat"))?;

    let starttime_ticks: u64 = starttime_raw
        .parse()
        .map_err(|e| anyhow::anyhow!("failed to parse starttime for pid {pid}: {e}"))?;

    let clock_ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let valid_ticks = clock_ticks_per_sec > 0;
    if !valid_ticks {
        anyhow::bail!("sysconf(_SC_CLK_TCK) returned invalid value");
    }

    let nanos = starttime_ticks * 1_000_000_000 / clock_ticks_per_sec as u64;
    Ok(nanos)
}

pub fn code_signature(_pid: u32) -> Option<String> {
    None
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
