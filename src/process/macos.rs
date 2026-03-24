use std::path::PathBuf;

/// Get binary path for a PID via proc_pidpath().
pub fn binary_path(pid: u32) -> anyhow::Result<PathBuf> {
    use std::ffi::CStr;

    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret =
        unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };

    if ret <= 0 {
        anyhow::bail!("proc_pidpath failed for pid {pid}");
    }

    let path = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };
    Ok(PathBuf::from(path.to_string_lossy().into_owned()))
}

/// Get process start time via sysctl(KERN_PROC).
///
/// `libc` doesn't expose `kinfo_proc` on macOS, so we use a raw byte buffer
/// and pull `p_starttime` at its known offset.
pub fn start_time(pid: u32) -> anyhow::Result<u64> {
    // kinfo_proc is 648 bytes on arm64 macOS; allocate generously.
    const KINFO_BUF_SIZE: usize = 1024;
    let mut buf = [0u8; KINFO_BUF_SIZE];
    let mut size: usize = KINFO_BUF_SIZE;

    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as i32,
    ];

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 {
        anyhow::bail!("sysctl KERN_PROC_PID failed for pid {pid}");
    }

    // p_starttime (struct timeval) offset within kinfo_proc.
    // On arm64 macOS: kp_proc starts at offset 0, p_starttime is at offset 136.
    // struct timeval { i64 tv_sec; i32 tv_usec; }
    const P_STARTTIME_OFFSET: usize = 136;

    if size < P_STARTTIME_OFFSET + 12 {
        anyhow::bail!("sysctl returned unexpectedly small kinfo_proc ({size} bytes)");
    }

    let tv_sec = i64::from_ne_bytes(
        buf[P_STARTTIME_OFFSET..P_STARTTIME_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let tv_usec = i32::from_ne_bytes(
        buf[P_STARTTIME_OFFSET + 8..P_STARTTIME_OFFSET + 12]
            .try_into()
            .unwrap(),
    );

    let nanos = tv_sec as u64 * 1_000_000_000 + tv_usec as u64 * 1_000;
    Ok(nanos)
}

/// Get code signature identity via `codesign` CLI.
pub fn code_signature(pid: u32) -> Option<String> {
    let output = std::process::Command::new("codesign")
        .args(["-d", "--verbose=2", &format!("--pid={pid}")])
        .output()
        .ok()?;

    // codesign writes to stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines() {
        if let Some(id) = line.strip_prefix("Identifier=") {
            return Some(id.to_string());
        }
    }
    None
}
