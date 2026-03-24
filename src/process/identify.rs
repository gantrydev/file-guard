use std::path::PathBuf;

/// Complete information about a process requesting file access.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub start_time: u64,
    pub binary_path: PathBuf,
    pub binary_name: String,
    pub parent_chain: Vec<ParentProcess>,
    pub code_signature: Option<String>,
}

/// A process in the parent chain.
#[derive(Debug, Clone)]
pub struct ParentProcess {
    pub pid: u32,
    pub name: String,
    pub binary_path: Option<PathBuf>,
}

/// Resolve a PID into full ProcessInfo.
pub fn identify(pid: u32) -> anyhow::Result<ProcessInfo> {
    let binary_path = super::macos::binary_path(pid)?;
    let binary_name = binary_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("pid:{pid}"));
    let start_time = super::macos::start_time(pid)?;
    let parent_chain = parent_chain(pid);
    let code_signature = super::macos::code_signature(pid);

    Ok(ProcessInfo {
        pid,
        start_time,
        binary_path,
        binary_name,
        parent_chain,
        code_signature,
    })
}

/// Walk the parent PID chain up to launchd.
pub fn parent_chain(pid: u32) -> Vec<ParentProcess> {
    let sys = sysinfo::System::new_all();
    let mut chain = Vec::new();
    let mut current = sysinfo::Pid::from_u32(pid);

    for _ in 0..16 {
        let Some(proc_info) = sys.process(current) else {
            break;
        };
        let Some(ppid) = proc_info.parent() else {
            break;
        };
        if ppid.as_u32() == 0 {
            break;
        }

        let parent = sys.process(ppid);
        chain.push(ParentProcess {
            pid: ppid.as_u32(),
            name: parent
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_default(),
            binary_path: parent.and_then(|p| p.exe().map(|e| e.to_path_buf())),
        });
        current = ppid;
    }

    chain
}
