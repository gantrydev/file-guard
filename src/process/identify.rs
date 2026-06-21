use std::path::PathBuf;

#[cfg(target_os = "macos")]
use super::macos as platform;

#[cfg(target_os = "linux")]
use super::linux as platform;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Process start time — together with `pid` it forms a recycle-proof
    /// identity for session grants (see `policy::session::ProcessId`).
    pub start_time: u64,
    pub binary_path: PathBuf,
    pub binary_name: String,
    /// For an interpreter (python/node/bash/…), the main script it is running,
    /// resolved from argv. Lets a rule distinguish "python running gcloud" from
    /// "python running something else" — `None` for compiled tools. Best-effort
    /// and argv-derived (forgeable), so it is defense-in-depth, not a boundary.
    pub script: Option<PathBuf>,
    pub parent_chain: Vec<ParentProcess>,
    pub code_signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParentProcess {
    pub pid: u32,
    pub name: String,
    pub binary_path: Option<PathBuf>,
}

pub fn identify(pid: u32) -> anyhow::Result<ProcessInfo> {
    let binary_path = platform::binary_path(pid)?;
    let binary_name = binary_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("pid:{pid}"));
    let start_time = platform::start_time(pid)?;
    let script = interpreter_script(pid, &binary_name);
    let parent_chain = parent_chain(pid);
    let code_signature = platform::code_signature(pid);

    Ok(ProcessInfo {
        pid,
        start_time,
        binary_path,
        binary_name,
        script,
        parent_chain,
        code_signature,
    })
}

/// If the binary is a known interpreter, resolve the main script it is running
/// from its argv. Returns `None` for compiled tools or inline code (`-c`/`-m`).
fn interpreter_script(pid: u32, binary_name: &str) -> Option<PathBuf> {
    if !is_interpreter(binary_name) {
        return None;
    }
    let args = platform::cmdline(pid).ok()?;
    extract_script(&args)
}

/// Names we treat as interpreters whose argv carries the real program identity.
fn is_interpreter(name: &str) -> bool {
    name.starts_with("python")
        || matches!(
            name,
            "node"
                | "nodejs"
                | "deno"
                | "bun"
                | "ruby"
                | "perl"
                | "php"
                | "bash"
                | "sh"
                | "dash"
                | "zsh"
                | "ksh"
                | "Rscript"
                | "java"
        )
}

/// Pull the script path out of an interpreter's argv (argv[0] is the
/// interpreter). `-c`/`-m`/`-e` mean inline code/module with no script file;
/// `-jar` (java) names the jar. Otherwise the script is the first argument that
/// names an existing file — this skips flags *and* their values (e.g. the
/// `ignore` in `python -W ignore script.py`) without enumerating which flags
/// take a value.
fn extract_script(args: &[String]) -> Option<PathBuf> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-jar" => return it.next().and_then(|v| canonical_file(v)),
            "-cp" | "-classpath" | "--class-path" => {
                it.next(); // classpath value; the main class is not a file
                return None;
            }
            "-c" | "-m" | "-e" => return None,
            other => {
                if let Some(script) = canonical_file(other) {
                    return Some(script);
                }
            }
        }
    }
    None
}

fn canonical_file(path: &str) -> Option<PathBuf> {
    let p = std::path::Path::new(path);
    if p.is_file() {
        std::fs::canonicalize(p).ok()
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreters_detected() {
        assert!(is_interpreter("python3.14"));
        assert!(is_interpreter("node"));
        assert!(is_interpreter("bash"));
        assert!(!is_interpreter("terraform"));
        assert!(!is_interpreter("gcloud"));
    }

    #[test]
    fn extract_script_skips_flags_and_finds_file() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("fg-script-{}.py", std::process::id()));
        std::fs::write(&tmp, b"print('x')").unwrap();
        let canon = std::fs::canonicalize(&tmp).unwrap();

        // Mirrors gcloud's real argv: value-taking flags (`-W ignore`) precede
        // the script and must not be mistaken for it.
        let args = vec![
            "python".to_string(),
            "-S".to_string(),
            "-B".to_string(),
            "-W".to_string(),
            "ignore".to_string(),
            tmp.to_string_lossy().into_owned(),
            "version".to_string(),
        ];
        assert_eq!(extract_script(&args), Some(canon));

        // Inline code / module → no script file.
        let inline = [
            "python".to_string(),
            "-c".to_string(),
            "print(1)".to_string(),
        ];
        assert_eq!(extract_script(&inline), None);
        let module = [
            "python".to_string(),
            "-m".to_string(),
            "http.server".to_string(),
        ];
        assert_eq!(extract_script(&module), None);

        std::fs::remove_file(&tmp).ok();
    }
}
