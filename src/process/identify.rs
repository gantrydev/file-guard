use std::path::PathBuf;

#[cfg(target_os = "linux")]
use super::linux as platform;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Process start time, used with the captured executable identity to keep
    /// session grants scoped across PID reuse and `exec`.
    pub start_time: u64,
    pub binary_path: PathBuf,
    pub binary_name: String,
    pub binary_sha256: String,
    /// For an interpreter (python/node/bash/…), the main script it is running,
    /// resolved from argv. Lets a rule distinguish "python running gcloud" from
    /// "python running something else" - `None` for compiled tools. Best-effort
    /// and argv-derived (forgeable), so it is defense-in-depth, not a boundary.
    pub script: Option<PathBuf>,
    pub parent_chain: Vec<ParentProcess>,
}

#[derive(Debug, Clone)]
pub struct ParentProcess {
    pub pid: u32,
    pub name: String,
    pub binary_path: Option<PathBuf>,
}

pub fn identify(pid: u32) -> anyhow::Result<ProcessInfo> {
    let start_time = platform::start_time(pid)?;
    let executable = super::integrity::capture_process_executable(pid, start_time)?;
    let binary_path = executable.path;
    let binary_name = binary_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("pid:{pid}"));
    let binary_sha256 = executable.sha256;
    let script = interpreter_script(pid, &binary_name);
    Ok(ProcessInfo {
        pid,
        start_time,
        binary_path,
        binary_name,
        binary_sha256,
        script,
        // Left empty on the access hot path: walking the parent chain reads
        // /proc per hop and is only needed to *display* a prompt, so it's
        // filled lazily by the prompt client (see `PromptClient`) rather than
        // on every open a rule already decides.
        parent_chain: Vec::new(),
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
/// names an existing file - this skips flags *and* their values (e.g. the
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

/// Walk the parent PID chain (up to 16 hops) by reading `/proc/<pid>/stat`
/// and `/proc/<pid>/exe` per hop, avoiding a full process-table scan.
pub fn parent_chain(pid: u32) -> Vec<ParentProcess> {
    let mut chain = Vec::new();
    let mut current = pid;

    for _ in 0..16 {
        let Some((ppid, name, binary_path)) = platform::parent_info(current) else {
            break;
        };
        chain.push(ParentProcess {
            pid: ppid,
            name,
            binary_path,
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
