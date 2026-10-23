use std::path::{Path, PathBuf};

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
    extract_script(&args, binary_name)
}

/// Names we treat as interpreters whose argv carries the real program identity.
pub(crate) fn is_interpreter(name: &str) -> bool {
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    name.starts_with("python")
        || matches!(
            stem,
            "pypy"
                | "node"
                | "nodejs"
                | "deno"
                | "bun"
                | "ruby"
                | "perl"
                | "php"
                | "lua"
                | "luajit"
                | "tclsh"
                | "wish"
                | "bash"
                | "sh"
                | "dash"
                | "zsh"
                | "ksh"
                | "Rscript"
                | "java"
        )
}

// A process can change cwd after loading its script. Only absolute paths and
// recognized argument forms can narrow an automatic permanent grant.
fn extract_script(args: &[String], binary_name: &str) -> Option<PathBuf> {
    let mut it = args.iter().skip(1);
    if binary_name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.') == "java" {
        if it.next()? != "-jar" {
            return None;
        }
        return it.next().and_then(|path| canonical_file(path));
    }
    let python = binary_name.starts_with("python") || binary_name.starts_with("pypy");
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--" => return it.next().and_then(|path| canonical_file(path)),
            "-B" | "-E" | "-I" | "-P" | "-s" | "-S" | "-u" | "-O" | "-OO" if python => {}
            "-W" | "-X" if python => {
                it.next()?;
            }
            value if python && (value.starts_with("-W") || value.starts_with("-X")) => {}
            value if value.starts_with('-') => return None,
            path => return canonical_file(path),
        }
    }
    None
}

fn canonical_file(path: &str) -> Option<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() && path.is_file() {
        std::fs::canonicalize(path).ok()
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
        for name in [
            "perl5.36.0",
            "ruby3.2",
            "php8.2",
            "lua5.4",
            "tclsh8.6",
            "pypy3",
        ] {
            assert!(is_interpreter(name), "{name}");
        }
        assert!(!is_interpreter("ruby-tool"));
        assert!(!is_interpreter("terraform"));
        assert!(!is_interpreter("gcloud"));
    }

    #[test]
    fn script_arguments_must_be_absolute_and_unambiguous() {
        let dir = std::env::temp_dir().join(format!("fg-script-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let script = dir.join("program.py");
        let option_value = dir.join("ignore");
        std::fs::write(&script, b"print('x')").unwrap();
        std::fs::write(&option_value, b"not a script").unwrap();
        let script_path = script.to_str().unwrap().to_owned();
        let value_path = option_value.to_str().unwrap().to_owned();
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            extract_script(
                &args(&[
                    "python",
                    "-S",
                    "-B",
                    "-W",
                    &value_path,
                    &script_path,
                    "version"
                ]),
                "python3.14"
            ),
            Some(script.clone())
        );
        for values in [
            vec!["python", "program.py"],
            vec!["python", "-c", &script_path],
            vec!["python", "-m", &script_path],
            vec!["python", "-unknown", &value_path, &script_path],
            vec!["python", "-W", "ignore", "program.py"],
            vec!["python", "/nonexistent/script.py", &script_path],
        ] {
            assert_eq!(extract_script(&args(&values), "python3"), None);
        }
        assert_eq!(
            extract_script(
                &args(&["node", "--require", &value_path, &script_path]),
                "node"
            ),
            None
        );
        assert_eq!(
            extract_script(&args(&["node", &script_path]), "node"),
            Some(script.clone())
        );
        assert_eq!(
            extract_script(&args(&["java", "-jar", &script_path]), "java"),
            Some(script.clone())
        );
        assert_eq!(
            extract_script(&args(&["java", "-cp", &value_path, &script_path]), "java"),
            None
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
