use crate::config::Config;
use crate::policy::rule::{Access, Decision};
use crate::process::identify::ProcessInfo;
use std::path::{Path, PathBuf};

/// A single access-log entry. Serialized as one JSON object per line (NDJSON)
/// to the audit-log file, forming a queryable audit trail.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub decision: String,
    pub access: String,
    pub file: String,
    pub binary: String,
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl std::fmt::Display for AccessLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{ts}  {dec:<5} {acc:<5} {file} ← {bin} (pid {pid}){extra}",
            ts = self.timestamp,
            dec = self.decision,
            acc = self.access,
            file = self.file,
            bin = self.binary,
            pid = self.pid,
            extra = self
                .detail
                .as_deref()
                .map(|d| format!(" [{d}]"))
                .unwrap_or_default(),
        )
    }
}

/// Where access entries are written, in addition to `tracing`.
enum Sink {
    /// `tracing` only (captured by the journal under systemd).
    Stdout,
    /// Append NDJSON to this file.
    File(PathBuf),
}

/// Access logger - emits each decision to `tracing` and, when configured, to a
/// structured audit-log file.
pub struct AccessLogger {
    sink: Sink,
}

impl AccessLogger {
    /// `destination`: `"stdout"` (tracing/journal only) or a filesystem path
    /// (NDJSON audit file; `~` is expanded and the parent directory created).
    pub fn new(destination: &str) -> anyhow::Result<Self> {
        let sink = match destination.trim() {
            "" | "stdout" | "journal" => Sink::Stdout,
            path => {
                let path = Config::expand_path(path);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Sink::File(path)
            }
        };
        Ok(Self { sink })
    }

    /// Log an access attempt.
    pub fn log(
        &self,
        process: &ProcessInfo,
        file: &Path,
        access: Access,
        decision: &Decision,
        detail: Option<&str>,
    ) {
        let decision_str = match decision {
            Decision::AllowAlways | Decision::AllowSession | Decision::AllowOnce => "ALLOW",
            Decision::DenyAlways | Decision::DenyOnce => "DENY",
        };
        let access_str = access.verb().to_uppercase();

        tracing::info!(
            "{decision_str} {access_str} {} ← {} (pid {}){extra}",
            file.display(),
            process.binary_path.display(),
            process.pid,
            extra = detail.map(|d| format!(" [{d}]")).unwrap_or_default(),
        );

        if let Sink::File(path) = &self.sink {
            let entry = AccessLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                decision: decision_str.to_string(),
                access: access_str,
                file: file.display().to_string(),
                binary: process.binary_path.display().to_string(),
                pid: process.pid,
                detail: detail.map(str::to_string),
            };
            if let Err(e) = append_entry(path, &entry) {
                tracing::warn!("failed to write audit log {}: {e}", path.display());
            }
        }
    }
}

/// Append one NDJSON entry under an exclusive lock so concurrent daemon threads
/// don't interleave partial lines.
fn append_entry(path: &Path, entry: &AccessLogEntry) -> anyhow::Result<()> {
    use fs2::FileExt;
    use std::io::Write;

    let line = serde_json::to_string(entry)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.lock_exclusive()?;
    let mut writer = std::io::BufWriter::new(&file);
    writeln!(writer, "{line}")?;
    writer.flush()?;
    drop(writer);
    file.unlock()?;
    Ok(())
}

/// Read the last `n` audit entries from `path`, oldest first. Missing file →
/// empty. Malformed lines are skipped.
pub fn read_recent(path: &Path, n: usize) -> Vec<AccessLogEntry> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut entries: Vec<AccessLogEntry> = contents
        .lines()
        .rev()
        .take(n)
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    entries.reverse();
    entries
}
