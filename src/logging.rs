use crate::config::Config;
use crate::policy::rule::{Access, Decision};
use crate::process::identify::ProcessInfo;
use std::collections::VecDeque;
use std::io::BufRead;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_AUDIT_LINE_BYTES: usize = 64 * 1024;

/// A single access-log entry. Serialized as one JSON object per line (NDJSON)
/// to the audit-log file, forming a queryable audit trail.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
                let path = Config::expand_path(path)?;
                prepare_audit_file(&path)?;
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
    use std::io::Write;

    let line = serde_json::to_string(entry)?;
    if line.len() > MAX_AUDIT_LINE_BYTES {
        anyhow::bail!("audit entry exceeds {MAX_AUDIT_LINE_BYTES} bytes");
    }
    let file = open_audit_append(path)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
    let mut writer = std::io::BufWriter::new(&file);
    writeln!(writer, "{line}")?;
    writer.flush()?;
    drop(writer);
    rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock)?;
    Ok(())
}

fn prepare_audit_file(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("audit log path must be absolute: {}", path.display());
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("audit log {} has no parent", path.display()))?;
    crate::secure_file::ensure_trusted_directory(parent, 0o755)?;
    open_audit_append(path)?.sync_all()?;
    Ok(())
}

fn open_audit_append(path: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != effective_uid {
        anyhow::bail!(
            "audit log {} must be a singly-linked regular file owned by uid {effective_uid}",
            path.display()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        anyhow::bail!(
            "audit log {} must not be writable by group or others",
            path.display()
        );
    }
    Ok(file)
}

fn open_audit_read(path: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("audit log {} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

/// Read the last `n` audit entries from `path`, oldest first. Missing file →
/// empty. Malformed lines are skipped.
pub fn read_recent(path: &Path, n: usize) -> Vec<AccessLogEntry> {
    read_recent_batch(path, n)
        .map(|batch| batch.entries)
        .unwrap_or_default()
}

#[derive(Debug, Default)]
pub(crate) struct AuditCursor {
    file: Option<std::fs::File>,
    offset: u64,
}

pub(crate) struct AuditBatch {
    pub entries: Vec<AccessLogEntry>,
    pub cursor: AuditCursor,
}

pub(crate) struct AuditUpdate {
    pub entries: Vec<AccessLogEntry>,
    pub advanced: bool,
}

pub(crate) fn read_recent_batch(path: &Path, n: usize) -> anyhow::Result<AuditBatch> {
    let file = match open_audit_read(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuditBatch {
                entries: Vec::new(),
                cursor: AuditCursor::default(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockShared)?;
    let result = scan_recent(std::io::BufReader::new(&file), n);
    rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock)?;
    let (entries, offset) = result?;
    Ok(AuditBatch {
        entries,
        cursor: AuditCursor {
            file: Some(file),
            offset,
        },
    })
}

pub(crate) fn read_new(
    path: &Path,
    cursor: &mut AuditCursor,
    max_bytes: usize,
) -> anyhow::Result<AuditUpdate> {
    use std::io::{Read, Seek};

    if max_bytes == 0 {
        anyhow::bail!("audit read limit must be greater than zero");
    }
    let candidate = match open_audit_read(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuditUpdate {
                entries: Vec::new(),
                advanced: false,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let candidate_metadata = candidate.metadata()?;
    let replaced = cursor
        .file
        .as_ref()
        .is_none_or(|current| match current.metadata() {
            Ok(metadata) => {
                metadata.dev() != candidate_metadata.dev()
                    || metadata.ino() != candidate_metadata.ino()
            }
            Err(_) => true,
        });
    if replaced {
        cursor.file = Some(candidate);
        cursor.offset = 0;
    }

    let file = cursor
        .file
        .as_mut()
        .expect("audit cursor file was installed");
    rustix::fs::flock(&*file, rustix::fs::FlockOperation::LockShared)?;
    let result = (|| -> anyhow::Result<AuditUpdate> {
        let metadata = file.metadata()?;
        let truncated = metadata.len() < cursor.offset;
        if truncated {
            cursor.offset = 0;
        }
        let start = cursor.offset;
        if start == metadata.len() {
            return Ok(AuditUpdate {
                entries: Vec::new(),
                advanced: replaced || truncated,
            });
        }

        file.seek(std::io::SeekFrom::Start(start))?;
        let read_len = metadata.len().saturating_sub(start).min(max_bytes as u64);
        let mut bytes = Vec::with_capacity(read_len as usize);
        (&mut *file).take(read_len).read_to_end(&mut bytes)?;

        let Some(complete_len) = bytes.iter().rposition(|byte| *byte == b'\n').map(|i| i + 1)
        else {
            if bytes.len() == max_bytes {
                anyhow::bail!("audit log contains a record larger than {max_bytes} bytes");
            }
            return Ok(AuditUpdate {
                entries: Vec::new(),
                advanced: replaced || truncated,
            });
        };
        let entries = bytes[..complete_len]
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty() && line.len() <= MAX_AUDIT_LINE_BYTES)
            .filter_map(|line| serde_json::from_slice(line).ok())
            .collect();
        cursor.offset = start + complete_len as u64;
        Ok(AuditUpdate {
            entries,
            advanced: true,
        })
    })();
    let unlock = rustix::fs::flock(&*file, rustix::fs::FlockOperation::Unlock);
    match (result, unlock) {
        (Ok(update), Ok(())) => Ok(update),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn scan_recent(
    mut reader: impl BufRead,
    limit: usize,
) -> anyhow::Result<(Vec<AccessLogEntry>, u64)> {
    let mut recent = VecDeque::with_capacity(limit);
    let mut line = Vec::new();
    let mut discarding = false;
    let mut consumed = 0_u64;
    let mut complete_offset = 0_u64;

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let available_len = available.len();
        let mut position = 0;
        while position < available_len {
            let remainder = &available[position..];
            let newline = remainder.iter().position(|byte| *byte == b'\n');
            let segment_len = newline.unwrap_or(remainder.len());
            let segment = &remainder[..segment_len];
            if !discarding {
                if line.len() + segment.len() <= MAX_AUDIT_LINE_BYTES {
                    line.extend_from_slice(segment);
                } else {
                    line.clear();
                    discarding = true;
                }
            }
            position += segment_len;
            if newline.is_some() {
                position += 1;
                complete_offset = consumed + position as u64;
                if !discarding
                    && let Ok(entry) = serde_json::from_slice(&line)
                    && limit > 0
                {
                    if recent.len() == limit {
                        recent.pop_front();
                    }
                    recent.push_back(entry);
                }
                line.clear();
                discarding = false;
            }
        }
        reader.consume(available_len);
        consumed += available_len as u64;
    }

    Ok((recent.into_iter().collect(), complete_offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "file-guard-audit-{}-{}.log",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn entry(pid: u32) -> AccessLogEntry {
        AccessLogEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            decision: "ALLOW".into(),
            access: "READ".into(),
            file: "/credential".into(),
            binary: "/usr/bin/tool".into(),
            pid,
            detail: None,
        }
    }

    #[test]
    fn cursor_advances_only_past_complete_records() {
        let path = path();
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&entry(1)).unwrap()).unwrap();
        let partial = serde_json::to_string(&entry(2)).unwrap();
        write!(file, "{}", &partial[..partial.len() / 2]).unwrap();
        file.flush().unwrap();

        let initial = read_recent_batch(&path, 10).unwrap();
        assert_eq!(initial.entries, vec![entry(1)]);
        let mut cursor = initial.cursor;
        let waiting = read_new(&path, &mut cursor, 1024).unwrap();
        assert!(waiting.entries.is_empty());
        assert!(!waiting.advanced);

        writeln!(file, "{}", &partial[partial.len() / 2..]).unwrap();
        file.flush().unwrap();
        let completed = read_new(&path, &mut cursor, 1024).unwrap();
        assert_eq!(completed.entries, vec![entry(2)]);
        assert!(completed.advanced);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cursor_detects_file_replacement_even_when_the_new_file_is_larger() {
        let path = path();
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entry(1)).unwrap()),
        )
        .unwrap();
        let initial = read_recent_batch(&path, 10).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&entry(2)).unwrap(),
                serde_json::to_string(&entry(3)).unwrap()
            ),
        )
        .unwrap();

        let mut cursor = initial.cursor;
        let replaced = read_new(&path, &mut cursor, 1024).unwrap();
        assert_eq!(replaced.entries, vec![entry(2), entry(3)]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn audit_sink_rejects_symlinks_and_hard_links() {
        let target = path();
        let symlink_path = path();
        let hardlink_path = path();
        std::fs::write(&target, b"").unwrap();
        symlink(&target, &symlink_path).unwrap();
        assert!(AccessLogger::new(symlink_path.to_str().unwrap()).is_err());

        std::fs::hard_link(&target, &hardlink_path).unwrap();
        assert!(
            AccessLogger::new(hardlink_path.to_str().unwrap())
                .err()
                .unwrap()
                .to_string()
                .contains("singly-linked")
        );

        std::fs::remove_file(symlink_path).unwrap();
        std::fs::remove_file(hardlink_path).unwrap();
        std::fs::remove_file(target).unwrap();
    }

    #[test]
    fn audit_sink_rejects_group_or_world_writable_files() {
        let path = path();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        assert!(
            AccessLogger::new(path.to_str().unwrap())
                .err()
                .unwrap()
                .to_string()
                .contains("must not be writable")
        );

        std::fs::remove_file(path).unwrap();
    }
}
