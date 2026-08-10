use std::collections::HashSet;
use std::ffi::CString;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fuser::{Config, MountOption, SessionACL};

use super::credential_fs::CredentialFs;
use crate::interceptor::{Interceptor, InterceptorArgs};
use crate::store::{BackingStore, Entry, UnmountNext};
use crate::transaction::TransactionManager;

fn unescape_mount_field(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..=index + 3]
                .iter()
                .all(|byte| (b'0'..=b'7').contains(byte))
        {
            let value = (bytes[index + 1] - b'0') as u32 * 64
                + (bytes[index + 2] - b'0') as u32 * 8
                + (bytes[index + 3] - b'0') as u32;
            if value <= u8::MAX as u32 {
                output.push(value as u8);
                index += 4;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfo {
    id: u64,
    target: PathBuf,
    fs_type: String,
    source: Vec<u8>,
    owner_uid: Option<u32>,
}

fn fields(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect()
}

fn parse_mountinfo(contents: &[u8]) -> Vec<MountInfo> {
    contents
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let separator = line.windows(3).position(|window| window == b" - ")?;
            let mount_fields = fields(&line[..separator]);
            let filesystem_fields = fields(&line[separator + 3..]);
            let owner_uid = filesystem_fields.get(2).and_then(|options| {
                options.split(|byte| *byte == b',').find_map(|option| {
                    option
                        .strip_prefix(b"user_id=")
                        .and_then(|value| std::str::from_utf8(value).ok())
                        .and_then(|value| value.parse().ok())
                })
            });
            Some(MountInfo {
                id: std::str::from_utf8(mount_fields.first()?)
                    .ok()?
                    .parse()
                    .ok()?,
                target: PathBuf::from(OsString::from_vec(unescape_mount_field(
                    mount_fields.get(4)?,
                ))),
                fs_type: std::str::from_utf8(filesystem_fields.first()?)
                    .ok()?
                    .to_string(),
                source: unescape_mount_field(filesystem_fields.get(1)?),
                owner_uid,
            })
        })
        .collect()
}

fn mountinfo() -> anyhow::Result<Vec<MountInfo>> {
    Ok(parse_mountinfo(&std::fs::read("/proc/self/mountinfo")?))
}

fn mounts_at(path: &Path) -> anyhow::Result<Vec<MountInfo>> {
    Ok(mountinfo()?
        .into_iter()
        .filter(|mount| mount.target == path)
        .collect())
}

fn expected_source(token: &str) -> String {
    format!("file-guard:{token}")
}

fn verify_mount(path: &Path, token: &str) -> anyhow::Result<Option<MountInfo>> {
    let expected = expected_source(token);
    let expected_uid = unsafe { libc::geteuid() };
    let mounts = mounts_at(path)?;
    if let Some(unexpected) = mounts.iter().find(|mount| {
        mount.source != expected.as_bytes()
            || !mount.fs_type.starts_with("fuse")
            || mount.owner_uid != Some(expected_uid)
    }) {
        anyhow::bail!(
            "refusing to operate on {}: mount {} has source {:?}, type {:?}, and owner {:?}; expected {:?} owned by uid {}",
            path.display(),
            unexpected.id,
            String::from_utf8_lossy(&unexpected.source),
            unexpected.fs_type,
            unexpected.owner_uid,
            expected,
            expected_uid
        )
    }
    if mounts.len() > 1 {
        anyhow::bail!("multiple mounts are stacked at {}", path.display())
    }
    Ok(mounts.into_iter().next())
}

fn detach_stale_mount(path: &Path, token: &str) -> anyhow::Result<()> {
    let Some(mount) = verify_mount(path, token)? else {
        return Ok(());
    };
    tracing::warn!(
        "detaching orphaned file-guard mount {} at {}",
        mount.id,
        path.display()
    );
    let encoded_path = CString::new(path.as_os_str().as_bytes())?;
    if unsafe { libc::umount2(encoded_path.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if verify_mount(path, token)?.is_some() {
        anyhow::bail!("mount remained present after detach")
    }
    Ok(())
}

struct MountSession {
    watched_path: PathBuf,
    token: String,
    session: Option<fuser::BackgroundSession>,
}

pub struct FuseInterceptor {
    args: Option<InterceptorArgs>,
    sessions: Vec<MountSession>,
    prepared: Vec<PathBuf>,
    store: Option<Arc<dyn BackingStore>>,
    manager: Option<TransactionManager>,
    restore_on_stop: bool,
}

impl FuseInterceptor {
    pub fn new(args: InterceptorArgs) -> Self {
        Self {
            args: Some(args),
            sessions: Vec::new(),
            prepared: Vec::new(),
            store: None,
            manager: None,
            restore_on_stop: false,
        }
    }

    fn rollback(&mut self) -> anyhow::Result<()> {
        self.restore_on_stop = true;
        <Self as Interceptor>::stop(self)
    }
}

impl Interceptor for FuseInterceptor {
    fn start(&mut self) -> anyhow::Result<()> {
        let args = self
            .args
            .take()
            .ok_or_else(|| anyhow::anyhow!("FuseInterceptor already started"))?;
        self.restore_on_stop = args.restore_on_stop;
        self.store = Some(args.store.clone());
        self.manager = Some(TransactionManager::new(args.store.clone()));

        let manager = self.manager.as_ref().unwrap().clone();
        let mut unique_paths = HashSet::new();
        let watched_paths = args
            .watched_paths
            .iter()
            .map(|path| manager.normalize_path(path))
            .collect::<anyhow::Result<Vec<_>>>()?;
        for path in &watched_paths {
            if !unique_paths.insert(path.clone()) {
                anyhow::bail!(
                    "duplicate watched path after normalization: {}",
                    path.display()
                )
            }
        }

        for watched_path in &watched_paths {
            let manager = self.manager.as_ref().unwrap().clone();
            let setup = (|| -> anyhow::Result<()> {
                if let Entry::Present(record) = manager.load(watched_path)? {
                    if let Some(reason) = &record.header.blocked_reason {
                        anyhow::bail!(
                            "transaction for {} requires manual recovery before mount reconciliation: {reason}",
                            watched_path.display()
                        )
                    }
                    detach_stale_mount(watched_path, &record.header.mount_token)?;
                    manager.reconcile_after_mount_absent(watched_path)?;
                } else if !mounts_at(watched_path)?.is_empty() {
                    anyhow::bail!(
                        "{} is mounted but has no v2 transaction record",
                        watched_path.display()
                    )
                }

                self.prepared.push(watched_path.clone());
                manager.prepare(watched_path)?;
                let record = manager.begin_mount(watched_path)?;
                let credential_fs = match CredentialFs::new(
                    watched_path.clone(),
                    args.store.clone(),
                    args.policy.clone(),
                    args.logger.clone(),
                    args.rt_handle.clone(),
                ) {
                    Ok(filesystem) => filesystem,
                    Err(error) => {
                        let rollback = manager.abort_mount(watched_path);
                        return match rollback {
                            Ok(_) => Err(error),
                            Err(rollback_error) => Err(anyhow::anyhow!(
                                "{error}; mount-intent rollback also failed: {rollback_error}"
                            )),
                        };
                    }
                };

                let source = expected_source(&record.header.mount_token);
                let mut config = Config::default();
                config.mount_options = vec![MountOption::FSName(source.clone())];
                if unsafe { libc::geteuid() == 0 } {
                    config.acl = SessionACL::All;
                }

                let session = match fuser::spawn_mount2(credential_fs, watched_path, &config) {
                    Ok(session) => session,
                    Err(error) => {
                        let rollback = (|| -> anyhow::Result<()> {
                            detach_stale_mount(watched_path, &record.header.mount_token)?;
                            manager.abort_mount(watched_path)?;
                            Ok(())
                        })();
                        return match rollback {
                            Ok(()) => Err(anyhow::anyhow!(
                                "failed to mount FUSE at {}: {error}",
                                watched_path.display()
                            )),
                            Err(rollback_error) => Err(anyhow::anyhow!(
                                "failed to mount FUSE at {}: {error}; rollback also failed: {rollback_error}",
                                watched_path.display()
                            )),
                        };
                    }
                };
                let Some(mount) = verify_mount(watched_path, &record.header.mount_token)? else {
                    drop(session);
                    detach_stale_mount(watched_path, &record.header.mount_token)?;
                    manager.abort_mount(watched_path)?;
                    anyhow::bail!(
                        "FUSE mount at {} returned success but was not observable",
                        watched_path.display()
                    )
                };
                self.sessions.push(MountSession {
                    watched_path: watched_path.clone(),
                    token: record.header.mount_token,
                    session: Some(session),
                });
                tracing::info!(
                    "FUSE mount {} active at {} ({source})",
                    mount.id,
                    watched_path.display()
                );
                Ok(())
            })();

            if let Err(error) = setup {
                let rollback = self.rollback();
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(anyhow::anyhow!(
                        "{error}; rollback also failed: {rollback_error}"
                    )),
                };
            }
        }

        tracing::info!(
            "file-guard FUSE started, watching {} files",
            self.sessions.len()
        );
        Ok(())
    }

    fn abort_start(&mut self) -> anyhow::Result<()> {
        self.rollback()
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        let sessions: Vec<_> = self.sessions.drain(..).collect();
        let mut errors = Vec::new();
        let mut retained = Vec::new();
        let manager = self
            .manager
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("transaction manager is unavailable during stop"))?;
        let next = if self.restore_on_stop {
            UnmountNext::Restore
        } else {
            UnmountNext::LeaveInstalled
        };
        let mut completed = HashSet::new();
        for mut mount in sessions {
            if mount.session.is_some()
                && let Err(error) = manager.begin_unmount(&mount.watched_path, next.clone())
            {
                errors.push(format!(
                    "failed to fence writes before unmounting {}: {error}",
                    mount.watched_path.display()
                ));
                retained.push(mount);
                continue;
            }
            if let Some(session) = mount.session.take()
                && let Err(error) = session.umount_and_join()
            {
                tracing::warn!(
                    "FUSE session unmount at {} returned {error}; reconciling against mountinfo",
                    mount.watched_path.display()
                );
            }
            let recovery = (|| -> anyhow::Result<()> {
                detach_stale_mount(&mount.watched_path, &mount.token)?;
                manager.reconcile_after_mount_absent(&mount.watched_path)?;
                if self.restore_on_stop {
                    manager.restore(&mount.watched_path)?;
                }
                Ok(())
            })();
            if let Err(error) = recovery {
                errors.push(format!(
                    "failed to reconcile unmount of {}: {error}",
                    mount.watched_path.display()
                ));
                retained.push(mount);
                continue;
            }
            tracing::info!("FUSE unmounted at {}", mount.watched_path.display());
            completed.insert(mount.watched_path);
        }
        self.sessions = retained;

        let retained_paths = self
            .sessions
            .iter()
            .map(|mount| mount.watched_path.clone())
            .collect::<HashSet<_>>();
        let mut retained_prepared = Vec::new();
        for path in self.prepared.drain(..) {
            if retained_paths.contains(&path) {
                retained_prepared.push(path);
                continue;
            }
            if completed.contains(&path) {
                continue;
            }
            let recovery = (|| -> anyhow::Result<()> {
                match manager.load(&path)? {
                    Entry::Present(record) => {
                        detach_stale_mount(&path, &record.header.mount_token)?;
                        manager.reconcile_after_mount_absent(&path)?;
                        if self.restore_on_stop {
                            manager.restore(&path)?;
                        }
                    }
                    Entry::Finalizing(_) if mounts_at(&path)?.is_empty() => {
                        manager.restore(&path)?;
                    }
                    Entry::Finalizing(_) => anyhow::bail!(
                        "{} is mounted while its snapshot is finalizing",
                        path.display()
                    ),
                    Entry::Missing if mounts_at(&path)?.is_empty() => {}
                    Entry::Missing => {
                        anyhow::bail!("{} is mounted without a snapshot record", path.display())
                    }
                }
                Ok(())
            })();
            if let Err(error) = recovery {
                errors.push(format!("failed to recover {}: {error}", path.display()));
                retained_prepared.push(path);
            }
        }
        self.prepared = retained_prepared;

        if self.sessions.is_empty() && self.prepared.is_empty() {
            self.manager = None;
            self.store = None;
        }

        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(errors.join("; "))
        }
    }
}

impl Drop for FuseInterceptor {
    fn drop(&mut self) {
        if (!self.sessions.is_empty() || !self.prepared.is_empty())
            && let Err(error) = <Self as Interceptor>::stop(self)
        {
            tracing::error!("failed to clean up FUSE interceptor during drop: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_parser_preserves_identity_and_escapes() {
        let input = "42 31 0:50 / /tmp/a\\040b rw,nosuid - fuse.file-guard file-guard:abc rw,user_id=0\n\
                     43 31 8:1 / /home rw - ext4 /dev/sda1 rw\n";
        assert_eq!(
            parse_mountinfo(input.as_bytes()),
            vec![
                MountInfo {
                    id: 42,
                    target: PathBuf::from("/tmp/a b"),
                    fs_type: "fuse.file-guard".to_string(),
                    source: b"file-guard:abc".to_vec(),
                    owner_uid: Some(0),
                },
                MountInfo {
                    id: 43,
                    target: PathBuf::from("/home"),
                    fs_type: "ext4".to_string(),
                    source: b"/dev/sda1".to_vec(),
                    owner_uid: None,
                },
            ]
        );
    }

    #[test]
    fn malformed_octal_escape_is_literal() {
        assert_eq!(unescape_mount_field(b"/a\\777b"), b"/a\\777b");
    }

    #[test]
    fn mountinfo_parser_preserves_non_utf8_paths() {
        let input = b"42 31 0:50 / /tmp/a\\377b rw - fuse.file-guard file-guard:abc rw\n";
        let mounts = parse_mountinfo(input);
        assert_eq!(mounts[0].target.as_os_str().as_bytes(), b"/tmp/a\xffb");
    }
}
