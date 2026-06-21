use std::path::{Path, PathBuf};
use std::sync::Arc;

use fuser::MountOption;

use super::credential_fs::CredentialFs;
use crate::interceptor::{Interceptor, InterceptorArgs};
use crate::store::BackingStore;

struct MountSession {
    watched_path: PathBuf,
    session: fuser::BackgroundSession,
}

pub struct FuseInterceptor {
    args: Option<InterceptorArgs>,
    sessions: Vec<MountSession>,
    store: Option<Arc<dyn BackingStore>>,
    restore_on_stop: bool,
}

impl FuseInterceptor {
    pub fn new(args: InterceptorArgs) -> Self {
        Self {
            args: Some(args),
            sessions: Vec::new(),
            store: None,
            restore_on_stop: false,
        }
    }

    /// Move the real credential into the backing store (if needed) and leave an
    /// empty file to mount over.
    fn prepare_mountpoint(
        watched_path: &Path,
        store: &Arc<dyn BackingStore>,
    ) -> anyhow::Result<()> {
        // M3: never operate on a symlink - following it could expose or clobber
        // an unintended target. Require the operator to resolve it first.
        if let Ok(meta) = std::fs::symlink_metadata(watched_path)
            && meta.file_type().is_symlink()
        {
            anyhow::bail!(
                "{} is a symlink; refusing to guard it (point the watch at the real file)",
                watched_path.display()
            );
        }

        let on_disk = std::fs::read(watched_path).ok();
        let in_store = store.read(watched_path).ok();

        // H2: if there is real on-disk content the store doesn't already hold
        // (a brand-new file, or one the user edited while we were stopped), it
        // is authoritative - capture it before we replace it, so we never lose
        // newer credentials. An *empty* on-disk file is a leftover mountpoint
        // from a previous run and must NOT overwrite stored content.
        if let Some(disk) = &on_disk
            && !disk.is_empty()
            && in_store.as_deref() != Some(disk.as_slice())
        {
            store.store(watched_path, disk)?;
        }

        if on_disk.is_some() {
            std::fs::remove_file(watched_path)
                .map_err(|e| anyhow::anyhow!("failed to remove {}: {e}", watched_path.display()))?;
        } else if let Some(parent) = watched_path.parent() {
            // H10: the watched file may not exist yet - make sure its directory
            // does, then mount an empty file there.
            std::fs::create_dir_all(parent).ok();
        }

        std::fs::write(watched_path, b"").map_err(|e| {
            anyhow::anyhow!(
                "failed to create mountpoint {}: {e}",
                watched_path.display()
            )
        })?;

        Ok(())
    }

    fn restore_original(watched_path: &Path, store: &Arc<dyn BackingStore>) -> anyhow::Result<()> {
        let contents = store.read(watched_path)?;
        std::fs::write(watched_path, contents)
            .map_err(|e| anyhow::anyhow!("failed to restore {}: {e}", watched_path.display()))?;

        Ok(())
    }

    /// H9: undo a partially-completed start. Unmount everything mounted so far
    /// and put every captured original back, so a failure midway never leaves
    /// credentials stranded in the store with no live mount.
    fn rollback(&mut self, store: &Arc<dyn BackingStore>, prepared: &[PathBuf]) {
        for mount in self.sessions.drain(..) {
            drop(mount.session);
        }
        for path in prepared {
            match store.read(path) {
                Ok(content) => {
                    let _ = std::fs::write(path, content);
                    let _ = store.delete(path);
                }
                // Nothing was captured (the original was absent) - just remove
                // the empty mountpoint we created.
                Err(_) => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
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

        let mut prepared: Vec<PathBuf> = Vec::new();

        for watched_path in &args.watched_paths {
            let setup = (|| -> anyhow::Result<()> {
                Self::prepare_mountpoint(watched_path, &args.store)?;
                prepared.push(watched_path.clone());

                let credential_fs = CredentialFs::new(
                    watched_path.clone(),
                    args.store.clone(),
                    args.policy.clone(),
                    args.logger.clone(),
                    args.rt_handle.clone(),
                )?;

                // Read-write mount: writes are gated per-open like reads.
                let mut mount_options = vec![MountOption::FSName("file-guard".to_string())];
                // When the daemon runs as root (the privileged deployment), the
                // mount must be reachable by the guarded user's own processes.
                // Requires `user_allow_other` in /etc/fuse.conf
                // (NixOS: programs.fuse.userAllowOther = true).
                if unsafe { libc::geteuid() == 0 } {
                    mount_options.push(MountOption::AllowOther);
                }

                let session = fuser::spawn_mount2(credential_fs, watched_path, &mount_options)
                    .map_err(|e| {
                        anyhow::anyhow!("failed to mount FUSE at {}: {e}", watched_path.display())
                    })?;

                self.sessions.push(MountSession {
                    watched_path: watched_path.clone(),
                    session,
                });
                tracing::info!("FUSE mounted at {}", watched_path.display());
                Ok(())
            })();

            if let Err(e) = setup {
                tracing::error!(
                    "failed to set up {}: {e}; rolling back",
                    watched_path.display()
                );
                self.rollback(&args.store, &prepared);
                return Err(e);
            }
        }

        tracing::info!(
            "file-guard FUSE started, watching {} files",
            self.sessions.len()
        );

        Ok(())
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        let sessions: Vec<MountSession> = self.sessions.drain(..).collect();
        let store = self.store.take();

        for mount in sessions {
            drop(mount.session);
            tracing::info!("FUSE unmounted at {}", mount.watched_path.display());

            let should_restore = self.restore_on_stop && store.is_some();
            if should_restore {
                let result = Self::restore_original(&mount.watched_path, store.as_ref().unwrap());
                if let Err(e) = result {
                    tracing::warn!("failed to restore {}: {e}", mount.watched_path.display());
                }
            }
        }

        Ok(())
    }
}
