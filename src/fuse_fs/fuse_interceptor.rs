use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fuser::{Config, MountOption, SessionACL};

use super::credential_fs::CredentialFs;
use crate::interceptor::{Interceptor, InterceptorArgs};
use crate::store::BackingStore;

/// Decode the octal escapes (`\040` space, `\011` tab, `\012` newline, `\134`
/// backslash) the kernel writes for whitespace in `/proc/mounts` fields.
fn unescape_mount_field(field: &str) -> String {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // Decode a `\ooo` escape in u32 (0..=511) and accept it only if it is a
        // real byte value. Naive u8 arithmetic would overflow and panic on a
        // leading octal digit >= 4; an out-of-range value falls through as a
        // literal backslash.
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..=i + 3].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64
                + (b[i + 2] - b'0') as u32 * 8
                + (b[i + 3] - b'0') as u32;
            if v <= u8::MAX as u32 {
                out.push(v as u8);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mountpoints in `/proc/mounts`-formatted `contents` that are file-guard
/// FUSE mounts (`<source> <target> <fstype> ...`, source field 1).
fn file_guard_mountpoints(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut f = line.split(' ');
            let source = f.next()?;
            let target = f.next()?;
            let fstype = f.next()?;
            (source == "file-guard" && fstype.starts_with("fuse"))
                .then(|| unescape_mount_field(target))
        })
        .collect()
}

/// Lazily detach any leftover file-guard mount at `watched_path`. A daemon that
/// died without running its unmount path (SIGKILL, crash, hard restart) leaves
/// the mountpoint as a wedged FUSE endpoint whose reads/writes fail with
/// ENOTCONN, so the next start can't recreate the file there. systemd runs a
/// single instance, so any file-guard mount still present at our path on start
/// is by definition orphaned and safe to detach — making startup self-healing.
fn clear_stale_mount(watched_path: &Path) {
    let proc_mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let target = watched_path.to_string_lossy();
    if !file_guard_mountpoints(&proc_mounts)
        .iter()
        .any(|m| m.as_str() == target)
    {
        return;
    }

    tracing::warn!(
        "clearing orphaned file-guard mount at {} (left by a previous daemon)",
        watched_path.display()
    );
    match CString::new(watched_path.as_os_str().as_bytes()) {
        // MNT_DETACH detaches even a wedged endpoint; the kernel completes the
        // teardown once the mount is no longer busy.
        Ok(c) => {
            if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } != 0 {
                tracing::warn!(
                    "failed to detach stale mount {}: {}",
                    watched_path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
        Err(e) => tracing::warn!("bad mountpoint path {}: {e}", watched_path.display()),
    }
}

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

    /// Capture the real credential into the backing store *without yet touching
    /// the original on disk*. Splitting capture from placeholder creation makes
    /// start() recoverable: once this returns Ok the content is durably in the
    /// store, so a later failure can always restore it. Idempotent.
    fn capture_original(watched_path: &Path, store: &Arc<dyn BackingStore>) -> anyhow::Result<()> {
        // Self-heal across an unclean shutdown: a leftover mount from a crashed
        // daemon wedges this path (ENOTCONN), so detach it before we touch it.
        clear_stale_mount(watched_path);

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

        // A read error must NOT be coerced to "absent": treating e.g. EACCES/EIO
        // as no-file would let the next step clobber a real credential with an
        // empty placeholder and lose it forever. Only a genuine NotFound counts
        // as absent; anything else aborts the guard loudly.
        let on_disk = match std::fs::read(watched_path) {
            Ok(content) => Some(content),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => anyhow::bail!(
                "refusing to guard {}: cannot read existing file: {e}",
                watched_path.display()
            ),
        };
        let in_store = store.read(watched_path).ok();

        // H2: if there is real on-disk content the store doesn't already hold
        // (a brand-new file, or one the user edited while we were stopped), it
        // is authoritative - capture it before we replace it, so we never lose
        // newer credentials. An *empty* on-disk file is treated as a leftover
        // mountpoint from a previous run and must NOT overwrite stored content.
        // NOTE (known limitation): an empty file is indistinguishable from a
        // credential the user *deliberately* blanked while we were stopped, so
        // we err toward preserving the stored content rather than risk losing a
        // real secret to a crash-leftover placeholder.
        if let Some(disk) = &on_disk
            && !disk.is_empty()
            && in_store.as_deref() != Some(disk.as_slice())
        {
            store.store(watched_path, disk)?;
        }

        Ok(())
    }

    /// Replace the original with an empty file to mount over. Runs only after
    /// `capture_original` has durably stored any real content.
    fn mount_placeholder(watched_path: &Path) -> anyhow::Result<()> {
        match std::fs::remove_file(watched_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // H10: the watched file may not exist yet - ensure its directory.
                if let Some(parent) = watched_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
            }
            Err(e) => {
                anyhow::bail!("failed to remove {}: {e}", watched_path.display())
            }
        }

        write_file_private(watched_path, b"").map_err(|e| {
            anyhow::anyhow!("failed to create mountpoint {}: {e}", watched_path.display())
        })
    }

    fn restore_original(watched_path: &Path, store: &Arc<dyn BackingStore>) -> anyhow::Result<()> {
        let contents = store.read(watched_path)?;
        // Restore the plaintext at 0600 - never the umask default (~0644), which
        // would expose a 0600 secret world-readable.
        write_file_private(watched_path, &contents)
            .map_err(|e| anyhow::anyhow!("failed to restore {}: {e}", watched_path.display()))?;

        Ok(())
    }

    /// H9: undo a partially-completed start. Unmount everything mounted so far
    /// and put every captured original back, so a failure midway never leaves
    /// credentials stranded in the store with no live mount, and never deletes a
    /// captured credential.
    fn rollback(&mut self, store: &Arc<dyn BackingStore>, prepared: &[PathBuf]) {
        for mount in self.sessions.drain(..) {
            drop(mount.session);
        }
        for path in prepared {
            match store.read(path) {
                Ok(content) => {
                    let _ = write_file_private(path, &content);
                    let _ = store.delete(path);
                }
                // Nothing was captured (the original was absent or empty) - just
                // remove the empty mountpoint we created.
                Err(_) => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

/// Write `contents` to `path`, creating it at mode 0600 (owner-only) so a
/// restored/placed credential is never left world-readable.
fn write_file_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    // create() only applies mode on a fresh file; force 0600 even if it existed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// The uid that owns `watched_path`'s directory — the only non-root user allowed
/// to reach the mount (see CredentialFs::authorize). Best-effort: None disables
/// the uid gate.
fn owner_uid_of(watched_path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        watched_path
            .parent()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = watched_path;
        None
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
            let owner_uid = owner_uid_of(watched_path);
            let setup = (|| -> anyhow::Result<()> {
                // Capture (durably) BEFORE marking the path recoverable and
                // BEFORE the destructive placeholder step, so any later failure
                // can always restore the original from the store.
                Self::capture_original(watched_path, &args.store)?;
                prepared.push(watched_path.clone());
                Self::mount_placeholder(watched_path)?;

                let credential_fs = CredentialFs::new(
                    watched_path.clone(),
                    args.store.clone(),
                    args.policy.clone(),
                    args.logger.clone(),
                    args.rt_handle.clone(),
                    owner_uid,
                )?;

                // Read-write mount: writes are gated per-open like reads.
                let mut config = Config::default();
                config.mount_options = vec![MountOption::FSName("file-guard".to_string())];
                // When the daemon runs as root (the privileged deployment), the
                // mount must be reachable by the guarded user's own processes.
                // Requires `user_allow_other` in /etc/fuse.conf
                // (NixOS: programs.fuse.userAllowOther = true).
                if unsafe { libc::geteuid() == 0 } {
                    config.acl = SessionACL::All;
                }

                let session =
                    fuser::spawn_mount2(credential_fs, watched_path, &config).map_err(|e| {
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

#[cfg(test)]
mod tests {
    use super::{
        FuseInterceptor, file_guard_mountpoints, owner_uid_of, unescape_mount_field,
        write_file_private,
    };
    use FuseInterceptor as Fi;
    use crate::store::BackingStore;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    struct MemStore(Mutex<std::collections::HashMap<PathBuf, Vec<u8>>>);
    impl MemStore {
        fn shared() -> Arc<dyn BackingStore> {
            Arc::new(MemStore(Mutex::new(std::collections::HashMap::new())))
        }
    }
    impl BackingStore for MemStore {
        fn read(&self, id: &Path) -> anyhow::Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not stored"))
        }
        fn store(&self, id: &Path, c: &[u8]) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(id.to_path_buf(), c.to_vec());
            Ok(())
        }
        fn delete(&self, id: &Path) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
        fn list(&self) -> anyhow::Result<Vec<PathBuf>> {
            Ok(self.0.lock().unwrap().keys().cloned().collect())
        }
        fn exists(&self, id: &Path) -> bool {
            self.0.lock().unwrap().contains_key(id)
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fg-it-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn unescape_decodes_octal_whitespace() {
        assert_eq!(unescape_mount_field("/a/b"), "/a/b");
        assert_eq!(unescape_mount_field("/a\\040b"), "/a b"); // space
        assert_eq!(unescape_mount_field("/a\\011b"), "/a\tb"); // tab
        assert_eq!(unescape_mount_field("/a\\134b"), "/a\\b"); // backslash
        assert_eq!(unescape_mount_field("trailing\\04"), "trailing\\04"); // not a full escape
    }

    #[test]
    fn unescape_high_octal_does_not_panic() {
        // Leading octal digit >= 4 overflows naive u8 arithmetic; must be left
        // as a literal, never panic (it would take down /proc/mounts parsing).
        assert_eq!(unescape_mount_field("x\\500y"), "x\\500y"); // 0o500 > 255: literal
        assert_eq!(unescape_mount_field("\\777"), "\\777"); // 0o777 > 255: literal
        assert_ne!(unescape_mount_field("\\377"), "\\377"); // 0o377 = 255: decoded (then lossy)
    }

    #[test]
    fn parser_tolerates_short_and_malformed_lines() {
        let mounts = file_guard_mountpoints("file-guard\nfile-guard /only-two\n\nfile-guard /p fuse rw\n");
        assert_eq!(mounts, vec!["/p".to_string()]);
    }

    #[test]
    fn write_file_private_creates_0600() {
        let dir = tmp("priv");
        let p = dir.join("secret");
        std::fs::write(&p, b"world-readable-before").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        write_file_private(&p, b"secret").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "restored secret must be 0600");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn capture_original_stores_real_content_keeps_empty() {
        let dir = tmp("capture");
        let store = MemStore::shared();

        // Non-empty original is captured.
        let real = dir.join("cred");
        std::fs::write(&real, b"SECRET").unwrap();
        Fi::capture_original(&real, &store).unwrap();
        assert_eq!(store.read(&real).unwrap(), b"SECRET");

        // Empty file is NOT captured (treated as a leftover placeholder).
        let empty = dir.join("empty");
        std::fs::write(&empty, b"").unwrap();
        Fi::capture_original(&empty, &store).unwrap();
        assert!(!store.exists(&empty));

        // Absent file is fine (no-op).
        Fi::capture_original(&dir.join("absent"), &store).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn capture_original_refuses_unreadable_file() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIP: root bypasses file permissions");
            return;
        }
        let dir = tmp("unreadable");
        let p = dir.join("cred");
        std::fs::write(&p, b"SECRET").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let store = MemStore::shared();
        // A read error must abort, NOT be coerced to "absent" (which would later
        // clobber the credential with an empty placeholder and lose it).
        assert!(Fi::capture_original(&p, &store).is_err());
        assert!(!store.exists(&p), "must not have captured anything");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).ok();
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn owner_uid_matches_directory_owner() {
        let dir = tmp("owner");
        let p = dir.join("cred");
        std::fs::write(&p, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let expected = std::fs::metadata(&dir).unwrap().uid();
            assert_eq!(owner_uid_of(&p), Some(expected));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finds_only_file_guard_fuse_mounts() {
        let proc_mounts = "\
proc /proc proc rw,nosuid 0 0
file-guard /home/u/.config/gcloud/credentials.db fuse rw,nosuid,allow_other 0 0
file-guard /home/u/with\\040space/adc.json fuse.file-guard rw 0 0
/dev/sda1 / ext4 rw 0 0
other-fuse /mnt/x fuse rw 0 0
";
        let mounts = file_guard_mountpoints(proc_mounts);
        assert_eq!(
            mounts,
            vec![
                "/home/u/.config/gcloud/credentials.db".to_string(),
                "/home/u/with space/adc.json".to_string(),
            ],
            "must match file-guard fuse mounts only, decoding escapes"
        );
    }
}
