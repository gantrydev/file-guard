mod credential_fs;
mod fuse_interceptor;

pub use fuse_interceptor::FuseInterceptor;

/// End-to-end tests that mount a real FUSE file and exercise the policy path
/// through actual filesystem operations. They are explicitly ignored by the
/// ordinary test suite and run as a required CI step on a FUSE-capable runner.
#[cfg(test)]
mod integration_tests {
    use super::credential_fs::CredentialFs;
    use crate::config::{Config, RuleAction, RuleEntry, Settings};
    use crate::logging::AccessLogger;
    use crate::policy::engine::PolicyEngine;
    use crate::policy::rule::Access;
    use crate::prompt::PromptClient;
    use crate::store::testing::{MemoryStore, mount_intent_record};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    fn memory_store(watched: &Path, contents: &[u8]) -> Arc<MemoryStore> {
        Arc::new(MemoryStore::with_record(
            watched.to_path_buf(),
            mount_intent_record(watched, contents),
        ))
    }

    fn settings(default_action: &str) -> Settings {
        toml::from_str(&format!("default_action = \"{default_action}\"")).unwrap()
    }

    /// Mount `fs` over a fresh file under a temp dir and return (mountpoint,
    /// session). The session keeps the mount up and unmounts when dropped.
    fn mount(fs: CredentialFs, tmp: &Path) -> (PathBuf, fuser::BackgroundSession) {
        let mountpoint = tmp.join("credential");
        std::fs::write(&mountpoint, b"").unwrap();
        let mut config = fuser::Config::default();
        config.mount_options = vec![fuser::MountOption::FSName("file-guard".into())];
        let session = fuser::spawn_mount2(fs, &mountpoint, &config)
            .expect("the required FUSE integration environment must permit mounting");
        std::thread::sleep(Duration::from_millis(100));
        (mountpoint, session)
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fg-it-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn unreachable_client() -> Arc<PromptClient> {
        Arc::new(PromptClient::new(
            PathBuf::from("/nonexistent.sock"),
            Duration::from_millis(50),
            0,
        ))
    }

    /// An "allow always" rule for this test binary lets the same binary read the
    /// real stored contents straight back through the mount.
    #[test]
    #[ignore = "requires /dev/fuse; CI runs this suite explicitly"]
    fn allowed_binary_reads_real_contents() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = temp_dir("allow");
        let watched = tmp.join("credential");
        let secret = b"super-secret-token\n";

        let store = memory_store(&watched, secret);

        // The caller the FUSE layer will see is this test process.
        let me = std::env::current_exe().unwrap();
        let config = Config {
            settings: settings("deny"),
            watch: vec![],
            rule: vec![RuleEntry {
                file: watched.to_string_lossy().into_owned(),
                binary: me.to_string_lossy().into_owned(),
                action: RuleAction::Allow,
                access: Access::Any,
                sha256: None, // unpinned → path match (this exact binary)
                signature: None,
                script: None,
                script_sha256: None,
            }],
        };
        let policy = Arc::new(PolicyEngine::new(&config, unreachable_client()));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(watched, store, policy, logger, rt.handle().clone()).unwrap();

        let (mountpoint, session) = mount(fs, &tmp);
        let got = std::fs::read(&mountpoint);
        drop(session);
        std::fs::remove_dir_all(&tmp).ok();

        assert_eq!(
            got.unwrap(),
            secret,
            "authorized binary must read the secret"
        );
    }

    /// End-to-end repro of the corruption: an authorized writer opens the file
    /// in place (no O_TRUNC), overwrites it with shorter content, and shrinks it
    /// with `set_len` — exactly an editor's save. The mount must persist only the
    /// new, shorter bytes, with no resurrected tail from the old content.
    #[test]
    #[ignore = "requires /dev/fuse; CI runs this suite explicitly"]
    fn in_place_overwrite_then_shrink_has_no_stale_tail() {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::PermissionsExt;

        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = temp_dir("shrink");
        let watched = tmp.join("credential");
        let old = b"OLD-LONGER-CREDENTIAL-CONTENTS\n";
        let new = b"new-short\n";

        let store = memory_store(&watched, old);
        let me = std::env::current_exe().unwrap();
        let config = Config {
            settings: settings("deny"),
            watch: vec![],
            rule: vec![RuleEntry {
                file: watched.to_string_lossy().into_owned(),
                binary: me.to_string_lossy().into_owned(),
                action: RuleAction::Allow,
                access: Access::Any,
                sha256: None,
                signature: None,
                script: None,
                script_sha256: None,
            }],
        };
        let policy = Arc::new(PolicyEngine::new(&config, unreachable_client()));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(watched, store, policy, logger, rt.handle().clone()).unwrap();

        let (mountpoint, session) = mount(fs, &tmp);

        // Open in place WITHOUT truncate, overwrite the head, then shrink — the
        // editor-save sequence that left a stale tail before the fix.
        let write_result = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).open(&mountpoint)?;
            f.seek(SeekFrom::Start(0))?;
            f.write_all(new)?;
            f.set_len(new.len() as u64)?;
            f.flush()
        })();
        let got = std::fs::read(&mountpoint);
        std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(0o600))
            .expect("idempotent chmod must succeed");
        let chmod_error =
            std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(0o644))
                .expect_err("unsupported chmod must not report success");
        let mode_after_chmod =
            std::fs::metadata(&mountpoint).unwrap().permissions().mode() & 0o7777;

        drop(session);
        std::fs::remove_dir_all(&tmp).ok();

        write_result.expect("authorized in-place write must succeed");
        assert_eq!(
            got.unwrap(),
            new,
            "shrink left a resurrected tail from the old content"
        );
        assert_eq!(chmod_error.raw_os_error(), Some(libc::EOPNOTSUPP));
        assert_eq!(mode_after_chmod, 0o600);
    }

    /// With no rule and an unreachable agent, the deny-by-default policy makes
    /// the kernel return EACCES on open — the secret never leaves the store.
    #[test]
    #[ignore = "requires /dev/fuse; CI runs this suite explicitly"]
    fn unauthorized_open_is_denied() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = temp_dir("deny");
        let watched = tmp.join("credential");

        let store = memory_store(&watched, b"secret");
        let config = Config {
            settings: settings("deny"),
            watch: vec![],
            rule: vec![],
        };
        let policy = Arc::new(PolicyEngine::new(&config, unreachable_client()));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(watched, store, policy, logger, rt.handle().clone()).unwrap();

        let (mountpoint, session) = mount(fs, &tmp);
        let got = std::fs::read(&mountpoint);
        drop(session);
        std::fs::remove_dir_all(&tmp).ok();

        let err = got.expect_err("unauthorized read must fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EACCES),
            "denied open should surface as EACCES, got {err:?}"
        );
    }

    /// A single allow rule for this binary, scoped to `access`.
    fn rule_config(watched: &Path, access: Access) -> Config {
        let me = std::env::current_exe().unwrap();
        Config {
            settings: settings("deny"),
            watch: vec![],
            rule: vec![RuleEntry {
                file: watched.to_string_lossy().into_owned(),
                binary: me.to_string_lossy().into_owned(),
                action: RuleAction::Allow,
                access,
                sha256: None,
                signature: None,
                script: None,
                script_sha256: None,
            }],
        }
    }

    /// A write-only grant must not become a read: O_RDONLY and O_RDWR are both
    /// denied (the latter would otherwise preload the secret into the buffer and
    /// serve it via read()), while O_WRONLY is allowed.
    #[test]
    #[ignore = "requires /dev/fuse; CI runs this suite explicitly"]
    fn write_only_grant_cannot_read_via_rdwr() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = temp_dir("wronly");
        let watched = tmp.join("credential");
        let store = memory_store(&watched, b"TOP-SECRET");
        let config = rule_config(&watched, Access::Write);
        let policy = Arc::new(PolicyEngine::new(&config, unreachable_client()));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(watched, store, policy, logger, rt.handle().clone()).unwrap();

        let (mountpoint, session) = mount(fs, &tmp);

        let ro = std::fs::OpenOptions::new().read(true).open(&mountpoint);
        let rw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mountpoint);
        let wo = std::fs::OpenOptions::new().write(true).open(&mountpoint);
        let wo_ok = wo.is_ok();
        drop(wo);

        drop(session);
        std::fs::remove_dir_all(&tmp).ok();

        assert_eq!(
            ro.err().and_then(|e| e.raw_os_error()),
            Some(libc::EACCES),
            "O_RDONLY must be denied for a write-only grant"
        );
        assert_eq!(
            rw.err().and_then(|e| e.raw_os_error()),
            Some(libc::EACCES),
            "O_RDWR must be denied (read not authorized) so the secret can't leak via read()"
        );
        assert!(wo_ok, "O_WRONLY must be allowed for a write grant");
    }

    /// A write at an absurd offset is rejected with EFBIG and the daemon stays
    /// up (a prior version attempted a multi-terabyte allocation and aborted).
    #[test]
    #[ignore = "requires /dev/fuse; CI runs this suite explicitly"]
    fn huge_offset_write_is_efbig_and_daemon_survives() {
        use std::os::unix::fs::FileExt;

        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = temp_dir("huge");
        let watched = tmp.join("credential");
        let store = memory_store(&watched, b"intact");
        let config = rule_config(&watched, Access::Any);
        let policy = Arc::new(PolicyEngine::new(&config, unreachable_client()));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(watched, store, policy, logger, rt.handle().clone()).unwrap();

        let (mountpoint, session) = mount(fs, &tmp);

        let write_err = {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&mountpoint)
                .unwrap();
            f.write_at(b"x", 1 << 50)
                .err()
                .and_then(|e| e.raw_os_error())
        };
        // Daemon must still be alive and serving the original content.
        let after = std::fs::read(&mountpoint);

        drop(session);
        std::fs::remove_dir_all(&tmp).ok();

        assert_eq!(
            write_err,
            Some(libc::EFBIG),
            "huge-offset write must be EFBIG"
        );
        assert_eq!(
            after.unwrap(),
            b"intact",
            "daemon survived and content intact"
        );
    }
}
