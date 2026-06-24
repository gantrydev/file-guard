mod credential_fs;
mod fuse_interceptor;

pub use fuse_interceptor::FuseInterceptor;

/// End-to-end tests that mount a real FUSE file and exercise the policy path
/// through an actual `open()`/`read()`. Skipped (not failed) when the host has
/// no usable `/dev/fuse`, so they run on dev machines and CI runners that
/// provide FUSE but don't break sandboxes that don't.
#[cfg(test)]
mod integration_tests {
    use super::credential_fs::CredentialFs;
    use crate::config::{Config, RuleAction, RuleEntry, Settings};
    use crate::logging::AccessLogger;
    use crate::policy::engine::PolicyEngine;
    use crate::policy::rule::Access;
    use crate::prompt::PromptClient;
    use crate::store::BackingStore;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Minimal in-memory backing store so the test doesn't touch the real
    /// store dir or its process-global `FILE_GUARD_STORE_DIR` env.
    struct MemStore(Mutex<std::collections::HashMap<PathBuf, Vec<u8>>>);

    impl BackingStore for MemStore {
        fn read(&self, id: &Path) -> anyhow::Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not stored"))
        }
        fn store(&self, id: &Path, contents: &[u8]) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(id.to_path_buf(), contents.to_vec());
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

    fn fuse_available() -> bool {
        Path::new("/dev/fuse").exists()
    }

    fn settings(default_action: &str) -> Settings {
        toml::from_str(&format!("default_action = \"{default_action}\"")).unwrap()
    }

    /// Mount `fs` over a fresh file under a temp dir and return (mountpoint,
    /// session). The session keeps the mount up and unmounts when dropped.
    fn mount(fs: CredentialFs, tmp: &Path) -> Option<(PathBuf, fuser::BackgroundSession)> {
        let mountpoint = tmp.join("credential");
        std::fs::write(&mountpoint, b"").unwrap();
        let mut config = fuser::Config::default();
        config.mount_options = vec![fuser::MountOption::FSName("file-guard".into())];
        match fuser::spawn_mount2(fs, &mountpoint, &config) {
            Ok(session) => {
                std::thread::sleep(Duration::from_millis(100));
                Some((mountpoint, session))
            }
            Err(e) => {
                eprintln!("SKIP: could not mount FUSE ({e})");
                None
            }
        }
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
    fn allowed_binary_reads_real_contents() {
        if !fuse_available() {
            eprintln!("SKIP: no /dev/fuse");
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = temp_dir("allow");
        let watched = tmp.join("credential");
        let secret = b"super-secret-token\n";

        let store = Arc::new(MemStore(Mutex::new(
            [(watched.clone(), secret.to_vec())].into_iter().collect(),
        )));

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

        let Some((mountpoint, session)) = mount(fs, &tmp) else {
            std::fs::remove_dir_all(&tmp).ok();
            return;
        };
        let got = std::fs::read(&mountpoint);
        drop(session);
        std::fs::remove_dir_all(&tmp).ok();

        assert_eq!(
            got.unwrap(),
            secret,
            "authorized binary must read the secret"
        );
    }

    /// With no rule and an unreachable agent, the deny-by-default policy makes
    /// the kernel return EACCES on open — the secret never leaves the store.
    #[test]
    fn unauthorized_open_is_denied() {
        if !fuse_available() {
            eprintln!("SKIP: no /dev/fuse");
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = temp_dir("deny");
        let watched = tmp.join("credential");

        let store = Arc::new(MemStore(Mutex::new(
            [(watched.clone(), b"secret".to_vec())]
                .into_iter()
                .collect(),
        )));
        let config = Config {
            settings: settings("deny"),
            watch: vec![],
            rule: vec![],
        };
        let policy = Arc::new(PolicyEngine::new(&config, unreachable_client()));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(watched, store, policy, logger, rt.handle().clone()).unwrap();

        let Some((mountpoint, session)) = mount(fs, &tmp) else {
            std::fs::remove_dir_all(&tmp).ok();
            return;
        };
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
}
