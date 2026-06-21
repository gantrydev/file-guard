use crate::store::BackingStore;
use std::path::{Path, PathBuf};

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Simplest backing store: originals moved to a directory the guarded user
/// cannot read.
///
/// SECURITY: this only protects against same-uid malware if the store is owned
/// by a *different* uid than the guarded user. In the supported privileged
/// deployment the daemon runs as root and the store
/// lives at `/var/lib/file-guard/store` (root:root, 0700), set via
/// `FILE_GUARD_STORE_DIR`. Running as your own user puts the plaintext at
/// `~/.local/share/file-guard/store`, readable by the very malware this tool
/// defends against - that mode is for development only.
pub struct MovedStore {
    store_dir: PathBuf,
}

impl MovedStore {
    pub fn new() -> anyhow::Result<Self> {
        let store_dir = match std::env::var_os("FILE_GUARD_STORE_DIR") {
            Some(dir) => PathBuf::from(dir),
            None if is_root() => PathBuf::from("/var/lib/file-guard/store"),
            None => dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("~/.local/share"))
                .join("file-guard")
                .join("store"),
        };

        if !store_dir.exists() {
            std::fs::create_dir_all(&store_dir)?;
            // Set directory permissions to 0700
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }

        Ok(Self { store_dir })
    }

    /// Map a watched file path to its store location.
    /// e.g., ~/.aws/credentials → store_dir/aws--credentials
    fn store_path(&self, file_id: &Path) -> PathBuf {
        let encoded = file_id
            .to_string_lossy()
            .trim_start_matches('/')
            .replace('/', "--");
        self.store_dir.join(encoded)
    }
}

impl BackingStore for MovedStore {
    fn read(&self, file_id: &Path) -> anyhow::Result<Vec<u8>> {
        let path = self.store_path(file_id);
        std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("failed to read backing store {}: {e}", path.display()))
    }

    fn store(&self, file_id: &Path, contents: &[u8]) -> anyhow::Result<()> {
        let path = self.store_path(file_id);
        std::fs::write(&path, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn delete(&self, file_id: &Path) -> anyhow::Result<()> {
        let path = self.store_path(file_id);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn list(&self) -> anyhow::Result<Vec<PathBuf>> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(&self.store_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().replace("--", "/");
            result.push(PathBuf::from(format!("/{name}")));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_encodes_separators() {
        let store = MovedStore {
            store_dir: PathBuf::from("/var/lib/file-guard/store"),
        };
        assert_eq!(
            store.store_path(Path::new("/home/alice/.aws/credentials")),
            PathBuf::from("/var/lib/file-guard/store/home--alice--.aws--credentials"),
        );
    }
}
