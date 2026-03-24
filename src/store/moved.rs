use crate::store::BackingStore;
use std::path::{Path, PathBuf};

/// Simplest backing store: originals moved to a secure directory.
/// Default location: ~/.local/share/cred-guard/store/
pub struct MovedStore {
    store_dir: PathBuf,
}

impl MovedStore {
    pub fn new() -> anyhow::Result<Self> {
        let store_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/share"))
            .join("cred-guard")
            .join("store");

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
