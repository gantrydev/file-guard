pub mod encrypted;
pub mod moved;

use std::path::{Path, PathBuf};

/// Pluggable backing store for real credential contents.
pub trait BackingStore: Send + Sync {
    /// Read the real contents of a stored credential.
    fn read(&self, file_id: &Path) -> anyhow::Result<Vec<u8>>;

    /// Store credential contents (move original into the backing store).
    fn store(&self, file_id: &Path, contents: &[u8]) -> anyhow::Result<()>;

    /// Delete stored credential.
    fn delete(&self, file_id: &Path) -> anyhow::Result<()>;

    /// List all stored credential file IDs.
    fn list(&self) -> anyhow::Result<Vec<PathBuf>>;
}

/// Create the default backing store (moved originals).
pub fn create_store() -> anyhow::Result<Box<dyn BackingStore>> {
    Ok(Box::new(moved::MovedStore::new()?))
}
