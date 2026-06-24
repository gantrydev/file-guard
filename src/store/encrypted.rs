// TODO: Implement age-encrypted backing store.
// Requires: age crate, passphrase or hardware key at daemon startup.
// Deferred - the BackingStore trait makes this pluggable.

use crate::store::BackingStore;
use std::path::{Path, PathBuf};

#[allow(dead_code)] // Reserved: selectable once `age` support lands (see TODO above).
pub struct EncryptedStore;

impl BackingStore for EncryptedStore {
    fn read(&self, _file_id: &Path) -> anyhow::Result<Vec<u8>> {
        todo!("age-encrypted backing store not yet implemented")
    }

    fn store(&self, _file_id: &Path, _contents: &[u8]) -> anyhow::Result<()> {
        todo!("age-encrypted backing store not yet implemented")
    }

    fn delete(&self, _file_id: &Path) -> anyhow::Result<()> {
        todo!("age-encrypted backing store not yet implemented")
    }

    fn exists(&self, _file_id: &Path) -> bool {
        todo!("age-encrypted backing store not yet implemented")
    }

    fn list(&self) -> anyhow::Result<Vec<PathBuf>> {
        todo!("age-encrypted backing store not yet implemented")
    }
}
