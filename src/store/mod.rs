pub mod sqlite;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_CREDENTIAL_SIZE: usize = 16 * 1024 * 1024;
pub const FORMAT_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtendedAttribute {
    pub name_hex: String,
    pub value_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub xattrs: Vec<ExtendedAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub device: u64,
    pub inode: u64,
    pub ctime: Timestamp,
    pub mtime: Timestamp,
    pub size: u64,
    pub links: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum OriginalState {
    Present {
        identity: ObjectIdentity,
        metadata: RestoreMetadata,
    },
    Absent {
        presentation: RestoreMetadata,
    },
}

impl OriginalState {
    pub fn metadata(&self) -> &RestoreMetadata {
        match self {
            Self::Present { metadata, .. } => metadata,
            Self::Absent { presentation } => presentation,
        }
    }

    pub fn existed(&self) -> bool {
        matches!(self, Self::Present { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreOrigin {
    Installed,
    Stored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmountNext {
    Restore,
    LeaveInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "phase", rename_all = "snake_case")]
pub enum Lifecycle {
    Captured,
    InstallIntent,
    Installed {
        detached_original: Option<ObjectIdentity>,
    },
    MountIntent {
        detached_original: Option<ObjectIdentity>,
    },
    UnmountIntent {
        next: UnmountNext,
        detached_original: Option<ObjectIdentity>,
    },
    RestoreIntent {
        origin: RestoreOrigin,
        restore_name: Option<String>,
        restore_identity: Option<ObjectIdentity>,
        detached_name: Option<String>,
        detached_identity: Option<ObjectIdentity>,
    },
    Restored {
        origin: RestoreOrigin,
        restored_identity: Option<ObjectIdentity>,
        displaced_name: Option<String>,
        displaced_identity: Option<ObjectIdentity>,
        detached_name: Option<String>,
        detached_identity: Option<ObjectIdentity>,
    },
    DeleteIntent {
        origin: RestoreOrigin,
        restored_identity: Option<ObjectIdentity>,
        displaced_name: Option<String>,
        displaced_identity: Option<ObjectIdentity>,
        detached_name: Option<String>,
        detached_identity: Option<ObjectIdentity>,
    },
    StoreIntent {
        detached_name: String,
    },
    Stored {
        detached_name: String,
        detached_original: ObjectIdentity,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordHeader {
    pub format: u32,
    pub path_hex: String,
    pub generation: String,
    pub revision: u64,
    pub lifecycle: Lifecycle,
    pub original: OriginalState,
    pub logical_present: bool,
    pub parent: ObjectIdentity,
    pub staging_path_hex: String,
    pub swap_name: String,
    pub stored_name: String,
    pub placeholder: Option<ObjectIdentity>,
    pub mount_token: String,
    pub content_sha256: String,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRecord {
    pub header: RecordHeader,
    pub contents: Vec<u8>,
}

impl SnapshotRecord {
    pub fn version(&self) -> RecordVersion {
        RecordVersion {
            generation: self.header.generation.clone(),
            revision: self.header.revision,
        }
    }

    pub fn successor(&self, lifecycle: Lifecycle, contents: Vec<u8>) -> Self {
        let mut next = self.clone();
        next.header.revision += 1;
        next.header.lifecycle = lifecycle;
        next.header.content_sha256 = sha256(&contents);
        next.contents = contents;
        next
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizationRecord {
    pub format: u32,
    pub path_hex: String,
    pub generation: String,
    pub revision: u64,
    pub logical_present: bool,
    pub parent: ObjectIdentity,
    pub staging_path_hex: String,
    pub final_name: String,
    pub final_identity: Option<ObjectIdentity>,
    pub restore_metadata: RestoreMetadata,
    pub content_length: u64,
    pub content_sha256: String,
}

impl FinalizationRecord {
    pub fn version(&self) -> RecordVersion {
        RecordVersion {
            generation: self.generation.clone(),
            revision: self.revision,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordVersion {
    pub generation: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Missing,
    Present(Box<SnapshotRecord>),
    Finalizing(Box<FinalizationRecord>),
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("backing store is already locked by another file-guard process")]
    Locked,
    #[error("unsupported backing-store format: {0}")]
    UnsupportedFormat(String),
    #[error("unsafe backing-store configuration: {0}")]
    UnsafeConfiguration(String),
    #[error("corrupt backing-store record: {0}")]
    Corrupt(String),
    #[error("backing-store revision conflict: {0}")]
    Conflict(String),
    #[error("backing-store operation has indeterminate durability: {0}")]
    Indeterminate(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

pub trait BackingStore: Send + Sync {
    fn load(&self, file_id: &Path) -> StoreResult<Entry>;

    fn commit(
        &self,
        file_id: &Path,
        expected: Option<&RecordVersion>,
        next: &SnapshotRecord,
    ) -> StoreResult<RecordVersion>;

    fn begin_finalization(
        &self,
        file_id: &Path,
        expected: &RecordVersion,
        marker: &FinalizationRecord,
    ) -> StoreResult<RecordVersion>;

    fn finish_finalization(&self, file_id: &Path, expected: &RecordVersion) -> StoreResult<()>;

    fn list(&self) -> StoreResult<Vec<Entry>>;
}

pub fn create_store() -> anyhow::Result<Box<dyn BackingStore>> {
    let store: Box<dyn BackingStore> = Box::new(sqlite::SqliteStore::new()?);
    store.list()?;
    Ok(store)
}

pub fn sha256(contents: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(contents))
}

pub fn path_to_hex(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    hex::encode(path.as_os_str().as_bytes())
}

pub fn path_from_hex(value: &str) -> StoreResult<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let bytes = hex::decode(value)
        .map_err(|error| StoreError::Corrupt(format!("invalid encoded path: {error}")))?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}
