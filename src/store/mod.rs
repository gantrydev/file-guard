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

#[cfg(test)]
pub mod testing {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::*;

    pub struct MemoryStore {
        state: Mutex<MemoryState>,
    }

    struct MemoryState {
        records: HashMap<PathBuf, SnapshotRecord>,
        finalizations: HashMap<PathBuf, FinalizationRecord>,
    }

    impl MemoryStore {
        pub fn with_record(path: PathBuf, record: SnapshotRecord) -> Self {
            Self {
                state: Mutex::new(MemoryState {
                    records: [(path, record)].into_iter().collect(),
                    finalizations: HashMap::new(),
                }),
            }
        }

        pub fn contents(&self, path: &Path) -> Vec<u8> {
            self.state.lock().unwrap().records[path].contents.clone()
        }
    }

    impl BackingStore for MemoryStore {
        fn load(&self, file_id: &Path) -> StoreResult<Entry> {
            let state = self.state.lock().unwrap();
            if let Some(record) = state.records.get(file_id).cloned() {
                return Ok(Entry::Present(Box::new(record)));
            }
            Ok(state
                .finalizations
                .get(file_id)
                .cloned()
                .map_or(Entry::Missing, |record| Entry::Finalizing(Box::new(record))))
        }

        fn commit(
            &self,
            file_id: &Path,
            expected: Option<&RecordVersion>,
            next: &SnapshotRecord,
        ) -> StoreResult<RecordVersion> {
            let mut state = self.state.lock().unwrap();
            if state.finalizations.contains_key(file_id) {
                return Err(StoreError::Conflict(
                    "memory-store path is finalizing".to_string(),
                ));
            }
            match (state.records.get(file_id), expected) {
                (None, None) if next.header.revision == 1 => {}
                (Some(current), Some(expected))
                    if current.version() == *expected
                        && current.header.generation == next.header.generation
                        && next.header.revision == expected.revision + 1 => {}
                _ => return Err(StoreError::Conflict("memory-store CAS failed".to_string())),
            }
            state.records.insert(file_id.to_path_buf(), next.clone());
            Ok(next.version())
        }

        fn begin_finalization(
            &self,
            file_id: &Path,
            expected: &RecordVersion,
            marker: &FinalizationRecord,
        ) -> StoreResult<RecordVersion> {
            let mut state = self.state.lock().unwrap();
            if state.records.get(file_id).map(SnapshotRecord::version) != Some(expected.clone()) {
                return Err(StoreError::Conflict(
                    "memory-store finalization CAS failed".to_string(),
                ));
            }
            state.records.remove(file_id);
            state
                .finalizations
                .insert(file_id.to_path_buf(), marker.clone());
            Ok(marker.version())
        }

        fn finish_finalization(&self, file_id: &Path, expected: &RecordVersion) -> StoreResult<()> {
            let mut state = self.state.lock().unwrap();
            if state
                .finalizations
                .get(file_id)
                .map(FinalizationRecord::version)
                != Some(expected.clone())
            {
                return Err(StoreError::Conflict(
                    "memory-store marker CAS failed".to_string(),
                ));
            }
            state.finalizations.remove(file_id);
            Ok(())
        }

        fn list(&self) -> StoreResult<Vec<Entry>> {
            let state = self.state.lock().unwrap();
            let mut entries: Vec<_> = state
                .records
                .values()
                .cloned()
                .map(|record| Entry::Present(Box::new(record)))
                .collect();
            entries.extend(
                state
                    .finalizations
                    .values()
                    .cloned()
                    .map(|record| Entry::Finalizing(Box::new(record))),
            );
            Ok(entries)
        }
    }

    pub fn mount_intent_record(path: &Path, contents: &[u8]) -> SnapshotRecord {
        let timestamp = Timestamp {
            seconds: 1,
            nanoseconds: 2,
        };
        let identity = |inode| ObjectIdentity {
            device: 1,
            inode,
            ctime: timestamp.clone(),
            mtime: timestamp.clone(),
            size: contents.len() as u64,
            links: 1,
            mode: libc::S_IFREG | 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        };
        let metadata = RestoreMetadata {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            mode: 0o600,
            atime: timestamp.clone(),
            mtime: timestamp.clone(),
            xattrs: vec![],
        };
        SnapshotRecord {
            header: RecordHeader {
                format: FORMAT_VERSION,
                path_hex: path_to_hex(path),
                generation: "00112233445566778899aabbccddeeff".to_string(),
                revision: 1,
                lifecycle: Lifecycle::MountIntent {
                    detached_original: Some(identity(2)),
                },
                original: OriginalState::Present {
                    identity: identity(2),
                    metadata,
                },
                logical_present: true,
                parent: identity(1),
                staging_path_hex: path_to_hex(Path::new("/unused")),
                swap_name: "swap".to_string(),
                stored_name: "stored".to_string(),
                placeholder: Some(identity(3)),
                mount_token: "ffeeddccbbaa99887766554433221100".to_string(),
                content_sha256: sha256(contents),
                blocked_reason: None,
            },
            contents: contents.to_vec(),
        }
    }
}
