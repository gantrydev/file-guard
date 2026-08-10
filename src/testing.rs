//! Test-only utilities shared across integration and unit tests.
//!
//! Provides an in-memory [`BackingStore`](crate::store::BackingStore) and
//! record factory so tests don't depend on SQLite or a filesystem layout.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::store::{
    BackingStore, Entry, FORMAT_VERSION, FinalizationRecord, Lifecycle, ObjectIdentity,
    OriginalState, RecordHeader, RecordVersion, RestoreMetadata, SnapshotRecord, StoreError,
    StoreResult, Timestamp, path_to_hex, sha256,
};

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
