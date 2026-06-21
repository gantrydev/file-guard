use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::policy::rule::Access;
use crate::process::identify::ProcessInfo;

/// Unique process identity — `pid` plus `start_time`, so a recycled PID cannot
/// inherit a prior process's session grant. The kernel guarantees the pair is
/// unique for the lifetime of a process.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProcessId {
    pub pid: u32,
    pub start_time: u64,
}

impl From<&ProcessInfo> for ProcessId {
    fn from(info: &ProcessInfo) -> Self {
        Self {
            pid: info.pid,
            start_time: info.start_time,
        }
    }
}

/// A session-scoped grant: this exact process instance, this file, this
/// direction.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct GrantKey {
    proc: ProcessId,
    file: PathBuf,
    access: Access,
}

/// Tracks "allow this session" decisions (cleared on daemon restart).
///
/// We intentionally do *not* store "allow once" grants: each FUSE `open()` is
/// evaluated independently and the resulting handle is cached for its own
/// lifetime, so "once" already means "this open and no future one" without any
/// persistence here.
pub struct SessionState {
    session_allows: RwLock<HashSet<GrantKey>>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            session_allows: RwLock::new(HashSet::new()),
        }
    }

    /// Record an "allow this session" grant for a specific process instance.
    pub fn grant_session(&self, proc: ProcessId, file: PathBuf, access: Access) {
        let key = GrantKey { proc, file, access };
        self.session_allows.write().unwrap().insert(key);
    }

    /// Is there a session grant covering this process instance + file +
    /// direction? An `Any` grant covers both read and write.
    pub fn is_session_allowed(&self, proc: &ProcessId, file: &Path, access: Access) -> bool {
        let allows = self.session_allows.read().unwrap();
        let has = |a: Access| {
            allows.contains(&GrantKey {
                proc: proc.clone(),
                file: file.to_path_buf(),
                access: a,
            })
        };
        has(access) || has(Access::Any)
    }

    /// Clear all session state.
    #[allow(dead_code)] // TODO: invoke on an explicit `session reset` / re-auth.
    pub fn clear(&self) {
        self.session_allows.write().unwrap().clear();
    }
}
