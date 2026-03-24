use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;

/// Unique process identity — prevents PID recycling attacks.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProcessId {
    pub pid: u32,
    pub start_time: u64,
}

/// Key for session-scoped grants.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SessionKey {
    binary: PathBuf,
    file: PathBuf,
}

/// Tracks session-scoped allow decisions (cleared on daemon restart).
pub struct SessionState {
    session_allows: RwLock<HashSet<SessionKey>>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            session_allows: RwLock::new(HashSet::new()),
        }
    }

    /// Record an "allow this session" grant.
    pub fn grant_session(&self, binary: PathBuf, file: PathBuf) {
        let key = SessionKey { binary, file };
        self.session_allows.write().unwrap().insert(key);
    }

    /// Check if a session-scoped allow exists for this binary+file pair.
    pub fn is_session_allowed(&self, binary: &PathBuf, file: &PathBuf) -> bool {
        let key = SessionKey {
            binary: binary.clone(),
            file: file.clone(),
        };
        self.session_allows.read().unwrap().contains(&key)
    }

    /// Clear all session state.
    pub fn clear(&self) {
        self.session_allows.write().unwrap().clear();
    }
}
