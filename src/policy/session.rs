use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::policy::rule::Access;
use crate::process::identify::ProcessInfo;

/// Identity of one executable image in one process instance. Linux preserves
/// process start time across `exec`, so PID and start time alone are not enough
/// to prevent a replacement image from inheriting a session grant.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProcessId {
    pid: u32,
    start_time: u64,
    binary_path: PathBuf,
    binary_sha256: String,
    script: Option<PathBuf>,
}

impl From<&ProcessInfo> for ProcessId {
    fn from(info: &ProcessInfo) -> Self {
        Self {
            pid: info.pid,
            start_time: info.start_time,
            binary_path: info.binary_path.clone(),
            binary_sha256: info.binary_sha256.clone(),
            script: info.script.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(binary: &str, hash: &str, script: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 42,
            start_time: 7,
            binary_path: PathBuf::from(binary),
            binary_name: "tool".into(),
            binary_sha256: hash.into(),
            script: script.map(PathBuf::from),
            parent_chain: Vec::new(),
        }
    }

    #[test]
    fn exec_identity_cannot_inherit_a_session_grant() {
        let state = SessionState::new();
        let file = PathBuf::from("/credential");
        let original = ProcessId::from(&process("/usr/bin/tool", "one", None));
        state.grant_session(original.clone(), file.clone(), Access::Any);

        assert!(state.is_session_allowed(&original, &file, Access::Read));
        let replacement = ProcessId::from(&process("/usr/bin/other", "two", None));
        assert!(!state.is_session_allowed(&replacement, &file, Access::Read));
    }

    #[test]
    fn interpreter_session_grants_are_script_scoped() {
        let state = SessionState::new();
        let file = PathBuf::from("/credential");
        let original = ProcessId::from(&process(
            "/usr/bin/python",
            "interpreter",
            Some("/program/one.py"),
        ));
        state.grant_session(original, file.clone(), Access::Any);

        let other_script = ProcessId::from(&process(
            "/usr/bin/python",
            "interpreter",
            Some("/program/two.py"),
        ));
        assert!(!state.is_session_allowed(&other_script, &file, Access::Write));
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
}
