use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persistent rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

/// Direction of a credential access. Concrete requests are always `Read` or
/// `Write`; `Any` only ever appears on a stored rule, meaning it covers both.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    Read,
    Write,
    Any,
}

impl Access {
    /// Does a rule scoped to `self` authorize a concrete `req`?
    pub fn covers(self, req: Access) -> bool {
        self == Access::Any || self == req
    }

    /// Derive the requested direction from `open(2)` flags. A handle counts as
    /// a write if it is writable, truncating, or appending; everything else
    /// (including `O_RDONLY | O_CREAT` on an existing mountpoint) is a read.
    pub fn from_open_flags(flags: i32) -> Access {
        let accmode = flags & libc::O_ACCMODE;
        let is_write = accmode == libc::O_WRONLY
            || accmode == libc::O_RDWR
            || (flags & libc::O_TRUNC) != 0
            || (flags & libc::O_APPEND) != 0;
        if is_write {
            Access::Write
        } else {
            Access::Read
        }
    }

    pub fn verb(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
            Access::Any => "access",
        }
    }
}

/// A persistent rule: binary X accessing file Y -> allow/deny, scoped to a
/// direction and (optionally) pinned to the binary's content hash / signature.
#[derive(Debug, Clone)]
pub struct Rule {
    pub file: PathBuf,
    pub binary: PathBuf,
    pub action: Action,
    pub access: Access,
    /// sha256 hex of the binary at the time the rule was captured. When set, a
    /// caller whose hash differs does **not** match (it re-prompts) rather than
    /// being denied - so a legitimate rebuild re-authorizes instead of breaking.
    pub sha256: Option<String>,
    /// macOS code-signing identity captured with the rule (unused on Linux).
    pub signature: Option<String>,
    /// For interpreter rules, the pinned script path. When set, a caller running
    /// the same interpreter but a *different* script does not match (re-prompts),
    /// narrowing "any python" to "this program".
    pub script: Option<String>,
    /// sha256 of the pinned script's contents. When set, a caller whose script
    /// hashes differently does not match (re-prompts) - catches in-place edits
    /// where the script path stays the same.
    pub script_sha256: Option<String>,
}

/// Outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed by a persistent rule.
    AllowAlways,
    /// Denied by a persistent rule.
    DenyAlways,
    /// Allowed for this session only.
    AllowSession,
    /// Allowed for this single open() only.
    AllowOnce,
    /// Denied for this single open() only.
    DenyOnce,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            Decision::AllowAlways | Decision::AllowSession | Decision::AllowOnce
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_flags_classify_direction() {
        assert_eq!(Access::from_open_flags(libc::O_RDONLY), Access::Read);
        assert_eq!(Access::from_open_flags(libc::O_WRONLY), Access::Write);
        assert_eq!(Access::from_open_flags(libc::O_RDWR), Access::Write);
        assert_eq!(
            Access::from_open_flags(libc::O_RDONLY | libc::O_TRUNC),
            Access::Write
        );
        assert_eq!(
            Access::from_open_flags(libc::O_WRONLY | libc::O_APPEND),
            Access::Write
        );
        // O_CREAT alone (read-create) is still a read; create() is gated separately.
        assert_eq!(
            Access::from_open_flags(libc::O_RDONLY | libc::O_CREAT),
            Access::Read
        );
    }

    #[test]
    fn covers_semantics() {
        assert!(Access::Any.covers(Access::Read));
        assert!(Access::Any.covers(Access::Write));
        assert!(Access::Read.covers(Access::Read));
        assert!(!Access::Read.covers(Access::Write));
        assert!(!Access::Write.covers(Access::Read));
    }
}
