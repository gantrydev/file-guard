use std::path::PathBuf;

/// Persistent rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

/// A persistent rule: binary X accessing file Y -> allow/deny.
#[derive(Debug, Clone)]
pub struct Rule {
    pub file: PathBuf,
    pub binary: PathBuf,
    pub action: Action,
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
    /// No rule; must prompt the user.
    Unknown,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            Decision::AllowAlways | Decision::AllowSession | Decision::AllowOnce
        )
    }
}
