use crate::config::DefaultAction;
use serde::{Deserialize, Serialize};

/// The user's response to a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserChoice {
    AllowOnce,
    AllowAlways,
    AllowSession,
    DenyOnce,
    DenyAlways,
}

/// The fallback choice when no interactive response arrives (agent timed out,
/// dismissed, or unreachable). This is where `settings.default_action` takes
/// effect — previously hard-coded to deny, so `default_action = "allow"` was
/// silently ignored.
pub fn default_choice(default: DefaultAction) -> UserChoice {
    match default {
        DefaultAction::Allow => UserChoice::AllowOnce,
        DefaultAction::Deny => UserChoice::DenyOnce,
    }
}
