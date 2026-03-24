use crate::process::identify::ProcessInfo;
use std::path::PathBuf;

/// A request to prompt the user about a credential file access.
#[derive(Debug, Clone)]
pub struct PromptRequest {
    pub process: ProcessInfo,
    pub file: PathBuf,
}

/// The user's response to a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserChoice {
    AllowOnce,
    AllowAlways,
    AllowSession,
    DenyOnce,
    DenyAlways,
}
