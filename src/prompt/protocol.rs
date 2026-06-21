//! Wire protocol between the root daemon (client) and the user-session agent
//! (server). One JSON request and one JSON response per connection (NDJSON:
//! each message is a single `\n`-terminated line).

use serde::{Deserialize, Serialize};

use crate::policy::rule::Access;
use crate::process::identify::ProcessInfo;
use crate::prompt::types::UserChoice;

pub const PROTOCOL_VERSION: u32 = 1;

/// Daemon → agent: "this process wants to read/write this file - ask the user".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub v: u32,
    pub id: u64,
    pub access: Access,
    pub file: String,
    pub process: ProcessDesc,
    pub timeout_ms: u64,
}

/// Agent → daemon: the outcome of rendering the prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub v: u32,
    pub id: u64,
    pub outcome: PromptOutcome,
}

/// What the agent learned from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptOutcome {
    /// The user made an explicit choice.
    Decided(UserChoice),
    /// No usable response (timed out, dismissed, or no backend) - the daemon
    /// applies its `default_action`.
    NoResponse,
}

/// A serializable snapshot of the calling process for display in the prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDesc {
    pub pid: u32,
    pub binary_path: String,
    pub binary_name: String,
    pub script: Option<String>,
    pub code_signature: Option<String>,
    pub parents: Vec<ParentDesc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentDesc {
    pub pid: u32,
    pub name: String,
    pub binary_path: Option<String>,
}

impl From<&ProcessInfo> for ProcessDesc {
    fn from(info: &ProcessInfo) -> Self {
        Self {
            pid: info.pid,
            binary_path: info.binary_path.to_string_lossy().into_owned(),
            binary_name: info.binary_name.clone(),
            script: info
                .script
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            code_signature: info.code_signature.clone(),
            parents: info
                .parent_chain
                .iter()
                .map(|p| ParentDesc {
                    pid: p.pid,
                    name: p.name.clone(),
                    binary_path: p
                        .binary_path
                        .as_ref()
                        .map(|b| b.to_string_lossy().into_owned()),
                })
                .collect(),
        }
    }
}

impl AgentRequest {
    /// One-line human summary, e.g. `aws (pid 1234) wants to WRITE /home/...`.
    /// For an interpreter, the script it is running is appended on a new line.
    pub fn summary(&self) -> String {
        let head = format!(
            "{} (pid {}) wants to {} {}",
            self.process.binary_name,
            self.process.pid,
            self.access.verb().to_uppercase(),
            self.file,
        );
        match &self.process.script {
            Some(script) => format!("{head}\n\nvia script: {script}"),
            None => head,
        }
    }
}
