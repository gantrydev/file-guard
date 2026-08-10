//! Wire protocol between the root daemon (client) and the user-session agent
//! (server). One JSON request and one JSON response per connection (NDJSON:
//! each message is a single `\n`-terminated line).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::policy::rule::Access;
use crate::process::identify::ProcessInfo;
use crate::prompt::types::UserChoice;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MESSAGE_BYTES: u64 = 64 * 1024;

pub async fn read_json_line<T, R>(reader: R) -> anyhow::Result<T>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader).take(MAX_MESSAGE_BYTES + 1);
    let mut bytes = Vec::new();
    let read = reader.read_until(b'\n', &mut bytes).await?;
    if read == 0 {
        anyhow::bail!("prompt peer closed without a message");
    }
    if bytes.len() as u64 > MAX_MESSAGE_BYTES {
        anyhow::bail!("prompt message exceeds {MAX_MESSAGE_BYTES} bytes");
    }
    if bytes.last() != Some(&b'\n') {
        anyhow::bail!("prompt message is not newline-terminated");
    }
    bytes.pop();
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn write_json_line<T, W>(mut writer: W, message: &T) -> anyhow::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let mut bytes = serde_json::to_vec(message)?;
    if bytes.len() as u64 + 1 > MAX_MESSAGE_BYTES {
        anyhow::bail!("prompt message exceeds {MAX_MESSAGE_BYTES} bytes");
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

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
            code_signature: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn framed_json_round_trips() {
        let (reader, mut writer) = tokio::io::duplex(1024);
        let response = AgentResponse {
            v: PROTOCOL_VERSION,
            id: 42,
            outcome: PromptOutcome::NoResponse,
        };
        write_json_line(&mut writer, &response).await.unwrap();
        let decoded: AgentResponse = read_json_line(reader).await.unwrap();
        assert_eq!(decoded.v, PROTOCOL_VERSION);
        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.outcome, PromptOutcome::NoResponse);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_without_unbounded_buffering() {
        let (reader, mut writer) = tokio::io::duplex(MAX_MESSAGE_BYTES as usize + 2);
        let task = tokio::spawn(async move {
            let mut bytes = vec![b'x'; MAX_MESSAGE_BYTES as usize + 1];
            bytes.push(b'\n');
            writer.write_all(&bytes).await.unwrap();
        });
        let error = read_json_line::<AgentRequest, _>(reader).await.unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn unterminated_frame_is_rejected() {
        let (reader, mut writer) = tokio::io::duplex(1024);
        writer.write_all(b"{}").await.unwrap();
        writer.shutdown().await.unwrap();
        let error = read_json_line::<AgentRequest, _>(reader).await.unwrap_err();
        assert!(error.to_string().contains("newline-terminated"));
    }
}
