//! Daemon-side prompt client. Connects to the user-session agent over a unix
//! socket and asks it to render a prompt. Any failure (agent unreachable,
//! protocol error, no response) falls back to `default_action` - the daemon
//! never blocks indefinitely on a missing agent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::config::DefaultAction;
use crate::policy::rule::Access;
use crate::process::identify::ProcessInfo;
use crate::prompt::protocol::{
    AgentRequest, AgentResponse, PROTOCOL_VERSION, ParentDesc, ProcessDesc, PromptOutcome,
};
use crate::prompt::types::{UserChoice, default_choice};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct PromptClient {
    socket_path: PathBuf,
    timeout: Duration,
    /// uid the agent is expected to run as (the guarded user). A peer with any
    /// other uid is rejected - defense in depth on top of the root-owned socket
    /// directory.
    expected_uid: u32,
}

impl PromptClient {
    pub fn new(socket_path: PathBuf, timeout: Duration, expected_uid: u32) -> Self {
        Self {
            socket_path,
            timeout,
            expected_uid,
        }
    }

    /// Ask the agent for a decision, falling back to `default_action` (resolved
    /// per watched file by the caller) when the agent doesn't decide.
    pub async fn prompt(
        &self,
        process: &ProcessInfo,
        file: &Path,
        access: Access,
        default_action: DefaultAction,
    ) -> UserChoice {
        match self.request(process, file, access).await {
            Ok(PromptOutcome::Decided(choice)) => choice,
            Ok(PromptOutcome::NoResponse) => {
                tracing::info!("agent returned no decision; applying default_action");
                default_choice(default_action)
            }
            Err(e) => {
                tracing::warn!(
                    "prompt agent at {} unreachable ({e}); applying default_action",
                    self.socket_path.display()
                );
                default_choice(default_action)
            }
        }
    }

    async fn request(
        &self,
        process: &ProcessInfo,
        file: &Path,
        access: Access,
    ) -> anyhow::Result<PromptOutcome> {
        // Fill the parent chain here, on the (rare) prompt path only: it scans
        // the process table and `identify` deliberately skips it on every open.
        // The scan is synchronous/blocking, so offload it like `decide_open`
        // does for `identify` rather than stalling an async worker.
        let pid = process.pid;
        let parents =
            tokio::task::spawn_blocking(move || crate::process::identify::parent_chain(pid))
                .await
                .unwrap_or_default();

        let mut process_desc = ProcessDesc::from(process);
        process_desc.parents = parents
            .into_iter()
            .map(|p| ParentDesc {
                pid: p.pid,
                name: p.name,
                binary_path: p.binary_path.map(|b| b.to_string_lossy().into_owned()),
            })
            .collect();

        let req = AgentRequest {
            v: PROTOCOL_VERSION,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            access,
            file: file.to_string_lossy().into_owned(),
            process: process_desc,
            timeout_ms: self.timeout.as_millis() as u64,
        };

        let exchange = async {
            let stream = UnixStream::connect(&self.socket_path).await?;

            // Verify the agent is the guarded user (or root), not some other
            // account that managed to occupy the socket path.
            let cred = stream.peer_cred()?;
            let peer_uid = cred.uid();
            if peer_uid != self.expected_uid && peer_uid != 0 {
                anyhow::bail!(
                    "agent peer uid {peer_uid} != expected {} - refusing",
                    self.expected_uid
                );
            }

            let (read_half, mut write_half) = stream.into_split();
            let mut line = serde_json::to_vec(&req)?;
            line.push(b'\n');
            write_half.write_all(&line).await?;
            write_half.flush().await?;

            let mut reader = BufReader::new(read_half);
            let mut buf = String::new();
            reader.read_line(&mut buf).await?;
            if buf.is_empty() {
                anyhow::bail!("agent closed connection without responding");
            }
            let resp: AgentResponse = serde_json::from_str(buf.trim())?;
            if resp.v != PROTOCOL_VERSION {
                anyhow::bail!("agent protocol version {} != {PROTOCOL_VERSION}", resp.v);
            }
            if resp.id != req.id {
                anyhow::bail!("agent response id {} != request id {}", resp.id, req.id);
            }
            Ok(resp.outcome)
        };

        // Hard upper bound: the agent renders for up to `timeout`; allow a small
        // grace so its own timeout wins over ours, then give up.
        let hard = self.timeout + Duration::from_secs(5);
        match tokio::time::timeout(hard, exchange).await {
            Ok(result) => result,
            Err(_) => Ok(PromptOutcome::NoResponse),
        }
    }
}
