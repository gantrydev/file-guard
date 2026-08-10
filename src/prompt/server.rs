//! User-session prompt agent. Listens on a unix socket; for each request from
//! the root daemon it renders one prompt (GUI / terminal / notification) and
//! returns the user's decision. Rendering is serialized so only one dialog is
//! ever live (fixes concurrent-stdin / popup-storm races).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{UnixListener, UnixStream};

use crate::config::PromptMethod;
use crate::prompt::gui::{self, GuiResult};
use crate::prompt::protocol::{
    AgentRequest, AgentResponse, PROTOCOL_VERSION, PromptOutcome, read_json_line, write_json_line,
};
use crate::prompt::types::UserChoice;
use crate::prompt::{notification, terminal};

struct RateLimiter {
    max_per_window: usize,
    window: Duration,
    timestamps: tokio::sync::Mutex<VecDeque<Instant>>,
}

impl RateLimiter {
    fn new(max_per_window: usize, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            timestamps: tokio::sync::Mutex::new(VecDeque::new()),
        }
    }

    async fn allow(&self) -> bool {
        let mut timestamps = self.timestamps.lock().await;
        let now = Instant::now();
        let cutoff = now - self.window;
        while timestamps
            .front()
            .is_some_and(|timestamp| *timestamp <= cutoff)
        {
            timestamps.pop_front();
        }
        if timestamps.len() >= self.max_per_window {
            return false;
        }
        timestamps.push_back(now);
        true
    }
}

pub struct PromptServer {
    method: PromptMethod,
    notify: bool,
    dialog_lock: tokio::sync::Mutex<()>,
    rate_limiter: RateLimiter,
}

impl PromptServer {
    pub fn new(method: PromptMethod, notify: bool) -> Self {
        Self {
            method,
            notify,
            dialog_lock: tokio::sync::Mutex::new(()),
            rate_limiter: RateLimiter::new(10, Duration::from_secs(60)),
        }
    }

    pub async fn serve(self, listener: UnixListener) -> anyhow::Result<()> {
        let server = Arc::new(self);
        tracing::info!("file-guard agent ready (method: {:?})", server.method);
        loop {
            let (stream, _addr) = listener.accept().await?;
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                if let Err(e) = server.handle_conn(stream).await {
                    tracing::warn!("agent connection error: {e}");
                }
            });
        }
    }

    async fn handle_conn(&self, stream: UnixStream) -> anyhow::Result<()> {
        let peer = stream.peer_cred()?.uid();
        let our_uid = unsafe { libc::getuid() };
        if peer != 0 && peer != our_uid {
            anyhow::bail!("rejecting prompt request from uid {peer}");
        }

        let (read_half, mut write_half) = stream.into_split();
        let req: AgentRequest =
            tokio::time::timeout(Duration::from_secs(5), read_json_line(read_half))
                .await
                .map_err(|_| anyhow::anyhow!("timed out reading prompt request"))??;
        if req.v != PROTOCOL_VERSION {
            anyhow::bail!("client protocol version {} != {PROTOCOL_VERSION}", req.v);
        }

        if !self.rate_limiter.allow().await {
            tracing::warn!("prompt rate limit exceeded; returning no response");
            return write_json_line(
                &mut write_half,
                &AgentResponse {
                    v: PROTOCOL_VERSION,
                    id: req.id,
                    outcome: PromptOutcome::NoResponse,
                },
            )
            .await;
        }

        let outcome = {
            let _guard = self.dialog_lock.lock().await;
            self.render(&req).await
        };

        let resp = AgentResponse {
            v: PROTOCOL_VERSION,
            id: req.id,
            outcome,
        };
        write_json_line(&mut write_half, &resp).await
    }

    async fn render(&self, req: &AgentRequest) -> PromptOutcome {
        if self.notify {
            notification::notify(req);
        }
        let timeout = Duration::from_millis(req.timeout_ms.max(1));

        match self.method {
            PromptMethod::Terminal => decided_or_none(terminal_prompt(req, timeout).await),
            PromptMethod::Gui => match gui::prompt(req, timeout).await {
                GuiResult::Choice(c) => PromptOutcome::Decided(c),
                GuiResult::Dismissed => PromptOutcome::NoResponse,
                GuiResult::Unavailable => {
                    tracing::warn!("no GUI backend available; falling back to terminal");
                    decided_or_none(terminal_prompt(req, timeout).await)
                }
            },
            PromptMethod::LogOnly => {
                tokio::time::sleep(timeout).await;
                PromptOutcome::NoResponse
            }
        }
    }
}

async fn terminal_prompt(req: &AgentRequest, timeout: Duration) -> Option<UserChoice> {
    tokio::time::timeout(timeout, terminal::prompt(req))
        .await
        .ok()
        .flatten()
}

fn decided_or_none(choice: Option<UserChoice>) -> PromptOutcome {
    match choice {
        Some(c) => PromptOutcome::Decided(c),
        None => PromptOutcome::NoResponse,
    }
}

/// Build the listener and run the agent until terminated.
pub async fn run_agent(
    method: PromptMethod,
    notify: bool,
    socket: Option<PathBuf>,
) -> anyhow::Result<()> {
    let listener = build_listener(socket)?;
    PromptServer::new(method, notify).serve(listener).await
}

fn build_listener(socket: Option<PathBuf>) -> anyhow::Result<UnixListener> {
    if let Some(std_listener) = systemd_listener()? {
        tracing::info!("using systemd socket-activated listener");
        std_listener.set_nonblocking(true)?;
        return Ok(UnixListener::from_std(std_listener)?);
    }

    let path = match socket {
        Some(path) => path,
        None => crate::config::agent_socket_path()?,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| anyhow::anyhow!("removing stale socket {}: {e}", path.display()))?;
    }
    let listener = UnixListener::bind(&path)
        .map_err(|e| anyhow::anyhow!("binding agent socket {}: {e}", path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::warn!(
        "agent self-bound at {} - dev mode; NOT hardened against same-uid \
         impersonation. Use systemd socket activation in production.",
        path.display()
    );
    Ok(listener)
}

/// Pick up a systemd socket-activated listener (`LISTEN_FDS`), if one was passed
/// to us. The root system socket unit owns the listening fd, so the socket name
/// can't be hijacked by same-uid malware.
fn systemd_listener() -> anyhow::Result<Option<std::os::unix::net::UnixListener>> {
    use std::os::unix::io::FromRawFd;

    let Ok(listen_pid) = std::env::var("LISTEN_PID") else {
        return Ok(None);
    };
    if listen_pid.parse::<u32>().ok() != Some(std::process::id()) {
        return Ok(None);
    }
    let count: i32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if count < 1 {
        return Ok(None);
    }

    // SD_LISTEN_FDS_START - systemd passes the first listener as fd 3.
    const SD_LISTEN_FDS_START: i32 = 3;
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(SD_LISTEN_FDS_START) };
    Ok(Some(listener))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::rule::Access;
    use crate::prompt::protocol::ProcessDesc;

    fn request(version: u32) -> AgentRequest {
        AgentRequest {
            v: version,
            id: 7,
            access: Access::Read,
            file: "/credential".into(),
            process: ProcessDesc {
                pid: 1,
                binary_path: "/usr/bin/tool".into(),
                binary_name: "tool".into(),
                script: None,
                code_signature: None,
                parents: Vec::new(),
            },
            timeout_ms: 60_000,
        }
    }

    #[tokio::test]
    async fn protocol_version_mismatch_returns_a_clear_error() {
        let server = PromptServer::new(PromptMethod::LogOnly, false);
        let (client, server_stream) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move { server.handle_conn(server_stream).await });
        let (_, mut write_half) = client.into_split();
        write_json_line(&mut write_half, &request(PROTOCOL_VERSION + 1))
            .await
            .unwrap();

        let error = task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("protocol version"));
    }

    #[tokio::test]
    async fn rate_limit_returns_no_response_without_rendering() {
        let server = PromptServer {
            method: PromptMethod::LogOnly,
            notify: false,
            dialog_lock: tokio::sync::Mutex::new(()),
            rate_limiter: RateLimiter::new(0, Duration::from_secs(60)),
        };
        let (client, server_stream) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move { server.handle_conn(server_stream).await });
        let (read_half, mut write_half) = client.into_split();
        write_json_line(&mut write_half, &request(PROTOCOL_VERSION))
            .await
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_millis(100),
            read_json_line::<AgentResponse, _>(read_half),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(response.id, 7);
        assert_eq!(response.outcome, PromptOutcome::NoResponse);
        task.await.unwrap().unwrap();
    }
}
