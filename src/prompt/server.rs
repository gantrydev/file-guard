//! User-session prompt agent. Listens on a unix socket; for each request from
//! the root daemon it renders one prompt (GUI / terminal / notification) and
//! returns the user's decision. Rendering is serialized so only one dialog is
//! ever live (fixes concurrent-stdin / popup-storm races).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::config::PromptMethod;
use crate::prompt::gui::{self, GuiResult};
use crate::prompt::protocol::{AgentRequest, AgentResponse, PROTOCOL_VERSION, PromptOutcome};
use crate::prompt::types::UserChoice;
use crate::prompt::{notification, terminal};

pub struct PromptServer {
    method: PromptMethod,
    dialog_lock: tokio::sync::Mutex<()>,
}

impl PromptServer {
    pub fn new(method: PromptMethod) -> Self {
        Self {
            method,
            dialog_lock: tokio::sync::Mutex::new(()),
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
        // Only root (the daemon) or our own uid may ask us to prompt.
        let peer = stream.peer_cred()?.uid();
        let our_uid = unsafe { libc::getuid() };
        if peer != 0 && peer != our_uid {
            anyhow::bail!("rejecting prompt request from uid {peer}");
        }

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let req: AgentRequest = serde_json::from_str(line.trim())?;
        if req.v != PROTOCOL_VERSION {
            anyhow::bail!("client protocol version {} != {PROTOCOL_VERSION}", req.v);
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
        let mut bytes = serde_json::to_vec(&resp)?;
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
        write_half.flush().await?;
        Ok(())
    }

    async fn render(&self, req: &AgentRequest) -> PromptOutcome {
        notification::notify(req);
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
            PromptMethod::Notification => {
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
pub async fn run_agent(method: PromptMethod, socket: Option<PathBuf>) -> anyhow::Result<()> {
    let listener = build_listener(socket)?;
    PromptServer::new(method).serve(listener).await
}

fn build_listener(socket: Option<PathBuf>) -> anyhow::Result<UnixListener> {
    if let Some(std_listener) = systemd_listener()? {
        tracing::info!("using systemd socket-activated listener");
        std_listener.set_nonblocking(true)?;
        return Ok(UnixListener::from_std(std_listener)?);
    }

    let path = socket.unwrap_or_else(crate::config::agent_socket_path);
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
