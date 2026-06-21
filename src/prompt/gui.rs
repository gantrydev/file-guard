//! Graphical prompt backends. Tries `zenity`, then `kdialog`. Each renders a
//! radio list of the five choices and prints a machine key on stdout.
//!
//! All arguments are passed as argv (never interpolated into a shell or an
//! AppleScript string), so a hostile file path or binary name can't inject.

use std::process::ExitStatus;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::prompt::protocol::AgentRequest;
use crate::prompt::types::UserChoice;

/// Outcome of attempting a GUI prompt.
pub enum GuiResult {
    /// The user picked a choice.
    Choice(UserChoice),
    /// A backend ran but the user cancelled or it timed out.
    Dismissed,
    /// No GUI backend is available (none installed / no display).
    Unavailable,
}

const ITEMS: &[(&str, &str)] = &[
    ("allow-once", "Allow once"),
    ("allow-session", "Allow this session"),
    ("allow-always", "Allow always (remember this binary)"),
    ("deny-once", "Deny once"),
    ("deny-always", "Deny always (remember this binary)"),
];

const TITLE: &str = "file-guard: credential access";

/// Render a GUI prompt, trying each backend in turn.
pub async fn prompt(req: &AgentRequest, timeout: Duration) -> GuiResult {
    match zenity(req, timeout).await {
        GuiResult::Unavailable => {}
        other => return other,
    }
    kdialog(req, timeout).await
}

fn parse_choice(stdout: &[u8]) -> Option<UserChoice> {
    let key = String::from_utf8_lossy(stdout);
    match key.trim() {
        "allow-once" => Some(UserChoice::AllowOnce),
        "allow-session" => Some(UserChoice::AllowSession),
        "allow-always" => Some(UserChoice::AllowAlways),
        "deny-once" => Some(UserChoice::DenyOnce),
        "deny-always" => Some(UserChoice::DenyAlways),
        _ => None,
    }
}

async fn zenity(req: &AgentRequest, timeout: Duration) -> GuiResult {
    let mut cmd = Command::new("zenity");
    cmd.arg("--list")
        .arg("--radiolist")
        .arg(format!("--title={TITLE}"))
        .arg(format!("--text={}", req.summary()))
        .arg("--width=560")
        .arg("--height=320")
        .arg(format!("--timeout={}", timeout.as_secs().max(1)))
        .arg("--column=") // radio boolean column (no header)
        .arg("--column=Choice")
        .arg("--column=key")
        .arg("--hide-column=3")
        .arg("--print-column=3");
    for (i, (key, label)) in ITEMS.iter().enumerate() {
        cmd.arg(if i == 0 { "TRUE" } else { "FALSE" });
        cmd.arg(label);
        cmd.arg(key);
    }

    interpret("zenity", run_dialog(cmd, timeout).await)
}

async fn kdialog(req: &AgentRequest, timeout: Duration) -> GuiResult {
    let mut cmd = Command::new("kdialog");
    cmd.arg("--title")
        .arg(TITLE)
        .arg("--radiolist")
        .arg(req.summary());
    for (i, (key, label)) in ITEMS.iter().enumerate() {
        cmd.arg(key);
        cmd.arg(label);
        cmd.arg(if i == 0 { "on" } else { "off" });
    }

    interpret("kdialog", run_dialog(cmd, timeout).await)
}

fn interpret(backend: &str, result: std::io::Result<Option<(ExitStatus, Vec<u8>)>>) -> GuiResult {
    match result {
        Ok(Some((status, stdout))) if status.success() => match parse_choice(&stdout) {
            Some(choice) => GuiResult::Choice(choice),
            None => GuiResult::Dismissed, // OK pressed with no/garbled selection
        },
        // Non-zero exit: cancel (1) or zenity timeout (5) → dismissed.
        Ok(Some(_)) => GuiResult::Dismissed,
        // Killed by our own backstop timeout.
        Ok(None) => GuiResult::Dismissed,
        // Couldn't even launch it → treat as not available, try the next.
        Err(e) => {
            tracing::debug!("{backend} unavailable: {e}");
            GuiResult::Unavailable
        }
    }
}

/// Spawn a dialog, capturing stdout. Returns `Ok(None)` if it outran `timeout`
/// (the child is killed), `Err` if it couldn't be spawned at all.
async fn run_dialog(
    mut cmd: Command,
    timeout: Duration,
) -> std::io::Result<Option<(ExitStatus, Vec<u8>)>> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn()?;
    let mut stdout = child.stdout.take().expect("piped stdout");

    // Grace beyond the dialog's own timeout so its self-exit wins.
    let backstop = timeout + Duration::from_secs(2);
    let status = match tokio::time::timeout(backstop, child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Ok(None);
        }
    };

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).await?;
    Ok(Some((status, buf)))
}
