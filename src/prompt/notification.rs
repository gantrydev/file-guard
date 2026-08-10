use crate::prompt::protocol::AgentRequest;

/// Send an informational OS notification about a credential access attempt.
/// Fired from the agent (the user's session), so it reaches the user's display
/// rather than root's nonexistent one. Informational only - does not collect a
/// response.
pub fn notify(req: &AgentRequest) {
    let title = "file-guard";
    let body = req.summary();

    #[cfg(target_os = "linux")]
    notify_linux(title, &body);
}

#[cfg(target_os = "linux")]
fn notify_linux(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .args([title, body])
        .spawn();
}
