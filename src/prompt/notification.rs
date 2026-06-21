use crate::prompt::protocol::AgentRequest;

/// Send an informational OS notification about a credential access attempt.
/// Fired from the agent (the user's session), so it reaches the user's display
/// rather than root's nonexistent one. Informational only - does not collect a
/// response.
pub fn notify(req: &AgentRequest) {
    let title = "file-guard";
    let body = req.summary();

    #[cfg(target_os = "macos")]
    notify_macos(title, &body);

    #[cfg(target_os = "linux")]
    notify_linux(title, &body);
}

#[cfg(target_os = "macos")]
fn notify_macos(title: &str, body: &str) {
    // argv only - never interpolate `body`/`title` into the AppleScript source.
    let script = r#"on run argv
    display notification (item 1 of argv) with title (item 2 of argv)
end run"#;
    let _ = std::process::Command::new("osascript")
        .args(["-e", script, body, title])
        .spawn();
}

#[cfg(target_os = "linux")]
fn notify_linux(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .args([title, body])
        .spawn();
}
