use crate::prompt::types::PromptRequest;

/// Send an informational OS notification about a credential access attempt.
/// Does NOT collect a response — informational only.
pub fn notify(req: &PromptRequest) {
    let title = "cred-guard";
    let body = format!(
        "{} wants to read {}",
        req.process.binary_name,
        req.file.display()
    );

    #[cfg(target_os = "macos")]
    notify_macos(title, &body);

    #[cfg(target_os = "linux")]
    notify_linux(title, &body);
}

#[cfg(target_os = "macos")]
fn notify_macos(title: &str, body: &str) {
    let script = format!(
        r#"display notification "{body}" with title "{title}""#,
        body = body.replace('"', r#"\""#),
        title = title.replace('"', r#"\""#),
    );
    let _ = std::process::Command::new("osascript")
        .args(["-e", &script])
        .spawn();
}

#[cfg(target_os = "linux")]
fn notify_linux(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .args([title, body])
        .spawn();
}
