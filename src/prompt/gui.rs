//! Graphical prompt backends. Tries `zenity`, then `kdialog`. Each renders the
//! five choices and prints the selected choice on stdout.
//!
//! All arguments are passed directly as argv (never interpolated into a shell
//! command), so a hostile file path or binary name can't inject.

use std::io;
use std::process::ExitStatus;
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process_group};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use crate::prompt::protocol::AgentRequest;
use crate::prompt::types::UserChoice;

/// Outcome of attempting a GUI prompt.
pub enum GuiResult {
    /// The user picked a choice.
    Choice(UserChoice),
    /// A backend ran but did not yield a usable choice.
    Dismissed,
    /// The GUI backend could not be started.
    Unavailable,
}

struct GuiItem {
    key: &'static str,
    label: &'static str,
    zenity_label: &'static str,
    choice: UserChoice,
}

// Zenity focuses its first extra button, so the first choice must deny.
const ITEMS: &[GuiItem] = &[
    GuiItem {
        key: "deny-once",
        label: "Deny once",
        zenity_label: "_Deny once",
        choice: UserChoice::DenyOnce,
    },
    GuiItem {
        key: "allow-once",
        label: "Allow once",
        zenity_label: "_Allow once",
        choice: UserChoice::AllowOnce,
    },
    GuiItem {
        key: "allow-session",
        label: "Allow this session",
        zenity_label: "Allow this _session",
        choice: UserChoice::AllowSession,
    },
    GuiItem {
        key: "allow-always",
        label: "Always allow this binary",
        zenity_label: "Al_ways allow this binary",
        choice: UserChoice::AllowAlways,
    },
    GuiItem {
        key: "deny-always",
        label: "Always deny this binary",
        zenity_label: "Alwa_ys deny this binary",
        choice: UserChoice::DenyAlways,
    },
];

const TITLE: &str = "file-guard: credential access";
const MAX_STDOUT_BYTES: usize = 16 * 1024;
const BACKSTOP_GRACE: Duration = Duration::from_secs(2);

enum DialogError {
    Spawn(io::Error),
    Runtime(io::Error),
}

enum DialogOutcome {
    Completed(ExitStatus, Vec<u8>),
    TimedOut,
    OutputTooLarge,
}

/// Render a GUI prompt, trying each backend in turn.
pub async fn prompt(req: &AgentRequest, timeout: Duration) -> GuiResult {
    match zenity(req, timeout).await {
        GuiResult::Unavailable => {}
        other => return other,
    }
    kdialog(req, timeout).await
}

fn parse_choice(stdout: &[u8]) -> Option<UserChoice> {
    let output = String::from_utf8_lossy(stdout);
    let output = output.trim();
    ITEMS
        .iter()
        .find_map(|item| (output == item.key || output == item.zenity_label).then_some(item.choice))
}

async fn zenity(req: &AgentRequest, timeout: Duration) -> GuiResult {
    let mut cmd = Command::new("zenity");
    cmd.arg("--question")
        .arg("--switch")
        .arg(format!("--title={TITLE}"))
        .arg(format!("--text={}", req.summary()))
        .arg("--no-markup")
        .arg("--width=560")
        .arg("--height=320")
        .arg(format!("--timeout={}", timeout.as_secs().max(1)));
    for item in ITEMS {
        cmd.arg(format!("--extra-button={}", item.zenity_label));
    }

    interpret_zenity(run_dialog(cmd, timeout).await)
}

async fn kdialog(req: &AgentRequest, timeout: Duration) -> GuiResult {
    let mut cmd = Command::new("kdialog");
    cmd.arg("--title")
        .arg(TITLE)
        .arg("--radiolist")
        .arg(req.summary());
    for (i, item) in ITEMS.iter().enumerate() {
        cmd.arg(item.key);
        cmd.arg(item.label);
        cmd.arg(if i == 0 { "on" } else { "off" });
    }

    interpret("kdialog", run_dialog(cmd, timeout).await)
}

fn interpret_zenity(result: Result<DialogOutcome, DialogError>) -> GuiResult {
    match result {
        Ok(DialogOutcome::Completed(status, stdout)) if status.code() == Some(1) => {
            match parse_choice(&stdout) {
                Some(choice) => GuiResult::Choice(choice),
                None => GuiResult::Dismissed,
            }
        }
        Ok(_) => GuiResult::Dismissed,
        Err(DialogError::Spawn(e)) => {
            tracing::debug!("zenity unavailable: {e}");
            GuiResult::Unavailable
        }
        Err(DialogError::Runtime(e)) => {
            tracing::debug!("zenity failed after launch: {e}");
            GuiResult::Dismissed
        }
    }
}

fn interpret(backend: &str, result: Result<DialogOutcome, DialogError>) -> GuiResult {
    match result {
        Ok(DialogOutcome::Completed(status, stdout)) if status.success() => {
            match parse_choice(&stdout) {
                Some(choice) => GuiResult::Choice(choice),
                None => GuiResult::Dismissed, // OK pressed with no/garbled selection
            }
        }
        Ok(_) => GuiResult::Dismissed,
        Err(DialogError::Spawn(e)) => {
            tracing::debug!("{backend} unavailable: {e}");
            GuiResult::Unavailable
        }
        Err(DialogError::Runtime(e)) => {
            tracing::debug!("{backend} failed after launch: {e}");
            GuiResult::Dismissed
        }
    }
}

async fn read_stdout(stdout: &mut tokio::process::ChildStdout) -> io::Result<DialogOutput> {
    let mut output = Vec::with_capacity(MAX_STDOUT_BYTES);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stdout.read(&mut chunk).await?;
        if read == 0 {
            return Ok(DialogOutput::Complete(output));
        }
        if read > MAX_STDOUT_BYTES - output.len() {
            return Ok(DialogOutput::TooLarge);
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

enum DialogOutput {
    Complete(Vec<u8>),
    TooLarge,
}

struct ProcessGroup(Option<Pid>);

impl ProcessGroup {
    fn new(child: &Child) -> Self {
        let pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(Pid::from_raw);
        Self(pid)
    }

    fn kill(&mut self) {
        if let Some(pid) = self.0.take() {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill();
    }
}

async fn terminate(process_group: &mut ProcessGroup, child: &mut Child) {
    process_group.kill();
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn run_dialog(mut cmd: Command, timeout: Duration) -> Result<DialogOutcome, DialogError> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = cmd.spawn().map_err(DialogError::Spawn)?;
    let mut process_group = ProcessGroup::new(&child);
    let mut stdout = child.stdout.take().expect("piped stdout");

    // Grace beyond the dialog's own timeout so its self-exit wins.
    let backstop = timeout.saturating_add(BACKSTOP_GRACE);
    let result = tokio::time::timeout(backstop, async {
        let mut wait = Box::pin(child.wait());
        let mut output = Box::pin(read_stdout(&mut stdout));
        tokio::select! {
            status = &mut wait => {
                let status = status.map_err(DialogError::Runtime)?;
                match output.await.map_err(DialogError::Runtime)? {
                    DialogOutput::Complete(stdout) => Ok(DialogOutcome::Completed(status, stdout)),
                    DialogOutput::TooLarge => Ok(DialogOutcome::OutputTooLarge),
                }
            }
            output = &mut output => {
                match output.map_err(DialogError::Runtime)? {
                    DialogOutput::Complete(stdout) => {
                        let status = wait.await.map_err(DialogError::Runtime)?;
                        Ok(DialogOutcome::Completed(status, stdout))
                    }
                    DialogOutput::TooLarge => Ok(DialogOutcome::OutputTooLarge),
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(outcome @ DialogOutcome::Completed(_, _))) => {
            process_group.disarm();
            Ok(outcome)
        }
        Ok(Ok(outcome @ DialogOutcome::OutputTooLarge)) => {
            terminate(&mut process_group, &mut child).await;
            Ok(outcome)
        }
        Ok(Ok(DialogOutcome::TimedOut)) => Ok(DialogOutcome::TimedOut),
        Ok(Err(error)) => {
            terminate(&mut process_group, &mut child).await;
            Err(error)
        }
        Err(_) => {
            terminate(&mut process_group, &mut child).await;
            Ok(DialogOutcome::TimedOut)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    #[test]
    fn choices_accept_backend_keys_and_zenity_mnemonics() {
        for item in ITEMS {
            for output in [item.key, item.zenity_label] {
                assert!(matches!(
                    parse_choice(output.as_bytes()),
                    Some(choice) if choice == item.choice
                ));
            }
        }
    }

    #[test]
    fn deny_once_is_the_first_item() {
        assert_eq!(ITEMS[0].key, "deny-once");
        assert_eq!(ITEMS[0].choice, UserChoice::DenyOnce);
        assert_eq!(ITEMS[0].zenity_label, "_Deny once");
    }

    #[test]
    fn zenity_extra_button_is_a_choice_despite_nonzero_status() {
        let result = interpret_zenity(Ok(DialogOutcome::Completed(
            ExitStatus::from_raw(1 << 8),
            b"Allow this _session\n".to_vec(),
        )));

        assert!(matches!(
            result,
            GuiResult::Choice(UserChoice::AllowSession)
        ));
    }

    #[test]
    fn zenity_signaled_output_is_dismissed() {
        let result = interpret_zenity(Ok(DialogOutcome::Completed(
            ExitStatus::from_raw(9),
            b"_Deny once\n".to_vec(),
        )));

        assert!(matches!(result, GuiResult::Dismissed));
    }

    #[test]
    fn zenity_unexpected_exit_empty_and_garbled_results_are_dismissed() {
        for result in [
            interpret_zenity(Ok(DialogOutcome::Completed(
                ExitStatus::from_raw(2 << 8),
                b"_Deny once\n".to_vec(),
            ))),
            interpret_zenity(Ok(DialogOutcome::Completed(
                ExitStatus::from_raw(1 << 8),
                Vec::new(),
            ))),
            interpret_zenity(Ok(DialogOutcome::Completed(
                ExitStatus::from_raw(1 << 8),
                b"unexpected\n".to_vec(),
            ))),
            interpret_zenity(Ok(DialogOutcome::TimedOut)),
        ] {
            assert!(matches!(result, GuiResult::Dismissed));
        }
    }

    #[test]
    fn zenity_spawn_failure_is_unavailable() {
        let result = interpret_zenity(Err(DialogError::Spawn(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "zenity",
        ))));

        assert!(matches!(result, GuiResult::Unavailable));
    }

    #[test]
    fn post_spawn_failure_is_dismissed() {
        let result = interpret_zenity(Err(DialogError::Runtime(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "stdout",
        ))));

        assert!(matches!(result, GuiResult::Dismissed));
    }

    #[test]
    fn kdialog_requires_success() {
        let choice = interpret(
            "kdialog",
            Ok(DialogOutcome::Completed(
                ExitStatus::from_raw(0),
                b"deny-once\n".to_vec(),
            )),
        );
        assert!(matches!(choice, GuiResult::Choice(UserChoice::DenyOnce)));

        let dismissed = interpret(
            "kdialog",
            Ok(DialogOutcome::Completed(
                ExitStatus::from_raw(1 << 8),
                b"deny-once\n".to_vec(),
            )),
        );
        assert!(matches!(dismissed, GuiResult::Dismissed));
    }

    #[tokio::test]
    async fn stdout_overflow_is_rejected_and_terminated() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "head -c 20000 /dev/zero"]);
        let result = tokio::time::timeout(Duration::from_secs(1), run_dialog(cmd, Duration::ZERO))
            .await
            .expect("overflow should terminate promptly");

        assert!(matches!(result, Ok(DialogOutcome::OutputTooLarge)));
    }

    #[tokio::test]
    async fn descendant_holding_stdout_is_killed_at_backstop() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30 & exit 0"]);
        let result = tokio::time::timeout(
            BACKSTOP_GRACE + Duration::from_secs(1),
            run_dialog(cmd, Duration::ZERO),
        )
        .await
        .expect("descendant should not hold the pipe indefinitely");

        assert!(matches!(result, Ok(DialogOutcome::TimedOut)));
    }
}
