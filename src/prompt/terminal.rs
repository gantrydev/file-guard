use crate::prompt::protocol::AgentRequest;
use crate::prompt::types::UserChoice;

/// Render an interactive terminal prompt on the agent's stdin/stderr. Blocks
/// until the user selects a choice; on EOF (no attached tty) returns `None`.
pub async fn prompt(req: &AgentRequest) -> Option<UserChoice> {
    let parent_chain: String = req
        .process
        .parents
        .iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(" ← ");

    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!("║  file-guard: credential access request               ║");
    eprintln!("╠══════════════════════════════════════════════════════╣");
    eprintln!("║  Action:  {}", req.access.verb().to_uppercase());
    eprintln!(
        "║  Process: {} (pid {})",
        req.process.binary_name, req.process.pid
    );
    eprintln!("║  Binary:  {}", req.process.binary_path);
    if let Some(ref script) = req.process.script {
        eprintln!("║  Script:  {script}");
    }
    if !parent_chain.is_empty() {
        eprintln!("║  Chain:   {parent_chain}");
    }
    if let Some(ref sig) = req.process.code_signature {
        eprintln!("║  Signed:  {sig}");
    }
    eprintln!("║  File:    {}", req.file);
    eprintln!("╠══════════════════════════════════════════════════════╣");
    eprintln!("║  [1] Allow once                                      ║");
    eprintln!("║  [2] Allow always                                    ║");
    eprintln!("║  [3] Allow this session                              ║");
    eprintln!("║  [4] Deny once                                       ║");
    eprintln!("║  [5] Deny always                                     ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprint!("Choice [1-5]: ");

    let line = tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        let n = std::io::stdin().read_line(&mut input).ok()?;
        if n == 0 {
            return None; // EOF: no tty attached
        }
        Some(input.trim().to_string())
    })
    .await
    .ok()
    .flatten()?;

    match line.as_str() {
        "1" => Some(UserChoice::AllowOnce),
        "2" => Some(UserChoice::AllowAlways),
        "3" => Some(UserChoice::AllowSession),
        "4" => Some(UserChoice::DenyOnce),
        "5" => Some(UserChoice::DenyAlways),
        _ => Some(UserChoice::DenyOnce),
    }
}
