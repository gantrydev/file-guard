use crate::prompt::types::{PromptRequest, UserChoice};

/// Render an interactive TUI prompt using ratatui/crossterm.
/// Blocks until the user selects a choice.
pub async fn prompt(req: &PromptRequest) -> UserChoice {
    // TODO: Full ratatui TUI implementation.
    // For now, use a simple stdin/stdout prompt as a working placeholder.

    let parent_chain: String = req
        .process
        .parent_chain
        .iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(" ← ");

    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!("║  cred-guard: credential access request              ║");
    eprintln!("╠══════════════════════════════════════════════════════╣");
    eprintln!(
        "║  Process: {} (pid {})",
        req.process.binary_name, req.process.pid
    );
    eprintln!("║  Binary:  {}", req.process.binary_path.display());
    if !parent_chain.is_empty() {
        eprintln!("║  Chain:   {parent_chain}");
    }
    if let Some(ref sig) = req.process.code_signature {
        eprintln!("║  Signed:  {sig}");
    }
    eprintln!("║  File:    {}", req.file.display());
    eprintln!("╠══════════════════════════════════════════════════════╣");
    eprintln!("║  [1] Allow once                                     ║");
    eprintln!("║  [2] Allow always                                   ║");
    eprintln!("║  [3] Allow this session                             ║");
    eprintln!("║  [4] Deny once                                      ║");
    eprintln!("║  [5] Deny always                                    ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprint!("Choice [1-5]: ");

    let choice = tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        input.trim().to_string()
    })
    .await
    .unwrap_or_default();

    match choice.as_str() {
        "1" => UserChoice::AllowOnce,
        "2" => UserChoice::AllowAlways,
        "3" => UserChoice::AllowSession,
        "4" => UserChoice::DenyOnce,
        "5" => UserChoice::DenyAlways,
        _ => UserChoice::DenyOnce,
    }
}
