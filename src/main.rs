mod cli;
mod config;
mod daemon;
mod interceptor;
mod logging;
mod policy;
mod process;
mod prompt;
mod store;

#[cfg(target_os = "macos")]
mod es;

#[cfg(target_os = "linux")]
mod fuse_fs;

use clap::Parser;
use cli::{Cli, Command, RulesAction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Start { daemon: _daemonize } => {
            let config = config::Config::load()?;
            let mut d = daemon::Daemon::new(config)?;
            d.start().await?;

            tracing::info!("file-guard running; Ctrl+C or SIGTERM to stop");
            wait_for_shutdown().await?;

            d.stop().await?;
        }
        Command::Agent { socket, method } => {
            // CLI flag wins; else the config's prompt_method; else GUI.
            let method = method
                .or_else(|| {
                    config::Config::load()
                        .ok()
                        .map(|c| c.settings.prompt_method)
                })
                .unwrap_or(config::PromptMethod::Gui);
            tracing::info!("starting file-guard agent");
            prompt::run_agent(method, socket).await?;
        }
        Command::Stop => {
            // TODO: signal the running daemon via a PID file. Until then, exit
            // non-zero with a message instead of panicking with a backtrace.
            anyhow::bail!(
                "`stop` is not implemented yet (no PID file). \
                 Stop a foreground daemon with Ctrl-C, or `systemctl stop file-guard`."
            );
        }
        Command::Status => {
            anyhow::bail!("`status` is not implemented yet");
        }
        Command::Log => {
            anyhow::bail!("`log` is not implemented yet; logs go to the daemon's stdout/journal");
        }
        Command::Rules { action } => match action {
            None => {
                let config = config::Config::load()?;
                for rule in &config.rule {
                    println!(
                        "{action:>5}  {binary}  →  {file}",
                        action = match rule.action {
                            config::RuleAction::Allow => "allow",
                            config::RuleAction::Deny => "deny",
                        },
                        binary = rule.binary,
                        file = rule.file,
                    );
                }
            }
            Some(RulesAction::Add) => anyhow::bail!(
                "`rules add` is not implemented yet; edit the config file or use an \
                 allow/deny prompt to add rules"
            ),
            Some(RulesAction::Remove) => anyhow::bail!(
                "`rules remove` is not implemented yet; edit the config file directly"
            ),
        },
        Command::Store { file } => {
            let store = store::create_store()?;
            let expanded = config::Config::expand_path(&file.to_string_lossy());
            let contents = std::fs::read(&expanded)?;
            store.store(&expanded, &contents)?;
            println!("stored {}", expanded.display());
        }
        Command::Restore { file } => {
            let store = store::create_store()?;
            let expanded = config::Config::expand_path(&file.to_string_lossy());
            let contents = store.read(&expanded)?;
            std::fs::write(&expanded, contents)?;
            store.delete(&expanded)?;
            println!("restored {}", expanded.display());
        }
    }

    Ok(())
}

/// Block until the daemon is asked to shut down. Handles SIGINT (Ctrl-C) and,
/// on Unix, SIGTERM (what `systemctl stop` / launchd send) so the daemon
/// always runs its unmount path instead of being killed with mounts live.
async fn wait_for_shutdown() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r?,
            _ = term.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}
