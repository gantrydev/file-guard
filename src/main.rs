mod cli;
mod config;
mod daemon;
mod es;
mod logging;
mod policy;
mod process;
mod prompt;
mod store;

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

            tracing::info!("cred-guard running, press Ctrl+C to stop");
            tokio::signal::ctrl_c().await?;

            d.stop().await?;
        }
        Command::Stop => {
            // TODO: Send signal to running daemon via PID file
            todo!("stop command: signal running daemon")
        }
        Command::Status => {
            // TODO: Read daemon state and display mount info
            todo!("status command")
        }
        Command::Log => {
            // TODO: Tail the access log file
            todo!("log command")
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
            Some(RulesAction::Add) => todo!("interactive rule add"),
            Some(RulesAction::Remove) => todo!("rule remove"),
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
