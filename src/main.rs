mod cli;
mod config;
mod control;
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
    // Restore default SIGPIPE so piping output into `head`/`grep` exits quietly
    // instead of panicking on EPIPE (Rust ignores SIGPIPE by default).
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

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
            control::stop()?;
        }
        Command::Status => {
            let config = config::Config::load()?;
            control::status(&config)?;
        }
        Command::Log { lines, follow } => {
            let config = config::Config::load()?;
            control::tail_log(&config, lines, follow)?;
        }
        Command::Rules { action } => match action {
            None => {
                let config = config::Config::load()?;
                for (i, rule) in config.rule.iter().enumerate() {
                    let pinned = if rule.sha256.is_some() || rule.script_sha256.is_some() {
                        " (pinned)"
                    } else {
                        ""
                    };
                    println!(
                        "{i:>3}  {action:>5} {access:<6} {binary}  →  {file}{pinned}",
                        action = match rule.action {
                            config::RuleAction::Allow => "allow",
                            config::RuleAction::Deny => "deny",
                        },
                        access = rule.access.verb(),
                        binary = rule.binary,
                        file = rule.file,
                    );
                }
            }
            Some(RulesAction::Add {
                file,
                binary,
                action,
                access,
                no_pin,
            }) => {
                let sha256 = if no_pin {
                    None
                } else {
                    match process::integrity::hash_file(&binary) {
                        Ok(h) => Some(h),
                        Err(e) => anyhow::bail!(
                            "cannot hash {} to pin the rule ({e}); pass --no-pin to add it unpinned",
                            binary.display()
                        ),
                    }
                };
                let entry = config::RuleEntry {
                    file: file.clone(),
                    binary: binary.to_string_lossy().into_owned(),
                    action: match action {
                        cli::RuleAction::Allow => config::RuleAction::Allow,
                        cli::RuleAction::Deny => config::RuleAction::Deny,
                    },
                    access,
                    sha256,
                    signature: None,
                    script: None,
                    script_sha256: None,
                };
                config::Config::append_rule(&entry)?;
                println!("added rule: {} → {}", binary.display(), file);
            }
            Some(RulesAction::Remove { index }) => {
                let (binary, file) = config::Config::remove_rule_at(index)?;
                println!("removed rule {index}: {binary} → {file}");
            }
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
