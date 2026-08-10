mod cli;
mod config;
mod control;
mod daemon;
mod interceptor;
mod logging;
mod policy;
mod process;
mod prompt;
mod secure_file;
mod store;
#[cfg(test)]
mod testing;
mod transaction;

#[cfg(target_os = "linux")]
mod fuse_fs;

use clap::Parser;
use cli::{Cli, Command, RuleAction, RulesAction};

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
            // Apply declarative seed changes (settings + watches) before load,
            // preserving learned rules; no-op unless FILE_GUARD_SEED_CONFIG set.
            config::Config::reconcile_seed()?;
            let config = config::Config::load()?;
            let mut d = daemon::Daemon::new(config)?;
            d.start().await?;

            tracing::info!("file-guard running; Ctrl+C or SIGTERM to stop");
            wait_for_shutdown().await?;

            d.stop().await?;
        }
        Command::Agent {
            socket,
            method,
            notify,
        } => {
            // CLI flag wins; else the config's prompt_method; else GUI.
            let config = config::Config::load().ok();
            let method = method
                .or_else(|| config.as_ref().map(|c| c.settings.prompt_method))
                .unwrap_or(config::PromptMethod::Gui);
            let notify = notify || config.as_ref().map(|c| c.settings.notify).unwrap_or(false);
            tracing::info!("starting file-guard agent");
            prompt::run_agent(method, notify, socket).await?;
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
                if config::Config::append_rule(&entry)? {
                    println!("added rule: {} → {}", binary.display(), file);
                } else {
                    println!("rule already exists: {} → {}", binary.display(), file);
                }
            }
            Some(RulesAction::Remove { index }) => {
                let (binary, file) = config::Config::remove_rule_at(index)?;
                println!("removed rule {index}: {binary} → {file}");
            }
            Some(RulesAction::Edit {
                index,
                action,
                access,
                repin,
                no_pin,
            }) => {
                let (binary, file) = config::Config::edit_rule_at(
                    index,
                    action.map(|a| match a {
                        RuleAction::Allow => config::RuleAction::Allow,
                        RuleAction::Deny => config::RuleAction::Deny,
                    }),
                    access,
                    repin,
                    no_pin,
                )?;
                println!("edited rule {index}: {binary} → {file}");
            }
            Some(RulesAction::Find {
                file,
                binary,
                action,
            }) => {
                let config = config::Config::load()?;
                for (i, rule) in config.rule.iter().enumerate() {
                    let matches_file = file.as_ref().is_none_or(|f| rule.file.contains(f));
                    let matches_binary = binary.as_ref().is_none_or(|b| rule.binary.contains(b));
                    let matches_action = action.is_none_or(|a| {
                        let want = match a {
                            RuleAction::Allow => config::RuleAction::Allow,
                            RuleAction::Deny => config::RuleAction::Deny,
                        };
                        rule.action == want
                    });
                    if matches_file && matches_binary && matches_action {
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
            }
            Some(RulesAction::Export) => {
                let rules_toml = config::Config::export_rules()?;
                if rules_toml.is_empty() {
                    println!("# no rules configured");
                } else {
                    print!("{rules_toml}");
                }
            }
            Some(RulesAction::Import) => {
                use std::io::Read;
                let mut stdin = String::new();
                std::io::stdin()
                    .read_to_string(&mut stdin)
                    .map_err(|e| anyhow::anyhow!("reading stdin: {e}"))?;
                let added = config::Config::import_rules(&stdin)?;
                println!("imported {added} rule(s)");
            }
        },
        Command::Store { file } => {
            let expanded = config::Config::expand_path(&file.to_string_lossy());

            // A live mount means the daemon already guards this path (it
            // captured the original itself); storing again and removing the
            // mountpoint would fight the daemon.
            if control::is_fuse_mount(&expanded) {
                anyhow::bail!(
                    "{} is already guarded by a live file-guard mount; nothing to store.",
                    expanded.display()
                );
            }

            let store: std::sync::Arc<dyn store::BackingStore> =
                std::sync::Arc::from(store::create_store()?);
            transaction::TransactionManager::new(store).store_offline(&expanded)?;
            println!("moved {} into the backing store", expanded.display());
        }
        Command::Restore { file } => {
            let expanded = config::Config::expand_path(&file.to_string_lossy());

            // A live mount means the daemon still owns this path; writing under
            // it fights the daemon and is overwritten when it stops (with
            // restore_on_stop). Stop the daemon instead, which restores it.
            if control::is_fuse_mount(&expanded) {
                anyhow::bail!(
                    "{} is a live file-guard mount; stop the daemon to recover it \
                     (`systemctl stop file-guard` writes it back when restore_on_stop \
                     is set) rather than restoring underneath the mount.",
                    expanded.display()
                );
            }

            let store: std::sync::Arc<dyn store::BackingStore> =
                std::sync::Arc::from(store::create_store()?);
            let manager = transaction::TransactionManager::new(store);
            match manager.restore(&expanded)? {
                transaction::RestoreOutcome::Restored => {
                    println!("restored {}", expanded.display());
                }
                transaction::RestoreOutcome::Missing
                    if std::fs::symlink_metadata(&expanded).is_ok() =>
                {
                    println!(
                        "{} is already on disk; nothing to restore.",
                        expanded.display()
                    );
                }
                transaction::RestoreOutcome::Missing => anyhow::bail!(
                    "no v2 snapshot for {} and no file on disk",
                    expanded.display()
                ),
            }
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
