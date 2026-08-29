use crate::cli::{Command, RuleAction, RulesAction};
use crate::control_api::{ControlCommand, ControlPayload};
use crate::policy::engine::{ManagedRule, RulePinUpdate};

pub(super) async fn execute(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Start { daemon: _daemonize } => {
            let database_path = crate::rule_store::rule_store_path()?;
            let rule_lease = std::sync::Arc::new(
                crate::rule_store::RuleLease::try_acquire(database_path)?.ok_or_else(|| {
                    anyhow::anyhow!("another learned-rule owner is already active")
                })?,
            );
            crate::config::Config::reconcile_seed(|previous, declarative| {
                migrate_legacy_rules(&rule_lease, previous, declarative)
            })?;
            let config = crate::config::Config::load()?;
            let mut d = crate::daemon::Daemon::new(config, rule_lease)?;
            d.start().await?;

            tracing::info!(target: "file_guard", "file-guard running; Ctrl+C or SIGTERM to stop");
            wait_for_shutdown().await?;

            d.stop().await?;
        }
        Command::Agent {
            socket,
            method,
            notify,
        } => {
            // CLI flag wins; else the config's prompt_method; else GUI.
            let config = crate::config::Config::load().ok();
            let method = method
                .or_else(|| config.as_ref().map(|c| c.settings.prompt_method))
                .unwrap_or(crate::config::PromptMethod::Gui);
            let notify = notify || config.as_ref().map(|c| c.settings.notify).unwrap_or(false);
            tracing::info!(target: "file_guard", "starting file-guard agent");
            crate::prompt::run_agent(method, notify, socket).await?;
        }
        Command::Stop => {
            crate::control::stop()?;
        }
        Command::Status => {
            let config = crate::config::Config::load()?;
            crate::control::status(&config)?;
        }
        Command::Log { lines, follow } => {
            let config = crate::config::Config::load()?;
            crate::control::tail_log(&config, lines, follow)?;
        }
        Command::Rules { action } => match action {
            None => {
                for (index, rule) in list_managed_rules().await?.iter().enumerate() {
                    print_rule(index, rule);
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
                    match crate::process::integrity::hash_file(&binary) {
                        Ok(h) => Some(h),
                        Err(e) => anyhow::bail!(
                            "cannot hash {} to pin the rule ({e}); pass --no-pin to add it unpinned",
                            binary.display()
                        ),
                    }
                };
                let entry = crate::config::RuleEntry {
                    file: file.clone(),
                    binary: binary.to_string_lossy().into_owned(),
                    action: match action {
                        crate::cli::RuleAction::Allow => crate::config::RuleAction::Allow,
                        crate::cli::RuleAction::Deny => crate::config::RuleAction::Deny,
                    },
                    access,
                    sha256,
                    signature: None,
                    script: None,
                    script_sha256: None,
                };
                let result =
                    crate::control_api::dispatch(ControlCommand::AddRule { entry }).await?;
                let ControlPayload::Added(added) = result else {
                    anyhow::bail!("control server returned an invalid add-rule response");
                };
                if added {
                    println!("added rule: {} → {}", binary.display(), file);
                } else {
                    println!("rule already exists: {} → {}", binary.display(), file);
                }
            }
            Some(RulesAction::Remove { index }) => {
                let rules = list_managed_rules().await?;
                let (id, _) = learned_rule_at(&rules, index)?;
                let result =
                    crate::control_api::dispatch(ControlCommand::RemoveRule { id }).await?;
                let ControlPayload::Removed(removed) = result else {
                    anyhow::bail!("control server returned an invalid remove-rule response");
                };
                println!(
                    "removed rule {index}: {} → {}",
                    removed.binary, removed.file
                );
            }
            Some(RulesAction::Edit {
                index,
                action,
                access,
                repin,
                no_pin,
            }) => {
                let rules = list_managed_rules().await?;
                let (id, entry) = learned_rule_at(&rules, index)?;
                let action = action.map(|action| match action {
                    RuleAction::Allow => crate::config::RuleAction::Allow,
                    RuleAction::Deny => crate::config::RuleAction::Deny,
                });
                let pin = if no_pin {
                    RulePinUpdate::Unpin
                } else if repin {
                    let binary = std::path::PathBuf::from(&entry.binary);
                    RulePinUpdate::Repin(crate::process::integrity::hash_file(&binary).map_err(
                        |error| anyhow::anyhow!("cannot re-pin {}: {error}", binary.display()),
                    )?)
                } else {
                    RulePinUpdate::Keep
                };
                let binary = entry.binary.clone();
                let file = entry.file.clone();
                let result = crate::control_api::dispatch(ControlCommand::EditRule {
                    id,
                    action,
                    access,
                    pin,
                })
                .await?;
                if !matches!(result, ControlPayload::Replaced) {
                    anyhow::bail!("control server returned an invalid replace-rule response");
                }
                println!("edited rule {index}: {binary} → {file}");
            }
            Some(RulesAction::Find {
                file,
                binary,
                action,
            }) => {
                for (index, rule) in list_managed_rules().await?.iter().enumerate() {
                    let matches_file = file
                        .as_ref()
                        .is_none_or(|file| rule.entry.file.contains(file));
                    let matches_binary = binary
                        .as_ref()
                        .is_none_or(|binary| rule.entry.binary.contains(binary));
                    let matches_action = action.is_none_or(|a| {
                        let want = match a {
                            RuleAction::Allow => crate::config::RuleAction::Allow,
                            RuleAction::Deny => crate::config::RuleAction::Deny,
                        };
                        rule.entry.action == want
                    });
                    if matches_file && matches_binary && matches_action {
                        print_rule(index, rule);
                    }
                }
            }
            Some(RulesAction::Export) => {
                let rules = list_managed_rules()
                    .await?
                    .into_iter()
                    .map(|rule| rule.entry)
                    .collect();
                let rules_toml = crate::config::serialize_rules_document(rules)?;
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
                let entries = crate::config::parse_rules_document(&stdin)?;
                let result =
                    crate::control_api::dispatch(ControlCommand::ImportRules { entries }).await?;
                let ControlPayload::Imported(added) = result else {
                    anyhow::bail!("control server returned an invalid import-rules response");
                };
                println!("imported {added} rule(s)");
            }
        },
        Command::Store { file } => {
            let expanded = crate::config::Config::expand_path(&file.to_string_lossy())?;

            // A live mount means the daemon already guards this path (it
            // captured the original itself); storing again and removing the
            // mountpoint would fight the daemon.
            if crate::control::is_fuse_mount(&expanded) {
                anyhow::bail!(
                    "{} is already guarded by a live file-guard mount; nothing to store.",
                    expanded.display()
                );
            }

            let store: std::sync::Arc<dyn crate::store::BackingStore> =
                std::sync::Arc::from(crate::store::create_store()?);
            crate::transaction::TransactionManager::new(store).store_offline(&expanded)?;
            println!("moved {} into the backing store", expanded.display());
        }
        Command::Restore { file } => {
            let expanded = crate::config::Config::expand_path(&file.to_string_lossy())?;

            // A live mount means the daemon still owns this path; writing under
            // it fights the daemon and is overwritten when it stops (with
            // restore_on_stop). Stop the daemon instead, which restores it.
            if crate::control::is_fuse_mount(&expanded) {
                anyhow::bail!(
                    "{} is a live file-guard mount; stop the daemon to recover it \
                     (`systemctl stop file-guard` writes it back when restore_on_stop \
                     is set) rather than restoring underneath the mount.",
                    expanded.display()
                );
            }

            let store: std::sync::Arc<dyn crate::store::BackingStore> =
                std::sync::Arc::from(crate::store::create_store()?);
            let manager = crate::transaction::TransactionManager::new(store);
            match manager.restore(&expanded)? {
                crate::transaction::RestoreOutcome::Restored => {
                    println!("restored {}", expanded.display());
                }
                crate::transaction::RestoreOutcome::Missing
                    if std::fs::symlink_metadata(&expanded).is_ok() =>
                {
                    println!(
                        "{} is already on disk; nothing to restore.",
                        expanded.display()
                    );
                }
                crate::transaction::RestoreOutcome::Missing => anyhow::bail!(
                    "no v2 snapshot for {} and no file on disk",
                    expanded.display()
                ),
            }
        }
    }

    Ok(())
}

fn migrate_legacy_rules(
    lease: &std::sync::Arc<crate::rule_store::RuleLease>,
    previous: Vec<crate::config::RuleEntry>,
    declarative: Vec<crate::config::RuleEntry>,
) -> anyhow::Result<()> {
    let legacy = legacy_rules(previous, declarative)?;
    if legacy.is_empty() {
        return Ok(());
    }
    let store = crate::rule_store::RuleStore::open(std::sync::Arc::clone(lease))?;
    let migrated = store.insert_many(&legacy)?.len();
    tracing::info!(target: "file_guard", "migrated {migrated} legacy learned rule(s) into the rule store");
    Ok(())
}

fn legacy_rules(
    previous: Vec<crate::config::RuleEntry>,
    declarative: Vec<crate::config::RuleEntry>,
) -> anyhow::Result<Vec<crate::config::RuleEntry>> {
    let declarative = declarative
        .into_iter()
        .map(crate::policy::engine::normalize_rule_entry)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(previous
        .into_iter()
        .map(crate::policy::engine::normalize_rule_entry)
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| !declarative.contains(entry))
        .collect())
}

async fn list_managed_rules() -> anyhow::Result<Vec<ManagedRule>> {
    let payload = crate::control_api::dispatch(ControlCommand::ListRules).await?;
    let ControlPayload::Rules(rules) = payload else {
        anyhow::bail!("control server returned an invalid list-rules response");
    };
    Ok(rules)
}

fn learned_rule_at(
    rules: &[ManagedRule],
    index: usize,
) -> anyhow::Result<(i64, crate::config::RuleEntry)> {
    let rule = rules.get(index).ok_or_else(|| {
        anyhow::anyhow!(
            "rule index {index} out of range (have {} rule(s))",
            rules.len()
        )
    })?;
    let id = rule.learned_id.ok_or_else(|| {
        anyhow::anyhow!("rule {index} is declarative and read-only; edit FILE_GUARD_CONFIG instead")
    })?;
    Ok((id, rule.entry.clone()))
}

fn print_rule(index: usize, rule: &ManagedRule) {
    let entry = &rule.entry;
    let pinned = if entry.sha256.is_some() || entry.script_sha256.is_some() {
        " (pinned)"
    } else {
        ""
    };
    let source = if rule.learned_id.is_some() {
        "learned"
    } else {
        "config"
    };
    println!(
        "{index:>3}  {action:>5} {access:<6} {binary}  →  {file}{pinned} [{source}]",
        action = match entry.action {
            crate::config::RuleAction::Allow => "allow",
            crate::config::RuleAction::Deny => "deny",
        },
        access = entry.access.verb(),
        binary = entry.binary,
        file = entry.file,
    );
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

#[cfg(test)]
mod startup_tests {
    use super::*;

    fn rule(binary: &str, hash: &str) -> crate::config::RuleEntry {
        crate::config::RuleEntry {
            file: "/credential".into(),
            binary: binary.into(),
            action: crate::config::RuleAction::Allow,
            access: crate::policy::rule::Access::Any,
            sha256: Some(hash.repeat(64)),
            signature: None,
            script: None,
            script_sha256: None,
        }
    }

    #[test]
    fn seed_migration_keeps_only_legacy_rules() {
        let seed_in_live = rule("/usr/bin/seed", "A");
        let legacy = rule("/usr/bin/legacy", "b");
        let selected = legacy_rules(
            vec![seed_in_live, legacy.clone()],
            vec![rule("/usr/bin/seed", "a")],
        )
        .unwrap();

        assert_eq!(selected, vec![legacy]);
    }
}
