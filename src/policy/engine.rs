use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, RwLock};

use crate::config::{Config, RuleAction};
use crate::policy::rule::{Access, Action, Decision, Rule};
use crate::policy::session::{ProcessId, SessionState};
use crate::process::identify::ProcessInfo;
use crate::prompt::PromptClient;
use crate::prompt::types::UserChoice;
use std::sync::Arc;

pub struct PolicyEngine {
    rules: RwLock<Vec<Rule>>,
    session: SessionState,
    prompter: Arc<PromptClient>,
}

impl PolicyEngine {
    pub fn new(config: &Config, prompter: Arc<PromptClient>) -> Self {
        let rules: Vec<Rule> = config
            .rule
            .iter()
            .map(|r| Rule {
                file: Config::expand_path(&r.file),
                binary: PathBuf::from(&r.binary),
                action: match r.action {
                    RuleAction::Allow => Action::Allow,
                    RuleAction::Deny => Action::Deny,
                },
                access: r.access,
                sha256: r.sha256.clone(),
                signature: r.signature.clone(),
                script: r.script.clone(),
            })
            .collect();

        Self {
            rules: RwLock::new(rules),
            session: SessionState::new(),
            prompter,
        }
    }

    /// Evaluate policy for a process accessing a watched file in a given
    /// direction. May block while prompting the user.
    pub async fn evaluate(
        &self,
        process: &ProcessInfo,
        watched_file: &Path,
        access: Access,
    ) -> Decision {
        // 1. Persistent rules (identity-pinned).
        if let Some(action) = self.lookup_rule(process, watched_file, access) {
            return match action {
                Action::Allow => Decision::AllowAlways,
                Action::Deny => Decision::DenyAlways,
            };
        }

        // 2. Session grants, keyed on this exact process instance.
        let proc_id = ProcessId::from(process);
        if self
            .session
            .is_session_allowed(&proc_id, watched_file, access)
        {
            return Decision::AllowSession;
        }

        // 3. Unknown — prompt the user (via the session agent).
        let choice = self.prompter.prompt(process, watched_file, access).await;

        match choice {
            UserChoice::AllowOnce => Decision::AllowOnce,
            // A permanent grant means "I trust this binary with this file" — it
            // covers both directions, so a tool that reads *and* writes a file
            // (e.g. an sqlite credential DB) isn't prompted once per direction.
            UserChoice::AllowAlways => {
                self.persist_rule(process, watched_file, Access::Any, Action::Allow);
                Decision::AllowAlways
            }
            UserChoice::AllowSession => {
                self.session
                    .grant_session(proc_id, watched_file.to_path_buf(), Access::Any);
                Decision::AllowSession
            }
            UserChoice::DenyOnce => Decision::DenyOnce,
            UserChoice::DenyAlways => {
                self.persist_rule(process, watched_file, Access::Any, Action::Deny);
                Decision::DenyAlways
            }
        }
    }

    fn lookup_rule(&self, process: &ProcessInfo, file: &Path, req: Access) -> Option<Action> {
        let rules = self.rules.read().unwrap();
        rules
            .iter()
            .find(|r| {
                r.file == file
                    && r.binary == process.binary_path
                    && r.access.covers(req)
                    && self.identity_matches(r, process)
            })
            .map(|r| r.action)
    }

    /// Whether a rule's pinned identity matches the calling process.
    ///
    /// A pin **mismatch is a non-match (re-prompt), not a deny** — so a
    /// legitimately rebuilt/upgraded binary re-authorizes interactively instead
    /// of being hard-blocked. An unpinned (legacy) rule matches on path alone.
    fn identity_matches(&self, rule: &Rule, process: &ProcessInfo) -> bool {
        if rule.sha256.is_none() && rule.signature.is_none() {
            warn_unpinned_once(&rule.binary);
            return true;
        }

        if let Some(expected) = &rule.sha256 {
            match crate::process::integrity::hash_file(&process.binary_path) {
                Ok(actual) if &actual == expected => {}
                Ok(_) => {
                    tracing::info!(
                        "binary {} changed since its rule was pinned — re-prompting",
                        process.binary_path.display()
                    );
                    return false;
                }
                Err(e) => {
                    tracing::warn!(
                        "cannot hash {} to verify its rule ({e}) — re-prompting",
                        process.binary_path.display()
                    );
                    return false;
                }
            }
        }

        #[cfg(target_os = "macos")]
        if let Some(expected) = &rule.signature
            && process.code_signature.as_deref() != Some(expected.as_str())
        {
            return false;
        }

        // Interpreter rules also pin the script: the same interpreter running a
        // different (or undetermined) program does not match — it re-prompts.
        if let Some(expected) = &rule.script {
            let actual = process.script.as_ref().map(|p| p.to_string_lossy());
            if actual.as_deref() != Some(expected.as_str()) {
                tracing::info!(
                    "interpreter {} is running a different script than its rule pinned — re-prompting",
                    process.binary_path.display()
                );
                return false;
            }
        }

        true
    }

    /// Capture a persistent rule from a prompt response, pinning the binary's
    /// current hash (and macOS signature) so a later change re-prompts.
    fn persist_rule(&self, process: &ProcessInfo, file: &Path, access: Access, action: Action) {
        let sha256 = match crate::process::integrity::hash_file(&process.binary_path) {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::warn!(
                    "cannot hash {} to pin its rule ({e}); writing an unpinned rule",
                    process.binary_path.display()
                );
                None
            }
        };

        let rule = Rule {
            file: file.to_path_buf(),
            binary: process.binary_path.clone(),
            action,
            access,
            sha256,
            // None on Linux (code_signature is always None there).
            signature: process.code_signature.clone(),
            // Some only for interpreters — pins the program, not just the runtime.
            script: process
                .script
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
        };

        // Best-effort persist; don't fail the access if the config write fails.
        if let Err(e) = self.add_persistent_rule(rule) {
            tracing::warn!("failed to persist rule: {e}");
        }
    }

    /// Add a new persistent rule and persist to the config file.
    pub fn add_persistent_rule(&self, rule: Rule) -> anyhow::Result<()> {
        let entry = crate::config::RuleEntry {
            file: rule.file.to_string_lossy().to_string(),
            binary: rule.binary.to_string_lossy().to_string(),
            action: match rule.action {
                Action::Allow => RuleAction::Allow,
                Action::Deny => RuleAction::Deny,
            },
            access: rule.access,
            sha256: rule.sha256.clone(),
            signature: rule.signature.clone(),
            script: rule.script.clone(),
        };
        Config::append_rule(&entry)?;
        self.rules.write().unwrap().push(rule);
        Ok(())
    }
}

/// Warn once per binary path that a rule isn't identity-pinned, so the log
/// isn't spammed on the access hot path.
fn warn_unpinned_once(binary: &Path) {
    static WARNED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let mut warned = WARNED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap();
    if warned.insert(binary.to_path_buf()) {
        tracing::warn!(
            "rule for {} is not identity-pinned (legacy/path-only); it authorizes \
             any binary at that path",
            binary.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::identify::ProcessInfo;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;

    fn engine() -> PolicyEngine {
        let config: Config = toml::from_str("watch = []\n[settings]\n").unwrap();
        let client = Arc::new(crate::prompt::PromptClient::new(
            PathBuf::from("/nonexistent.sock"),
            Duration::from_secs(1),
            crate::config::DefaultAction::Deny,
            0,
        ));
        PolicyEngine::new(&config, client)
    }

    fn info_for(binary: &Path) -> ProcessInfo {
        ProcessInfo {
            pid: 1,
            start_time: 1,
            binary_path: binary.to_path_buf(),
            binary_name: "x".into(),
            script: None,
            parent_chain: vec![],
            code_signature: None,
        }
    }

    fn rule_for(binary: &Path, sha256: Option<String>) -> Rule {
        Rule {
            file: PathBuf::from("/f"),
            binary: binary.to_path_buf(),
            action: Action::Allow,
            access: Access::Read,
            sha256,
            signature: None,
            script: None,
        }
    }

    #[test]
    fn sha256_mismatch_is_a_nonmatch_not_a_deny() {
        let mut bin = std::env::temp_dir();
        bin.push(format!("file-guard-engine-{}", std::process::id()));
        std::fs::File::create(&bin)
            .unwrap()
            .write_all(b"v1")
            .unwrap();

        let eng = engine();
        let pinned = crate::process::integrity::hash_file(&bin).unwrap();

        // Correct pin → matches.
        assert!(eng.identity_matches(&rule_for(&bin, Some(pinned.clone())), &info_for(&bin)));

        // Binary changed (different length busts the hash cache) → the rule no
        // longer matches, so evaluate() falls through to a fresh prompt. This is
        // a non-match (re-prompt), NOT a deny — the load-bearing invariant that
        // keeps a rebuilt binary from being hard-blocked.
        std::fs::File::create(&bin)
            .unwrap()
            .write_all(b"v2-longer")
            .unwrap();
        assert!(!eng.identity_matches(&rule_for(&bin, Some(pinned)), &info_for(&bin)));

        // Unpinned (legacy) rule matches on path alone.
        assert!(eng.identity_matches(&rule_for(&bin, None), &info_for(&bin)));

        std::fs::remove_file(&bin).ok();
    }
}
