use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, RwLock};

use crate::config::{Config, DefaultAction, RuleAction};
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
    /// Action applied when a prompt times out / the agent is unreachable.
    global_default: DefaultAction,
    /// Per-watched-file overrides of `global_default`.
    file_defaults: HashMap<PathBuf, DefaultAction>,
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
                script: r.script.clone(),
                script_sha256: r.script_sha256.clone(),
            })
            .collect();

        let file_defaults = config
            .watch
            .iter()
            .filter_map(|w| w.default_action.map(|d| (Config::expand_path(&w.path), d)))
            .collect();

        Self {
            rules: RwLock::new(rules),
            session: SessionState::new(),
            prompter,
            global_default: config.settings.default_action,
            file_defaults,
        }
    }

    /// The fallback action for `file`: its per-watch override, else the global.
    fn default_for(&self, file: &Path) -> DefaultAction {
        self.file_defaults
            .get(file)
            .copied()
            .unwrap_or(self.global_default)
    }

    /// Evaluate an `open()` that may need to read, write, or both, prompting the
    /// user **at most once** for the whole open.
    ///
    /// Each required direction is first resolved non-interactively against
    /// persistent rules and session grants, so the read-vs-write distinction is
    /// still enforced (a write-only rule never authorizes a read, and a deny
    /// rule wins outright). Only if some required direction is still unresolved
    /// do we prompt - once - and apply that single decision to the whole open,
    /// rather than firing a separate dialog (and audit line) per direction as a
    /// naive read-then-write gate would for an `O_RDWR` open of e.g. an sqlite
    /// credential DB.
    pub async fn evaluate_open(
        &self,
        process: &ProcessInfo,
        watched_file: &Path,
        needs_read: bool,
        needs_write: bool,
    ) -> Decision {
        let proc_id = ProcessId::from(process);

        let mut all_pre_authorized = true;
        for (needed, access) in [(needs_read, Access::Read), (needs_write, Access::Write)] {
            if !needed {
                continue;
            }
            match self.lookup_rule(process, watched_file, access) {
                // A persistent deny on any required direction denies the open.
                Some(Action::Deny) => return Decision::DenyAlways,
                Some(Action::Allow) => continue,
                None => {
                    if !self
                        .session
                        .is_session_allowed(&proc_id, watched_file, access)
                    {
                        all_pre_authorized = false;
                    }
                }
            }
        }

        // Every required direction was already granted (rule or session): no prompt.
        if all_pre_authorized {
            return Decision::AllowAlways;
        }

        // Prompt once. The verb shown reflects what the open actually needs.
        let prompt_access = match (needs_read, needs_write) {
            (true, true) => Access::Any,
            (_, true) => Access::Write,
            _ => Access::Read,
        };
        self.prompt_and_apply(process, proc_id, watched_file, prompt_access)
            .await
    }

    /// Prompt the user for an unresolved access and turn their choice into a
    /// `Decision`, persisting a rule or session grant as chosen. A permanent or
    /// session grant covers both directions (`Access::Any`) so a tool that both
    /// reads and writes a file isn't re-prompted per direction.
    async fn prompt_and_apply(
        &self,
        process: &ProcessInfo,
        proc_id: ProcessId,
        watched_file: &Path,
        prompt_access: Access,
    ) -> Decision {
        let choice = self
            .prompter
            .prompt(
                process,
                watched_file,
                prompt_access,
                self.default_for(watched_file),
            )
            .await;

        match choice {
            UserChoice::AllowOnce => Decision::AllowOnce,
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
    /// A pin **mismatch is a non-match (re-prompt), not a deny** - so a
    /// legitimately rebuilt/upgraded binary re-authorizes interactively instead
    /// of being hard-blocked. An unpinned (legacy) rule matches on path alone.
    fn identity_matches(&self, rule: &Rule, process: &ProcessInfo) -> bool {
        if rule.sha256.is_none() {
            warn_unpinned_once(&rule.binary);
            return true;
        }

        if let Some(expected) = &rule.sha256 {
            match crate::process::integrity::hash_file(&process.binary_path) {
                Ok(actual) if &actual == expected => {}
                Ok(_) => {
                    tracing::info!(
                        "binary {} changed since its rule was pinned - re-prompting",
                        process.binary_path.display()
                    );
                    return false;
                }
                Err(e) => {
                    tracing::warn!(
                        "cannot hash {} to verify its rule ({e}) - re-prompting",
                        process.binary_path.display()
                    );
                    return false;
                }
            }
        }

        // Interpreter rules also pin the script: the same interpreter running a
        // different (or undetermined) program does not match - it re-prompts.
        if let Some(expected) = &rule.script {
            let actual = process.script.as_ref().map(|p| p.to_string_lossy());
            if actual.as_deref() != Some(expected.as_str()) {
                tracing::info!(
                    "interpreter {} is running a different script than its rule pinned - re-prompting",
                    process.binary_path.display()
                );
                return false;
            }
        }

        // ...and the script's contents, so an in-place edit at the same path
        // re-prompts (path-pinning alone misses this on mutable-path distros).
        if let Some(expected) = &rule.script_sha256 {
            let Some(script) = &process.script else {
                return false;
            };
            match crate::process::integrity::hash_file(script) {
                Ok(actual) if &actual == expected => {}
                Ok(_) => {
                    tracing::info!(
                        "script {} changed since its rule was pinned - re-prompting",
                        script.display()
                    );
                    return false;
                }
                Err(e) => {
                    tracing::warn!(
                        "cannot hash script {} to verify its rule ({e}) - re-prompting",
                        script.display()
                    );
                    return false;
                }
            }
        }

        true
    }

    /// Capture a persistent rule from a prompt response, pinning the binary's
    /// current hash so a later change re-prompts.
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

        // Some only for interpreters - pins the program, not just the runtime,
        // by both path and content hash.
        let script_sha256 =
            process
                .script
                .as_ref()
                .and_then(|s| match crate::process::integrity::hash_file(s) {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("cannot hash script {} to pin its rule ({e})", s.display());
                        None
                    }
                });

        let rule = Rule {
            file: file.to_path_buf(),
            binary: process.binary_path.clone(),
            action,
            access,
            sha256,
            script: process
                .script
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            script_sha256,
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
            signature: None,
            script: rule.script.clone(),
            script_sha256: rule.script_sha256.clone(),
        };
        let _ = Config::append_rule(&entry)?;
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
        }
    }

    fn rule_for(binary: &Path, sha256: Option<String>) -> Rule {
        Rule {
            file: PathBuf::from("/f"),
            binary: binary.to_path_buf(),
            action: Action::Allow,
            access: Access::Read,
            sha256,
            script: None,
            script_sha256: None,
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
        // a non-match (re-prompt), NOT a deny - the load-bearing invariant that
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

    #[test]
    fn script_content_change_is_a_nonmatch() {
        let dir = std::env::temp_dir();
        let bin = dir.join(format!("fg-interp-{}", std::process::id()));
        let script = dir.join(format!("fg-prog-{}.py", std::process::id()));
        std::fs::write(&bin, b"interp").unwrap();
        std::fs::write(&script, b"print('v1')").unwrap();

        let eng = engine();
        let bin_hash = crate::process::integrity::hash_file(&bin).unwrap();
        let script_hash = crate::process::integrity::hash_file(&script).unwrap();

        let mut info = info_for(&bin);
        info.script = Some(script.clone());

        let rule = |script_sha256| Rule {
            file: PathBuf::from("/f"),
            binary: bin.clone(),
            action: Action::Allow,
            access: Access::Read,
            sha256: Some(bin_hash.clone()),
            script: Some(script.to_string_lossy().into_owned()),
            script_sha256,
        };

        // Matching script content → matches.
        assert!(eng.identity_matches(&rule(Some(script_hash.clone())), &info));

        // Edited in place at the same path → no match (re-prompt).
        std::fs::write(&script, b"print('v2-longer')").unwrap();
        assert!(!eng.identity_matches(&rule(Some(script_hash)), &info));

        // No script pin → content is not checked (path pin still holds).
        assert!(eng.identity_matches(&rule(None), &info));

        std::fs::remove_file(&bin).ok();
        std::fs::remove_file(&script).ok();
    }

    #[test]
    fn per_file_default_action_overrides_global() {
        // Global deny, but /a is allow-by-default. With no rule and no reachable
        // agent, evaluate() falls back to each file's default.
        let config: Config = toml::from_str(
            "[settings]\ndefault_action = \"deny\"\n\
             [[watch]]\npath = \"/a\"\ndefault_action = \"allow\"\n\
             [[watch]]\npath = \"/b\"\n",
        )
        .unwrap();
        let client = Arc::new(crate::prompt::PromptClient::new(
            PathBuf::from("/nonexistent.sock"),
            Duration::from_millis(50),
            0,
        ));
        let eng = PolicyEngine::new(&config, client);
        let proc = info_for(Path::new("/usr/bin/whatever"));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let a = rt.block_on(eng.evaluate_open(&proc, Path::new("/a"), true, false));
        let b = rt.block_on(eng.evaluate_open(&proc, Path::new("/b"), true, false));
        assert_eq!(a, Decision::AllowOnce);
        assert_eq!(b, Decision::DenyOnce);
    }
}
