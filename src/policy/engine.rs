use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, RwLock};

use crate::config::{Config, DefaultAction, RuleAction, RuleEntry};
use crate::policy::rule::{Access, Action, Decision, IdentityPin, Rule, ScriptIdentity};
use crate::policy::session::{ProcessId, SessionState};
use crate::process::identify::ProcessInfo;
use crate::prompt::PromptClient;
use crate::prompt::types::UserChoice;
use crate::rule_store::RuleRepository;
use std::sync::Arc;

pub struct PolicyEngine {
    rules: RwLock<Vec<ActiveRule>>,
    rule_store: Arc<dyn RuleRepository>,
    session: SessionState,
    prompter: Arc<PromptClient>,
    /// Action applied when a prompt times out / the agent is unreachable.
    global_default: DefaultAction,
    /// Per-watched-file overrides of `global_default`.
    file_defaults: HashMap<PathBuf, DefaultAction>,
}

struct ActiveRule {
    entry: RuleEntry,
    compiled: Rule,
    learned_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManagedRule {
    pub entry: RuleEntry,
    pub learned_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "sha256", rename_all = "snake_case")]
pub enum RulePinUpdate {
    Keep,
    Repin(String),
    Unpin,
}

impl PolicyEngine {
    pub fn new(
        config: &Config,
        prompter: Arc<PromptClient>,
        rule_store: Arc<dyn RuleRepository>,
    ) -> anyhow::Result<Self> {
        let mut rules = config
            .rule
            .iter()
            .cloned()
            .map(|entry| {
                let (entry, compiled) = prepare_rule_entry(entry)?;
                Ok(ActiveRule {
                    compiled,
                    entry,
                    learned_id: None,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let learned = rule_store
            .list()?
            .into_iter()
            .map(|stored| {
                let (entry, compiled) = prepare_rule_entry(stored.entry)?;
                Ok(ActiveRule {
                    compiled,
                    entry,
                    learned_id: Some(stored.id),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        rules.extend(learned);

        let mut file_defaults = HashMap::new();
        for watch in &config.watch {
            if let Some(default) = watch.default_action {
                file_defaults.insert(Config::expand_path(&watch.path)?, default);
            }
        }

        Ok(Self {
            rules: RwLock::new(rules),
            rule_store,
            session: SessionState::new(),
            prompter,
            global_default: config.settings.default_action,
            file_defaults,
        })
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
                match self.persist_rule(process, watched_file, Access::Any, Action::Allow) {
                    Ok(()) => Decision::AllowAlways,
                    Err(error) => {
                        tracing::warn!(
                            "permanent allow for {} was not persisted ({error}); allowing once",
                            process.binary_path.display()
                        );
                        Decision::AllowOnce
                    }
                }
            }
            UserChoice::AllowSession => {
                self.session
                    .grant_session(proc_id, watched_file.to_path_buf(), Access::Any);
                Decision::AllowSession
            }
            UserChoice::DenyOnce => Decision::DenyOnce,
            UserChoice::DenyAlways => {
                match self.persist_rule(process, watched_file, Access::Any, Action::Deny) {
                    Ok(()) => Decision::DenyAlways,
                    Err(error) => {
                        tracing::warn!(
                            "permanent deny for {} was not persisted ({error}); denying once",
                            process.binary_path.display()
                        );
                        Decision::DenyOnce
                    }
                }
            }
        }
    }

    fn lookup_rule(&self, process: &ProcessInfo, file: &Path, req: Access) -> Option<Action> {
        let rules = self.rules.read().unwrap();
        let mut matched_allow = false;
        for rule in rules.iter().filter(|rule| {
            rule.compiled.file == file
                && rule.compiled.binary == process.binary_path
                && rule.compiled.access.covers(req)
        }) {
            if !self.identity_matches(&rule.compiled, process) {
                continue;
            }
            match rule.compiled.action {
                Action::Deny => return Some(Action::Deny),
                Action::Allow => matched_allow = true,
            }
        }
        matched_allow.then_some(Action::Allow)
    }

    /// Whether a rule's pinned identity matches the calling process.
    ///
    /// A pin **mismatch is a non-match (re-prompt), not a deny** - so a
    /// legitimately rebuilt/upgraded binary re-authorizes interactively instead
    /// of being hard-blocked. An unpinned (legacy) rule matches on path alone.
    fn identity_matches(&self, rule: &Rule, process: &ProcessInfo) -> bool {
        match &rule.identity {
            IdentityPin::Unpinned => warn_unpinned_once(&rule.binary),
            IdentityPin::Sha256(expected) if &process.binary_sha256 == expected => {}
            IdentityPin::Sha256(_) => {
                tracing::info!(
                    "binary {} changed since its rule was pinned - re-prompting",
                    process.binary_path.display()
                );
                return false;
            }
        }

        if let Some(expected) = &rule.script {
            let actual = process.script.as_ref().map(|p| p.to_string_lossy());
            if actual.as_deref() != Some(expected.path.as_str()) {
                tracing::info!(
                    "interpreter {} is running a different script than its rule pinned - re-prompting",
                    process.binary_path.display()
                );
                return false;
            }

            match &expected.pin {
                IdentityPin::Unpinned => warn_unpinned_script_once(Path::new(&expected.path)),
                IdentityPin::Sha256(expected_hash) => {
                    let Some(script) = &process.script else {
                        return false;
                    };
                    match crate::process::integrity::hash_file(script) {
                        Ok(actual) if &actual == expected_hash => {}
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
            }
        }

        true
    }

    fn persist_rule(
        &self,
        process: &ProcessInfo,
        file: &Path,
        access: Access,
        action: Action,
    ) -> anyhow::Result<()> {
        let script = process
            .script
            .as_ref()
            .map(|path| {
                crate::process::integrity::hash_file(path)
                    .map(|sha256| ScriptIdentity {
                        path: path.to_string_lossy().into_owned(),
                        pin: IdentityPin::Sha256(sha256),
                    })
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "cannot hash script {} to create a permanent rule: {error}",
                            path.display()
                        )
                    })
            })
            .transpose()?;

        self.add_persistent_rule(Rule {
            file: file.to_path_buf(),
            binary: process.binary_path.clone(),
            action,
            access,
            identity: IdentityPin::Sha256(process.binary_sha256.clone()),
            script,
        })
    }

    /// Add a new persistent rule to the daemon-owned learned-rule store.
    pub fn add_persistent_rule(&self, rule: Rule) -> anyhow::Result<()> {
        let entry = crate::config::RuleEntry {
            file: rule.file.to_string_lossy().to_string(),
            binary: rule.binary.to_string_lossy().to_string(),
            action: match rule.action {
                Action::Allow => RuleAction::Allow,
                Action::Deny => RuleAction::Deny,
            },
            access: rule.access,
            sha256: rule.identity.sha256().map(str::to_owned),
            signature: None,
            script: rule.script.as_ref().map(|identity| identity.path.clone()),
            script_sha256: rule
                .script
                .as_ref()
                .and_then(|identity| identity.pin.sha256().map(str::to_owned)),
        };
        self.add_managed_rule(entry).map(drop)
    }

    pub fn managed_rules(&self) -> Vec<ManagedRule> {
        self.rules
            .read()
            .unwrap()
            .iter()
            .map(|rule| ManagedRule {
                entry: rule.entry.clone(),
                learned_id: rule.learned_id,
            })
            .collect()
    }

    pub fn add_managed_rule(&self, entry: RuleEntry) -> anyhow::Result<bool> {
        let (entry, compiled) = prepare_rule_entry(entry)?;
        let mut rules = self.rules.write().unwrap();
        if rules.iter().any(|active| active.entry == entry) {
            return Ok(false);
        }
        let Some(stored) = self.rule_store.insert(&entry)? else {
            return Ok(false);
        };
        rules.push(ActiveRule {
            entry,
            compiled,
            learned_id: Some(stored.id),
        });
        Ok(true)
    }

    pub fn import_managed_rules(&self, entries: Vec<RuleEntry>) -> anyhow::Result<usize> {
        let prepared = entries
            .into_iter()
            .map(prepare_rule_entry)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut rules = self.rules.write().unwrap();
        let new_entries = prepared
            .iter()
            .map(|(entry, _)| entry)
            .filter(|entry| !rules.iter().any(|active| active.entry == **entry))
            .cloned()
            .collect::<Vec<_>>();
        let inserted = self.rule_store.insert_many(&new_entries)?;
        let added = inserted.len();
        for stored in inserted {
            let compiled = prepared
                .iter()
                .find(|(entry, _)| entry == &stored.entry)
                .map(|(_, compiled)| compiled.clone())
                .ok_or_else(|| anyhow::anyhow!("rule repository returned an unknown rule"))?;
            rules.push(ActiveRule {
                compiled,
                entry: stored.entry,
                learned_id: Some(stored.id),
            });
        }
        Ok(added)
    }

    pub fn edit_managed_rule(
        &self,
        id: i64,
        action: Option<RuleAction>,
        access: Option<Access>,
        pin: RulePinUpdate,
    ) -> anyhow::Result<RuleEntry> {
        let mut rules = self.rules.write().unwrap();
        let index = rules
            .iter()
            .position(|rule| rule.learned_id == Some(id))
            .ok_or_else(|| anyhow::anyhow!("learned rule {id} is not active"))?;
        let (entry, compiled) = prepare_rule_entry(apply_rule_edit(
            rules[index].entry.clone(),
            action,
            access,
            pin,
        ))?;
        if rules
            .iter()
            .any(|active| active.learned_id != Some(id) && active.entry == entry)
        {
            anyhow::bail!("an identical rule already exists");
        }
        self.rule_store.replace(id, &entry)?;
        let active = &mut rules[index];
        active.entry = entry.clone();
        active.compiled = compiled;
        Ok(entry)
    }

    pub fn remove_managed_rule(&self, id: i64) -> anyhow::Result<RuleEntry> {
        let mut rules = self.rules.write().unwrap();
        let index = rules
            .iter()
            .position(|rule| rule.learned_id == Some(id))
            .ok_or_else(|| anyhow::anyhow!("learned rule {id} is not active"))?;
        self.rule_store.remove(id)?;
        Ok(rules.remove(index).entry)
    }
}

pub(crate) fn normalize_rule_entry(entry: RuleEntry) -> anyhow::Result<RuleEntry> {
    prepare_rule_entry(entry).map(|(entry, _)| entry)
}

pub(crate) fn edit_rule_entry(
    entry: RuleEntry,
    action: Option<RuleAction>,
    access: Option<Access>,
    pin: RulePinUpdate,
) -> anyhow::Result<RuleEntry> {
    prepare_rule_entry(apply_rule_edit(entry, action, access, pin)).map(|(entry, _)| entry)
}

fn apply_rule_edit(
    mut entry: RuleEntry,
    action: Option<RuleAction>,
    access: Option<Access>,
    pin: RulePinUpdate,
) -> RuleEntry {
    if let Some(action) = action {
        entry.action = action;
    }
    if let Some(access) = access {
        entry.access = access;
    }
    match pin {
        RulePinUpdate::Keep => {}
        RulePinUpdate::Repin(sha256) => entry.sha256 = Some(sha256),
        RulePinUpdate::Unpin => {
            entry.sha256 = None;
            entry.script_sha256 = None;
        }
    }
    entry
}

fn prepare_rule_entry(mut entry: RuleEntry) -> anyhow::Result<(RuleEntry, Rule)> {
    normalize_hash(&mut entry.sha256, "sha256")?;
    normalize_hash(&mut entry.script_sha256, "script_sha256")?;
    let compiled = rule_from_entry(&entry)?;
    Ok((entry, compiled))
}

fn normalize_hash(value: &mut Option<String>, field: &str) -> anyhow::Result<()> {
    if let Some(hash) = value {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            anyhow::bail!("rule {field} must be a 64-character hexadecimal SHA-256");
        }
        hash.make_ascii_lowercase();
    }
    Ok(())
}

fn rule_from_entry(entry: &RuleEntry) -> anyhow::Result<Rule> {
    let file = Config::expand_path(&entry.file)?;
    if !file.is_absolute() {
        anyhow::bail!("rule file path must be absolute: {}", entry.file);
    }
    let binary = PathBuf::from(&entry.binary);
    if !binary.is_absolute() {
        anyhow::bail!("rule binary path must be absolute: {}", entry.binary);
    }
    let identity = identity_pin(entry.sha256.as_deref(), "sha256")?;
    let script = match (&entry.script, entry.script_sha256.as_deref()) {
        (None, Some(_)) => anyhow::bail!("script_sha256 requires a script path"),
        (None, None) => None,
        (Some(path), hash) => {
            if !Path::new(path).is_absolute() {
                anyhow::bail!("rule script path must be absolute: {path}");
            }
            Some(ScriptIdentity {
                path: path.clone(),
                pin: identity_pin(hash, "script_sha256")?,
            })
        }
    };
    Ok(Rule {
        file,
        binary,
        action: match entry.action {
            RuleAction::Allow => Action::Allow,
            RuleAction::Deny => Action::Deny,
        },
        access: entry.access,
        identity,
        script,
    })
}

fn identity_pin(value: Option<&str>, field: &str) -> anyhow::Result<IdentityPin> {
    match value {
        None => Ok(IdentityPin::Unpinned),
        Some(value) if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            Ok(IdentityPin::Sha256(value.to_ascii_lowercase()))
        }
        Some(_) => anyhow::bail!("rule {field} must be a 64-character hexadecimal SHA-256"),
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

fn warn_unpinned_script_once(script: &Path) {
    static WARNED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let mut warned = WARNED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap();
    if warned.insert(script.to_path_buf()) {
        tracing::warn!(
            "script rule for {} is path-only; it does not verify script contents",
            script.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::identify::ProcessInfo;
    use crate::rule_store::MemoryRuleStore;
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
        PolicyEngine::new(&config, client, Arc::new(MemoryRuleStore::new())).unwrap()
    }

    fn info_for(binary: &Path) -> ProcessInfo {
        ProcessInfo {
            pid: 1,
            start_time: 1,
            binary_path: binary.to_path_buf(),
            binary_name: "x".into(),
            binary_sha256: crate::process::integrity::hash_file(binary)
                .unwrap_or_else(|_| "0".repeat(64)),
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
            identity: IdentityPin::from_sha256(sha256),
            script: None,
        }
    }

    fn entry_for(binary: &Path, action: RuleAction) -> RuleEntry {
        RuleEntry {
            file: "/f".into(),
            binary: binary.to_string_lossy().into_owned(),
            action,
            access: Access::Read,
            sha256: None,
            signature: None,
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
        let changed = info_for(&bin);
        assert!(!eng.identity_matches(&rule_for(&bin, Some(pinned)), &changed));

        // Unpinned (legacy) rule matches on path alone.
        assert!(eng.identity_matches(&rule_for(&bin, None), &changed));

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
            identity: IdentityPin::Sha256(bin_hash.clone()),
            script: Some(ScriptIdentity {
                path: script.to_string_lossy().into_owned(),
                pin: IdentityPin::from_sha256(script_sha256),
            }),
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
    fn unpinned_interpreter_rule_still_checks_its_script_pin() {
        let dir = std::env::temp_dir();
        let bin = dir.join(format!("fg-unpinned-interp-{}", std::process::id()));
        let script = dir.join(format!("fg-unpinned-prog-{}.py", std::process::id()));
        std::fs::write(&bin, b"interp").unwrap();
        std::fs::write(&script, b"print('v1')").unwrap();

        let eng = engine();
        let script_hash = crate::process::integrity::hash_file(&script).unwrap();
        let mut info = info_for(&bin);
        info.script = Some(script.clone());
        let rule = Rule {
            file: PathBuf::from("/f"),
            binary: bin.clone(),
            action: Action::Allow,
            access: Access::Read,
            identity: IdentityPin::Unpinned,
            script: Some(ScriptIdentity {
                path: script.to_string_lossy().into_owned(),
                pin: IdentityPin::Sha256(script_hash),
            }),
        };

        std::fs::write(&script, b"print('v2-longer')").unwrap();
        assert!(!eng.identity_matches(&rule, &info));

        std::fs::remove_file(&bin).ok();
        std::fs::remove_file(&script).ok();
    }

    #[test]
    fn failed_script_identity_capture_does_not_create_a_rule() {
        let eng = engine();
        let missing = PathBuf::from(format!(
            "/nonexistent/file-guard-script-{}",
            std::process::id()
        ));
        let mut process = info_for(Path::new("/usr/bin/tool"));
        process.script = Some(missing);

        assert!(
            eng.persist_rule(&process, Path::new("/f"), Access::Any, Action::Allow)
                .is_err()
        );
        assert!(eng.rules.read().unwrap().is_empty());
    }

    #[test]
    fn deny_wins_independent_of_rule_order() {
        let binary = Path::new("/usr/bin/tool");
        let process = info_for(binary);
        for actions in [
            [RuleAction::Allow, RuleAction::Deny],
            [RuleAction::Deny, RuleAction::Allow],
        ] {
            let eng = engine();
            for action in actions {
                assert!(eng.add_managed_rule(entry_for(binary, action)).unwrap());
            }
            assert_eq!(
                eng.lookup_rule(&process, Path::new("/f"), Access::Read),
                Some(Action::Deny)
            );
        }
    }

    #[test]
    fn managed_rule_changes_keep_memory_and_repository_in_sync() {
        let config: Config = toml::from_str(
            "[settings]\n[[rule]]\nfile = \"/f\"\nbinary = \"/usr/bin/tool\"\n\
             action = \"allow\"\n",
        )
        .unwrap();
        let client = Arc::new(crate::prompt::PromptClient::new(
            PathBuf::from("/nonexistent.sock"),
            Duration::from_secs(1),
            0,
        ));
        let store = Arc::new(MemoryRuleStore::new());
        let eng = PolicyEngine::new(&config, client, store.clone()).unwrap();
        let declarative = entry_for(Path::new("/usr/bin/tool"), RuleAction::Allow);

        assert_eq!(
            eng.managed_rules(),
            vec![ManagedRule {
                entry: declarative.clone(),
                learned_id: None,
            }]
        );
        assert!(!eng.add_managed_rule(declarative).unwrap());

        let learned = entry_for(Path::new("/usr/bin/tool"), RuleAction::Deny);
        assert!(eng.add_managed_rule(learned.clone()).unwrap());
        let id = store.list().unwrap()[0].id;
        assert_eq!(eng.managed_rules()[1].learned_id, Some(id));

        eng.edit_managed_rule(id, None, Some(Access::Write), RulePinUpdate::Keep)
            .unwrap();
        let replacement = eng
            .edit_managed_rule(id, Some(RuleAction::Allow), None, RulePinUpdate::Keep)
            .unwrap();
        assert_eq!(replacement.action, RuleAction::Allow);
        assert_eq!(replacement.access, Access::Write);
        assert_eq!(store.list().unwrap()[0].entry, replacement);

        assert_eq!(eng.remove_managed_rule(id).unwrap().file, "/f");
        assert!(store.list().unwrap().is_empty());
        assert_eq!(eng.managed_rules().len(), 1);
        assert!(eng.managed_rules()[0].learned_id.is_none());
    }

    #[test]
    fn invalid_import_is_rejected_before_any_rule_is_persisted() {
        let config: Config = toml::from_str("[settings]\n").unwrap();
        let client = Arc::new(crate::prompt::PromptClient::new(
            PathBuf::from("/nonexistent.sock"),
            Duration::from_secs(1),
            0,
        ));
        let store = Arc::new(MemoryRuleStore::new());
        let eng = PolicyEngine::new(&config, client, store.clone()).unwrap();
        let valid = entry_for(Path::new("/usr/bin/tool"), RuleAction::Allow);
        let mut invalid = entry_for(Path::new("/usr/bin/other"), RuleAction::Allow);
        invalid.script_sha256 = Some("0".repeat(64));

        assert!(eng.import_managed_rules(vec![valid, invalid]).is_err());
        assert!(store.list().unwrap().is_empty());
        assert!(eng.managed_rules().is_empty());
    }

    #[test]
    fn hashes_are_normalized_before_deduplication_and_persistence() {
        let config: Config = toml::from_str("[settings]\n").unwrap();
        let client = Arc::new(crate::prompt::PromptClient::new(
            PathBuf::from("/nonexistent.sock"),
            Duration::from_secs(1),
            0,
        ));
        let store = Arc::new(MemoryRuleStore::new());
        let eng = PolicyEngine::new(&config, client, store.clone()).unwrap();
        let mut uppercase = entry_for(Path::new("/usr/bin/tool"), RuleAction::Allow);
        uppercase.sha256 = Some("A".repeat(64));
        let mut lowercase = uppercase.clone();
        lowercase.sha256 = Some("a".repeat(64));

        assert!(eng.add_managed_rule(uppercase).unwrap());
        assert!(!eng.add_managed_rule(lowercase.clone()).unwrap());
        assert_eq!(store.list().unwrap()[0].entry, lowercase);
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
        let eng = PolicyEngine::new(&config, client, Arc::new(MemoryRuleStore::new())).unwrap();
        let proc = info_for(Path::new("/usr/bin/whatever"));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let a = rt.block_on(eng.evaluate_open(&proc, Path::new("/a"), true, false));
        let b = rt.block_on(eng.evaluate_open(&proc, Path::new("/b"), true, false));
        assert_eq!(a, Decision::AllowOnce);
        assert_eq!(b, Decision::DenyOnce);
    }
}
