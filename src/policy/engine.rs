use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::config::{Config, RuleAction};
use crate::policy::rule::{Action, Decision, Rule};
use crate::policy::session::SessionState;
use crate::process::identify::ProcessInfo;
use crate::prompt::types::{PromptRequest, UserChoice};
use crate::prompt::PromptDispatcher;

pub struct PolicyEngine {
    rules: RwLock<Vec<Rule>>,
    session: SessionState,
    prompter: Arc<PromptDispatcher>,
    default_action: Action,
}

impl PolicyEngine {
    pub fn new(config: &Config, prompter: Arc<PromptDispatcher>) -> Self {
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
            })
            .collect();

        let default_action = match config.settings.default_action {
            crate::config::DefaultAction::Allow => Action::Allow,
            crate::config::DefaultAction::Deny => Action::Deny,
        };

        Self {
            rules: RwLock::new(rules),
            session: SessionState::new(),
            prompter,
            default_action,
        }
    }

    /// Evaluate policy for a process accessing a watched file.
    /// May block while prompting the user.
    pub async fn evaluate(&self, process: &ProcessInfo, watched_file: &Path) -> Decision {
        // 1. Check persistent rules
        if let Some(action) = self.lookup_rule(&process.binary_path, watched_file) {
            return match action {
                Action::Allow => Decision::AllowAlways,
                Action::Deny => Decision::DenyAlways,
            };
        }

        // 2. Check session-scoped grants
        if self
            .session
            .is_session_allowed(&process.binary_path, &watched_file.to_path_buf())
        {
            return Decision::AllowSession;
        }

        // 3. Unknown — prompt the user
        let req = PromptRequest {
            process: process.clone(),
            file: watched_file.to_path_buf(),
        };

        let choice = self.prompter.prompt(&req).await;

        match choice {
            UserChoice::AllowOnce => Decision::AllowOnce,
            UserChoice::AllowAlways => {
                let rule = Rule {
                    file: watched_file.to_path_buf(),
                    binary: process.binary_path.clone(),
                    action: Action::Allow,
                };
                // Best-effort persist; don't fail the access if config write fails
                let _ = self.add_persistent_rule(rule);
                Decision::AllowAlways
            }
            UserChoice::AllowSession => {
                self.session
                    .grant_session(process.binary_path.clone(), watched_file.to_path_buf());
                Decision::AllowSession
            }
            UserChoice::DenyOnce => Decision::DenyOnce,
            UserChoice::DenyAlways => {
                let rule = Rule {
                    file: watched_file.to_path_buf(),
                    binary: process.binary_path.clone(),
                    action: Action::Deny,
                };
                let _ = self.add_persistent_rule(rule);
                Decision::DenyAlways
            }
        }
    }

    fn lookup_rule(&self, binary: &Path, file: &Path) -> Option<Action> {
        let rules = self.rules.read().unwrap();
        rules
            .iter()
            .find(|r| r.binary == binary && r.file == file)
            .map(|r| r.action)
    }

    /// Add a new persistent rule and persist to config file.
    pub fn add_persistent_rule(&self, rule: Rule) -> anyhow::Result<()> {
        let entry = crate::config::RuleEntry {
            file: rule.file.to_string_lossy().to_string(),
            binary: rule.binary.to_string_lossy().to_string(),
            action: match rule.action {
                Action::Allow => RuleAction::Allow,
                Action::Deny => RuleAction::Deny,
            },
        };
        Config::append_rule(&entry)?;
        self.rules.write().unwrap().push(rule);
        Ok(())
    }
}
