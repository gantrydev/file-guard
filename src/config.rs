use crate::policy::rule::Access;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub settings: Settings,
    #[serde(default)]
    pub watch: Vec<WatchEntry>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule: Vec<RuleEntry>,
}

#[derive(Debug, Serialize)]
pub struct Settings {
    #[serde(default)]
    pub default_action: DefaultAction,
    #[serde(default = "default_timeout")]
    pub prompt_timeout: u64,
    #[serde(default)]
    pub prompt_method: PromptMethod,
    /// Fire a desktop notification alongside every prompt, even for
    /// `log_only` (which otherwise has no visible feedback). On Linux
    /// this calls `notify-send` from the user's session agent.
    pub notify: bool,
    #[serde(default)]
    pub restore_on_stop: bool,
    #[serde(default = "default_log_dest")]
    pub log_destination: String,
}

#[derive(Deserialize)]
struct SettingsInput {
    #[serde(default)]
    default_action: DefaultAction,
    #[serde(default = "default_timeout")]
    prompt_timeout: u64,
    #[serde(default)]
    prompt_method: PromptMethodInput,
    #[serde(default)]
    notify: Option<bool>,
    #[serde(default)]
    restore_on_stop: bool,
    #[serde(default = "default_log_dest")]
    log_destination: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PromptMethodInput {
    #[default]
    Terminal,
    Gui,
    LogOnly,
    Notification,
}

impl<'de> Deserialize<'de> for Settings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = SettingsInput::deserialize(deserializer)?;
        let legacy_notification = matches!(input.prompt_method, PromptMethodInput::Notification);
        let prompt_method = match input.prompt_method {
            PromptMethodInput::Terminal => PromptMethod::Terminal,
            PromptMethodInput::Gui => PromptMethod::Gui,
            PromptMethodInput::LogOnly | PromptMethodInput::Notification => PromptMethod::LogOnly,
        };

        Ok(Self {
            default_action: input.default_action,
            prompt_timeout: input.prompt_timeout,
            prompt_method,
            notify: input.notify.unwrap_or(legacy_notification),
            restore_on_stop: input.restore_on_stop,
            log_destination: input.log_destination,
        })
    }
}

fn default_timeout() -> u64 {
    30
}

fn default_log_dest() -> String {
    "stdout".to_string()
}

#[derive(Debug, Deserialize, Serialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PromptMethod {
    #[default]
    Terminal,
    Gui,
    /// Log-only: no interactive prompt. Falls back to `default_action` after
    /// the configured prompt timeout. If `notify` is set, a desktop
    /// notification is also fired.
    LogOnly,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WatchEntry {
    pub path: String,
    /// Per-file override of `settings.default_action`, applied when a prompt
    /// times out or the agent is unreachable for this file.
    #[serde(default)]
    pub default_action: Option<DefaultAction>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct RuleEntry {
    pub file: String,
    pub binary: String,
    pub action: RuleAction,
    /// Direction the rule authorizes. Absent in legacy configs → `read`, so
    /// every previously-written rule keeps its read-only meaning.
    #[serde(default, skip_serializing_if = "access_is_read")]
    pub access: Access,
    /// sha256 of the binary when the rule was captured (binary-identity pin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Legacy field retained so older rule files continue to round-trip.
    /// Ignored by the Linux policy engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// For interpreter rules, the pinned script path (narrows the interpreter
    /// to a specific program).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// sha256 of the pinned script's contents (interpreter rules only). Catches
    /// in-place tampering on distros where the script path is stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_sha256: Option<String>,
}

fn access_is_read(access: &Access) -> bool {
    *access == Access::Read
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Deserialize, Serialize)]
struct RulesDocument {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rule: Vec<RuleEntry>,
}

pub fn parse_rules_document(contents: &str) -> anyhow::Result<Vec<RuleEntry>> {
    Ok(toml::from_str::<RulesDocument>(contents)?.rule)
}

pub fn serialize_rules_document(rules: Vec<RuleEntry>) -> anyhow::Result<String> {
    Ok(toml::to_string(&RulesDocument { rule: rules })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings_watch_rule() {
        let toml = r#"
[settings]
default_action = "deny"

[[watch]]
path = "~/.aws/credentials"

[[rule]]
file = "~/.aws/credentials"
binary = "/usr/bin/aws"
action = "allow"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.watch.len(), 1);
        assert_eq!(config.rule.len(), 1);
        assert_eq!(config.settings.default_action, DefaultAction::Deny);
        assert_eq!(config.settings.prompt_timeout, 30);
        assert_eq!(config.rule[0].action, RuleAction::Allow);
    }

    #[test]
    fn settings_only_config_defaults_to_no_watches() {
        let config: Config = toml::from_str(
            r#"
[settings]
default_action = "deny"
"#,
        )
        .unwrap();

        assert!(config.watch.is_empty());
        assert!(config.rule.is_empty());
    }

    #[test]
    fn legacy_notification_method_keeps_notifications_enabled() {
        let config: Config = toml::from_str(
            r#"
[settings]
prompt_method = "notification"
"#,
        )
        .unwrap();

        assert_eq!(config.settings.prompt_method, PromptMethod::LogOnly);
        assert!(config.settings.notify);

        let serialized = toml::to_string(&config).unwrap();
        assert!(serialized.contains("prompt_method = \"log_only\""));
        assert!(serialized.contains("notify = true"));
    }

    #[test]
    fn log_only_defaults_to_no_desktop_notification() {
        let config: Config = toml::from_str(
            r#"
[settings]
prompt_method = "log_only"
"#,
        )
        .unwrap();

        assert_eq!(config.settings.prompt_method, PromptMethod::LogOnly);
        assert!(!config.settings.notify);
    }

    #[test]
    fn empty_rules_are_not_serialized() {
        let config = Config {
            settings: Settings {
                default_action: DefaultAction::Deny,
                prompt_timeout: default_timeout(),
                prompt_method: PromptMethod::Gui,
                notify: false,
                restore_on_stop: true,
                log_destination: default_log_dest(),
            },
            watch: vec![WatchEntry {
                path: "~/.config/gcloud/credentials.db".into(),
                default_action: None,
            }],
            rule: Vec::new(),
        };

        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("rule = []"));
        assert!(!serialized.contains("[[rule]]"));
    }

    #[test]
    fn legacy_rule_defaults_to_unpinned_read() {
        let toml = r#"
[settings]
[[watch]]
path = "~/.aws/credentials"
[[rule]]
file = "~/.aws/credentials"
binary = "/usr/bin/aws"
action = "allow"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.rule[0].access, Access::Read);
        assert!(config.rule[0].sha256.is_none());
        assert!(config.rule[0].signature.is_none());
    }

    #[test]
    fn write_rule_with_pin_round_trips() {
        let entry = RuleEntry {
            file: "/home/a/.config/x".into(),
            binary: "/usr/bin/x".into(),
            action: RuleAction::Allow,
            access: Access::Write,
            sha256: Some("deadbeef".into()),
            signature: None,
            script: None,
            script_sha256: None,
        };
        let serialized = toml::to_string(&entry).unwrap();
        assert!(serialized.contains("access = \"write\""));
        assert!(serialized.contains("sha256 = \"deadbeef\""));
        assert!(!serialized.contains("signature"));

        let back: RuleEntry = toml::from_str(&serialized).unwrap();
        assert_eq!(back.access, Access::Write);
        assert_eq!(back.sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn rules_document_round_trips_without_settings() {
        let rule = RuleEntry {
            file: "/home/a/.config/x".into(),
            binary: "/usr/bin/x".into(),
            action: RuleAction::Allow,
            access: Access::Any,
            sha256: Some("hash".into()),
            signature: None,
            script: None,
            script_sha256: None,
        };
        let exported = serialize_rules_document(vec![rule.clone()]).unwrap();

        assert!(!exported.contains("[settings]"));
        assert_eq!(parse_rules_document(&exported).unwrap(), vec![rule]);
    }
}
