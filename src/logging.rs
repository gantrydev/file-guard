use crate::policy::rule::{Access, Decision};
use crate::process::identify::ProcessInfo;
use std::path::Path;

/// A single access log entry.
// TODO: AccessLogger only emits via `tracing`. Wire it to the configured
// `log_destination` (file / syslog) as a queryable audit trail, and implement
// the `log` CLI command.
#[allow(dead_code)]
#[derive(Debug, serde::Serialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub decision: String,
    pub access: String,
    pub file: String,
    pub binary: String,
    pub pid: u32,
    pub detail: Option<String>,
}

/// Access logger - writes structured entries to the configured sink.
pub struct AccessLogger;

impl AccessLogger {
    pub fn new(_destination: &str) -> anyhow::Result<Self> {
        // TODO: Support file and syslog destinations
        Ok(Self)
    }

    /// Log an access attempt.
    pub fn log(
        &self,
        process: &ProcessInfo,
        file: &Path,
        access: Access,
        decision: &Decision,
        detail: Option<&str>,
    ) {
        let decision_str = match decision {
            Decision::AllowAlways | Decision::AllowSession | Decision::AllowOnce => "ALLOW",
            Decision::DenyAlways | Decision::DenyOnce => "DENY",
        };
        let access_str = access.verb().to_uppercase();

        tracing::info!(
            "{decision_str} {access_str} {} ← {} (pid {}){extra}",
            file.display(),
            process.binary_path.display(),
            process.pid,
            extra = detail.map(|d| format!(" [{d}]")).unwrap_or_default(),
        );
    }
}
