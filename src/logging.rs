use crate::policy::rule::Decision;
use crate::process::identify::ProcessInfo;
use std::path::Path;

/// A single access log entry.
#[derive(Debug, serde::Serialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub decision: String,
    pub file: String,
    pub binary: String,
    pub pid: u32,
    pub detail: Option<String>,
}

/// Access logger — writes structured entries to the configured sink.
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
        decision: &Decision,
        detail: Option<&str>,
    ) {
        let decision_str = match decision {
            Decision::AllowAlways | Decision::AllowSession | Decision::AllowOnce => "ALLOW",
            Decision::DenyAlways | Decision::DenyOnce => "DENY",
            Decision::Unknown => "PROMPT",
        };

        tracing::info!(
            "{decision_str} {} ← {} (pid {}){extra}",
            file.display(),
            process.binary_path.display(),
            process.pid,
            extra = detail.map(|d| format!(" [{d}]")).unwrap_or_default(),
        );
    }
}
