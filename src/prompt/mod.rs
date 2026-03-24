pub mod notification;
pub mod terminal;
pub mod types;

use crate::config::PromptMethod;
use std::time::Duration;
use types::{PromptRequest, UserChoice};

/// Dispatches prompts to the configured method(s).
/// Notification is always sent (informational).
/// The interactive method (terminal/GUI) collects the actual response.
pub struct PromptDispatcher {
    method: PromptMethod,
    timeout: Duration,
}

impl PromptDispatcher {
    pub fn new(method: PromptMethod, timeout: Duration) -> Self {
        Self { method, timeout }
    }

    /// Prompt the user and wait for a response, or timeout to deny.
    pub async fn prompt(&self, req: &PromptRequest) -> UserChoice {
        // Always fire an OS notification (informational)
        notification::notify(req);

        let result = match self.method {
            PromptMethod::Terminal => {
                tokio::time::timeout(self.timeout, terminal::prompt(req)).await
            }
            // TODO: GUI prompt method
            PromptMethod::Gui => {
                tracing::warn!("GUI prompt not yet implemented, falling back to terminal");
                tokio::time::timeout(self.timeout, terminal::prompt(req)).await
            }
            // Notification-only: no interactive response, default to deny after timeout
            PromptMethod::Notification => {
                tracing::info!("notification-only mode, waiting for timeout");
                tokio::time::sleep(self.timeout).await;
                return UserChoice::DenyOnce;
            }
        };

        // Timeout → deny
        result.unwrap_or(UserChoice::DenyOnce)
    }
}
