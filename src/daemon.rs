use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::es::EsClient;
use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::prompt::PromptDispatcher;

/// Main daemon that orchestrates all components.
pub struct Daemon {
    config: Config,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    es_client: Option<EsClient>,
    rt_handle: tokio::runtime::Handle,
}

impl Daemon {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let logger = Arc::new(AccessLogger::new(&config.settings.log_destination)?);

        let prompter = Arc::new(PromptDispatcher::new(
            config.settings.prompt_method,
            Duration::from_secs(config.settings.prompt_timeout),
        ));

        let policy = Arc::new(PolicyEngine::new(&config, prompter));
        let rt_handle = tokio::runtime::Handle::current();

        Ok(Self {
            config,
            policy,
            logger,
            es_client: None,
            rt_handle,
        })
    }

    /// Start: create ES client, subscribe to AUTH_OPEN on watched paths.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let watched = self.config.watched_paths();

        let es = EsClient::new(
            watched.clone(),
            Arc::clone(&self.policy),
            Arc::clone(&self.logger),
            self.rt_handle.clone(),
        )?;

        self.es_client = Some(es);

        tracing::info!(
            "cred-guard started, watching {} files",
            watched.len()
        );
        Ok(())
    }

    /// Stop: drop the ES client (unsubscribes automatically).
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        self.es_client.take(); // Drop triggers cleanup
        tracing::info!("cred-guard stopped");
        Ok(())
    }
}
