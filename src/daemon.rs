use std::sync::Arc;
use std::time::Duration;

use crate::config::{self, Config};
use crate::interceptor::{self, Interceptor, InterceptorArgs};
use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::prompt::PromptClient;
use crate::store;

pub struct Daemon {
    config: Config,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    store: Arc<dyn store::BackingStore>,
    interceptor: Option<Box<dyn Interceptor>>,
    rt_handle: tokio::runtime::Handle,
}

impl Daemon {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let logger = Arc::new(AccessLogger::new(&config.settings.log_destination)?);

        // The daemon never renders prompts itself (it may have no tty/display);
        // it asks the user-session agent over a unix socket, falling back to
        // `default_action` if the agent is unreachable.
        let prompter = Arc::new(PromptClient::new(
            config::agent_socket_path(),
            Duration::from_secs(config.settings.prompt_timeout),
            config.settings.default_action,
            config::target_uid(),
        ));

        let policy = Arc::new(PolicyEngine::new(&config, prompter));
        let store: Arc<dyn store::BackingStore> = Arc::from(store::create_store()?);
        let rt_handle = tokio::runtime::Handle::current();

        Ok(Self {
            config,
            policy,
            logger,
            store,
            interceptor: None,
            rt_handle,
        })
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        let watched = self.config.watched_paths();

        let args = InterceptorArgs {
            watched_paths: watched.clone(),
            policy: Arc::clone(&self.policy),
            logger: Arc::clone(&self.logger),
            store: Arc::clone(&self.store),
            rt_handle: self.rt_handle.clone(),
            restore_on_stop: self.config.settings.restore_on_stop,
        };

        let mut interceptor = interceptor::create_interceptor(args)?;
        interceptor.start()?;
        self.interceptor = Some(interceptor);

        write_pid_file()?;

        tracing::info!("file-guard started, watching {} files", watched.len());

        Ok(())
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut interceptor) = self.interceptor.take() {
            interceptor.stop()?;
        }
        remove_pid_file();
        tracing::info!("file-guard stopped");

        Ok(())
    }
}

/// Record this process's PID so `file-guard stop`/`status` can find it.
fn write_pid_file() -> anyhow::Result<()> {
    let path = config::pid_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, format!("{}\n", std::process::id()))?;
    Ok(())
}

fn remove_pid_file() {
    let path = config::pid_file_path();
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("failed to remove PID file {}: {e}", path.display());
    }
}
