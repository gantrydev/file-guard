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
        if let Err(e) = publish_config_pointer() {
            // Non-fatal: the daemon still runs; only CLI auto-discovery degrades.
            tracing::warn!("failed to publish config pointer: {e}");
        }

        tracing::info!("file-guard started, watching {} files", watched.len());

        Ok(())
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut interceptor) = self.interceptor.take() {
            interceptor.stop()?;
        }
        remove_pid_file();
        remove_config_pointer();
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

/// Publish this daemon's resolved config path so a separate CLI invocation
/// (which lacks FILE_GUARD_CONFIG) can find and act on the same config.
fn publish_config_pointer() -> anyhow::Result<()> {
    let pointer = config::runtime_config_pointer_path();
    if let Some(parent) = pointer.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&pointer, format!("{}\n", config::config_path().display()))?;
    // World-readable: it holds only a path, and the guarded (non-root) user
    // must read it to locate the daemon's config.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pointer, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

fn remove_config_pointer() {
    let path = config::runtime_config_pointer_path();
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("failed to remove config pointer {}: {e}", path.display());
    }
}
