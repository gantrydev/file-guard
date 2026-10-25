use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::config_runtime;
use crate::interceptor::{self, Interceptor, InterceptorArgs};
use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::prompt::PromptClient;
use crate::rule_store::{RuleLease, RuleStore};
use crate::store;

pub struct Daemon {
    config: Config,
    policy: Option<Arc<PolicyEngine>>,
    logger: Arc<AccessLogger>,
    store: Arc<dyn store::BackingStore>,
    interceptor: Option<Box<dyn Interceptor>>,
    control: Option<crate::control_api::ControlEndpoint>,
    control_task: Option<tokio::task::JoinHandle<()>>,
    guarded_uid: u32,
    rt_handle: tokio::runtime::Handle,
}

impl Daemon {
    pub fn new(config: Config, rule_lease: Arc<RuleLease>) -> anyhow::Result<Self> {
        let (guarded_uid, guarded_gid) = config_runtime::target_identity()?;
        let control = crate::control_api::bind_listener(guarded_gid)?;
        let logger = Arc::new(AccessLogger::new(&config.settings.log_destination)?);

        // The daemon never renders prompts itself (it may have no tty/display);
        // it asks the user-session agent over a unix socket, falling back to
        // `default_action` if the agent is unreachable.
        let prompter = Arc::new(PromptClient::new(
            config_runtime::agent_socket_path()?,
            Duration::from_secs(config.settings.prompt_timeout),
            guarded_uid,
        ));

        let rule_store = Arc::new(RuleStore::open(rule_lease)?);
        let policy = Arc::new(PolicyEngine::new(&config, prompter, rule_store)?);
        let store: Arc<dyn store::BackingStore> = Arc::from(store::create_store()?);
        let rt_handle = tokio::runtime::Handle::current();

        Ok(Self {
            config,
            policy: Some(policy),
            logger,
            store,
            interceptor: None,
            control: Some(control),
            control_task: None,
            guarded_uid,
            rt_handle,
        })
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        let watched = config_runtime::watched_paths(&self.config)?;
        let control_listener = self
            .control
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("control endpoint is unavailable"))?
            .take_listener()?;

        let args = InterceptorArgs {
            watched_paths: watched.clone(),
            policy: Arc::clone(
                self.policy
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("policy engine is unavailable"))?,
            ),
            logger: Arc::clone(&self.logger),
            store: Arc::clone(&self.store),
            rt_handle: self.rt_handle.clone(),
            restore_on_stop: self.config.settings.restore_on_stop,
        };

        let mut interceptor = match interceptor::create_interceptor(args) {
            Ok(interceptor) => interceptor,
            Err(error) => return Err(error),
        };
        if let Err(error) = start_and_publish(interceptor.as_mut(), write_pid_file) {
            remove_pid_file();
            return Err(error);
        }
        self.interceptor = Some(interceptor);
        let policy = Arc::clone(
            self.policy
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("policy engine is unavailable"))?,
        );
        let guarded_uid = self.guarded_uid;
        self.control_task = Some(tokio::spawn(async move {
            crate::control_api::serve(control_listener, policy, guarded_uid).await;
        }));
        if let Err(e) = publish_config_pointer() {
            // Non-fatal: the daemon still runs; only CLI auto-discovery degrades.
            tracing::warn!("failed to publish config pointer: {e}");
        }

        notify_systemd_ready();

        tracing::info!("file-guard started, watching {} files", watched.len());

        Ok(())
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        notify_systemd_stopping();
        if let Some(task) = self.control_task.take() {
            task.abort();
            let _ = task.await;
        }
        let stop_result = match self.interceptor.take() {
            Some(mut interceptor) => interceptor.stop(),
            None => Ok(()),
        };
        drop(self.control.take());
        drop(self.policy.take());
        remove_pid_file();
        remove_config_pointer();
        stop_result?;
        tracing::info!("file-guard stopped");

        Ok(())
    }
}

fn start_and_publish(
    interceptor: &mut dyn Interceptor,
    publish: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    interceptor.start()?;
    if let Err(error) = publish() {
        return match interceptor.abort_start() {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(anyhow::anyhow!(
                "{error}; startup rollback also failed: {rollback_error}"
            )),
        };
    }
    Ok(())
}

/// Record this process's PID so `file-guard stop`/`status` can find it.
fn write_pid_file() -> anyhow::Result<()> {
    let path = config_runtime::pid_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let pid = std::process::id();
    let start_time = crate::process::start_time(pid)?;
    std::fs::write(&path, format!("{pid} {start_time}\n"))?;
    Ok(())
}

fn remove_pid_file() {
    let path = match config_runtime::pid_file_path() {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!("cannot resolve PID file for cleanup: {error}");
            return;
        }
    };
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("failed to remove PID file {}: {e}", path.display());
    }
}

/// Publish this daemon's resolved config path so a separate CLI invocation
/// (which lacks FILE_GUARD_CONFIG) can find and act on the same config.
fn publish_config_pointer() -> anyhow::Result<()> {
    let pointer = config_runtime::runtime_config_pointer_path();
    if let Some(parent) = pointer.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &pointer,
        format!("{}\n", config_runtime::config_path()?.display()),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pointer, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

fn remove_config_pointer() {
    let path = config_runtime::runtime_config_pointer_path();
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("failed to remove config pointer {}: {e}", path.display());
    }
}

fn notify_systemd_ready() {
    if let Err(error) = libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
    {
        tracing::warn!("systemd readiness notification failed: {error}");
    }
}

fn notify_systemd_stopping() {
    if let Err(error) =
        libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Stopping])
    {
        tracing::warn!("systemd stopping notification failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingInterceptor {
        started: bool,
        aborted: bool,
    }

    impl Interceptor for RecordingInterceptor {
        fn start(&mut self) -> anyhow::Result<()> {
            self.started = true;
            Ok(())
        }

        fn abort_start(&mut self) -> anyhow::Result<()> {
            self.aborted = true;
            Ok(())
        }

        fn stop(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn publication_failure_rolls_back_started_interceptor() {
        let mut interceptor = RecordingInterceptor {
            started: false,
            aborted: false,
        };

        let result = start_and_publish(&mut interceptor, || {
            anyhow::bail!("injected PID publication failure")
        });

        assert!(result.is_err());
        assert!(interceptor.started);
        assert!(interceptor.aborted);
    }

    #[test]
    fn systemd_notification_supports_filesystem_socket() {
        let directory = crate::testing::temp_dir("notify");
        let path = directory.path().join("notify.sock");
        let listener = std::os::unix::net::UnixDatagram::bind(&path).unwrap();

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daemon::tests::send_systemd_notifications",
                "--ignored",
            ])
            .env("NOTIFY_SOCKET", &path)
            .status()
            .unwrap();
        assert!(status.success());
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut received = [0; 32];
        for expected in [b"READY=1\n".as_slice(), b"STOPPING=1\n"] {
            let length = listener.recv(&mut received).unwrap();
            assert_eq!(&received[..length], expected);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_notification_supports_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;

        let name = format!("file-guard-notify-{}", std::process::id());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = std::os::unix::net::UnixDatagram::bind_addr(&address).unwrap();

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daemon::tests::send_systemd_notifications",
                "--ignored",
            ])
            .env("NOTIFY_SOCKET", format!("@{name}"))
            .status()
            .unwrap();
        assert!(status.success());
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut received = [0; 32];
        for expected in [b"READY=1\n".as_slice(), b"STOPPING=1\n"] {
            let length = listener.recv(&mut received).unwrap();
            assert_eq!(&received[..length], expected);
        }
    }

    #[test]
    #[ignore = "subprocess entry point for notification tests"]
    fn send_systemd_notifications() {
        notify_systemd_ready();
        notify_systemd_stopping();
    }
}
