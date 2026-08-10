use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::config::{RuleAction, RuleEntry};
use crate::policy::engine::{ManagedRule, PolicyEngine, RulePinUpdate};
use crate::policy::rule::Access;
use crate::rule_store::{RuleLease, RuleStore};

const PROTOCOL_VERSION: u32 = 1;
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    pub version: u32,
    pub command: ControlCommand,
}

impl ControlRequest {
    pub fn new(command: ControlCommand) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlCommand {
    ListRules,
    AddRule {
        entry: RuleEntry,
    },
    ImportRules {
        entries: Vec<RuleEntry>,
    },
    EditRule {
        id: i64,
        action: Option<RuleAction>,
        access: Option<Access>,
        pin: RulePinUpdate,
    },
    RemoveRule {
        id: i64,
    },
}

impl ControlCommand {
    fn mutates(&self) -> bool {
        !matches!(self, Self::ListRules)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    Ok { payload: ControlPayload },
    Error { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ControlPayload {
    Rules(Vec<ManagedRule>),
    Added(bool),
    Imported(usize),
    Replaced,
    Removed(RuleEntry),
}

#[derive(Debug)]
pub struct ControlEndpoint {
    listener: Option<UnixListener>,
    path: PathBuf,
    identity: (u64, u64),
}

impl ControlEndpoint {
    pub fn take_listener(&mut self) -> anyhow::Result<UnixListener> {
        self.listener
            .take()
            .ok_or_else(|| anyhow::anyhow!("control listener is already running"))
    }
}

impl Drop for ControlEndpoint {
    fn drop(&mut self) {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                tracing::warn!(
                    "failed to inspect control socket {} during cleanup: {error}",
                    self.path.display()
                );
                return;
            }
        };
        if metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == self.identity
            && let Err(error) = std::fs::remove_file(&self.path)
        {
            tracing::warn!(
                "failed to remove control socket {}: {error}",
                self.path.display()
            );
        }
    }
}

pub fn bind_listener(guarded_gid: u32) -> anyhow::Result<ControlEndpoint> {
    let path = crate::config::control_socket_path()?;
    bind_listener_at(path, guarded_gid)
}

fn bind_listener_at(path: PathBuf, guarded_gid: u32) -> anyhow::Result<ControlEndpoint> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("control socket {} has no parent", path.display()))?;
    crate::secure_file::ensure_trusted_directory(parent, 0o755)?;
    remove_existing_socket(&path)?;
    let listener = UnixListener::bind(&path)
        .map_err(|error| anyhow::anyhow!("binding control socket {}: {error}", path.display()))?;
    let metadata = std::fs::symlink_metadata(&path)?;
    let endpoint = ControlEndpoint {
        listener: Some(listener),
        path,
        identity: (metadata.dev(), metadata.ino()),
    };
    std::os::unix::fs::chown(&endpoint.path, None, Some(guarded_gid))?;
    std::fs::set_permissions(&endpoint.path, std::fs::Permissions::from_mode(0o660))?;
    Ok(endpoint)
}

pub async fn serve(listener: UnixListener, policy: Arc<PolicyEngine>, guarded_uid: u32) {
    let daemon_uid = unsafe { libc::geteuid() };
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut handlers = tokio::task::JoinSet::new();
    loop {
        while handlers.try_join_next().is_some() {}
        let permit = match Arc::clone(&connections).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return,
        };
        let (stream, _) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::error!("control socket accept failed: {error}");
                return;
            }
        };
        let policy = Arc::clone(&policy);
        handlers.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, &policy, daemon_uid, guarded_uid).await {
                tracing::warn!("control request failed: {error}");
            }
        });
    }
}

async fn request_at(path: &Path, command: ControlCommand) -> anyhow::Result<ControlPayload> {
    let stream = tokio::time::timeout(IO_TIMEOUT, UnixStream::connect(path))
        .await
        .map_err(|_| anyhow::anyhow!("timed out connecting to {}", path.display()))??;
    let peer_uid = stream.peer_cred()?.uid();
    let our_uid = unsafe { libc::geteuid() };
    if peer_uid != 0 && peer_uid != our_uid {
        anyhow::bail!("control socket peer uid {peer_uid} is not trusted");
    }

    let (read_half, mut write_half) = stream.into_split();
    let mut bytes = serde_json::to_vec(&ControlRequest::new(command))?;
    if bytes.len() as u64 + 1 > MAX_REQUEST_BYTES {
        anyhow::bail!("control request exceeds {MAX_REQUEST_BYTES} bytes");
    }
    bytes.push(b'\n');
    tokio::time::timeout(IO_TIMEOUT, async {
        write_half.write_all(&bytes).await?;
        write_half.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out writing control request"))??;

    let response = read_message(read_half).await?;
    match serde_json::from_slice::<ControlResponse>(&response)? {
        ControlResponse::Ok { payload } => Ok(payload),
        ControlResponse::Error { message } => anyhow::bail!(message),
    }
}

pub async fn dispatch(command: ControlCommand) -> anyhow::Result<ControlPayload> {
    let paths = crate::config::control_socket_client_paths()?;
    for path in &paths {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                return dispatch_to_endpoint(command, path).await;
            }
            Ok(_) => anyhow::bail!("control path {} is not a Unix socket", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    dispatch_without_endpoint(command, &paths).await
}

async fn dispatch_to_endpoint(
    command: ControlCommand,
    path: &Path,
) -> anyhow::Result<ControlPayload> {
    match request_at(path, command.clone()).await {
        Ok(payload) => Ok(payload),
        Err(request_error) => {
            let database_path = crate::rule_store::rule_store_path()?;
            let lease = match RuleLease::try_acquire(database_path) {
                Ok(Some(lease)) => lease,
                Ok(None) | Err(_) => return Err(request_error),
            };
            remove_existing_socket(path)?;
            execute_offline(command, lease)
        }
    }
}

async fn dispatch_without_endpoint(
    command: ControlCommand,
    control_paths: &[PathBuf],
) -> anyhow::Result<ControlPayload> {
    let database_path = crate::rule_store::rule_store_path()?;
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    loop {
        match RuleLease::try_acquire(database_path.clone()) {
            Ok(Some(lease)) => {
                for path in control_paths {
                    match std::fs::symlink_metadata(path) {
                        Ok(metadata) if metadata.file_type().is_socket() => {
                            remove_existing_socket(path)?;
                        }
                        Ok(_) => {
                            anyhow::bail!("control path {} is not a Unix socket", path.display())
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                return execute_offline(command, lease);
            }
            Ok(None) => {}
            Err(error) if unsafe { libc::geteuid() } != 0 => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }

        for path in control_paths {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_socket() => {
                    return request_at(path, command).await;
                }
                Ok(_) => anyhow::bail!("control path {} is not a Unix socket", path.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("learned-rule owner is active but no control endpoint appeared");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn handle_connection(
    stream: UnixStream,
    policy: &PolicyEngine,
    daemon_uid: u32,
    guarded_uid: u32,
) -> anyhow::Result<()> {
    let peer_uid = stream.peer_cred()?.uid();
    let (read_half, mut write_half) = stream.into_split();
    let request = match read_message(read_half).await {
        Ok(bytes) => serde_json::from_slice::<ControlRequest>(&bytes),
        Err(error) => return Err(error),
    };
    let response = match request {
        Ok(request) if request.version != PROTOCOL_VERSION => ControlResponse::Error {
            message: format!(
                "control protocol version {} is not supported",
                request.version
            ),
        },
        Ok(_) if peer_uid != daemon_uid && peer_uid != guarded_uid => ControlResponse::Error {
            message: format!("uid {peer_uid} may not access file-guard control state"),
        },
        Ok(request) if request.command.mutates() && peer_uid != daemon_uid => {
            ControlResponse::Error {
                message: "rule mutations require root; re-run with sudo".to_string(),
            }
        }
        Ok(request) => execute(policy, request.command),
        Err(error) => ControlResponse::Error {
            message: format!("invalid control request: {error}"),
        },
    };

    let bytes = encode_response(response)?;
    tokio::time::timeout(IO_TIMEOUT, async {
        write_half.write_all(&bytes).await?;
        write_half.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out writing control response"))??;
    Ok(())
}

fn encode_response(response: ControlResponse) -> anyhow::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&response)?;
    if bytes.len() as u64 + 1 > MAX_REQUEST_BYTES {
        bytes = serde_json::to_vec(&ControlResponse::Error {
            message: format!(
                "control response exceeds {MAX_REQUEST_BYTES} bytes; reduce the rule set"
            ),
        })?;
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn execute(policy: &PolicyEngine, command: ControlCommand) -> ControlResponse {
    let result = match command {
        ControlCommand::ListRules => Ok(ControlPayload::Rules(policy.managed_rules())),
        ControlCommand::AddRule { entry } => {
            policy.add_managed_rule(entry).map(ControlPayload::Added)
        }
        ControlCommand::ImportRules { entries } => policy
            .import_managed_rules(entries)
            .map(ControlPayload::Imported),
        ControlCommand::EditRule {
            id,
            action,
            access,
            pin,
        } => policy
            .edit_managed_rule(id, action, access, pin)
            .map(|_| ControlPayload::Replaced),
        ControlCommand::RemoveRule { id } => {
            policy.remove_managed_rule(id).map(ControlPayload::Removed)
        }
    };
    match result {
        Ok(payload) => ControlResponse::Ok { payload },
        Err(error) => ControlResponse::Error {
            message: error.to_string(),
        },
    }
}

fn execute_offline(command: ControlCommand, lease: RuleLease) -> anyhow::Result<ControlPayload> {
    if command.mutates() && unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("offline rule mutations require root; re-run with sudo");
    }
    let store = RuleStore::open(Arc::new(lease))?;
    match command {
        ControlCommand::ListRules => {
            let mut rules = normalized_declarative_rules()?
                .into_iter()
                .map(|entry| ManagedRule {
                    entry,
                    learned_id: None,
                })
                .collect::<Vec<_>>();
            rules.extend(
                store
                    .list()?
                    .into_iter()
                    .map(|stored| {
                        Ok(ManagedRule {
                            entry: crate::policy::engine::normalize_rule_entry(stored.entry)?,
                            learned_id: Some(stored.id),
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
            Ok(ControlPayload::Rules(rules))
        }
        ControlCommand::AddRule { entry } => {
            let entry = crate::policy::engine::normalize_rule_entry(entry)?;
            let declarative = normalized_declarative_rules()?;
            if declarative.contains(&entry) {
                return Ok(ControlPayload::Added(false));
            }
            Ok(ControlPayload::Added(store.insert(&entry)?.is_some()))
        }
        ControlCommand::ImportRules { entries } => {
            let entries = entries
                .into_iter()
                .map(crate::policy::engine::normalize_rule_entry)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let declarative = normalized_declarative_rules()?;
            let entries = entries
                .into_iter()
                .filter(|entry| !declarative.contains(entry))
                .collect::<Vec<_>>();
            Ok(ControlPayload::Imported(store.insert_many(&entries)?.len()))
        }
        ControlCommand::EditRule {
            id,
            action,
            access,
            pin,
        } => {
            let current = store
                .list()?
                .into_iter()
                .find(|stored| stored.id == id)
                .ok_or_else(|| anyhow::anyhow!("learned rule {id} does not exist"))?;
            let entry = crate::policy::engine::edit_rule_entry(current.entry, action, access, pin)?;
            if normalized_declarative_rules()?.contains(&entry)
                || store
                    .list()?
                    .iter()
                    .any(|stored| stored.id != id && stored.entry == entry)
            {
                anyhow::bail!("an identical rule already exists");
            }
            store.replace(id, &entry)?;
            Ok(ControlPayload::Replaced)
        }
        ControlCommand::RemoveRule { id } => {
            let entry = store
                .list()?
                .into_iter()
                .find(|stored| stored.id == id)
                .ok_or_else(|| anyhow::anyhow!("learned rule {id} does not exist"))?
                .entry;
            store.remove(id)?;
            Ok(ControlPayload::Removed(entry))
        }
    }
}

fn normalized_declarative_rules() -> anyhow::Result<Vec<RuleEntry>> {
    crate::config::Config::load()?
        .rule
        .into_iter()
        .map(crate::policy::engine::normalize_rule_entry)
        .collect()
}

async fn read_message(read_half: tokio::net::unix::OwnedReadHalf) -> anyhow::Result<Vec<u8>> {
    let mut reader = BufReader::new(read_half).take(MAX_REQUEST_BYTES + 1);
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(IO_TIMEOUT, reader.read_until(b'\n', &mut bytes))
        .await
        .map_err(|_| anyhow::anyhow!("timed out reading control message"))??;
    if read == 0 {
        anyhow::bail!("control peer closed without a message");
    }
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        anyhow::bail!("control message exceeds {MAX_REQUEST_BYTES} bytes");
    }
    if bytes.last() != Some(&b'\n') {
        anyhow::bail!("control message is not newline-terminated");
    }
    bytes.pop();
    Ok(bytes)
}

fn remove_existing_socket(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!(
            "refusing to replace unsafe control socket path {}",
            path.display()
        );
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => anyhow::bail!("a control listener is already active at {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "cannot verify whether control socket {} is stale: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RuleAction};
    use crate::policy::rule::Access;
    use crate::prompt::PromptClient;
    use crate::rule_store::MemoryRuleStore;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn endpoint_test_directory() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::current_dir().unwrap().join(format!(
            ".fg-ctl-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn policy() -> Arc<PolicyEngine> {
        let config: Config = toml::from_str("[settings]\n").unwrap();
        let prompt = Arc::new(PromptClient::new(
            PathBuf::from("/nonexistent.sock"),
            Duration::from_secs(1),
            unsafe { libc::getuid() },
        ));
        Arc::new(PolicyEngine::new(&config, prompt, Arc::new(MemoryRuleStore::new())).unwrap())
    }

    fn entry() -> RuleEntry {
        RuleEntry {
            file: "/credential".into(),
            binary: "/usr/bin/tool".into(),
            action: RuleAction::Allow,
            access: Access::Any,
            sha256: None,
            signature: None,
            script: None,
            script_sha256: None,
        }
    }

    #[test]
    fn commands_mutate_the_policy_repository() {
        let policy = policy();
        assert!(matches!(
            execute(&policy, ControlCommand::AddRule { entry: entry() }),
            ControlResponse::Ok {
                payload: ControlPayload::Added(true)
            }
        ));
        let id = match execute(&policy, ControlCommand::ListRules) {
            ControlResponse::Ok {
                payload: ControlPayload::Rules(rules),
            } => rules[0].learned_id.unwrap(),
            _ => panic!("unexpected list response"),
        };
        assert!(matches!(
            execute(
                &policy,
                ControlCommand::EditRule {
                    id,
                    action: Some(RuleAction::Deny),
                    access: None,
                    pin: RulePinUpdate::Keep,
                }
            ),
            ControlResponse::Ok {
                payload: ControlPayload::Replaced
            }
        ));
        assert!(matches!(
            execute(
                &policy,
                ControlCommand::EditRule {
                    id,
                    action: None,
                    access: Some(Access::Read),
                    pin: RulePinUpdate::Keep,
                }
            ),
            ControlResponse::Ok {
                payload: ControlPayload::Replaced
            }
        ));
        let edited = policy.managed_rules();
        assert_eq!(edited[0].entry.action, RuleAction::Deny);
        assert_eq!(edited[0].entry.access, Access::Read);
        assert!(matches!(
            execute(&policy, ControlCommand::RemoveRule { id }),
            ControlResponse::Ok {
                payload: ControlPayload::Removed(_)
            }
        ));
        assert!(policy.managed_rules().is_empty());
    }

    #[tokio::test]
    async fn protocol_version_mismatch_returns_an_error_response() {
        let (client, server) = UnixStream::pair().unwrap();
        let policy = policy();
        let uid = unsafe { libc::geteuid() };
        let task = tokio::spawn(async move { handle_connection(server, &policy, uid, uid).await });
        let (read_half, mut write_half) = client.into_split();
        let mut bytes = serde_json::to_vec(&ControlRequest {
            version: PROTOCOL_VERSION + 1,
            command: ControlCommand::ListRules,
        })
        .unwrap();
        bytes.push(b'\n');
        write_half.write_all(&bytes).await.unwrap();
        write_half.flush().await.unwrap();

        let mut line = String::new();
        BufReader::new(read_half)
            .read_line(&mut line)
            .await
            .unwrap();
        let response: ControlResponse = serde_json::from_str(line.trim()).unwrap();
        match response {
            ControlResponse::Error { message } => {
                assert!(message.contains("not supported"));
            }
            _ => panic!("unexpected control response"),
        }
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn oversized_message_is_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        let (_, mut write_half) = client.into_split();
        let (read_half, _) = server.into_split();
        let writer = tokio::spawn(async move {
            let mut bytes = vec![b'x'; MAX_REQUEST_BYTES as usize + 1];
            bytes.push(b'\n');
            let _ = write_half.write_all(&bytes).await;
        });
        let error = read_message(read_half).await.unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        writer.await.unwrap();
    }

    #[test]
    fn oversized_response_becomes_a_bounded_error() {
        let mut oversized = entry();
        oversized.binary = "x".repeat(MAX_REQUEST_BYTES as usize);
        let bytes = encode_response(ControlResponse::Ok {
            payload: ControlPayload::Rules(vec![ManagedRule {
                entry: oversized,
                learned_id: None,
            }]),
        })
        .unwrap();
        assert!(bytes.len() as u64 <= MAX_REQUEST_BYTES);
        let response: ControlResponse = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        assert!(matches!(response, ControlResponse::Error { .. }));
    }

    #[tokio::test]
    async fn active_control_socket_cannot_be_replaced() {
        let directory = endpoint_test_directory();
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("control.sock");
        let endpoint = bind_listener_at(path.clone(), unsafe { libc::getegid() }).unwrap();

        let error = bind_listener_at(path.clone(), unsafe { libc::getegid() }).unwrap_err();
        assert!(error.to_string().contains("already active"));
        assert!(path.exists());

        drop(endpoint);
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn stale_control_socket_is_replaced_and_cleaned_up() {
        let directory = endpoint_test_directory();
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("control.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());

        let endpoint = bind_listener_at(path.clone(), unsafe { libc::getegid() }).unwrap();
        std::os::unix::net::UnixStream::connect(&path).unwrap();

        drop(endpoint);
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }
}
