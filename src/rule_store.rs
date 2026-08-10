use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::config::RuleEntry;

const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRule {
    pub id: i64,
    pub entry: RuleEntry,
}

pub struct RuleStore {
    connection: Mutex<Connection>,
    _lease: Arc<RuleLease>,
}

#[derive(Debug)]
pub struct RuleLease {
    database_path: PathBuf,
    _file: std::fs::File,
}

pub trait RuleRepository: Send + Sync {
    fn list(&self) -> anyhow::Result<Vec<StoredRule>>;
    fn insert(&self, entry: &RuleEntry) -> anyhow::Result<Option<StoredRule>>;
    fn insert_many(&self, entries: &[RuleEntry]) -> anyhow::Result<Vec<StoredRule>>;
    fn replace(&self, id: i64, entry: &RuleEntry) -> anyhow::Result<()>;
    fn remove(&self, id: i64) -> anyhow::Result<()>;
}

impl RuleStore {
    pub fn open(lease: Arc<RuleLease>) -> anyhow::Result<Self> {
        let path = &lease.database_path;
        if !path.is_absolute() {
            anyhow::bail!("rule database path must be absolute: {}", path.display());
        }
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("rule database {} has no parent", path.display()))?;
        prepare_parent(parent)?;
        prepare_database_file(path)?;

        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_schema(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            _lease: lease,
        })
    }

    pub fn list(&self) -> anyhow::Result<Vec<StoredRule>> {
        let connection = self.connection.lock().unwrap();
        let mut statement =
            connection.prepare("SELECT id, entry_json FROM learned_rules ORDER BY id ASC")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (id, json) = row?;
            let entry = serde_json::from_slice(&json)
                .map_err(|error| anyhow::anyhow!("learned rule {id} is corrupt: {error}"))?;
            Ok(StoredRule { id, entry })
        })
        .collect()
    }

    pub fn insert(&self, entry: &RuleEntry) -> anyhow::Result<Option<StoredRule>> {
        Ok(self.insert_many(std::slice::from_ref(entry))?.pop())
    }

    pub fn insert_many(&self, entries: &[RuleEntry]) -> anyhow::Result<Vec<StoredRule>> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut inserted = Vec::new();
        for entry in entries {
            let json = serde_json::to_vec(entry)?;
            let changed = transaction.execute(
                "INSERT OR IGNORE INTO learned_rules(entry_json) VALUES (?1)",
                params![json],
            )?;
            if changed == 0 {
                continue;
            }
            let id = transaction
                .query_row(
                    "SELECT id FROM learned_rules WHERE entry_json = ?1",
                    params![json],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or_else(|| anyhow::anyhow!("inserted learned rule could not be reloaded"))?;
            inserted.push(StoredRule {
                id,
                entry: entry.clone(),
            });
        }
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn replace(&self, id: i64, entry: &RuleEntry) -> anyhow::Result<()> {
        let json = serde_json::to_vec(entry)?;
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE learned_rules SET entry_json = ?1 WHERE id = ?2",
            params![json, id],
        )?;
        if changed != 1 {
            anyhow::bail!("learned rule {id} does not exist");
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn remove(&self, id: i64) -> anyhow::Result<()> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed =
            transaction.execute("DELETE FROM learned_rules WHERE id = ?1", params![id])?;
        if changed != 1 {
            anyhow::bail!("learned rule {id} does not exist");
        }
        transaction.commit()?;
        Ok(())
    }
}

impl RuleLease {
    pub fn try_acquire(database_path: PathBuf) -> anyhow::Result<Option<Self>> {
        if !database_path.is_absolute() {
            anyhow::bail!(
                "rule database path must be absolute: {}",
                database_path.display()
            );
        }
        let parent = database_path.parent().ok_or_else(|| {
            anyhow::anyhow!("rule database {} has no parent", database_path.display())
        })?;
        prepare_parent(parent)?;
        let lock_path = owner_lock_path(&database_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            anyhow::bail!(
                "rule owner lock {} must be a regular file owned by uid {}",
                lock_path.display(),
                unsafe { libc::geteuid() }
            );
        }
        if metadata.mode() & 0o7777 != 0o600 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self {
                database_path,
                _file: file,
            })),
            Err(rustix::io::Errno::AGAIN) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl RuleRepository for RuleStore {
    fn list(&self) -> anyhow::Result<Vec<StoredRule>> {
        RuleStore::list(self)
    }

    fn insert(&self, entry: &RuleEntry) -> anyhow::Result<Option<StoredRule>> {
        RuleStore::insert(self, entry)
    }

    fn insert_many(&self, entries: &[RuleEntry]) -> anyhow::Result<Vec<StoredRule>> {
        RuleStore::insert_many(self, entries)
    }

    fn replace(&self, id: i64, entry: &RuleEntry) -> anyhow::Result<()> {
        RuleStore::replace(self, id, entry)
    }

    fn remove(&self, id: i64) -> anyhow::Result<()> {
        RuleStore::remove(self, id)
    }
}

#[cfg(test)]
pub struct MemoryRuleStore {
    state: Mutex<MemoryRuleState>,
}

#[cfg(test)]
struct MemoryRuleState {
    rules: Vec<StoredRule>,
    next_id: i64,
}

#[cfg(test)]
impl MemoryRuleStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemoryRuleState {
                rules: Vec::new(),
                next_id: 1,
            }),
        }
    }
}

#[cfg(test)]
impl RuleRepository for MemoryRuleStore {
    fn list(&self) -> anyhow::Result<Vec<StoredRule>> {
        Ok(self.state.lock().unwrap().rules.clone())
    }

    fn insert(&self, entry: &RuleEntry) -> anyhow::Result<Option<StoredRule>> {
        Ok(self.insert_many(std::slice::from_ref(entry))?.pop())
    }

    fn insert_many(&self, entries: &[RuleEntry]) -> anyhow::Result<Vec<StoredRule>> {
        let mut state = self.state.lock().unwrap();
        let mut inserted = Vec::new();
        for entry in entries {
            if state.rules.iter().any(|stored| stored.entry == *entry) {
                continue;
            }
            let stored = StoredRule {
                id: state.next_id,
                entry: entry.clone(),
            };
            state.next_id += 1;
            state.rules.push(stored.clone());
            inserted.push(stored);
        }
        Ok(inserted)
    }

    fn replace(&self, id: i64, entry: &RuleEntry) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state
            .rules
            .iter()
            .any(|stored| stored.id != id && stored.entry == *entry)
        {
            anyhow::bail!("an identical rule already exists");
        }
        let stored = state
            .rules
            .iter_mut()
            .find(|stored| stored.id == id)
            .ok_or_else(|| anyhow::anyhow!("learned rule {id} does not exist"))?;
        stored.entry = entry.clone();
        Ok(())
    }

    fn remove(&self, id: i64) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        let index = state
            .rules
            .iter()
            .position(|stored| stored.id == id)
            .ok_or_else(|| anyhow::anyhow!("learned rule {id} does not exist"))?;
        state.rules.remove(index);
        Ok(())
    }
}

pub fn rule_store_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("FILE_GUARD_RULES_DB") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            anyhow::bail!("FILE_GUARD_RULES_DB must be an absolute path");
        }
        return Ok(path);
    }
    if let Some(store) = std::env::var_os("FILE_GUARD_STORE_DIR") {
        let store = PathBuf::from(store);
        if !store.is_absolute() {
            anyhow::bail!("FILE_GUARD_STORE_DIR must be absolute");
        }
        if let Some(parent) = store.parent() {
            return Ok(parent.join("rules.sqlite"));
        }
    }
    Ok(PathBuf::from("/var/lib/file-guard/rules.sqlite"))
}

fn initialize_schema(connection: &mut Connection) -> anyhow::Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        0 => {
            transaction.execute_batch(
                "CREATE TABLE learned_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_json BLOB NOT NULL UNIQUE
                );",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        SCHEMA_VERSION => {}
        other => anyhow::bail!("unsupported learned-rule database schema version {other}"),
    }
    transaction.commit()?;
    Ok(())
}

fn prepare_parent(path: &Path) -> anyhow::Result<()> {
    crate::secure_file::ensure_trusted_directory(path, 0o700)?;
    Ok(())
}

fn owner_lock_path(path: &Path) -> anyhow::Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("rule database {} has no file name", path.display()))?
        .to_os_string();
    name.push(".owner.lock");
    Ok(path.with_file_name(name))
}

fn prepare_database_file(path: &Path) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() }
    {
        anyhow::bail!(
            "rule database {} must be a regular file owned by uid {}",
            path.display(),
            unsafe { libc::geteuid() }
        );
    }
    if metadata.mode() & 0o7777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleAction;
    use crate::policy::rule::Access;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "file-guard-rules-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn rule(hash: &str) -> RuleEntry {
        RuleEntry {
            file: "/credential".into(),
            binary: "/usr/bin/tool".into(),
            action: RuleAction::Allow,
            access: Access::Any,
            sha256: Some(hash.into()),
            signature: None,
            script: None,
            script_sha256: None,
        }
    }

    fn cleanup(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let candidate = suffixed(path, suffix);
            if candidate.exists() {
                std::fs::remove_file(candidate).unwrap();
            }
        }
        let lock = owner_lock_path(path).unwrap();
        if lock.exists() {
            std::fs::remove_file(lock).unwrap();
        }
    }

    fn suffixed(path: &Path, suffix: &str) -> PathBuf {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        PathBuf::from(candidate)
    }

    #[test]
    fn inserts_deduplicates_replaces_and_removes_rules() {
        let path = path();
        let lease = Arc::new(RuleLease::try_acquire(path.clone()).unwrap().unwrap());
        let store = RuleStore::open(Arc::clone(&lease)).unwrap();
        let stored = store.insert(&rule("one")).unwrap().unwrap();
        assert!(store.insert(&rule("one")).unwrap().is_none());
        assert_eq!(store.list().unwrap(), vec![stored.clone()]);

        for suffix in ["", "-wal", "-shm"] {
            let candidate = suffixed(&path, suffix);
            if candidate.exists() {
                assert_eq!(std::fs::metadata(candidate).unwrap().mode() & 0o7777, 0o600);
            }
        }

        store.replace(stored.id, &rule("two")).unwrap();
        assert_eq!(store.list().unwrap()[0].entry, rule("two"));
        store.remove(stored.id).unwrap();
        assert!(store.list().unwrap().is_empty());
        drop(store);
        drop(lease);
        cleanup(&path);
    }

    #[test]
    fn concurrent_connections_preserve_every_insert() {
        use std::sync::{Arc, Barrier};

        let path = path();
        let lease = Arc::new(RuleLease::try_acquire(path.clone()).unwrap().unwrap());
        let stores = [
            RuleStore::open(Arc::clone(&lease)).unwrap(),
            RuleStore::open(Arc::clone(&lease)).unwrap(),
        ];
        let barrier = Arc::new(Barrier::new(stores.len()));
        let threads = stores
            .into_iter()
            .enumerate()
            .map(|(worker, store)| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for index in 0..32 {
                        store.insert(&rule(&format!("{worker}-{index}"))).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }

        let store = RuleStore::open(Arc::clone(&lease)).unwrap();
        assert_eq!(store.list().unwrap().len(), 64);
        drop(store);
        drop(lease);
        cleanup(&path);
    }

    #[test]
    fn owner_lease_is_exclusive_and_recoverable() {
        let path = path();
        let first = RuleLease::try_acquire(path.clone()).unwrap().unwrap();
        assert!(RuleLease::try_acquire(path.clone()).unwrap().is_none());

        drop(first);
        let second = RuleLease::try_acquire(path.clone()).unwrap().unwrap();
        drop(second);
        cleanup(&path);
    }

    #[test]
    fn open_store_retains_its_owner_lease() {
        let path = path();
        let lease = Arc::new(RuleLease::try_acquire(path.clone()).unwrap().unwrap());
        let store = RuleStore::open(Arc::clone(&lease)).unwrap();
        drop(lease);
        assert!(RuleLease::try_acquire(path.clone()).unwrap().is_none());

        drop(store);
        let recovered = RuleLease::try_acquire(path.clone()).unwrap().unwrap();
        drop(recovered);
        cleanup(&path);
    }
}
