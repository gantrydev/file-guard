//! SQLite-backed implementation of the [`crate::store::BackingStore`] trait.
//!
//! Each guarded file gets one row in the `snapshot` table, storing the
//! serialized [`SnapshotRecord`] and its content blob. Writes use
//! compare-and-swap (`WHERE generation = ? AND revision = ?`) so concurrent
//! daemon access is detected at the database layer.
//!
//! # Storage layout
//!
//! The database lives at `$FILE_GUARD_RUNTIME_DIR/snapshot.db` (default:
//! `/var/lib/file-guard/` for the root daemon, `$XDG_RUNTIME_DIR/file-guard/`
//! for a user-mode daemon). The directory is created with mode `0700` and the
//! database file is protected with `flock`-based exclusive locking on open,
//! so only one daemon process can hold it at a time.
//!
//! # Crash safety
//!
//! - **Commit**: writes the new record in a single transaction. If the write
//!   hits the disk but the caller crashes before seeing the result, the next
//!   load sees the committed state — the caller is responsible for reloading
//!   on indeterminate errors (see [`crate::transaction::TransactionManager`]).
//! - **Finalization**: two-phase: insert a marker row, then delete it after the
//!   filesystem rename. A marker found at startup means a finalization was
//!   interrupted and can be completed or rolled back.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use super::record::{
    StoredFinalization, StoredRow, absolute_lexical, decode_finalization, decode_row,
    encode_finalization_header, encode_snapshot_header, phase_name, validate_finalization,
    validate_successor,
};
use super::{
    BackingStore, Entry, FinalizationRecord, Lifecycle, RecordVersion, SnapshotRecord, StoreError,
    StoreResult, path_to_hex,
};

const DATABASE_NAME: &str = "snapshots-v2.sqlite3";
const LOCK_NAME: &str = ".snapshots-v2.lock";
const APPLICATION_ID: i32 = 0x4647_5332;
const SCHEMA_VERSION: i32 = 2;
const SNAPSHOTS_SCHEMA: &str = "CREATE TABLE snapshots (
    path BLOB PRIMARY KEY NOT NULL,
    generation TEXT NOT NULL CHECK(length(generation) = 32),
    revision INTEGER NOT NULL CHECK(revision > 0),
    phase TEXT NOT NULL CHECK(phase IN (
        'captured', 'installing', 'installed', 'mounting', 'unmounting',
        'storing', 'stored', 'restoring', 'restored', 'deleting'
    )),
    header BLOB NOT NULL CHECK(length(header) <= 1048576),
    contents BLOB NOT NULL CHECK(length(contents) <= 16777216)
) STRICT";
const FINALIZATIONS_SCHEMA: &str = "CREATE TABLE finalizations (
    path BLOB PRIMARY KEY NOT NULL,
    generation TEXT NOT NULL CHECK(length(generation) = 32),
    revision INTEGER NOT NULL CHECK(revision > 0),
    header BLOB NOT NULL CHECK(length(header) <= 1048576)
) STRICT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorePoint {
    BeforeCommit,
    AfterCommit,
    BeforeFinalization,
    AfterFinalization,
    BeforeMarkerDelete,
    AfterMarkerDelete,
}

trait StoreHook: Send + Sync {
    fn hit(&self, point: StorePoint) -> StoreResult<()>;
}

struct NoopStoreHook;

impl StoreHook for NoopStoreHook {
    fn hit(&self, _point: StorePoint) -> StoreResult<()> {
        Ok(())
    }
}

pub struct SqliteStore {
    connection: Mutex<Connection>,
    _lock: File,
    hook: Arc<dyn StoreHook>,
}

impl SqliteStore {
    pub fn new() -> StoreResult<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(StoreError::UnsafeConfiguration(
                "the snapshot database must be opened by the root daemon".to_string(),
            ));
        }
        let root = absolute_lexical(&default_store_root()?)?;
        validate_trusted_ancestors(&root)?;
        Self::open_with_hook(root, Arc::new(NoopStoreHook))
    }

    #[cfg(test)]
    pub fn open(root: PathBuf) -> StoreResult<Self> {
        Self::open_with_hook(root, Arc::new(NoopStoreHook))
    }

    fn open_with_hook(root: PathBuf, hook: Arc<dyn StoreHook>) -> StoreResult<Self> {
        let root = prepare_private_root(&absolute_lexical(&root)?)?;
        let lock = open_private_file(&root, LOCK_NAME)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |e| match e {
                rustix::io::Errno::AGAIN => StoreError::Locked,
                _ => StoreError::Io(e.into()),
            },
        )?;

        let database_path = root.join(DATABASE_NAME);
        let database_file = open_private_file(&root, DATABASE_NAME)?;
        validate_private_file(&database_file, "snapshot database")?;
        database_file.sync_all()?;
        open_directory_for_sync(&root)?.sync_all()?;
        drop(database_file);

        let mut connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&connection)?;
        initialize_schema(&mut connection)?;
        verify_database(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            _lock: lock,
            hook,
        })
    }
}

impl BackingStore for SqliteStore {
    fn load(&self, file_id: &Path) -> StoreResult<Entry> {
        let connection = self.connection.lock().unwrap();
        load_record(&connection, file_id)
    }

    fn commit(
        &self,
        file_id: &Path,
        expected: Option<&RecordVersion>,
        next: &SnapshotRecord,
    ) -> StoreResult<RecordVersion> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_record(&transaction, file_id)?;
        validate_successor(file_id, expected, &current, next)?;
        let header = encode_snapshot_header(&next.header)?;
        let path = file_id.as_os_str().as_bytes();
        let revision = revision_to_sql(next.header.revision)?;
        let changed = match expected {
            None => transaction.execute(
                "INSERT INTO snapshots(path, generation, revision, phase, header, contents) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    path,
                    next.header.generation,
                    revision,
                    phase_name(&next.header.lifecycle),
                    header,
                    next.contents,
                ],
            )?,
            Some(expected) => transaction.execute(
                "UPDATE snapshots SET revision = ?1, phase = ?2, header = ?3, contents = ?4 \
                 WHERE path = ?5 AND generation = ?6 AND revision = ?7",
                params![
                    revision,
                    phase_name(&next.header.lifecycle),
                    header,
                    next.contents,
                    path,
                    expected.generation,
                    revision_to_sql(expected.revision)?,
                ],
            )?,
        };
        if changed != 1 {
            return Err(StoreError::Conflict(
                "snapshot compare-and-swap changed no row".to_string(),
            ));
        }
        self.hook.hit(StorePoint::BeforeCommit)?;
        transaction.commit().map_err(|error| {
            StoreError::Indeterminate(format!(
                "SQLite snapshot commit returned an uncertain result: {error}"
            ))
        })?;
        self.hook.hit(StorePoint::AfterCommit).map_err(|error| {
            StoreError::Indeterminate(format!(
                "SQLite snapshot committed before injected failure: {error}"
            ))
        })?;
        Ok(next.version())
    }

    fn begin_finalization(
        &self,
        file_id: &Path,
        expected: &RecordVersion,
        marker: &FinalizationRecord,
    ) -> StoreResult<RecordVersion> {
        validate_finalization(marker)?;
        if marker.path_hex != path_to_hex(file_id)
            || marker.generation != expected.generation
            || marker.revision != expected.revision + 1
        {
            return Err(StoreError::Conflict(
                "finalization marker does not succeed the snapshot".to_string(),
            ));
        }
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_record(&transaction, file_id)?;
        let Entry::Present(current) = current else {
            return Err(StoreError::Conflict(
                "snapshot is not available for finalization".to_string(),
            ));
        };
        if current.version() != *expected {
            return Err(StoreError::Conflict(
                "snapshot revision changed before deletion".to_string(),
            ));
        }
        if current.header.blocked_reason.is_some()
            || !matches!(current.header.lifecycle, Lifecycle::DeleteIntent { .. })
        {
            return Err(StoreError::Conflict(
                "snapshot finalization requires an unblocked deletion intent".to_string(),
            ));
        }
        let marker_header = encode_finalization_header(marker)?;
        transaction.execute(
            "INSERT INTO finalizations(path, generation, revision, header) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                file_id.as_os_str().as_bytes(),
                marker.generation,
                revision_to_sql(marker.revision)?,
                marker_header,
            ],
        )?;
        let changed = transaction.execute(
            "DELETE FROM snapshots WHERE path = ?1 AND generation = ?2 AND revision = ?3",
            params![
                file_id.as_os_str().as_bytes(),
                expected.generation,
                revision_to_sql(expected.revision)?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(
                "snapshot finalization compare-and-swap deleted no row".to_string(),
            ));
        }
        self.hook.hit(StorePoint::BeforeFinalization)?;
        transaction.commit().map_err(|error| {
            StoreError::Indeterminate(format!(
                "SQLite snapshot finalization returned an uncertain result: {error}"
            ))
        })?;
        self.hook
            .hit(StorePoint::AfterFinalization)
            .map_err(|error| {
                StoreError::Indeterminate(format!(
                    "SQLite snapshot finalized before injected failure: {error}"
                ))
            })?;
        Ok(marker.version())
    }

    fn finish_finalization(&self, file_id: &Path, expected: &RecordVersion) -> StoreResult<()> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_record(&transaction, file_id)?;
        let Entry::Finalizing(marker) = current else {
            return Err(StoreError::Conflict(
                "finalization marker is already absent".to_string(),
            ));
        };
        if marker.version() != *expected {
            return Err(StoreError::Conflict(
                "finalization marker revision changed before deletion".to_string(),
            ));
        }
        let changed = transaction.execute(
            "DELETE FROM finalizations WHERE path = ?1 AND generation = ?2 AND revision = ?3",
            params![
                file_id.as_os_str().as_bytes(),
                expected.generation,
                revision_to_sql(expected.revision)?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(
                "finalization marker compare-and-swap deleted no row".to_string(),
            ));
        }
        self.hook.hit(StorePoint::BeforeMarkerDelete)?;
        transaction.commit().map_err(|error| {
            StoreError::Indeterminate(format!(
                "SQLite marker deletion returned an uncertain result: {error}"
            ))
        })?;
        self.hook
            .hit(StorePoint::AfterMarkerDelete)
            .map_err(|error| {
                StoreError::Indeterminate(format!(
                    "SQLite marker was deleted before injected failure: {error}"
                ))
            })
    }

    fn list(&self) -> StoreResult<Vec<Entry>> {
        let connection = self.connection.lock().unwrap();
        let mut records = Vec::new();
        {
            let mut statement = connection.prepare(
                "SELECT path, generation, revision, phase, header, contents \
                 FROM snapshots ORDER BY path",
            )?;
            let rows = statement.query_map([], stored_row)?;
            for row in rows {
                records.push(Entry::Present(Box::new(decode_row(row?)?)));
            }
        }
        let mut statement = connection.prepare(
            "SELECT path, generation, revision, header FROM finalizations ORDER BY path",
        )?;
        let rows = statement.query_map([], finalization_row)?;
        for row in rows {
            records.push(Entry::Finalizing(Box::new(decode_finalization(row?)?)));
        }
        Ok(records)
    }
}

fn stored_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRow> {
    Ok(StoredRow {
        path: row.get(0)?,
        generation: row.get(1)?,
        revision: row.get(2)?,
        phase: row.get(3)?,
        header: row.get(4)?,
        contents: row.get(5)?,
    })
}

fn finalization_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredFinalization> {
    Ok(StoredFinalization {
        path: row.get(0)?,
        generation: row.get(1)?,
        revision: row.get(2)?,
        header: row.get(3)?,
    })
}

fn load_record(connection: &Connection, file_id: &Path) -> StoreResult<Entry> {
    let row = connection
        .query_row(
            "SELECT path, generation, revision, phase, header, contents \
             FROM snapshots WHERE path = ?1",
            [file_id.as_os_str().as_bytes()],
            stored_row,
        )
        .optional()?;
    if let Some(row) = row {
        return Ok(Entry::Present(Box::new(decode_row(row)?)));
    }
    let marker = connection
        .query_row(
            "SELECT path, generation, revision, header FROM finalizations WHERE path = ?1",
            [file_id.as_os_str().as_bytes()],
            finalization_row,
        )
        .optional()?;
    marker.map_or(Ok(Entry::Missing), |value| {
        Ok(Entry::Finalizing(Box::new(decode_finalization(value)?)))
    })
}

fn configure(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA busy_timeout = 0;",
    )?;
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> StoreResult<()> {
    let application_id: i32 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let has_tables: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%')",
        [],
        |row| row.get(0),
    )?;
    if application_id == 0 && !has_tables {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.execute_batch(SNAPSHOTS_SCHEMA)?;
        transaction.execute_batch(FINALIZATIONS_SCHEMA)?;
        transaction.commit().map_err(|error| {
            StoreError::Indeterminate(format!(
                "SQLite schema initialization returned an uncertain result: {error}"
            ))
        })?;
        return Ok(());
    }
    if application_id != APPLICATION_ID {
        return Err(StoreError::UnsupportedFormat(format!(
            "snapshot database application id is {application_id:#x}, expected {APPLICATION_ID:#x}"
        )));
    }
    let schema_version: i32 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if schema_version != SCHEMA_VERSION {
        return Err(StoreError::UnsupportedFormat(format!(
            "snapshot database schema is {schema_version}, expected {SCHEMA_VERSION}"
        )));
    }
    verify_schema(connection)?;
    Ok(())
}

fn verify_schema(connection: &Connection) -> StoreResult<()> {
    for (name, expected) in [
        ("snapshots", SNAPSHOTS_SCHEMA),
        ("finalizations", FINALIZATIONS_SCHEMA),
    ] {
        let schema: Option<(String, String)> = connection
            .query_row(
                "SELECT type, sql FROM sqlite_schema WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((object_type, schema)) = schema else {
            return Err(StoreError::Corrupt(format!(
                "snapshot database has no {name} table"
            )));
        };
        if object_type != "table" || normalize_schema(&schema) != normalize_schema(expected) {
            return Err(StoreError::Corrupt(format!(
                "{name} table schema does not match schema version 2"
            )));
        }
    }
    let unexpected_objects: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%' AND name NOT IN ('snapshots', 'finalizations')
        )",
        [],
        |row| row.get(0),
    )?;
    if unexpected_objects {
        return Err(StoreError::Corrupt(
            "snapshot database contains unexpected schema objects".to_string(),
        ));
    }
    Ok(())
}

fn normalize_schema(schema: &str) -> String {
    schema
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_string()
}

fn verify_database(connection: &Connection) -> StoreResult<()> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if result != "ok" {
        return Err(StoreError::Corrupt(format!(
            "SQLite quick_check failed: {result}"
        )));
    }
    {
        let mut statement = connection
            .prepare("SELECT path, generation, revision, phase, header, contents FROM snapshots")?;
        let rows = statement.query_map([], stored_row)?;
        for row in rows {
            decode_row(row?)?;
        }
    }
    let mut statement =
        connection.prepare("SELECT path, generation, revision, header FROM finalizations")?;
    let rows = statement.query_map([], finalization_row)?;
    for row in rows {
        decode_finalization(row?)?;
    }
    let overlap: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM snapshots
            INNER JOIN finalizations USING(path)
        )",
        [],
        |row| row.get(0),
    )?;
    if overlap {
        return Err(StoreError::Corrupt(
            "a path has both a snapshot and a finalization marker".to_string(),
        ));
    }
    Ok(())
}

fn revision_to_sql(revision: u64) -> StoreResult<i64> {
    i64::try_from(revision)
        .map_err(|_| StoreError::Corrupt("snapshot revision is out of range".to_string()))
}

fn default_store_root() -> StoreResult<PathBuf> {
    let path = std::env::var_os("FILE_GUARD_STORE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/file-guard/store"));
    if !path.is_absolute() {
        return Err(StoreError::UnsafeConfiguration(format!(
            "FILE_GUARD_STORE_DIR must be absolute: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn prepare_private_root(path: &Path) -> StoreResult<PathBuf> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(StoreError::UnsafeConfiguration(format!(
            "snapshot root {} must be a mode-0700 directory owned by uid {}",
            path.display(),
            unsafe { libc::geteuid() }
        )));
    }
    if created {
        open_directory_for_sync(path)?.sync_all()?;
        let parent = path.parent().ok_or_else(|| {
            StoreError::UnsafeConfiguration("snapshot root has no parent".to_string())
        })?;
        open_directory_for_sync(parent)?.sync_all()?;
    }
    Ok(path.to_path_buf())
}

fn open_directory_for_sync(path: &Path) -> StoreResult<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?)
}

fn open_private_file(root: &Path, name: &str) -> StoreResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(root.join(name))?;
    validate_private_file(&file, name)?;
    Ok(file)
}

fn validate_private_file(file: &File, label: &str) -> StoreResult<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(StoreError::UnsafeConfiguration(format!(
            "{label} must be a private, singly-linked regular file"
        )));
    }
    Ok(())
}

fn validate_trusted_ancestors(path: &Path) -> StoreResult<()> {
    let parent = path.parent().ok_or_else(|| {
        StoreError::UnsafeConfiguration("snapshot root has no parent".to_string())
    })?;
    let mut traversed = PathBuf::from("/");
    validate_trusted_ancestor(&traversed)?;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                traversed.push(name);
                validate_trusted_ancestor(&traversed)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(StoreError::UnsafeConfiguration(
                    "snapshot root is not normalized".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_trusted_ancestor(path: &Path) -> StoreResult<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
        return Err(StoreError::UnsafeConfiguration(format!(
            "snapshot ancestor {} must be a root-owned real directory",
            path.display()
        )));
    }
    let writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & libc::S_ISVTX != 0;
    if writable && !sticky {
        return Err(StoreError::UnsafeConfiguration(format!(
            "snapshot ancestor {} must not be writable by group or others",
            path.display()
        )));
    }
    Ok(())
}

pub fn random_token() -> StoreResult<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::super::record::validate_snapshot;
    use super::*;
    use crate::store::{
        FORMAT_VERSION, ObjectIdentity, OriginalState, RecordHeader, RestoreMetadata,
        RestoreOrigin, Timestamp, path_from_hex, path_to_hex, sha256,
    };

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct FailAt {
        point: StorePoint,
        fired: AtomicBool,
    }

    impl FailAt {
        fn new(point: StorePoint) -> Self {
            Self {
                point,
                fired: AtomicBool::new(false),
            }
        }
    }

    impl StoreHook for FailAt {
        fn hit(&self, point: StorePoint) -> StoreResult<()> {
            if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
                return Err(StoreError::Io(std::io::Error::other(format!(
                    "injected failure at {point:?}"
                ))));
            }
            Ok(())
        }
    }

    fn directory(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "file-guard-sqlite-{tag}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn identity(inode: u64) -> ObjectIdentity {
        ObjectIdentity {
            device: 1,
            inode,
            ctime: Timestamp {
                seconds: 2,
                nanoseconds: 3,
            },
            mtime: Timestamp {
                seconds: 2,
                nanoseconds: 3,
            },
            size: 6,
            links: 1,
            mode: libc::S_IFREG | 0o600,
            uid: 1000,
            gid: 1000,
        }
    }

    fn metadata() -> RestoreMetadata {
        RestoreMetadata {
            uid: 1000,
            gid: 1000,
            mode: 0o600,
            atime: Timestamp {
                seconds: 1,
                nanoseconds: 2,
            },
            mtime: Timestamp {
                seconds: 2,
                nanoseconds: 3,
            },
            xattrs: Vec::new(),
        }
    }

    fn record(path: &Path) -> SnapshotRecord {
        let contents = b"secret".to_vec();
        let mut parent = identity(9);
        parent.mode = libc::S_IFDIR | 0o700;
        SnapshotRecord {
            header: RecordHeader {
                format: FORMAT_VERSION,
                path_hex: path_to_hex(path),
                generation: "00112233445566778899aabbccddeeff".to_string(),
                revision: 1,
                lifecycle: Lifecycle::Captured,
                original: OriginalState::Present {
                    identity: identity(10),
                    metadata: metadata(),
                },
                logical_present: true,
                parent,
                staging_path_hex: path_to_hex(Path::new("/staging/transaction")),
                swap_name: "swap".to_string(),
                stored_name: "stored".to_string(),
                placeholder: None,
                mount_token: "ffeeddccbbaa99887766554433221100".to_string(),
                content_sha256: sha256(&contents),
                blocked_reason: None,
            },
            contents,
        }
    }

    fn insert_record(store: &SqliteStore, record: &SnapshotRecord) {
        validate_snapshot(record).unwrap();
        let path = path_from_hex(&record.header.path_hex).unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO snapshots(path, generation, revision, phase, header, contents) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    path.as_os_str().as_bytes(),
                    record.header.generation,
                    revision_to_sql(record.header.revision).unwrap(),
                    phase_name(&record.header.lifecycle),
                    encode_snapshot_header(&record.header).unwrap(),
                    record.contents,
                ],
            )
            .unwrap();
    }

    fn deleting_record(path: &Path) -> SnapshotRecord {
        let mut deleting = record(path);
        deleting.header.lifecycle = Lifecycle::DeleteIntent {
            origin: RestoreOrigin::Stored,
            restored_identity: Some(identity(20)),
            displaced_name: None,
            displaced_identity: None,
            detached_name: Some("stored".to_string()),
            detached_identity: Some(identity(10)),
        };
        deleting
    }

    fn finalization(record: &SnapshotRecord) -> FinalizationRecord {
        FinalizationRecord {
            format: FORMAT_VERSION,
            path_hex: record.header.path_hex.clone(),
            generation: record.header.generation.clone(),
            revision: record.header.revision + 1,
            logical_present: true,
            parent: record.header.parent.clone(),
            staging_path_hex: record.header.staging_path_hex.clone(),
            final_name: "final".to_string(),
            final_identity: Some(identity(30)),
            restore_metadata: metadata(),
            content_length: record.contents.len() as u64,
            content_sha256: record.header.content_sha256.clone(),
        }
    }

    #[test]
    fn snapshot_and_metadata_commit_as_one_row() {
        let root = directory("commit");
        let store = SqliteStore::open(root.clone()).unwrap();
        let path = Path::new("/credential");
        let initial = record(path);
        let version = store.commit(path, None, &initial).unwrap();
        assert_eq!(
            store.load(path).unwrap(),
            Entry::Present(Box::new(initial.clone()))
        );

        let mut next = initial.successor(Lifecycle::InstallIntent, initial.contents.clone());
        next.header.placeholder = Some(identity(11));
        store.commit(path, Some(&version), &next).unwrap();
        assert_eq!(store.load(path).unwrap(), Entry::Present(Box::new(next)));
        drop(store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn transaction_faults_expose_only_old_or_new_rows() {
        for (point, committed) in [
            (StorePoint::BeforeCommit, false),
            (StorePoint::AfterCommit, true),
        ] {
            let root = directory("fault");
            let hook = Arc::new(FailAt::new(point));
            let store = SqliteStore::open_with_hook(root.clone(), hook.clone()).unwrap();
            let path = Path::new("/credential");
            let expected = record(path);
            assert!(store.commit(path, None, &expected).is_err());
            assert!(hook.fired.load(Ordering::SeqCst));
            let actual = store.load(path).unwrap();
            assert_eq!(
                actual,
                if committed {
                    Entry::Present(Box::new(expected))
                } else {
                    Entry::Missing
                }
            );
            drop(store);
            std::fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn finalization_requires_a_durable_deletion_intent() {
        let root = directory("delete");
        let store = SqliteStore::open(root.clone()).unwrap();
        let path = Path::new("/credential");
        let initial = record(path);
        let version = store.commit(path, None, &initial).unwrap();
        let marker = finalization(&initial);
        assert!(matches!(
            store.begin_finalization(path, &version, &marker),
            Err(StoreError::Conflict(_))
        ));
        drop(store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn finalization_faults_expose_the_snapshot_or_marker() {
        for (point, finalized) in [
            (StorePoint::BeforeFinalization, false),
            (StorePoint::AfterFinalization, true),
        ] {
            let root = directory("delete-fault");
            let hook = Arc::new(FailAt::new(point));
            let store = SqliteStore::open_with_hook(root.clone(), hook.clone()).unwrap();
            let path = Path::new("/credential");
            let deleting = deleting_record(path);
            let marker = finalization(&deleting);
            insert_record(&store, &deleting);

            assert!(
                store
                    .begin_finalization(path, &deleting.version(), &marker)
                    .is_err()
            );
            assert!(hook.fired.load(Ordering::SeqCst));
            assert_eq!(
                store.load(path).unwrap(),
                if finalized {
                    Entry::Finalizing(Box::new(marker))
                } else {
                    Entry::Present(Box::new(deleting))
                }
            );
            drop(store);
            std::fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn marker_deletion_faults_leave_the_marker_or_nothing() {
        for (point, deleted) in [
            (StorePoint::BeforeMarkerDelete, false),
            (StorePoint::AfterMarkerDelete, true),
        ] {
            let root = directory("marker-delete-fault");
            let store = SqliteStore::open(root.clone()).unwrap();
            let path = Path::new("/credential");
            let deleting = deleting_record(path);
            let marker = finalization(&deleting);
            insert_record(&store, &deleting);
            store
                .begin_finalization(path, &deleting.version(), &marker)
                .unwrap();
            drop(store);

            let hook = Arc::new(FailAt::new(point));
            let store = SqliteStore::open_with_hook(root.clone(), hook.clone()).unwrap();
            assert!(store.finish_finalization(path, &marker.version()).is_err());
            assert!(hook.fired.load(Ordering::SeqCst));
            assert_eq!(
                store.load(path).unwrap(),
                if deleted {
                    Entry::Missing
                } else {
                    Entry::Finalizing(Box::new(marker))
                }
            );
            drop(store);
            std::fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn malformed_absent_snapshot_is_rejected() {
        let root = directory("absent");
        let store = SqliteStore::open(root.clone()).unwrap();
        let path = Path::new("/credential");
        let mut malformed = record(path);
        malformed.header.original = OriginalState::Absent {
            presentation: metadata(),
        };
        malformed.header.logical_present = false;
        assert!(matches!(
            store.commit(path, None, &malformed),
            Err(StoreError::Corrupt(_))
        ));
        drop(store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn detached_inode_bindings_cannot_change() {
        let root = directory("detached-binding");
        let store = SqliteStore::open(root.clone()).unwrap();
        let path = Path::new("/credential");
        let captured = record(path);
        let captured_version = store.commit(path, None, &captured).unwrap();

        let mut installing =
            captured.successor(Lifecycle::InstallIntent, captured.contents.clone());
        installing.header.placeholder = Some(identity(11));
        let installing_version = store
            .commit(path, Some(&captured_version), &installing)
            .unwrap();

        let wrong = installing.successor(
            Lifecycle::Installed {
                detached_original: Some(identity(99)),
            },
            installing.contents.clone(),
        );
        assert!(matches!(
            store.commit(path, Some(&installing_version), &wrong),
            Err(StoreError::Corrupt(_))
        ));

        let installed = installing.successor(
            Lifecycle::Installed {
                detached_original: Some(identity(10)),
            },
            installing.contents.clone(),
        );
        let installed_version = store
            .commit(path, Some(&installing_version), &installed)
            .unwrap();
        let mut changed_identity = identity(10);
        changed_identity.ctime.seconds += 1;
        let restoring = installed.successor(
            Lifecycle::RestoreIntent {
                origin: RestoreOrigin::Installed,
                restore_name: Some("restore-00112233445566778899aabbccddeeff".to_string()),
                restore_identity: None,
                detached_name: Some("swap".to_string()),
                detached_identity: Some(changed_identity),
            },
            installed.contents.clone(),
        );
        assert!(matches!(
            store.commit(path, Some(&installed_version), &restoring),
            Err(StoreError::Conflict(_))
        ));

        drop(store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn roots_are_exclusively_locked() {
        let root = directory("lock");
        let store = SqliteStore::open(root.clone()).unwrap();
        assert!(matches!(
            SqliteStore::open(root.clone()),
            Err(StoreError::Locked)
        ));
        drop(store);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn matching_version_without_snapshot_table_is_rejected() {
        let root = directory("missing-table");
        drop(SqliteStore::open(root.clone()).unwrap());
        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        connection.execute_batch("DROP TABLE snapshots;").unwrap();
        drop(connection);

        assert!(matches!(
            SqliteStore::open(root.clone()),
            Err(StoreError::Corrupt(message)) if message.contains("no snapshots table")
        ));
        std::fs::remove_dir_all(root).ok();
    }
}
