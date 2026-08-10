use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use fs2::FileExt;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use super::{
    BackingStore, Entry, FORMAT_VERSION, FinalizationRecord, Lifecycle, MAX_CREDENTIAL_SIZE,
    ObjectIdentity, OriginalState, RecordHeader, RecordVersion, RestoreMetadata, RestoreOrigin,
    SnapshotRecord, StoreError, StoreResult, UnmountNext, path_from_hex, path_to_hex, sha256,
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
        let root = absolute_lexical(&default_store_root())?;
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
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                StoreError::Locked
            } else {
                StoreError::Io(error)
            }
        })?;

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

    fn validate_successor(
        file_id: &Path,
        expected: Option<&RecordVersion>,
        current: &Entry,
        next: &SnapshotRecord,
    ) -> StoreResult<()> {
        validate_snapshot(next)?;
        if next.header.path_hex != path_to_hex(file_id) {
            return Err(StoreError::Conflict(
                "candidate snapshot is bound to a different path".to_string(),
            ));
        }
        match (expected, current) {
            (None, Entry::Missing)
                if next.header.revision == 1
                    && matches!(next.header.lifecycle, Lifecycle::Captured)
                    && next.header.logical_present == next.header.original.existed()
                    && next.header.placeholder.is_none()
                    && next.header.blocked_reason.is_none() =>
            {
                Ok(())
            }
            (None, Entry::Missing) => Err(StoreError::Conflict(
                "a new snapshot must start as an unblocked revision-1 capture".to_string(),
            )),
            (None, Entry::Present(_)) => {
                Err(StoreError::Conflict("snapshot already exists".to_string()))
            }
            (None, Entry::Finalizing(_)) => Err(StoreError::Conflict(
                "snapshot path still has a finalization marker".to_string(),
            )),
            (Some(_), Entry::Missing) => Err(StoreError::Conflict(
                "snapshot was deleted before it could be updated".to_string(),
            )),
            (Some(_), Entry::Finalizing(_)) => Err(StoreError::Conflict(
                "snapshot became a finalization marker before update".to_string(),
            )),
            (Some(expected), Entry::Present(current)) => {
                if current.version() != *expected {
                    return Err(StoreError::Conflict(
                        "snapshot revision changed before update".to_string(),
                    ));
                }
                if next.header.generation != expected.generation
                    || next.header.revision != expected.revision + 1
                {
                    return Err(StoreError::Conflict(
                        "successor must retain its generation and increment revision once"
                            .to_string(),
                    ));
                }
                validate_successor_fields(current, next)
            }
        }
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
        Self::validate_successor(file_id, expected, &current, next)?;
        let header = serde_json::to_vec(&next.header)?;
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
        let marker_header = serde_json::to_vec(marker)?;
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

struct StoredRow {
    path: Vec<u8>,
    generation: String,
    revision: i64,
    phase: String,
    header: Vec<u8>,
    contents: Vec<u8>,
}

struct StoredFinalization {
    path: Vec<u8>,
    generation: String,
    revision: i64,
    header: Vec<u8>,
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

fn decode_row(row: StoredRow) -> StoreResult<SnapshotRecord> {
    let header: RecordHeader = serde_json::from_slice(&row.header)?;
    let revision = u64::try_from(row.revision)
        .map_err(|_| StoreError::Corrupt("snapshot revision is out of range".to_string()))?;
    if header.path_hex != hex::encode(&row.path)
        || header.generation != row.generation
        || header.revision != revision
        || phase_name(&header.lifecycle) != row.phase
    {
        return Err(StoreError::Corrupt(
            "snapshot row indexes disagree with its header".to_string(),
        ));
    }
    let record = SnapshotRecord {
        header,
        contents: row.contents,
    };
    validate_snapshot(&record)?;
    Ok(record)
}

fn decode_finalization(row: StoredFinalization) -> StoreResult<FinalizationRecord> {
    let marker: FinalizationRecord = serde_json::from_slice(&row.header)?;
    let revision = u64::try_from(row.revision)
        .map_err(|_| StoreError::Corrupt("marker revision is out of range".to_string()))?;
    if marker.path_hex != hex::encode(&row.path)
        || marker.generation != row.generation
        || marker.revision != revision
    {
        return Err(StoreError::Corrupt(
            "finalization row indexes disagree with its header".to_string(),
        ));
    }
    validate_finalization(&marker)?;
    Ok(marker)
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

fn validate_successor_fields(current: &SnapshotRecord, next: &SnapshotRecord) -> StoreResult<()> {
    let current_header = &current.header;
    let next_header = &next.header;
    if current_header.path_hex != next_header.path_hex
        || current_header.generation != next_header.generation
        || current_header.original != next_header.original
        || current_header.parent != next_header.parent
        || current_header.staging_path_hex != next_header.staging_path_hex
        || current_header.swap_name != next_header.swap_name
        || current_header.stored_name != next_header.stored_name
        || current_header.mount_token != next_header.mount_token
    {
        return Err(StoreError::Conflict(
            "immutable capture fields changed".to_string(),
        ));
    }
    if current_header.placeholder != next_header.placeholder
        && !(matches!(
            (&current_header.lifecycle, &next_header.lifecycle),
            (Lifecycle::InstallIntent, Lifecycle::Installed { .. })
        ) && identities_match_after_rename(
            current_header.placeholder.as_ref(),
            next_header.placeholder.as_ref(),
        ))
        && !(matches!(
            (&current_header.lifecycle, &next_header.lifecycle),
            (Lifecycle::Captured, Lifecycle::InstallIntent)
        ) && current_header.placeholder.is_none()
            && next_header.placeholder.is_some())
    {
        return Err(StoreError::Conflict(
            "placeholder identity changed outside installation".to_string(),
        ));
    }
    if current_header.blocked_reason.is_some() {
        return Err(StoreError::Conflict(
            "a blocked snapshot cannot transition automatically".to_string(),
        ));
    }
    let blocking = next_header.blocked_reason.is_some()
        && current_header.blocked_reason.is_none()
        && current_header.lifecycle == next_header.lifecycle
        && current_header.logical_present == next_header.logical_present
        && current.contents == next.contents;
    if blocking {
        return Ok(());
    }
    if next_header.blocked_reason.is_some() {
        return Err(StoreError::Conflict(
            "blocking a snapshot may not change its phase or contents".to_string(),
        ));
    }
    let mounted_update = matches!(
        (&current_header.lifecycle, &next_header.lifecycle),
        (Lifecycle::MountIntent { .. }, Lifecycle::MountIntent { .. })
    );
    if current.contents != next.contents && !mounted_update {
        return Err(StoreError::Conflict(
            "credential contents changed outside a mounted update".to_string(),
        ));
    }
    if current_header.logical_present != next_header.logical_present
        && !(mounted_update && !current_header.logical_present && next_header.logical_present)
    {
        return Err(StoreError::Conflict(
            "logical presence changed outside the first mounted write".to_string(),
        ));
    }
    if !lifecycle_transition_is_valid(current_header, next_header) {
        return Err(StoreError::Conflict(format!(
            "invalid snapshot transition from {:?} to {:?}",
            current_header.lifecycle, next_header.lifecycle
        )));
    }
    Ok(())
}

fn lifecycle_transition_is_valid(current: &RecordHeader, next: &RecordHeader) -> bool {
    use Lifecycle::*;
    match (&current.lifecycle, &next.lifecycle) {
        (Captured, InstallIntent) => true,
        (Captured, StoreIntent { detached_name }) => detached_name == &current.stored_name,
        (InstallIntent, Installed { .. }) => true,
        (
            Installed {
                detached_original: current_detached,
            },
            MountIntent {
                detached_original: next_detached,
            },
        )
        | (
            MountIntent {
                detached_original: current_detached,
            },
            Installed {
                detached_original: next_detached,
            },
        )
        | (
            MountIntent {
                detached_original: current_detached,
            },
            MountIntent {
                detached_original: next_detached,
            },
        ) => current_detached == next_detached,
        (
            MountIntent {
                detached_original: current_detached,
            },
            UnmountIntent {
                detached_original: next_detached,
                ..
            },
        ) => current_detached == next_detached,
        (
            UnmountIntent {
                next: UnmountNext::LeaveInstalled,
                detached_original: current_detached,
            },
            Installed {
                detached_original: next_detached,
            },
        ) => current_detached == next_detached,
        (
            Installed { detached_original },
            RestoreIntent {
                origin,
                detached_identity,
                ..
            },
        ) => {
            *origin == RestoreOrigin::Installed
                && detached_original == detached_identity
                && restore_intent_matches_header(next)
        }
        (
            UnmountIntent {
                next: UnmountNext::Restore,
                detached_original,
            },
            RestoreIntent {
                origin,
                detached_identity,
                ..
            },
        ) => {
            *origin == RestoreOrigin::Installed
                && detached_original == detached_identity
                && restore_intent_matches_header(next)
        }
        (
            StoreIntent {
                detached_name: intended,
            },
            Stored { detached_name, .. },
        ) => intended == detached_name,
        (
            Stored {
                detached_name,
                detached_original,
            },
            RestoreIntent {
                origin,
                detached_name: next_name,
                detached_identity,
                ..
            },
        ) => {
            *origin == RestoreOrigin::Stored
                && next_name.as_ref() == Some(detached_name)
                && detached_identity.as_ref() == Some(detached_original)
                && restore_intent_matches_header(next)
        }
        (
            RestoreIntent {
                origin: current_origin,
                restore_name: current_name,
                restore_identity: None,
                detached_name: current_detached_name,
                detached_identity: current_detached_identity,
            },
            RestoreIntent {
                origin: next_origin,
                restore_name: next_name,
                restore_identity: Some(_),
                detached_name: next_detached_name,
                detached_identity: next_detached_identity,
            },
        ) => {
            current.logical_present
                && current_origin == next_origin
                && current_name == next_name
                && current_detached_name == next_detached_name
                && current_detached_identity == next_detached_identity
        }
        (
            RestoreIntent {
                origin: current_origin,
                restore_name,
                restore_identity,
                detached_name: current_detached_name,
                detached_identity: current_detached_identity,
            },
            Restored {
                origin: next_origin,
                restored_identity,
                displaced_name,
                detached_name: next_detached_name,
                detached_identity: next_detached_identity,
                ..
            },
        ) => {
            current_origin == next_origin
                && identities_match_after_rename(
                    restore_identity.as_ref(),
                    restored_identity.as_ref(),
                )
                && current_detached_name == next_detached_name
                && current_detached_identity == next_detached_identity
                && match current_origin {
                    RestoreOrigin::Installed => displaced_name == restore_name,
                    RestoreOrigin::Stored => displaced_name.is_none(),
                }
        }
        (
            Restored {
                origin: current_origin,
                restored_identity: current_restored,
                displaced_name: current_displaced_name,
                displaced_identity: current_displaced_identity,
                detached_name: current_detached_name,
                detached_identity: current_detached_identity,
            },
            DeleteIntent {
                origin: next_origin,
                restored_identity: next_restored,
                displaced_name: next_displaced_name,
                displaced_identity: next_displaced_identity,
                detached_name: next_detached_name,
                detached_identity: next_detached_identity,
            },
        ) => {
            current_origin == next_origin
                && current_restored == next_restored
                && current_displaced_name == next_displaced_name
                && current_displaced_identity == next_displaced_identity
                && current_detached_name == next_detached_name
                && current_detached_identity == next_detached_identity
        }
        _ => false,
    }
}

fn identities_match_after_rename(
    before: Option<&ObjectIdentity>,
    after: Option<&ObjectIdentity>,
) -> bool {
    match (before, after) {
        (None, None) => true,
        (Some(before), Some(after)) => {
            before.device == after.device
                && before.inode == after.inode
                && before.mtime == after.mtime
                && before.size == after.size
                && before.links == after.links
                && before.mode == after.mode
                && before.uid == after.uid
                && before.gid == after.gid
        }
        _ => false,
    }
}

fn validate_snapshot(record: &SnapshotRecord) -> StoreResult<()> {
    let header = &record.header;
    if header.format != FORMAT_VERSION {
        return corrupt("snapshot format is unsupported");
    }
    if header.revision == 0 {
        return corrupt("snapshot revision must be positive");
    }
    validate_token(&header.generation, "generation")?;
    validate_token(&header.mount_token, "mount token")?;
    if record.contents.len() > MAX_CREDENTIAL_SIZE {
        return corrupt("credential exceeds the maximum snapshot size");
    }
    if header.content_sha256 != sha256(&record.contents) {
        return corrupt("snapshot content digest is incorrect");
    }
    if header
        .blocked_reason
        .as_ref()
        .is_some_and(|reason| reason.is_empty())
    {
        return corrupt("blocked snapshots require a reason");
    }
    let path = path_from_hex(&header.path_hex)?;
    let staging_path = path_from_hex(&header.staging_path_hex)?;
    if !path.is_absolute()
        || !staging_path.is_absolute()
        || absolute_lexical(&path)? != path
        || absolute_lexical(&staging_path)? != staging_path
    {
        return corrupt("snapshot paths must be absolute and normalized");
    }
    validate_entry_name(&header.swap_name)?;
    validate_entry_name(&header.stored_name)?;
    validate_identity(&header.parent, libc::S_IFDIR, "parent")?;
    match (
        lifecycle_requires_placeholder(&header.lifecycle),
        &header.placeholder,
    ) {
        (true, Some(identity)) => validate_identity(identity, libc::S_IFREG, "placeholder")?,
        (true, None) => return corrupt("snapshot phase requires a placeholder identity"),
        (false, None) => {}
        (false, Some(_)) => return corrupt("snapshot phase cannot retain a placeholder identity"),
    }
    validate_metadata(header.original.metadata())?;
    if let OriginalState::Present { identity, .. } = &header.original {
        validate_identity(identity, libc::S_IFREG, "original")?;
        if identity.links != 1 || !header.logical_present {
            return corrupt("present originals must be singly linked and logically present");
        }
    }
    if !header.logical_present && !record.contents.is_empty() {
        return corrupt("logically absent credentials must have empty contents");
    }
    if matches!(
        header.lifecycle,
        Lifecycle::Captured | Lifecycle::InstallIntent
    ) && let OriginalState::Present { identity, .. } = &header.original
        && identity.size != record.contents.len() as u64
    {
        return corrupt("captured contents length disagrees with the original identity");
    }
    validate_lifecycle_structure(header, &header.lifecycle)
}

fn validate_finalization(marker: &FinalizationRecord) -> StoreResult<()> {
    if marker.format != FORMAT_VERSION || marker.revision == 0 {
        return corrupt("finalization marker has an unsupported format or revision");
    }
    validate_token(&marker.generation, "generation")?;
    let path = path_from_hex(&marker.path_hex)?;
    let staging_path = path_from_hex(&marker.staging_path_hex)?;
    if !path.is_absolute()
        || !staging_path.is_absolute()
        || absolute_lexical(&path)? != path
        || absolute_lexical(&staging_path)? != staging_path
    {
        return corrupt("finalization paths must be absolute and normalized");
    }
    validate_entry_name(&marker.final_name)?;
    validate_identity(&marker.parent, libc::S_IFDIR, "finalization parent")?;
    validate_metadata(&marker.restore_metadata)?;
    if marker.content_length > MAX_CREDENTIAL_SIZE as u64 {
        return corrupt("finalization content length exceeds the snapshot limit");
    }
    let digest = hex::decode(&marker.content_sha256)
        .map_err(|error| StoreError::Corrupt(format!("invalid content digest: {error}")))?;
    if digest.len() != 32 {
        return corrupt("finalization content digest must contain 32 bytes");
    }
    match (&marker.final_identity, marker.logical_present) {
        (Some(identity), true) => {
            validate_identity(identity, libc::S_IFREG, "final restoration")?;
            if identity.links != 1
                || identity.size != marker.content_length
                || identity.uid != marker.restore_metadata.uid
                || identity.gid != marker.restore_metadata.gid
                || identity.mode & 0o7777 != marker.restore_metadata.mode
                || identity.mtime != marker.restore_metadata.mtime
            {
                return corrupt("final restoration identity disagrees with its metadata");
            }
        }
        (None, false) if marker.content_length == 0 && marker.content_sha256 == sha256(&[]) => {}
        (None, true) => return corrupt("present finalization has no restoration inode"),
        (Some(_), false) => return corrupt("absent finalization has a restoration inode"),
        (None, false) => return corrupt("absent finalization has non-empty content metadata"),
    }
    Ok(())
}

fn validate_lifecycle_structure(header: &RecordHeader, lifecycle: &Lifecycle) -> StoreResult<()> {
    use Lifecycle::*;
    match lifecycle {
        Captured | InstallIntent => Ok(()),
        Installed { detached_original }
        | MountIntent { detached_original }
        | UnmountIntent {
            detached_original, ..
        } => validate_detached_original(header, detached_original),
        StoreIntent { detached_name } => {
            validate_entry_name(detached_name)?;
            require_present_original(header, "offline-store intent")
        }
        Stored {
            detached_name,
            detached_original,
        } => {
            validate_entry_name(detached_name)?;
            require_present_original(header, "offline-store state")?;
            validate_detached_identity(header, detached_original, "stored original")
        }
        RestoreIntent {
            origin,
            restore_name,
            restore_identity,
            detached_name,
            detached_identity,
        } => {
            let name = restore_name
                .as_deref()
                .ok_or_else(|| StoreError::Corrupt("restore intent has no entry name".into()))?;
            validate_entry_name(name)?;
            if let Some(identity) = restore_identity {
                validate_identity(identity, libc::S_IFREG, "restoration")?;
            }
            if !header.logical_present && restore_identity.is_some() {
                return corrupt("absent logical files cannot have a restoration inode");
            }
            validate_restore_detached(header, origin, detached_name, detached_identity)
        }
        Restored {
            origin,
            restored_identity,
            displaced_name,
            displaced_identity,
            detached_name,
            detached_identity,
        }
        | DeleteIntent {
            origin,
            restored_identity,
            displaced_name,
            displaced_identity,
            detached_name,
            detached_identity,
        } => {
            if header.logical_present != restored_identity.is_some() {
                return corrupt("restored target identity disagrees with logical presence");
            }
            if let Some(identity) = restored_identity {
                validate_identity(identity, libc::S_IFREG, "restored target")?;
            }
            match origin {
                RestoreOrigin::Installed => {
                    validate_entry_name(displaced_name.as_deref().ok_or_else(|| {
                        StoreError::Corrupt("installed restore has no displaced name".into())
                    })?)?;
                    validate_identity(
                        displaced_identity.as_ref().ok_or_else(|| {
                            StoreError::Corrupt("installed restore has no displaced inode".into())
                        })?,
                        libc::S_IFREG,
                        "displaced placeholder",
                    )?;
                }
                RestoreOrigin::Stored
                    if displaced_name.is_some() || displaced_identity.is_some() =>
                {
                    return corrupt("offline restore cannot have a displaced placeholder");
                }
                RestoreOrigin::Stored => {}
            }
            validate_restore_detached(header, origin, detached_name, detached_identity)
        }
    }
}

fn restore_intent_matches_header(header: &RecordHeader) -> bool {
    validate_lifecycle_structure(header, &header.lifecycle).is_ok()
}

fn validate_restore_detached(
    header: &RecordHeader,
    origin: &RestoreOrigin,
    detached_name: &Option<String>,
    detached_identity: &Option<ObjectIdentity>,
) -> StoreResult<()> {
    match origin {
        RestoreOrigin::Installed if header.original.existed() => {
            if detached_name.as_deref() != Some(&header.swap_name) || detached_identity.is_none() {
                return corrupt("installed restore lost its detached original binding");
            }
        }
        RestoreOrigin::Installed => {
            if detached_name.is_some() || detached_identity.is_some() {
                return corrupt("absent original unexpectedly has a detached inode");
            }
            return Ok(());
        }
        RestoreOrigin::Stored => {
            require_present_original(header, "offline restore")?;
            if detached_name.as_deref() != Some(&header.stored_name) || detached_identity.is_none()
            {
                return corrupt("offline restore lost its stored inode binding");
            }
        }
    }
    validate_entry_name(detached_name.as_deref().unwrap())?;
    validate_detached_identity(
        header,
        detached_identity.as_ref().unwrap(),
        "detached original",
    )
}

fn validate_detached_original(
    header: &RecordHeader,
    detached: &Option<ObjectIdentity>,
) -> StoreResult<()> {
    match (&header.original, detached) {
        (OriginalState::Present { .. }, Some(identity)) => {
            validate_detached_identity(header, identity, "detached original")
        }
        (OriginalState::Absent { .. }, None) => Ok(()),
        _ => corrupt("detached original disagrees with the captured source"),
    }
}

fn validate_detached_identity(
    header: &RecordHeader,
    detached: &ObjectIdentity,
    label: &str,
) -> StoreResult<()> {
    validate_identity(detached, libc::S_IFREG, label)?;
    let OriginalState::Present { identity, .. } = &header.original else {
        return corrupt(&format!("{label} exists for an absent original"));
    };
    if !identities_match_after_rename(Some(identity), Some(detached)) {
        return corrupt(&format!("{label} does not match the captured original"));
    }
    Ok(())
}

fn require_present_original(header: &RecordHeader, phase: &str) -> StoreResult<()> {
    if header.original.existed() && header.logical_present {
        Ok(())
    } else {
        corrupt(&format!("{phase} requires a present original"))
    }
}

fn validate_identity(identity: &ObjectIdentity, kind: u32, label: &str) -> StoreResult<()> {
    if identity.mode & libc::S_IFMT != kind || identity.links == 0 {
        return corrupt(&format!("{label} has an invalid object identity"));
    }
    validate_timestamp(&identity.ctime)?;
    validate_timestamp(&identity.mtime)
}

fn validate_metadata(metadata: &RestoreMetadata) -> StoreResult<()> {
    if metadata.uid == u32::MAX || metadata.gid == u32::MAX {
        return corrupt("restore ownership contains the reserved unchanged value");
    }
    if metadata.mode & !0o7777 != 0 {
        return corrupt("restore mode contains file-type bits");
    }
    validate_timestamp(&metadata.atime)?;
    validate_timestamp(&metadata.mtime)?;
    let mut previous = None;
    for attribute in &metadata.xattrs {
        let name = hex::decode(&attribute.name_hex)
            .map_err(|error| StoreError::Corrupt(format!("invalid xattr name: {error}")))?;
        if name.contains(&0) {
            return corrupt("xattr name contains NUL");
        }
        hex::decode(&attribute.value_hex)
            .map_err(|error| StoreError::Corrupt(format!("invalid xattr value: {error}")))?;
        if previous
            .as_ref()
            .is_some_and(|value| value >= &attribute.name_hex)
        {
            return corrupt("xattrs must be strictly sorted and unique");
        }
        previous = Some(attribute.name_hex.clone());
    }
    Ok(())
}

fn validate_timestamp(timestamp: &super::Timestamp) -> StoreResult<()> {
    if !(0..1_000_000_000).contains(&timestamp.nanoseconds) {
        corrupt("timestamp nanoseconds are out of range")
    } else {
        Ok(())
    }
}

fn validate_token(value: &str, label: &str) -> StoreResult<()> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        corrupt(&format!("{label} must contain 32 hexadecimal characters"))
    }
}

fn validate_entry_name(value: &str) -> StoreResult<()> {
    if value.is_empty() || value == "." || value == ".." || value.as_bytes().contains(&b'/') {
        corrupt("snapshot contains an invalid staging entry name")
    } else if value.as_bytes().contains(&0) {
        corrupt("staging entry contains NUL")
    } else {
        Ok(())
    }
}

fn phase_name(lifecycle: &Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Captured => "captured",
        Lifecycle::InstallIntent => "installing",
        Lifecycle::Installed { .. } => "installed",
        Lifecycle::MountIntent { .. } => "mounting",
        Lifecycle::UnmountIntent { .. } => "unmounting",
        Lifecycle::StoreIntent { .. } => "storing",
        Lifecycle::Stored { .. } => "stored",
        Lifecycle::RestoreIntent { .. } => "restoring",
        Lifecycle::Restored { .. } => "restored",
        Lifecycle::DeleteIntent { .. } => "deleting",
    }
}

fn lifecycle_requires_placeholder(lifecycle: &Lifecycle) -> bool {
    match lifecycle {
        Lifecycle::InstallIntent
        | Lifecycle::Installed { .. }
        | Lifecycle::MountIntent { .. }
        | Lifecycle::UnmountIntent { .. }
        | Lifecycle::RestoreIntent {
            origin: RestoreOrigin::Installed,
            ..
        }
        | Lifecycle::Restored {
            origin: RestoreOrigin::Installed,
            ..
        }
        | Lifecycle::DeleteIntent {
            origin: RestoreOrigin::Installed,
            ..
        } => true,
        Lifecycle::Captured
        | Lifecycle::StoreIntent { .. }
        | Lifecycle::Stored { .. }
        | Lifecycle::RestoreIntent {
            origin: RestoreOrigin::Stored,
            ..
        }
        | Lifecycle::Restored {
            origin: RestoreOrigin::Stored,
            ..
        }
        | Lifecycle::DeleteIntent {
            origin: RestoreOrigin::Stored,
            ..
        } => false,
    }
}

fn revision_to_sql(revision: u64) -> StoreResult<i64> {
    i64::try_from(revision)
        .map_err(|_| StoreError::Corrupt("snapshot revision is out of range".to_string()))
}

fn default_store_root() -> PathBuf {
    std::env::var_os("FILE_GUARD_STORE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/file-guard/store"))
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

fn absolute_lexical(path: &Path) -> StoreResult<PathBuf> {
    let input = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut output = PathBuf::from("/");
    for component in input.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => output.push(part),
            Component::ParentDir => {
                if output == Path::new("/") || !output.pop() {
                    return Err(StoreError::UnsupportedFormat(
                        "path escapes the filesystem root".to_string(),
                    ));
                }
            }
            Component::Prefix(_) => {
                return Err(StoreError::UnsupportedFormat(
                    "unsupported path prefix".to_string(),
                ));
            }
        }
    }
    Ok(output)
}

fn corrupt<T>(message: &str) -> StoreResult<T> {
    Err(StoreError::Corrupt(message.to_string()))
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

    use super::*;
    use crate::store::{Timestamp, path_to_hex};

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
                    serde_json::to_vec(&record.header).unwrap(),
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
