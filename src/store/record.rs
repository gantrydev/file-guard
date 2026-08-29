use std::path::{Component, Path, PathBuf};

use super::{
    Entry, FORMAT_VERSION, FinalizationRecord, Lifecycle, MAX_CREDENTIAL_SIZE, ObjectIdentity,
    OriginalState, RecordHeader, RecordVersion, RestoreMetadata, RestoreOrigin, SnapshotRecord,
    StoreError, StoreResult, UnmountNext, path_from_hex, path_to_hex, sha256,
};

pub(super) struct StoredRow {
    pub(super) path: Vec<u8>,
    pub(super) generation: String,
    pub(super) revision: i64,
    pub(super) phase: String,
    pub(super) header: Vec<u8>,
    pub(super) contents: Vec<u8>,
}

pub(super) struct StoredFinalization {
    pub(super) path: Vec<u8>,
    pub(super) generation: String,
    pub(super) revision: i64,
    pub(super) header: Vec<u8>,
}

pub(super) fn decode_row(row: StoredRow) -> StoreResult<SnapshotRecord> {
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

pub(super) fn decode_finalization(row: StoredFinalization) -> StoreResult<FinalizationRecord> {
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

pub(super) fn validate_successor(
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
                    "successor must retain its generation and increment revision once".to_string(),
                ));
            }
            validate_successor_fields(current, next)
        }
    }
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

pub(super) fn validate_snapshot(record: &SnapshotRecord) -> StoreResult<()> {
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

pub(super) fn validate_finalization(marker: &FinalizationRecord) -> StoreResult<()> {
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

pub(super) fn phase_name(lifecycle: &Lifecycle) -> &'static str {
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

pub(super) fn encode_snapshot_header(header: &RecordHeader) -> StoreResult<Vec<u8>> {
    Ok(serde_json::to_vec(header)?)
}

pub(super) fn encode_finalization_header(marker: &FinalizationRecord) -> StoreResult<Vec<u8>> {
    Ok(serde_json::to_vec(marker)?)
}

fn corrupt<T>(message: &str) -> StoreResult<T> {
    Err(StoreError::Corrupt(message.to_string()))
}

pub(super) fn absolute_lexical(path: &Path) -> StoreResult<PathBuf> {
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
