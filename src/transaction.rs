use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;

use crate::secure_file::{
    ResolvedPath, StagingArea, default_staging_root, same_file_after_rename, same_object,
};
use crate::store::sqlite::random_token;
use crate::store::{
    BackingStore, Entry, FORMAT_VERSION, FinalizationRecord, Lifecycle, ObjectIdentity,
    OriginalState, RecordHeader, RestoreOrigin, SnapshotRecord, StoreError, UnmountNext,
    path_from_hex, path_to_hex, sha256,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionPoint {
    PlaceholderCreated,
    CapturedCommitted,
    InstallIntentCommitted,
    InstallRenamed,
    InstallDirectoriesSynced,
    InstalledCommitted,
    MountIntentCommitted,
    MountAbortedCommitted,
    UnmountIntentCommitted,
    UnmountedCommitted,
    StoreIntentCommitted,
    StoreRenamed,
    StoredCommitted,
    RestoreIntentCommitted,
    RestoreFileCreated,
    RestoreFileCommitted,
    RestoreRenamed,
    RestoreDirectoriesSynced,
    RestoredCommitted,
    DeleteIntentCommitted,
    FinalCopyCreated,
    RestoredTargetRetired,
    PreFinalizationSynced,
    FinalizationCommitted,
    FinalRename,
    FinalDirectoriesSynced,
    MarkerDeleted,
}

const FINAL_NAME: &str = "final";
const RETIRED_NAME: &str = "retired";

pub trait TransitionHook: Send + Sync {
    fn hit(&self, point: TransitionPoint) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    Missing,
    Restored,
}

struct NoopHook;

impl TransitionHook for NoopHook {
    fn hit(&self, _point: TransitionPoint) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct TransactionManager {
    store: Arc<dyn BackingStore>,
    staging_root: Option<PathBuf>,
    hook: Arc<dyn TransitionHook>,
}

impl TransactionManager {
    pub fn new(store: Arc<dyn BackingStore>) -> Self {
        Self {
            store,
            staging_root: None,
            hook: Arc::new(NoopHook),
        }
    }

    #[cfg(test)]
    pub fn with_test_parts(
        store: Arc<dyn BackingStore>,
        staging_root: PathBuf,
        hook: Arc<dyn TransitionHook>,
    ) -> Self {
        Self {
            store,
            staging_root: Some(staging_root),
            hook,
        }
    }

    pub fn prepare(&self, path: &Path) -> anyhow::Result<SnapshotRecord> {
        let path = self.normalize_path(path)?;
        loop {
            match self.store.load(&path)? {
                Entry::Missing => return self.capture_new(&path),
                Entry::Finalizing(marker) => {
                    self.finish_finalization(*marker)?;
                    continue;
                }
                Entry::Present(record) => {
                    let record = *record;
                    self.require_unblocked(&path, &record)?;
                    match record.header.lifecycle.clone() {
                        Lifecycle::Captured => {
                            let record = self.begin_install(record)?;
                            return self.finish_install(record);
                        }
                        Lifecycle::InstallIntent => return self.finish_install(record),
                        Lifecycle::Installed { .. } => {
                            return self.require_installed(&path, record);
                        }
                        Lifecycle::MountIntent { .. } | Lifecycle::UnmountIntent { .. } => {
                            anyhow::bail!(
                                "mount lifecycle for {} must be reconciled against the kernel mount table",
                                path.display()
                            )
                        }
                        Lifecycle::RestoreIntent { .. } => {
                            let record = self.finish_restore(record)?;
                            self.cleanup_restored(record)?;
                        }
                        Lifecycle::Restored { .. } | Lifecycle::DeleteIntent { .. } => {
                            self.cleanup_restored(record)?
                        }
                        Lifecycle::StoreIntent { .. } | Lifecycle::Stored { .. } => {
                            anyhow::bail!(
                                "{} is stored offline; restore it before starting the daemon",
                                path.display()
                            )
                        }
                    }
                }
            }
        }
    }

    pub fn update_contents(
        &self,
        current: &SnapshotRecord,
        contents: Vec<u8>,
    ) -> anyhow::Result<SnapshotRecord> {
        let path = path_from_hex(&current.header.path_hex)?;
        self.require_unblocked(&path, current)?;
        if !matches!(current.header.lifecycle, Lifecycle::MountIntent { .. }) {
            anyhow::bail!("credential is no longer accepting mounted writes")
        }
        let next = current.successor(current.header.lifecycle.clone(), contents);
        let mut next = next;
        next.header.logical_present = true;
        match self.store.commit(&path, Some(&current.version()), &next) {
            Ok(version) if version == next.version() => Ok(next),
            Ok(_) => Err(StoreError::Conflict(
                "backing store returned the wrong committed revision".to_string(),
            )
            .into()),
            Err(StoreError::Indeterminate(commit_error)) => match self.store.load(&path) {
                Ok(Entry::Present(observed)) if *observed == next => Ok(*observed),
                Ok(_) => Err(StoreError::Indeterminate(format!(
                    "{commit_error}; reload did not observe the candidate revision"
                ))
                .into()),
                Err(reload_error) => Err(StoreError::Indeterminate(format!(
                    "{commit_error}; reload failed: {reload_error}"
                ))
                .into()),
            },
            Err(error) => Err(error.into()),
        }
    }

    pub fn normalize_path(&self, path: &Path) -> anyhow::Result<PathBuf> {
        Ok(ResolvedPath::new(path)?.path().to_path_buf())
    }

    pub fn begin_mount(&self, path: &Path) -> anyhow::Result<SnapshotRecord> {
        let path = self.normalize_path(path)?;
        let record = match self.store.load(&path)? {
            Entry::Missing => anyhow::bail!("no v2 transaction for {}", path.display()),
            Entry::Finalizing(_) => {
                anyhow::bail!("{} is completing a restored snapshot", path.display())
            }
            Entry::Present(record) => *record,
        };
        self.require_unblocked(&path, &record)?;
        match record.header.lifecycle.clone() {
            Lifecycle::Installed { detached_original } => {
                let record =
                    self.require_installed_layout(&path, record, detached_original.clone())?;
                let mounted =
                    self.transition(&record, Lifecycle::MountIntent { detached_original })?;
                self.hook.hit(TransitionPoint::MountIntentCommitted)?;
                Ok(mounted)
            }
            Lifecycle::MountIntent { detached_original } => {
                self.require_installed_layout(&path, record, detached_original)
            }
            _ => anyhow::bail!("{} is not ready to mount", path.display()),
        }
    }

    pub fn abort_mount(&self, path: &Path) -> anyhow::Result<SnapshotRecord> {
        let path = self.normalize_path(path)?;
        let record = match self.store.load(&path)? {
            Entry::Missing => anyhow::bail!("no v2 transaction for {}", path.display()),
            Entry::Finalizing(_) => {
                anyhow::bail!("{} is completing a restored snapshot", path.display())
            }
            Entry::Present(record) => *record,
        };
        self.require_unblocked(&path, &record)?;
        match record.header.lifecycle.clone() {
            Lifecycle::MountIntent { detached_original } => {
                let record =
                    self.require_installed_layout(&path, record, detached_original.clone())?;
                let installed =
                    self.transition(&record, Lifecycle::Installed { detached_original })?;
                self.hook.hit(TransitionPoint::MountAbortedCommitted)?;
                Ok(installed)
            }
            Lifecycle::Installed { .. } => self.require_installed(&path, record),
            _ => anyhow::bail!("{} is not awaiting mount completion", path.display()),
        }
    }

    pub fn begin_unmount(&self, path: &Path, next: UnmountNext) -> anyhow::Result<SnapshotRecord> {
        let path = self.normalize_path(path)?;
        loop {
            let record = match self.store.load(&path)? {
                Entry::Missing => anyhow::bail!("no v2 transaction for {}", path.display()),
                Entry::Finalizing(_) => {
                    anyhow::bail!("{} is completing a restored snapshot", path.display())
                }
                Entry::Present(record) => *record,
            };
            self.require_unblocked(&path, &record)?;
            match record.header.lifecycle.clone() {
                Lifecycle::MountIntent { detached_original } => {
                    match self.transition(
                        &record,
                        Lifecycle::UnmountIntent {
                            next: next.clone(),
                            detached_original,
                        },
                    ) {
                        Ok(unmounting) => {
                            self.hook.hit(TransitionPoint::UnmountIntentCommitted)?;
                            return Ok(unmounting);
                        }
                        Err(error)
                            if error
                                .downcast_ref::<StoreError>()
                                .is_some_and(|store_error| {
                                    matches!(store_error, StoreError::Conflict(_))
                                }) =>
                        {
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Lifecycle::UnmountIntent {
                    next: current_next, ..
                } if current_next == next => return Ok(record),
                Lifecycle::UnmountIntent { .. } => {
                    anyhow::bail!("{} already has a different unmount outcome", path.display())
                }
                _ => anyhow::bail!("{} is not mounted by this transaction", path.display()),
            }
        }
    }

    pub fn reconcile_after_mount_absent(&self, path: &Path) -> anyhow::Result<()> {
        let path = self.normalize_path(path)?;
        let record = match self.store.load(&path)? {
            Entry::Missing => return Ok(()),
            Entry::Finalizing(marker) => {
                self.finish_finalization(*marker)?;
                return Ok(());
            }
            Entry::Present(record) => *record,
        };
        self.require_unblocked(&path, &record)?;
        match record.header.lifecycle.clone() {
            Lifecycle::MountIntent { .. } => {
                self.abort_mount(&path)?;
                Ok(())
            }
            Lifecycle::UnmountIntent {
                next: UnmountNext::LeaveInstalled,
                detached_original,
            } => {
                let record =
                    self.require_installed_layout(&path, record, detached_original.clone())?;
                self.transition(&record, Lifecycle::Installed { detached_original })?;
                self.hook.hit(TransitionPoint::UnmountedCommitted)?;
                Ok(())
            }
            Lifecycle::UnmountIntent {
                next: UnmountNext::Restore,
                detached_original,
            } => {
                let record = self.require_installed_layout(&path, record, detached_original)?;
                let record = self.begin_restore(record)?;
                self.cleanup_restored(record)
            }
            _ => Ok(()),
        }
    }

    pub fn restore(&self, path: &Path) -> anyhow::Result<RestoreOutcome> {
        let path = self.normalize_path(path)?;
        let record = match self.store.load(&path)? {
            Entry::Missing => return Ok(RestoreOutcome::Missing),
            Entry::Finalizing(marker) => {
                self.finish_finalization(*marker)?;
                return Ok(RestoreOutcome::Restored);
            }
            Entry::Present(record) => *record,
        };
        self.require_unblocked(&path, &record)?;
        let record = match record.header.lifecycle.clone() {
            Lifecycle::Captured => {
                let record = self.begin_install(record)?;
                self.finish_install(record)?
            }
            Lifecycle::InstallIntent => self.finish_install(record)?,
            Lifecycle::Installed { .. } | Lifecycle::Stored { .. } => record,
            Lifecycle::MountIntent { .. } | Lifecycle::UnmountIntent { .. } => anyhow::bail!(
                "mount lifecycle for {} must be reconciled before restore",
                path.display()
            ),
            Lifecycle::RestoreIntent { .. } => self.finish_restore(record)?,
            Lifecycle::Restored { .. } | Lifecycle::DeleteIntent { .. } => record,
            Lifecycle::StoreIntent { .. } => self.finish_store(record)?,
        };
        let record = if matches!(
            record.header.lifecycle,
            Lifecycle::Restored { .. } | Lifecycle::DeleteIntent { .. }
        ) {
            record
        } else {
            self.begin_restore(record)?
        };
        self.cleanup_restored(record)?;
        Ok(RestoreOutcome::Restored)
    }

    pub fn store_offline(&self, path: &Path) -> anyhow::Result<()> {
        let path = self.normalize_path(path)?;
        let record = match self.store.load(&path)? {
            Entry::Missing => self.capture_record(&path, true)?,
            Entry::Finalizing(marker) => {
                self.finish_finalization(*marker)?;
                self.capture_record(&path, true)?
            }
            Entry::Present(record) => *record,
        };
        self.require_unblocked(&path, &record)?;
        let record = match record.header.lifecycle.clone() {
            Lifecycle::Captured => {
                if !record.header.original.existed() {
                    anyhow::bail!(
                        "{} does not exist and cannot be stored offline",
                        path.display()
                    )
                }
                let record = self.prepare_offline_staging(record)?;
                let detached_name = record.header.stored_name.clone();
                let record = self.transition(&record, Lifecycle::StoreIntent { detached_name })?;
                self.hook.hit(TransitionPoint::StoreIntentCommitted)?;
                record
            }
            Lifecycle::StoreIntent { .. } => record,
            Lifecycle::Stored { .. } => {
                self.require_stored(&path, record)?;
                return Ok(());
            }
            _ => anyhow::bail!("{} already has an active v2 transaction", path.display()),
        };
        self.finish_store(record)?;
        Ok(())
    }

    pub fn load(&self, path: &Path) -> anyhow::Result<Entry> {
        let path = self.normalize_path(path)?;
        Ok(self.store.load(&path)?)
    }

    fn capture_new(&self, path: &Path) -> anyhow::Result<SnapshotRecord> {
        let record = self.capture_record(path, false)?;
        let record = self.begin_install(record)?;
        self.finish_install(record)
    }

    fn capture_record(&self, path: &Path, require_present: bool) -> anyhow::Result<SnapshotRecord> {
        let resolved = ResolvedPath::new(path)?;
        let captured = resolved.capture()?;
        if require_present && !captured.original.existed() {
            anyhow::bail!(
                "{} does not exist and cannot be stored offline",
                path.display()
            )
        }
        let logical_present = captured.original.existed();
        let parent = resolved.parent_identity()?;
        let generation = random_token()?;
        let staging_root = self
            .staging_root
            .clone()
            .map(Ok)
            .unwrap_or_else(|| default_staging_root(&resolved))?;
        let staging_path = StagingArea::planned_path(&staging_root, &generation)?;
        let swap_name = "swap".to_string();

        let record = SnapshotRecord {
            header: RecordHeader {
                format: FORMAT_VERSION,
                path_hex: path_to_hex(resolved.path()),
                generation,
                revision: 1,
                lifecycle: Lifecycle::Captured,
                original: captured.original,
                logical_present,
                parent,
                staging_path_hex: path_to_hex(&staging_path),
                swap_name,
                stored_name: "stored".to_string(),
                placeholder: None,
                mount_token: random_token()?,
                content_sha256: sha256(&captured.contents),
                blocked_reason: None,
            },
            contents: captured.contents,
        };
        self.store.commit(path, None, &record)?;
        self.hook.hit(TransitionPoint::CapturedCommitted)?;
        Ok(record)
    }

    fn begin_install(&self, record: SnapshotRecord) -> anyhow::Result<SnapshotRecord> {
        let path = path_from_hex(&record.header.path_hex)?;
        let resolved = self.resolve_bound_path(&path, &record)?;
        if let Err(error) = self.validate_captured_source(&record, &resolved) {
            return self.conflict(
                record,
                &format!("captured source changed before placeholder preparation: {error}"),
            );
        }
        let staging_path = path_from_hex(&record.header.staging_path_hex)?;
        let staging_root = staging_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("staging transaction has no root"))?;
        let staging = StagingArea::create(
            staging_root,
            &record.header.generation,
            record.header.parent.device,
        )?;
        staging.discard_construction(&record.header.swap_name)?;
        let placeholder = match staging.observe(&record.header.swap_name)? {
            None => staging
                .create_placeholder(&record.header.swap_name, record.header.original.metadata())?,
            Some(_) => match staging
                .verify_placeholder(&record.header.swap_name, record.header.original.metadata())
            {
                Ok(identity) => identity,
                Err(_) => {
                    staging.discard_uncommitted(&record.header.swap_name)?;
                    staging.create_placeholder(
                        &record.header.swap_name,
                        record.header.original.metadata(),
                    )?
                }
            },
        };
        self.hook.hit(TransitionPoint::PlaceholderCreated)?;
        let mut installing = record.successor(Lifecycle::InstallIntent, record.contents.clone());
        installing.header.placeholder = Some(placeholder);
        self.commit_successor(&record, &installing)?;
        self.hook.hit(TransitionPoint::InstallIntentCommitted)?;
        Ok(installing)
    }

    fn prepare_offline_staging(&self, record: SnapshotRecord) -> anyhow::Result<SnapshotRecord> {
        let path = path_from_hex(&record.header.path_hex)?;
        let resolved = self.resolve_bound_path(&path, &record)?;
        if let Err(error) = self.validate_captured_source(&record, &resolved) {
            return self.conflict(
                record,
                &format!("captured source changed before offline storage: {error}"),
            );
        }
        let staging_path = path_from_hex(&record.header.staging_path_hex)?;
        let staging_root = staging_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("staging transaction has no root"))?;
        let staging = StagingArea::create(
            staging_root,
            &record.header.generation,
            record.header.parent.device,
        )?;
        if !staging.is_empty()? {
            return self.conflict(record, "offline staging contains unexpected entries");
        }
        Ok(record)
    }

    fn finish_install(&self, record: SnapshotRecord) -> anyhow::Result<SnapshotRecord> {
        let path = path_from_hex(&record.header.path_hex)?;
        let resolved = self.resolve_bound_path(&path, &record)?;
        let staging = self.open_staging(&record)?;
        let placeholder = record
            .header
            .placeholder
            .clone()
            .ok_or_else(|| anyhow::anyhow!("install intent has no placeholder identity"))?;
        let (before, after) = match &record.header.original {
            OriginalState::Present { identity, .. } => (
                (Some(identity.clone()), Some(placeholder.clone())),
                (Some(placeholder.clone()), Some(identity.clone())),
            ),
            OriginalState::Absent { .. } => (
                (None, Some(placeholder.clone())),
                (Some(placeholder.clone()), None),
            ),
        };

        let mut observed = (
            resolved.observe()?,
            staging.observe(&record.header.swap_name)?,
        );
        if layout_matches(&observed, &before, false) {
            let operation = if record.header.original.existed() {
                resolved.exchange_with(&staging, &record.header.swap_name)
            } else {
                resolved.install_absent(&staging, &record.header.swap_name)
            };
            if let Err(error) = operation {
                observed = (
                    resolved.observe()?,
                    staging.observe(&record.header.swap_name)?,
                );
                if !layout_matches(&observed, &after, true) {
                    return Err(error.into());
                }
            } else {
                observed = (
                    resolved.observe()?,
                    staging.observe(&record.header.swap_name)?,
                );
            }
            self.hook.hit(TransitionPoint::InstallRenamed)?;
        }
        if !layout_matches(&observed, &after, true) {
            return self.conflict(
                record,
                "capture/install identities do not match either recoverable layout",
            );
        }
        if let OriginalState::Present { metadata, .. } = &record.header.original {
            let verified =
                staging.verify_snapshot(&record.header.swap_name, &record.contents, metadata);
            if let Err(error) = verified {
                return self.conflict(
                    record,
                    &format!("detached original failed post-install verification: {error}"),
                );
            }
        }

        resolved.sync_with(&staging)?;
        self.hook.hit(TransitionPoint::InstallDirectoriesSynced)?;
        let mut installed = record.successor(
            Lifecycle::Installed {
                detached_original: observed.1.clone(),
            },
            record.contents.clone(),
        );
        installed.header.placeholder = observed.0.clone();
        self.commit_successor(&record, &installed)?;
        self.hook.hit(TransitionPoint::InstalledCommitted)?;
        self.require_installed(&path, installed)
    }

    fn finish_store(&self, record: SnapshotRecord) -> anyhow::Result<SnapshotRecord> {
        let Lifecycle::StoreIntent { detached_name } = record.header.lifecycle.clone() else {
            anyhow::bail!("record is not awaiting offline storage")
        };
        let OriginalState::Present { identity, metadata } = &record.header.original else {
            return self.conflict(
                record,
                "cannot store an originally absent credential offline",
            );
        };
        let expected_original = identity.clone();
        let expected_metadata = metadata.clone();
        let path = path_from_hex(&record.header.path_hex)?;
        let resolved = self.resolve_bound_path(&path, &record)?;
        let staging = self.open_staging(&record)?;

        let before = (Some(expected_original.clone()), None);
        let after = (None, Some(expected_original.clone()));
        let mut observed = (resolved.observe()?, staging.observe(&detached_name)?);
        if layout_matches(&observed, &before, false) {
            if let Err(error) = resolved.move_to_staging(&staging, &detached_name) {
                observed = (resolved.observe()?, staging.observe(&detached_name)?);
                if !layout_matches(&observed, &after, true) {
                    return Err(error.into());
                }
            } else {
                observed = (resolved.observe()?, staging.observe(&detached_name)?);
            }
            self.hook.hit(TransitionPoint::StoreRenamed)?;
        }
        if !layout_matches(&observed, &after, true) {
            return self.conflict(
                record,
                "offline-store identities do not match either recoverable layout",
            );
        }
        let detached_original =
            match staging.verify_snapshot(&detached_name, &record.contents, &expected_metadata) {
                Ok(actual) if same_file_after_rename(&expected_original, &actual) => actual,
                Ok(_) => {
                    return self.conflict(
                        record,
                        "offline-store detached inode changed during verification",
                    );
                }
                Err(error) => {
                    return self.conflict(
                        record,
                        &format!("offline-store detached original failed verification: {error}"),
                    );
                }
            };
        resolved.sync_with(&staging)?;
        let stored = self.transition(
            &record,
            Lifecycle::Stored {
                detached_name,
                detached_original,
            },
        )?;
        self.hook.hit(TransitionPoint::StoredCommitted)?;
        self.require_stored(&path, stored)
    }

    fn begin_restore(&self, record: SnapshotRecord) -> anyhow::Result<SnapshotRecord> {
        let path = path_from_hex(&record.header.path_hex)?;
        let (origin, detached_name, detached_identity) = match &record.header.lifecycle {
            Lifecycle::Installed { detached_original } => (
                RestoreOrigin::Installed,
                record
                    .header
                    .original
                    .existed()
                    .then(|| record.header.swap_name.clone()),
                detached_original.clone(),
            ),
            Lifecycle::UnmountIntent {
                next: UnmountNext::Restore,
                detached_original,
            } => (
                RestoreOrigin::Installed,
                record
                    .header
                    .original
                    .existed()
                    .then(|| record.header.swap_name.clone()),
                detached_original.clone(),
            ),
            Lifecycle::Stored {
                detached_name,
                detached_original,
            } => (
                RestoreOrigin::Stored,
                Some(detached_name.clone()),
                Some(detached_original.clone()),
            ),
            _ => anyhow::bail!("record is not ready to restore"),
        };

        let record = if origin == RestoreOrigin::Installed {
            self.require_installed_layout(&path, record, detached_identity.clone())?
        } else {
            self.require_stored(&path, record)?
        };
        let resolved = self.resolve_bound_path(&path, &record)?;
        let staging = self.open_staging(&record)?;

        let restore_name = if record.header.logical_present {
            Some(format!("restore-{}", random_token()?))
        } else {
            Some(format!("displaced-{}", random_token()?))
        };

        let restoring = self.transition(
            &record,
            Lifecycle::RestoreIntent {
                origin,
                restore_name,
                restore_identity: None,
                detached_name,
                detached_identity,
            },
        )?;
        self.hook.hit(TransitionPoint::RestoreIntentCommitted)?;
        self.finish_restore_with(resolved, staging, restoring)
    }

    fn finish_restore(&self, record: SnapshotRecord) -> anyhow::Result<SnapshotRecord> {
        let path = path_from_hex(&record.header.path_hex)?;
        let resolved = self.resolve_bound_path(&path, &record)?;
        let staging = self.open_staging(&record)?;
        self.finish_restore_with(resolved, staging, record)
    }

    fn finish_restore_with(
        &self,
        resolved: ResolvedPath,
        staging: StagingArea,
        record: SnapshotRecord,
    ) -> anyhow::Result<SnapshotRecord> {
        let mut record = record;
        let Lifecycle::RestoreIntent {
            origin,
            restore_name,
            mut restore_identity,
            detached_name,
            detached_identity,
        } = record.header.lifecycle.clone()
        else {
            anyhow::bail!("record is not awaiting restore")
        };
        let restore_name = restore_name
            .ok_or_else(|| anyhow::anyhow!("restore intent has no staging entry name"))?;
        staging.discard_construction(&restore_name)?;

        if record.header.logical_present && restore_identity.is_none() {
            let identity = match staging.observe(&restore_name)? {
                None => {
                    let identity = staging.create_restoration(
                        &restore_name,
                        &record.contents,
                        record.header.original.metadata(),
                    )?;
                    self.hook.hit(TransitionPoint::RestoreFileCreated)?;
                    identity
                }
                Some(_) => match staging.verify_restoration(
                    &restore_name,
                    &record.contents,
                    record.header.original.metadata(),
                ) {
                    Ok(identity) => identity,
                    Err(_) => {
                        staging.discard_uncommitted(&restore_name)?;
                        let identity = staging.create_restoration(
                            &restore_name,
                            &record.contents,
                            record.header.original.metadata(),
                        )?;
                        self.hook.hit(TransitionPoint::RestoreFileCreated)?;
                        identity
                    }
                },
            };
            record = self.transition(
                &record,
                Lifecycle::RestoreIntent {
                    origin: origin.clone(),
                    restore_name: Some(restore_name.clone()),
                    restore_identity: Some(identity.clone()),
                    detached_name: detached_name.clone(),
                    detached_identity: detached_identity.clone(),
                },
            )?;
            self.hook.hit(TransitionPoint::RestoreFileCommitted)?;
            restore_identity = Some(identity);
        }

        let (before, after, displaced_name) = match (&origin, &restore_identity) {
            (RestoreOrigin::Installed, Some(restored)) => (
                (
                    Some(record.header.placeholder.clone().ok_or_else(|| {
                        anyhow::anyhow!("installed restore has no placeholder identity")
                    })?),
                    Some(restored.clone()),
                ),
                (
                    Some(restored.clone()),
                    Some(record.header.placeholder.clone().ok_or_else(|| {
                        anyhow::anyhow!("installed restore has no placeholder identity")
                    })?),
                ),
                Some(restore_name.clone()),
            ),
            (RestoreOrigin::Installed, None) => (
                (
                    Some(record.header.placeholder.clone().ok_or_else(|| {
                        anyhow::anyhow!("installed restore has no placeholder identity")
                    })?),
                    None,
                ),
                (
                    None,
                    Some(record.header.placeholder.clone().ok_or_else(|| {
                        anyhow::anyhow!("installed restore has no placeholder identity")
                    })?),
                ),
                Some(restore_name.clone()),
            ),
            (RestoreOrigin::Stored, Some(restored)) => (
                (None, Some(restored.clone())),
                (Some(restored.clone()), None),
                None,
            ),
            (RestoreOrigin::Stored, None) => {
                return self.conflict(record, "stored credential has no restoration inode");
            }
        };

        let mut observed = (resolved.observe()?, staging.observe(&restore_name)?);
        if layout_matches(&observed, &before, false) {
            let operation = match (&origin, &restore_identity) {
                (RestoreOrigin::Installed, Some(_)) => {
                    resolved.exchange_with(&staging, &restore_name)
                }
                (RestoreOrigin::Installed, None) => {
                    resolved.move_to_staging(&staging, &restore_name)
                }
                (RestoreOrigin::Stored, Some(_)) => {
                    resolved.install_absent(&staging, &restore_name)
                }
                (RestoreOrigin::Stored, None) => unreachable!(),
            };
            if let Err(error) = operation {
                observed = (resolved.observe()?, staging.observe(&restore_name)?);
                if !layout_matches(&observed, &after, true) {
                    return Err(error.into());
                }
            } else {
                observed = (resolved.observe()?, staging.observe(&restore_name)?);
            }
            self.hook.hit(TransitionPoint::RestoreRenamed)?;
        }
        if !layout_matches(&observed, &after, true) {
            return self.conflict(
                record,
                "restore identities do not match either recoverable layout",
            );
        }

        if record.header.logical_present {
            let expected = restore_identity
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("logical credential has no restoration identity"))?;
            match resolved.verify_restoration(&record.contents, record.header.original.metadata()) {
                Ok(actual) if same_file_after_rename(expected, &actual) => {
                    observed.0 = Some(actual);
                }
                Ok(_) => {
                    return self.conflict(
                        record,
                        "restored inode identity changed during content verification",
                    );
                }
                Err(error) => {
                    return self.conflict(
                        record,
                        &format!("restored contents or metadata failed verification: {error}"),
                    );
                }
            }
        } else if resolved.observe()?.is_some() {
            return self.conflict(record, "logically absent target reappeared during restore");
        }

        resolved.sync_with(&staging)?;
        self.hook.hit(TransitionPoint::RestoreDirectoriesSynced)?;
        let restored = self.transition(
            &record,
            Lifecycle::Restored {
                origin,
                restored_identity: observed.0.clone(),
                displaced_name,
                displaced_identity: observed.1.clone(),
                detached_name,
                detached_identity,
            },
        )?;
        self.hook.hit(TransitionPoint::RestoredCommitted)?;
        Ok(restored)
    }

    fn cleanup_restored(&self, record: SnapshotRecord) -> anyhow::Result<()> {
        let path = path_from_hex(&record.header.path_hex)?;
        let resolved = match self.resolve_bound_path(&path, &record) {
            Ok(resolved) => resolved,
            Err(error) => {
                return self.conflict(
                    record,
                    &format!("restored parent binding failed verification: {error}"),
                );
            }
        };
        let record = match record.header.lifecycle.clone() {
            Lifecycle::Restored {
                origin,
                restored_identity,
                displaced_name,
                displaced_identity,
                detached_name,
                detached_identity,
            } => {
                if let Err(error) = self.validate_restored_target(&record, &resolved) {
                    return self.conflict(
                        record,
                        &format!(
                            "restored target failed verification before deletion intent: {error}"
                        ),
                    );
                }
                let deleting = self.transition(
                    &record,
                    Lifecycle::DeleteIntent {
                        origin,
                        restored_identity,
                        displaced_name,
                        displaced_identity,
                        detached_name,
                        detached_identity,
                    },
                )?;
                self.hook.hit(TransitionPoint::DeleteIntentCommitted)?;
                deleting
            }
            Lifecycle::DeleteIntent { .. } => record,
            _ => anyhow::bail!("record is not restored"),
        };

        let Lifecycle::DeleteIntent {
            restored_identity,
            displaced_name,
            displaced_identity,
            detached_name,
            detached_identity,
            ..
        } = record.header.lifecycle.clone()
        else {
            unreachable!()
        };
        let staging = self.open_staging(&record)?;
        staging.discard_construction(FINAL_NAME)?;
        let final_identity = if record.header.logical_present {
            let identity = match staging.observe(FINAL_NAME)? {
                None => staging.create_restoration(
                    FINAL_NAME,
                    &record.contents,
                    record.header.original.metadata(),
                )?,
                Some(_) => match staging.verify_restoration(
                    FINAL_NAME,
                    &record.contents,
                    record.header.original.metadata(),
                ) {
                    Ok(identity) => identity,
                    Err(_) => {
                        staging.discard_uncommitted(FINAL_NAME)?;
                        staging.create_restoration(
                            FINAL_NAME,
                            &record.contents,
                            record.header.original.metadata(),
                        )?
                    }
                },
            };
            self.hook.hit(TransitionPoint::FinalCopyCreated)?;
            Some(identity)
        } else {
            if staging.observe(FINAL_NAME)?.is_some() {
                return self.conflict(record, "absent restore has an unexpected final copy");
            }
            None
        };

        self.retire_restored_target(&record, &resolved, &staging, restored_identity.as_ref())?;
        self.hook.hit(TransitionPoint::RestoredTargetRetired)?;

        if let (Some(name), Some(expected)) = (displaced_name, displaced_identity) {
            match staging.observe(&name)? {
                Some(actual) if actual == expected => {
                    staging.remove_verified(&name, &expected)?;
                }
                None => {}
                Some(_) => return self.conflict(record, "displaced placeholder was replaced"),
            }
        }

        if let (Some(name), Some(expected)) = (detached_name, detached_identity) {
            let OriginalState::Present { .. } = &record.header.original else {
                return self.conflict(record, "absent source unexpectedly has a detached inode");
            };
            match staging.observe(&name)? {
                Some(actual) if actual == expected => staging.remove_verified(&name, &expected)?,
                None => {}
                Some(_) => {
                    return self.conflict(
                        record,
                        "detached original changed through a pre-existing descriptor; both versions were retained",
                    );
                }
            }
        }

        if let Some(expected) = restored_identity.as_ref() {
            match staging.observe(RETIRED_NAME)? {
                Some(actual) if same_file_after_rename(expected, &actual) => {
                    let verified = staging.verify_finalization(
                        RETIRED_NAME,
                        record.contents.len() as u64,
                        &record.header.content_sha256,
                        record.header.original.metadata(),
                    )?;
                    staging.remove_verified(RETIRED_NAME, &verified)?;
                }
                None => {}
                Some(_) => {
                    return self.conflict(record, "retired restored target changed during cleanup");
                }
            }
        } else if staging.observe(RETIRED_NAME)?.is_some() {
            return self.conflict(record, "absent restore has an unexpected retired target");
        }
        staging.sync()?;
        if !staging.contains_only(if final_identity.is_some() {
            &[FINAL_NAME]
        } else {
            &[]
        })? {
            return self.conflict(
                record,
                "staging directory contains unrecognized recovery data",
            );
        }
        if let Some(expected) = final_identity.as_ref() {
            let actual = staging.verify_finalization(
                FINAL_NAME,
                record.contents.len() as u64,
                &record.header.content_sha256,
                record.header.original.metadata(),
            )?;
            if &actual != expected {
                return self.conflict(record, "final restoration changed before marker commit");
            }
        }
        if resolved.observe()?.is_some() {
            anyhow::bail!(
                "{} became occupied while preparing final restoration",
                path.display()
            )
        }
        resolved.sync_with(&staging)?;
        self.hook.hit(TransitionPoint::PreFinalizationSynced)?;

        let marker = FinalizationRecord {
            format: FORMAT_VERSION,
            path_hex: record.header.path_hex.clone(),
            generation: record.header.generation.clone(),
            revision: record.header.revision + 1,
            logical_present: record.header.logical_present,
            parent: record.header.parent.clone(),
            staging_path_hex: record.header.staging_path_hex.clone(),
            final_name: FINAL_NAME.to_string(),
            final_identity,
            restore_metadata: record.header.original.metadata().clone(),
            content_length: record.contents.len() as u64,
            content_sha256: record.header.content_sha256.clone(),
        };
        let marker = self.begin_finalization(&path, &record, marker)?;
        self.hook.hit(TransitionPoint::FinalizationCommitted)?;
        self.finish_finalization(marker)
    }

    fn retire_restored_target(
        &self,
        record: &SnapshotRecord,
        resolved: &ResolvedPath,
        staging: &StagingArea,
        expected: Option<&ObjectIdentity>,
    ) -> anyhow::Result<()> {
        let mut layout = (resolved.observe()?, staging.observe(RETIRED_NAME)?);
        match expected {
            Some(expected) if layout.0.as_ref() == Some(expected) && layout.1.is_none() => {
                if let Err(error) = resolved.move_to_staging(staging, RETIRED_NAME) {
                    layout = (resolved.observe()?, staging.observe(RETIRED_NAME)?);
                    if layout.0.is_some()
                        || !layout
                            .1
                            .as_ref()
                            .is_some_and(|actual| same_file_after_rename(expected, actual))
                    {
                        return Err(error.into());
                    }
                } else {
                    layout = (resolved.observe()?, staging.observe(RETIRED_NAME)?);
                }
            }
            Some(_) if layout.0.is_none() && layout.1.is_none() => return Ok(()),
            None if layout.0.is_none() && layout.1.is_none() => return Ok(()),
            _ => {}
        }
        match expected {
            Some(expected)
                if layout.0.is_none()
                    && layout
                        .1
                        .as_ref()
                        .is_some_and(|actual| same_file_after_rename(expected, actual)) =>
            {
                Ok(())
            }
            Some(_) => anyhow::bail!(
                "{} changed while its restored inode was being retired",
                path_from_hex(&record.header.path_hex)?.display()
            ),
            None => anyhow::bail!(
                "{} appeared while an absent restore was being finalized",
                path_from_hex(&record.header.path_hex)?.display()
            ),
        }
    }

    fn begin_finalization(
        &self,
        path: &Path,
        snapshot: &SnapshotRecord,
        marker: FinalizationRecord,
    ) -> anyhow::Result<FinalizationRecord> {
        match self
            .store
            .begin_finalization(path, &snapshot.version(), &marker)
        {
            Ok(_) => Ok(marker),
            Err(error) => match self.store.load(path)? {
                Entry::Finalizing(actual) if *actual == marker => Ok(marker),
                Entry::Present(actual) if actual.version() == snapshot.version() => {
                    Err(error.into())
                }
                Entry::Missing => anyhow::bail!(
                    "snapshot and finalization marker both disappeared after an uncertain commit"
                ),
                _ => anyhow::bail!(
                    "snapshot changed unexpectedly while committing its finalization marker"
                ),
            },
        }
    }

    fn finish_finalization(&self, marker: FinalizationRecord) -> anyhow::Result<()> {
        let path = path_from_hex(&marker.path_hex)?;
        let resolved = ResolvedPath::new(&path)?;
        if !same_object(&resolved.parent_identity()?, &marker.parent) {
            anyhow::bail!(
                "finalization parent for {} no longer matches its recorded directory",
                path.display()
            )
        }
        let staging_path = path_from_hex(&marker.staging_path_hex)?;
        let staging = StagingArea::open(&staging_path, marker.parent.device)?;

        match marker.final_identity.as_ref() {
            Some(expected) => {
                let mut layout = (resolved.observe()?, staging.observe(&marker.final_name)?);
                if layout.0.is_none() && layout.1.as_ref() == Some(expected) {
                    if let Err(error) = resolved.install_absent(&staging, &marker.final_name) {
                        layout = (resolved.observe()?, staging.observe(&marker.final_name)?);
                        if layout.1.is_some()
                            || !layout
                                .0
                                .as_ref()
                                .is_some_and(|actual| same_file_after_rename(expected, actual))
                        {
                            return Err(error.into());
                        }
                    } else {
                        layout = (resolved.observe()?, staging.observe(&marker.final_name)?);
                    }
                    self.hook.hit(TransitionPoint::FinalRename)?;
                }
                if layout.1.is_some()
                    || !layout
                        .0
                        .as_ref()
                        .is_some_and(|actual| same_file_after_rename(expected, actual))
                {
                    anyhow::bail!(
                        "finalization layout for {} is neither pre-rename nor post-rename",
                        path.display()
                    )
                }
                let actual = resolved.verify_finalization(
                    marker.content_length,
                    &marker.content_sha256,
                    &marker.restore_metadata,
                )?;
                if !same_file_after_rename(expected, &actual) {
                    anyhow::bail!("final restoration identity for {} changed", path.display())
                }
            }
            None => {
                if resolved.observe()?.is_some() || staging.observe(&marker.final_name)?.is_some() {
                    anyhow::bail!(
                        "absent finalization for {} has an unexpected filesystem object",
                        path.display()
                    )
                }
            }
        }

        resolved.sync_with(&staging)?;
        self.hook.hit(TransitionPoint::FinalDirectoriesSynced)?;
        match marker.final_identity.as_ref() {
            Some(expected) => {
                let actual = resolved.verify_finalization(
                    marker.content_length,
                    &marker.content_sha256,
                    &marker.restore_metadata,
                )?;
                if !same_file_after_rename(expected, &actual) {
                    anyhow::bail!("final restoration changed before marker deletion")
                }
            }
            None if resolved.observe()?.is_none() => {}
            None => anyhow::bail!("absent target appeared before marker deletion"),
        }

        match self.store.finish_finalization(&path, &marker.version()) {
            Ok(()) => {}
            Err(error) => match self.store.load(&path)? {
                Entry::Missing => {}
                Entry::Finalizing(actual) if *actual == marker => return Err(error.into()),
                _ => anyhow::bail!(
                    "finalization marker changed unexpectedly during deletion for {}",
                    path.display()
                ),
            },
        }
        self.hook.hit(TransitionPoint::MarkerDeleted)?;
        if let Err(error) = staging.remove_if_empty() {
            tracing::warn!(
                "finalized {} but could not remove its empty staging directory: {error}",
                path.display()
            );
        }
        Ok(())
    }

    fn validate_restored_target(
        &self,
        record: &SnapshotRecord,
        resolved: &ResolvedPath,
    ) -> anyhow::Result<()> {
        let restored_identity = match &record.header.lifecycle {
            Lifecycle::Restored {
                restored_identity, ..
            }
            | Lifecycle::DeleteIntent {
                restored_identity, ..
            } => restored_identity,
            _ => anyhow::bail!("record is not in restored cleanup"),
        };
        match restored_identity {
            Some(expected) if record.header.logical_present => {
                let actual = resolved
                    .verify_restoration(&record.contents, record.header.original.metadata())?;
                if &actual != expected {
                    anyhow::bail!("restored inode identity changed")
                }
            }
            None if !record.header.logical_present && resolved.observe()?.is_none() => {}
            _ => anyhow::bail!("restored target presence disagrees with the snapshot"),
        }
        Ok(())
    }

    fn validate_installed_layout(
        &self,
        path: &Path,
        record: &SnapshotRecord,
        detached_original: &Option<ObjectIdentity>,
    ) -> anyhow::Result<()> {
        let resolved = self.resolve_bound_path(path, record)?;
        let staging = self.open_staging(record)?;
        let placeholder = record
            .header
            .placeholder
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("installed snapshot has no placeholder identity"))?;
        if resolved.observe()?.as_ref() != Some(placeholder) {
            anyhow::bail!(
                "{} no longer contains the recorded placeholder",
                path.display()
            )
        }
        match (&record.header.original, detached_original) {
            (OriginalState::Present { .. }, Some(detached))
                if staging.observe(&record.header.swap_name)? == Some(detached.clone()) =>
            {
                Ok(())
            }
            (OriginalState::Absent { .. }, None)
                if staging.observe(&record.header.swap_name)?.is_none() =>
            {
                Ok(())
            }
            _ => anyhow::bail!(
                "{} has inconsistent installed recovery state",
                path.display()
            ),
        }
    }

    fn validate_captured_source(
        &self,
        record: &SnapshotRecord,
        resolved: &ResolvedPath,
    ) -> anyhow::Result<()> {
        match &record.header.original {
            OriginalState::Present {
                identity: expected_identity,
                metadata: expected_metadata,
            } => {
                let captured = resolved.capture()?;
                let OriginalState::Present { identity, metadata } = captured.original else {
                    anyhow::bail!("captured file disappeared")
                };
                if identity != *expected_identity
                    || captured.contents != record.contents
                    || metadata.uid != expected_metadata.uid
                    || metadata.gid != expected_metadata.gid
                    || metadata.mode != expected_metadata.mode
                    || metadata.mtime != expected_metadata.mtime
                    || metadata.xattrs != expected_metadata.xattrs
                {
                    anyhow::bail!("captured file no longer matches its durable snapshot")
                }
            }
            OriginalState::Absent { .. } if resolved.observe()?.is_none() => {}
            OriginalState::Absent { .. } => anyhow::bail!("captured absent path appeared"),
        }
        Ok(())
    }

    fn require_installed(
        &self,
        path: &Path,
        record: SnapshotRecord,
    ) -> anyhow::Result<SnapshotRecord> {
        let Lifecycle::Installed { detached_original } = record.header.lifecycle.clone() else {
            return self.conflict(record, "record claims an invalid installed lifecycle");
        };
        self.require_installed_layout(path, record, detached_original)
    }

    fn require_installed_layout(
        &self,
        path: &Path,
        record: SnapshotRecord,
        detached_original: Option<ObjectIdentity>,
    ) -> anyhow::Result<SnapshotRecord> {
        match self.validate_installed_layout(path, &record, &detached_original) {
            Ok(()) => Ok(record),
            Err(error) => self.conflict(
                record,
                &format!("installed filesystem layout is invalid: {error}"),
            ),
        }
    }

    fn validate_stored(&self, path: &Path, record: &SnapshotRecord) -> anyhow::Result<()> {
        let Lifecycle::Stored {
            detached_name,
            detached_original,
        } = &record.header.lifecycle
        else {
            anyhow::bail!("record is not stored offline")
        };
        let OriginalState::Present { .. } = &record.header.original else {
            anyhow::bail!("stored record claims its original path was absent")
        };
        let resolved = self.resolve_bound_path(path, record)?;
        let staging = self.open_staging(record)?;
        if resolved.observe()?.is_some()
            || staging.observe(detached_name)? != Some(detached_original.clone())
        {
            anyhow::bail!("{} has inconsistent offline-store state", path.display())
        }
        Ok(())
    }

    fn require_stored(
        &self,
        path: &Path,
        record: SnapshotRecord,
    ) -> anyhow::Result<SnapshotRecord> {
        match self.validate_stored(path, &record) {
            Ok(()) => Ok(record),
            Err(error) => self.conflict(
                record,
                &format!("offline-store filesystem layout is invalid: {error}"),
            ),
        }
    }

    fn resolve_bound_path(
        &self,
        path: &Path,
        record: &SnapshotRecord,
    ) -> anyhow::Result<ResolvedPath> {
        let resolved = ResolvedPath::new(path)?;
        let actual_parent = resolved.parent_identity()?;
        if !same_object(&actual_parent, &record.header.parent) {
            anyhow::bail!(
                "parent directory for {} changed since capture",
                path.display()
            )
        }
        Ok(resolved)
    }

    fn open_staging(&self, record: &SnapshotRecord) -> anyhow::Result<StagingArea> {
        let path = path_from_hex(&record.header.staging_path_hex)?;
        Ok(StagingArea::open(&path, record.header.parent.device)?)
    }

    fn transition(
        &self,
        current: &SnapshotRecord,
        lifecycle: Lifecycle,
    ) -> anyhow::Result<SnapshotRecord> {
        let path = path_from_hex(&current.header.path_hex)?;
        let next = current.successor(lifecycle, current.contents.clone());
        self.commit_successor(current, &next)
            .with_context(|| format!("commit lifecycle transition for {}", path.display()))?;
        Ok(next)
    }

    fn commit_successor(
        &self,
        current: &SnapshotRecord,
        next: &SnapshotRecord,
    ) -> anyhow::Result<()> {
        let path = path_from_hex(&current.header.path_hex)?;
        self.store
            .commit(&path, Some(&current.version()), next)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn conflict<T>(&self, record: SnapshotRecord, reason: &str) -> anyhow::Result<T> {
        let path = path_from_hex(&record.header.path_hex)?;
        let mut conflict =
            record.successor(record.header.lifecycle.clone(), record.contents.clone());
        conflict.header.blocked_reason = Some(reason.to_string());
        match self.store.commit(&path, Some(&record.version()), &conflict) {
            Ok(_) => anyhow::bail!("{}: {reason}", path.display()),
            Err(error) => anyhow::bail!(
                "{}: {reason}; additionally failed to persist conflict state: {error}",
                path.display()
            ),
        }
    }

    fn require_unblocked(&self, path: &Path, record: &SnapshotRecord) -> anyhow::Result<()> {
        if let Some(reason) = &record.header.blocked_reason {
            anyhow::bail!(
                "transaction for {} requires manual recovery: {reason}",
                path.display()
            )
        }
        Ok(())
    }
}

fn layout_matches(
    actual: &(Option<ObjectIdentity>, Option<ObjectIdentity>),
    expected: &(Option<ObjectIdentity>, Option<ObjectIdentity>),
    after_rename: bool,
) -> bool {
    object_matches(actual.0.as_ref(), expected.0.as_ref(), after_rename)
        && object_matches(actual.1.as_ref(), expected.1.as_ref(), after_rename)
}

fn object_matches(
    actual: Option<&ObjectIdentity>,
    expected: Option<&ObjectIdentity>,
    after_rename: bool,
) -> bool {
    match (actual, expected) {
        (None, None) => true,
        (Some(actual), Some(expected)) if after_rename => same_file_after_rename(expected, actual),
        (Some(actual), Some(expected)) => actual == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;
    use crate::store::sqlite::SqliteStore;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        store: PathBuf,
        staging: PathBuf,
        watched: PathBuf,
    }

    impl Fixture {
        fn present(tag: &str, contents: &[u8]) -> Self {
            let fixture = Self::new(tag);
            std::fs::write(&fixture.watched, contents).unwrap();
            std::fs::set_permissions(&fixture.watched, std::fs::Permissions::from_mode(0o640))
                .unwrap();
            fixture
        }

        fn absent(tag: &str) -> Self {
            Self::new(tag)
        }

        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "file-guard-transaction-{tag}-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let watched_parent = root.join("watched");
            std::fs::create_dir_all(&watched_parent).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                store: root.join("store"),
                staging: root.join("staging"),
                watched: watched_parent.join("credential"),
                root,
            }
        }

        fn manager(&self, hook: Arc<dyn TransitionHook>) -> TransactionManager {
            let store: Arc<dyn BackingStore> =
                Arc::new(SqliteStore::open(self.store.clone()).unwrap());
            TransactionManager::with_test_parts(store, self.staging.clone(), hook)
        }

        fn normal_manager(&self) -> TransactionManager {
            self.manager(Arc::new(NoopHook))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    struct FailAt {
        point: TransitionPoint,
        fired: AtomicBool,
    }

    impl FailAt {
        fn new(point: TransitionPoint) -> Self {
            Self {
                point,
                fired: AtomicBool::new(false),
            }
        }

        fn fired(&self) -> bool {
            self.fired.load(Ordering::SeqCst)
        }
    }

    impl TransitionHook for FailAt {
        fn hit(&self, point: TransitionPoint) -> anyhow::Result<()> {
            if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
                anyhow::bail!("injected crash at {point:?}")
            }
            Ok(())
        }
    }

    struct ActAt {
        point: TransitionPoint,
        fired: AtomicBool,
        action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl ActAt {
        fn new(point: TransitionPoint, action: impl FnOnce() + Send + 'static) -> Self {
            Self {
                point,
                fired: AtomicBool::new(false),
                action: Mutex::new(Some(Box::new(action))),
            }
        }
    }

    impl TransitionHook for ActAt {
        fn hit(&self, point: TransitionPoint) -> anyhow::Result<()> {
            if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
                self.action.lock().unwrap().take().unwrap()();
            }
            Ok(())
        }
    }

    fn assert_complete_copy(manager: &TransactionManager, path: &Path, expected: &[u8]) {
        let path_has_copy = std::fs::read(path).is_ok_and(|contents| contents == expected);
        let store_has_copy = match manager.load(path).unwrap() {
            Entry::Present(record) => record.contents == expected,
            Entry::Finalizing(marker) => path_from_hex(&marker.staging_path_hex)
                .ok()
                .and_then(|staging| std::fs::read(staging.join(&marker.final_name)).ok())
                .is_some_and(|contents| contents == expected),
            Entry::Missing => false,
        };
        assert!(
            path_has_copy || store_has_copy,
            "neither the watched path nor the store has a complete copy"
        );
    }

    fn assert_restored(fixture: &Fixture, expected: &[u8]) {
        assert_eq!(std::fs::read(&fixture.watched).unwrap(), expected);
        assert_eq!(
            std::fs::metadata(&fixture.watched)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let manager = fixture.normal_manager();
        assert_eq!(manager.load(&fixture.watched).unwrap(), Entry::Missing);
    }

    #[test]
    fn capture_faults_always_leave_a_recoverable_copy() {
        let points = [
            TransitionPoint::PlaceholderCreated,
            TransitionPoint::CapturedCommitted,
            TransitionPoint::InstallIntentCommitted,
            TransitionPoint::InstallRenamed,
            TransitionPoint::InstallDirectoriesSynced,
            TransitionPoint::InstalledCommitted,
        ];
        for point in points {
            let fixture = Fixture::present("capture-fault", b"original-secret");
            let hook = Arc::new(FailAt::new(point));
            let manager = fixture.manager(hook.clone());
            assert!(manager.prepare(&fixture.watched).is_err(), "{point:?}");
            assert!(hook.fired(), "transition {point:?} was not exercised");
            assert_complete_copy(&manager, &fixture.watched, b"original-secret");
            drop(manager);

            let manager = fixture.normal_manager();
            manager.prepare(&fixture.watched).unwrap();
            manager.restore(&fixture.watched).unwrap();
            drop(manager);
            assert_restored(&fixture, b"original-secret");
        }
    }

    #[test]
    fn capture_commits_before_staging_is_created() {
        let fixture = Fixture::present("capture-order", b"original-secret");
        let hook = Arc::new(FailAt::new(TransitionPoint::CapturedCommitted));
        let manager = fixture.manager(hook.clone());
        assert!(manager.prepare(&fixture.watched).is_err());
        assert!(hook.fired());
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("capture hook fired without a durable snapshot")
        };
        assert!(matches!(record.header.lifecycle, Lifecycle::Captured));
        assert!(record.header.placeholder.is_none());
        assert!(
            !path_from_hex(&record.header.staging_path_hex)
                .unwrap()
                .exists()
        );
        assert_eq!(std::fs::read(&fixture.watched).unwrap(), b"original-secret");
    }

    #[test]
    fn partial_placeholder_is_rebuilt_from_the_snapshot() {
        let fixture = Fixture::present("partial-placeholder", b"original-secret");
        let hook = Arc::new(FailAt::new(TransitionPoint::CapturedCommitted));
        let manager = fixture.manager(hook);
        assert!(manager.prepare(&fixture.watched).is_err());
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("capture should be committed")
        };
        let staging_path = path_from_hex(&record.header.staging_path_hex).unwrap();
        let staging = StagingArea::create(
            staging_path.parent().unwrap(),
            &record.header.generation,
            record.header.parent.device,
        )
        .unwrap();
        std::fs::write(staging.path().join(&record.header.swap_name), b"partial").unwrap();
        drop(staging);
        drop(manager);

        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        manager.restore(&fixture.watched).unwrap();
        drop(manager);
        assert_restored(&fixture, b"original-secret");
    }

    #[test]
    fn restore_faults_replay_without_losing_the_snapshot() {
        let points = [
            TransitionPoint::RestoreIntentCommitted,
            TransitionPoint::RestoreFileCreated,
            TransitionPoint::RestoreFileCommitted,
            TransitionPoint::RestoreRenamed,
            TransitionPoint::RestoreDirectoriesSynced,
            TransitionPoint::RestoredCommitted,
            TransitionPoint::DeleteIntentCommitted,
            TransitionPoint::FinalCopyCreated,
            TransitionPoint::RestoredTargetRetired,
            TransitionPoint::PreFinalizationSynced,
            TransitionPoint::FinalizationCommitted,
            TransitionPoint::FinalRename,
            TransitionPoint::FinalDirectoriesSynced,
            TransitionPoint::MarkerDeleted,
        ];
        for point in points {
            let fixture = Fixture::present("restore-fault", b"updated-secret");
            let manager = fixture.normal_manager();
            manager.prepare(&fixture.watched).unwrap();
            drop(manager);

            let hook = Arc::new(FailAt::new(point));
            let manager = fixture.manager(hook.clone());
            assert!(manager.restore(&fixture.watched).is_err(), "{point:?}");
            assert!(hook.fired(), "transition {point:?} was not exercised");
            assert_complete_copy(&manager, &fixture.watched, b"updated-secret");
            drop(manager);

            let manager = fixture.normal_manager();
            manager.restore(&fixture.watched).unwrap();
            drop(manager);
            assert_restored(&fixture, b"updated-secret");
        }
    }

    #[test]
    fn partial_restoration_is_rebuilt_from_the_snapshot() {
        let fixture = Fixture::present("partial-restore", b"original-secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        drop(manager);

        let hook = Arc::new(FailAt::new(TransitionPoint::RestoreIntentCommitted));
        let manager = fixture.manager(hook);
        assert!(manager.restore(&fixture.watched).is_err());
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("restore intent should be committed")
        };
        let Lifecycle::RestoreIntent {
            restore_name: Some(restore_name),
            ..
        } = &record.header.lifecycle
        else {
            panic!("record should contain a restore intent")
        };
        let staging_path = path_from_hex(&record.header.staging_path_hex).unwrap();
        std::fs::write(staging_path.join(restore_name), b"partial").unwrap();
        drop(manager);

        let manager = fixture.normal_manager();
        manager.restore(&fixture.watched).unwrap();
        drop(manager);
        assert_restored(&fixture, b"original-secret");
    }

    #[test]
    fn partial_final_copy_is_rebuilt_from_the_snapshot() {
        let fixture = Fixture::present("partial-final", b"original-secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        drop(manager);

        let hook = Arc::new(FailAt::new(TransitionPoint::DeleteIntentCommitted));
        let manager = fixture.manager(hook);
        assert!(manager.restore(&fixture.watched).is_err());
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("deletion intent should be committed")
        };
        assert!(matches!(
            record.header.lifecycle,
            Lifecycle::DeleteIntent { .. }
        ));
        let staging_path = path_from_hex(&record.header.staging_path_hex).unwrap();
        std::fs::write(staging_path.join(FINAL_NAME), b"partial").unwrap();
        drop(manager);

        let manager = fixture.normal_manager();
        manager.restore(&fixture.watched).unwrap();
        drop(manager);
        assert_restored(&fixture, b"original-secret");
    }

    #[test]
    fn offline_store_faults_replay_before_restore() {
        let points = [
            TransitionPoint::StoreIntentCommitted,
            TransitionPoint::StoreRenamed,
            TransitionPoint::StoredCommitted,
        ];
        for point in points {
            let fixture = Fixture::present("store-fault", b"offline-secret");
            let hook = Arc::new(FailAt::new(point));
            let manager = fixture.manager(hook.clone());
            assert!(
                manager.store_offline(&fixture.watched).is_err(),
                "{point:?}"
            );
            assert!(hook.fired(), "transition {point:?} was not exercised");
            assert_complete_copy(&manager, &fixture.watched, b"offline-secret");
            drop(manager);

            let manager = fixture.normal_manager();
            manager.store_offline(&fixture.watched).unwrap();
            manager.restore(&fixture.watched).unwrap();
            drop(manager);
            assert_restored(&fixture, b"offline-secret");
        }
    }

    #[test]
    fn offline_store_rejects_detached_inode_mutation_before_commit() {
        use std::io::{Seek, SeekFrom, Write};

        let fixture = Fixture::present("store-descriptor-mutation", b"original-secret");
        let hook = Arc::new(FailAt::new(TransitionPoint::StoreIntentCommitted));
        let manager = fixture.manager(hook.clone());
        assert!(manager.store_offline(&fixture.watched).is_err());
        assert!(hook.fired());

        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("offline-store intent should be committed")
        };
        let Lifecycle::StoreIntent { detached_name } = record.header.lifecycle.clone() else {
            panic!("record should contain an offline-store intent")
        };
        let original_mtime = std::fs::metadata(&fixture.watched)
            .unwrap()
            .modified()
            .unwrap();
        let mut descriptor = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.watched)
            .unwrap();
        let resolved = manager
            .resolve_bound_path(&fixture.watched, &record)
            .unwrap();
        let staging = manager.open_staging(&record).unwrap();
        resolved.move_to_staging(&staging, &detached_name).unwrap();

        descriptor.seek(SeekFrom::Start(0)).unwrap();
        descriptor.write_all(b"attacker-secret").unwrap();
        descriptor
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        descriptor.sync_all().unwrap();

        assert!(manager.store_offline(&fixture.watched).is_err());
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("snapshot was deleted after detached-inode mutation")
        };
        assert_eq!(record.contents, b"original-secret");
        assert!(record.header.blocked_reason.is_some());
        assert_eq!(
            std::fs::read(staging.path().join(detached_name)).unwrap(),
            b"attacker-secret"
        );
    }

    #[test]
    fn mount_intents_fence_late_writes_and_reconcile_after_absence() {
        let fixture = Fixture::present("mount-lifecycle", b"initial");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        let mounted = manager.begin_mount(&fixture.watched).unwrap();
        let mounted = manager
            .update_contents(&mounted, b"durable-update".to_vec())
            .unwrap();
        manager
            .begin_unmount(&fixture.watched, UnmountNext::Restore)
            .unwrap();
        assert!(
            manager
                .update_contents(&mounted, b"late-write".to_vec())
                .is_err()
        );
        manager
            .reconcile_after_mount_absent(&fixture.watched)
            .unwrap();
        drop(manager);
        assert_restored(&fixture, b"durable-update");
    }

    #[test]
    fn unmount_intent_does_not_require_a_visible_placeholder() {
        let fixture = Fixture::present("mounted-view", b"initial");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        manager.begin_mount(&fixture.watched).unwrap();

        let hidden_placeholder = fixture.watched.with_extension("placeholder");
        std::fs::rename(&fixture.watched, &hidden_placeholder).unwrap();
        std::fs::write(&fixture.watched, b"mounted-view").unwrap();

        let record = manager
            .begin_unmount(&fixture.watched, UnmountNext::Restore)
            .unwrap();
        assert!(matches!(
            record.header.lifecycle,
            Lifecycle::UnmountIntent {
                next: UnmountNext::Restore,
                ..
            }
        ));
        assert_eq!(record.contents, b"initial");
    }

    #[test]
    fn mount_transition_faults_are_idempotent() {
        let fixture = Fixture::present("mount-fault", b"secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        drop(manager);

        let hook = Arc::new(FailAt::new(TransitionPoint::MountIntentCommitted));
        let manager = fixture.manager(hook.clone());
        assert!(manager.begin_mount(&fixture.watched).is_err());
        assert!(hook.fired());
        drop(manager);

        let hook = Arc::new(FailAt::new(TransitionPoint::MountAbortedCommitted));
        let manager = fixture.manager(hook.clone());
        assert!(
            manager
                .reconcile_after_mount_absent(&fixture.watched)
                .is_err()
        );
        assert!(hook.fired());
        drop(manager);

        let manager = fixture.normal_manager();
        let mounted = manager.begin_mount(&fixture.watched).unwrap();
        assert!(matches!(
            mounted.header.lifecycle,
            Lifecycle::MountIntent { .. }
        ));
        drop(manager);

        let hook = Arc::new(FailAt::new(TransitionPoint::UnmountIntentCommitted));
        let manager = fixture.manager(hook.clone());
        assert!(
            manager
                .begin_unmount(&fixture.watched, UnmountNext::LeaveInstalled)
                .is_err()
        );
        assert!(hook.fired());
        drop(manager);

        let hook = Arc::new(FailAt::new(TransitionPoint::UnmountedCommitted));
        let manager = fixture.manager(hook.clone());
        assert!(
            manager
                .reconcile_after_mount_absent(&fixture.watched)
                .is_err()
        );
        assert!(hook.fired());
        drop(manager);

        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        manager.restore(&fixture.watched).unwrap();
        drop(manager);
        assert_restored(&fixture, b"secret");
    }

    #[test]
    fn empty_and_absent_sources_remain_distinct() {
        let empty = Fixture::present("empty", b"");
        let manager = empty.normal_manager();
        let record = manager.prepare(&empty.watched).unwrap();
        assert!(matches!(
            record.header.original,
            OriginalState::Present { .. }
        ));
        manager.restore(&empty.watched).unwrap();
        drop(manager);
        assert_restored(&empty, b"");

        let absent = Fixture::absent("absent");
        let manager = absent.normal_manager();
        let record = manager.prepare(&absent.watched).unwrap();
        assert!(matches!(
            record.header.original,
            OriginalState::Absent { .. }
        ));
        assert!(absent.watched.exists());
        manager.restore(&absent.watched).unwrap();
        assert!(!absent.watched.exists());
        assert_eq!(manager.load(&absent.watched).unwrap(), Entry::Missing);
    }

    #[test]
    fn absent_source_install_and_restore_renames_replay() {
        let fixture = Fixture::absent("absent-fault");
        let hook = Arc::new(FailAt::new(TransitionPoint::InstallRenamed));
        let manager = fixture.manager(hook.clone());
        assert!(manager.prepare(&fixture.watched).is_err());
        assert!(hook.fired());
        drop(manager);

        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        drop(manager);

        let hook = Arc::new(FailAt::new(TransitionPoint::RestoreRenamed));
        let manager = fixture.manager(hook.clone());
        assert!(manager.restore(&fixture.watched).is_err());
        assert!(hook.fired());
        drop(manager);

        let manager = fixture.normal_manager();
        manager.restore(&fixture.watched).unwrap();
        assert!(!fixture.watched.exists());
        assert_eq!(manager.load(&fixture.watched).unwrap(), Entry::Missing);
    }

    #[test]
    fn write_to_an_absent_source_restores_a_new_file() {
        let fixture = Fixture::absent("absent-created");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        let mounted = manager.begin_mount(&fixture.watched).unwrap();
        manager
            .update_contents(&mounted, b"new-credential".to_vec())
            .unwrap();
        manager
            .begin_unmount(&fixture.watched, UnmountNext::Restore)
            .unwrap();
        manager
            .reconcile_after_mount_absent(&fixture.watched)
            .unwrap();

        assert_eq!(std::fs::read(&fixture.watched).unwrap(), b"new-credential");
        assert_eq!(manager.load(&fixture.watched).unwrap(), Entry::Missing);
        assert_eq!(
            std::fs::metadata(&fixture.watched)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn replacing_the_placeholder_persists_a_conflict_and_retains_the_snapshot() {
        let fixture = Fixture::present("replace", b"original-secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        let displaced = fixture.watched.with_extension("placeholder");
        std::fs::rename(&fixture.watched, &displaced).unwrap();
        std::fs::write(&fixture.watched, b"attacker-file").unwrap();

        assert!(manager.restore(&fixture.watched).is_err());
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("conflicted snapshot was deleted")
        };
        assert_eq!(record.contents, b"original-secret");
        assert!(matches!(
            record.header.lifecycle,
            Lifecycle::Installed { .. }
        ));
        assert!(record.header.blocked_reason.is_some());
        assert_eq!(std::fs::read(&fixture.watched).unwrap(), b"attacker-file");
    }

    #[test]
    fn symlink_replacement_is_never_followed_during_restore() {
        let fixture = Fixture::present("symlink-replace", b"original-secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        let displaced = fixture.watched.with_extension("placeholder");
        let attacker = fixture.watched.with_extension("attacker");
        std::fs::rename(&fixture.watched, &displaced).unwrap();
        std::fs::write(&attacker, b"attacker-file").unwrap();
        std::os::unix::fs::symlink(&attacker, &fixture.watched).unwrap();

        assert!(manager.restore(&fixture.watched).is_err());
        assert_eq!(std::fs::read(&attacker).unwrap(), b"attacker-file");
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("snapshot was deleted after symlink replacement")
        };
        assert_eq!(record.contents, b"original-secret");
        assert!(record.header.blocked_reason.is_some());
    }

    #[test]
    fn detached_original_mutation_fails_cleanup_with_both_copies_retained() {
        use std::io::{Seek, SeekFrom, Write};

        let fixture = Fixture::present("descriptor-mutation", b"original-secret");
        let mut descriptor = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.watched)
            .unwrap();
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        descriptor.seek(SeekFrom::Start(0)).unwrap();
        descriptor.write_all(b"changed-through-fd").unwrap();
        descriptor
            .set_len(b"changed-through-fd".len() as u64)
            .unwrap();
        descriptor.sync_all().unwrap();

        assert!(manager.restore(&fixture.watched).is_err());
        assert_eq!(std::fs::read(&fixture.watched).unwrap(), b"");
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("snapshot was deleted after detached-inode mutation")
        };
        assert_eq!(record.contents, b"original-secret");
        assert!(record.header.blocked_reason.is_some());
        let staging = StagingArea::open(
            &path_from_hex(&record.header.staging_path_hex).unwrap(),
            record.header.parent.device,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(staging.path().join(&record.header.swap_name)).unwrap(),
            b"changed-through-fd"
        );
    }

    #[test]
    fn target_replacement_during_finalization_keeps_the_private_copy() {
        let fixture = Fixture::present("cleanup-replacement", b"original-secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        drop(manager);

        let watched = fixture.watched.clone();
        let hook = Arc::new(ActAt::new(
            TransitionPoint::PreFinalizationSynced,
            move || {
                std::fs::write(&watched, b"attacker-file").unwrap();
            },
        ));
        let manager = fixture.manager(hook.clone());
        assert!(manager.restore(&fixture.watched).is_err());
        assert!(hook.fired.load(Ordering::SeqCst));
        let Entry::Finalizing(marker) = manager.load(&fixture.watched).unwrap() else {
            panic!("snapshot was not replaced by a finalization marker")
        };
        assert_eq!(
            std::fs::read(
                path_from_hex(&marker.staging_path_hex)
                    .unwrap()
                    .join(&marker.final_name)
            )
            .unwrap(),
            b"original-secret"
        );
        assert_eq!(std::fs::read(&fixture.watched).unwrap(), b"attacker-file");

        std::fs::remove_file(&fixture.watched).unwrap();
        drop(manager);
        let manager = fixture.normal_manager();
        manager.restore(&fixture.watched).unwrap();
        drop(manager);
        assert_restored(&fixture, b"original-secret");
    }

    #[test]
    fn same_inode_content_mutation_during_restore_is_detected() {
        let fixture = Fixture::present("restore-mutation", b"original-secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        drop(manager);

        let watched = fixture.watched.clone();
        let hook = Arc::new(ActAt::new(TransitionPoint::RestoreRenamed, move || {
            let before = std::fs::metadata(&watched).unwrap();
            std::fs::write(&watched, b"attacker-secret").unwrap();
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&watched)
                .unwrap();
            file.set_times(
                std::fs::FileTimes::new()
                    .set_accessed(before.accessed().unwrap())
                    .set_modified(before.modified().unwrap()),
            )
            .unwrap();
        }));
        let manager = fixture.manager(hook.clone());
        assert!(manager.restore(&fixture.watched).is_err());
        assert!(hook.fired.load(Ordering::SeqCst));
        assert_eq!(std::fs::read(&fixture.watched).unwrap(), b"attacker-secret");
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("snapshot was deleted after restored inode mutation")
        };
        assert_eq!(record.contents, b"original-secret");
        assert!(record.header.blocked_reason.is_some());
    }

    #[test]
    fn parent_replacement_during_restore_keeps_the_snapshot() {
        let fixture = Fixture::present("parent-replacement", b"original-secret");
        let manager = fixture.normal_manager();
        manager.prepare(&fixture.watched).unwrap();
        drop(manager);

        let parent = fixture.watched.parent().unwrap().to_path_buf();
        let displaced = fixture.root.join("watched-displaced");
        let hook = Arc::new(ActAt::new(
            TransitionPoint::RestoreDirectoriesSynced,
            move || {
                std::fs::rename(&parent, &displaced).unwrap();
                std::fs::create_dir(&parent).unwrap();
            },
        ));
        let manager = fixture.manager(hook.clone());
        assert!(manager.restore(&fixture.watched).is_err());
        assert!(hook.fired.load(Ordering::SeqCst));
        assert!(!fixture.watched.exists());
        assert_eq!(
            std::fs::read(fixture.root.join("watched-displaced/credential")).unwrap(),
            b"original-secret"
        );
        let Entry::Present(record) = manager.load(&fixture.watched).unwrap() else {
            panic!("snapshot was deleted after parent replacement")
        };
        assert_eq!(record.contents, b"original-secret");
        assert!(record.header.blocked_reason.is_some());
    }
}
