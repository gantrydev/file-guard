use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyWrite, Request, TimeOrNow, WriteFlags,
};

use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::policy::rule::{Access, Decision};
use crate::process::identify::ProcessInfo;
use crate::store::{BackingStore, Entry, Lifecycle, RestoreMetadata, SnapshotRecord};
use crate::transaction::TransactionManager;

/// Upper bound on the in-memory content of a guarded file. Credential files are
/// tiny; this cap turns a malicious or buggy write/truncate at a huge offset
/// into an `EFBIG` error instead of a multi-gigabyte allocation that aborts the
/// daemon (and with it every other mount).
const MAX_CONTENT_LEN: u64 = 16 * 1024 * 1024;

/// Zero attribute TTL: the kernel must re-`getattr` rather than trust a cached
/// size. Paired with `FOPEN_DIRECT_IO` (see `open`), this keeps the kernel from
/// holding a stale, larger size and writing back cached pages over a file that
/// a truncate has since shrunk — the resurrection that corrupts on editor saves.
fn default_ttl() -> Duration {
    Duration::ZERO
}

fn build_file_attr(file_size: u64, metadata: &RestoreMetadata) -> FileAttr {
    let now = SystemTime::now();

    FileAttr {
        ino: INodeNo::ROOT,
        size: file_size,
        blocks: 1,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::RegularFile,
        perm: (metadata.mode & 0o7777) as u16,
        nlink: 1,
        uid: metadata.uid,
        gid: metadata.gid,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

fn slice_content(content: &[u8], offset: u64, size: u32) -> &[u8] {
    let start = offset as usize;
    let content_len = content.len();
    let past_end = start >= content_len;
    if past_end {
        return &[];
    }

    let remaining = content_len - start;
    let read_size = std::cmp::min(size as usize, remaining);

    &content[start..start + read_size]
}

/// The end offset a write would reach, rejected (`EFBIG`) if it overflows or
/// exceeds the content cap. Pure so it can be unit-tested directly.
fn checked_write_end(offset: u64, len: usize) -> Result<usize, Errno> {
    let end = offset.checked_add(len as u64).ok_or(Errno::EFBIG)?;
    if end > MAX_CONTENT_LEN {
        return Err(Errno::EFBIG);
    }
    Ok(end as usize)
}

/// The single, authoritative live content of the guarded file. Every open
/// handle reads and writes *this* buffer (POSIX shared-inode semantics), rather
/// than a private per-handle copy — so concurrent writers can't lose each
/// other's edits and a truncate can't be reverted by a stale handle buffer.
struct Content {
    bytes: Vec<u8>,
    record: SnapshotRecord,
}

#[derive(Debug)]
enum MutationError {
    Invalid(Errno),
    Commit(anyhow::Error),
}

/// Per-open-handle bookkeeping. The buffer lives in `Content`, shared across
/// handles; a handle only records what it was authorized to do.
struct OpenHandle {
    access: Access,
    /// May this handle serve `read()`? True for `O_RDONLY` and for `O_RDWR`
    /// opens that also passed read authorization — never for `O_WRONLY`, so a
    /// write-only grant cannot read the secret back out of the buffer.
    can_read: bool,
}

/// Mutable state shared between the FUSE handlers and any authorization task
/// spawned off the session thread (see `open`). Held behind an `Arc` so an
/// async `open` can register its handle / apply an `O_TRUNC` after the (possibly
/// user-blocking) policy decision without pinning the single-threaded FUSE read
/// loop.
struct Shared {
    content: Mutex<Content>,
    handles: Mutex<HashMap<u64, OpenHandle>>,
    next_fh: AtomicU64,
}

impl Shared {
    fn register_handle(&self, handle: OpenHandle) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().unwrap().insert(fh, handle);
        fh
    }

    fn apply_write(
        &self,
        manager: &TransactionManager,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, MutationError> {
        match self.handles.lock().unwrap().get(&fh) {
            Some(h) if h.access == Access::Write => {}
            Some(_) | None => return Err(MutationError::Invalid(Errno::EACCES)),
        }

        let end = checked_write_end(offset, data.len()).map_err(MutationError::Invalid)?;
        let start = offset as usize;

        let mut content = self.content.lock().unwrap();
        let mut candidate = content.bytes.clone();
        if candidate.len() < end {
            candidate.resize(end, 0);
        }
        candidate[start..end].copy_from_slice(data);
        let next = manager
            .update_contents(&content.record, candidate.clone())
            .map_err(MutationError::Commit)?;
        content.bytes = candidate;
        content.record = next;
        Ok(data.len() as u32)
    }

    fn apply_truncate(
        &self,
        manager: &TransactionManager,
        new_size: u64,
    ) -> Result<(), MutationError> {
        if new_size > MAX_CONTENT_LEN {
            return Err(MutationError::Invalid(Errno::EFBIG));
        }
        let mut content = self.content.lock().unwrap();
        let mut candidate = content.bytes.clone();
        candidate.resize(new_size as usize, 0);
        let next = manager
            .update_contents(&content.record, candidate.clone())
            .map_err(MutationError::Commit)?;
        content.bytes = candidate;
        content.record = next;
        Ok(())
    }

    fn truncate_on_open(&self, manager: &TransactionManager) -> Result<(), MutationError> {
        self.apply_truncate(manager, 0)
    }

    fn current_size(&self) -> u64 {
        self.content.lock().unwrap().bytes.len() as u64
    }
}

pub struct CredentialFs {
    watched_path: PathBuf,
    manager: TransactionManager,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    rt_handle: tokio::runtime::Handle,
    /// Expected requester uid (the owner of the guarded file's directory). When
    /// set, only that uid — or root — may access the mount, even though
    /// `allow_other` makes it reachable by any local user.
    owner_uid: u32,
    presentation: RestoreMetadata,
    shared: Arc<Shared>,
}

impl CredentialFs {
    pub fn new(
        watched_path: PathBuf,
        store: Arc<dyn BackingStore>,
        policy: Arc<PolicyEngine>,
        logger: Arc<AccessLogger>,
        rt_handle: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let manager = TransactionManager::new(store);
        let Entry::Present(record) = manager.load(&watched_path)? else {
            anyhow::bail!("no installed v2 record for {}", watched_path.display())
        };
        let record = *record;
        if let Some(reason) = &record.header.blocked_reason {
            anyhow::bail!(
                "v2 record for {} requires manual recovery: {reason}",
                watched_path.display()
            )
        }
        if !matches!(record.header.lifecycle, Lifecycle::MountIntent { .. }) {
            anyhow::bail!(
                "v2 record for {} is not awaiting its mount",
                watched_path.display()
            )
        }
        let bytes = record.contents.clone();
        let presentation = record.header.original.metadata().clone();
        let owner_uid = record.header.parent.uid;

        Ok(Self {
            watched_path,
            manager,
            policy,
            logger,
            rt_handle,
            owner_uid,
            presentation,
            shared: Arc::new(Shared {
                content: Mutex::new(Content { bytes, record }),
                handles: Mutex::new(HashMap::new()),
                next_fh: AtomicU64::new(1),
            }),
        })
    }

    /// Whether `uid` may reach the mount at all. `allow_other` makes the root
    /// mount reachable by any local user, but only the owning user (or root)
    /// may touch another user's credential — enforced on every entry point, not
    /// just `open`, so a foreign user can't even `stat` it to learn its size.
    fn uid_permitted(&self, uid: u32) -> bool {
        uid == self.owner_uid || uid == 0
    }

    /// Identify the calling process, evaluate policy for a single `access`
    /// direction, and return the process info iff allowed. Runs on the caller's
    /// thread (used by the handle-less `setattr` truncate); `open` uses the
    /// off-thread `decide_open` instead so a pending prompt can't freeze the
    /// single-threaded FUSE session.
    fn authorize(&self, req: &Request, access: Access) -> Option<ProcessInfo> {
        let info = match crate::process::identify::identify(req.pid()) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("failed to identify pid {}: {e}", req.pid());
                return None;
            }
        };

        if !self.uid_permitted(req.uid()) {
            tracing::warn!(
                "denying uid {} access to {} (owner uid {:?})",
                req.uid(),
                self.watched_path.display(),
                self.owner_uid,
            );
            self.logger
                .log(&info, &self.watched_path, access, &Decision::DenyOnce, None);
            return None;
        }

        let needs_read = access != Access::Write;
        let needs_write = access != Access::Read;
        let decision = self.rt_handle.block_on(self.policy.evaluate_open(
            &info,
            &self.watched_path,
            needs_read,
            needs_write,
        ));
        self.logger
            .log(&info, &self.watched_path, access, &decision, None);

        decision.is_allowed().then_some(info)
    }

    fn apply_write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, MutationError> {
        self.shared.apply_write(&self.manager, fh, offset, data)
    }

    fn apply_truncate(&self, new_size: u64) -> Result<(), MutationError> {
        self.shared.apply_truncate(&self.manager, new_size)
    }

    fn current_size(&self) -> u64 {
        self.shared.current_size()
    }
}

/// Off-thread `open()` authorization: identify the caller, apply the uid gate,
/// and evaluate policy for the direction(s) the open needs. Returns the process
/// info iff the open is allowed. Kept free-standing so it can run inside a task
/// spawned off the FUSE session thread — a user prompt taking seconds must not
/// block unrelated operations on the (single-threaded) mount.
#[allow(clippy::too_many_arguments)]
async fn decide_open(
    policy: &PolicyEngine,
    logger: &AccessLogger,
    watched: &std::path::Path,
    owner_uid: u32,
    uid: u32,
    pid: u32,
    needs_read: bool,
    needs_write: bool,
) -> Option<ProcessInfo> {
    // Identifying a process stats /proc and hashes the binary — offload it so it
    // doesn't occupy an async worker thread.
    let info =
        match tokio::task::spawn_blocking(move || crate::process::identify::identify(pid)).await {
            Ok(Ok(info)) => info,
            Ok(Err(e)) => {
                tracing::warn!("failed to identify pid {pid}: {e}");
                return None;
            }
            Err(e) => {
                tracing::warn!("identify task for pid {pid} panicked: {e}");
                return None;
            }
        };

    let log_access = match (needs_read, needs_write) {
        (true, true) => Access::Any,
        (_, true) => Access::Write,
        _ => Access::Read,
    };

    if uid != owner_uid && uid != 0 {
        tracing::warn!(
            "denying uid {uid} access to {} (owner uid {owner_uid})",
            watched.display()
        );
        logger.log(&info, watched, log_access, &Decision::DenyOnce, None);
        return None;
    }

    let decision = policy
        .evaluate_open(&info, watched, needs_read, needs_write)
        .await;
    logger.log(&info, watched, log_access, &decision, None);
    decision.is_allowed().then_some(info)
}

impl Filesystem for CredentialFs {
    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        // Gate the probe on uid too: the reported `size` is the secret's length,
        // which a foreign local user must not learn via `stat` under allow_other.
        if !self.uid_permitted(req.uid()) {
            reply.error(Errno::EACCES);
            return;
        }
        reply.attr(
            &default_ttl(),
            &build_file_attr(self.current_size(), &self.presentation),
        );
    }

    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        reply.error(Errno::ENOENT);
    }

    /// `access(2)` is only an advisory permission probe — it grants nothing. The
    /// real boundary is `open()`/`read()`/`write()`, each gated by policy, so we
    /// answer the probe affirmatively (for a permitted uid) rather than leave it
    /// unimplemented (which made fuser log a `[Not Implemented]` warning on every
    /// check) and never leak the policy decision through a side channel.
    fn access(&self, req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        if !self.uid_permitted(req.uid()) {
            reply.error(Errno::EACCES);
            return;
        }
        reply.ok();
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let flags = flags.0;
        let accmode = flags & libc::O_ACCMODE;

        // O_RDWR needs both read and write authority; a write-only grant must
        // not read the secret back out of the shared buffer via read(). Both
        // directions are resolved in a *single* policy decision (one prompt,
        // one audit line) rather than a separate read-then-write gate.
        let needs_read = accmode == libc::O_RDONLY || accmode == libc::O_RDWR;
        let needs_write = Access::from_open_flags(flags) == Access::Write;
        let truncate_on_open = needs_write && (flags & libc::O_TRUNC) != 0;

        // An open requesting neither read nor write (the invalid `O_ACCMODE == 3`
        // ioctl-only form) is meaningless for a credential file and would sail
        // through policy vacuously — reject it rather than log a spurious ALLOW.
        if !needs_read && !needs_write {
            reply.error(Errno::EINVAL);
            return;
        }

        // Authorize off the FUSE session thread: a prompt can take seconds, and
        // the single-threaded session would otherwise stall every other op on
        // this mount (a concurrent `stat`, a read on another handle) until the
        // user answers. The reply is delivered from the spawned task.
        let policy = self.policy.clone();
        let logger = self.logger.clone();
        let shared = self.shared.clone();
        let manager = self.manager.clone();
        let watched = self.watched_path.clone();
        let owner_uid = self.owner_uid;
        let uid = req.uid();
        let pid = req.pid();

        self.rt_handle.spawn(async move {
            match decide_open(
                &policy,
                &logger,
                &watched,
                owner_uid,
                uid,
                pid,
                needs_read,
                needs_write,
            )
            .await
            {
                Some(_info) => {
                    // O_TRUNC empties the shared file immediately, even if the
                    // handle is closed without a subsequent write.
                    if truncate_on_open {
                        match shared.truncate_on_open(&manager) {
                            Ok(()) => {}
                            Err(MutationError::Invalid(error)) => {
                                reply.error(error);
                                return;
                            }
                            Err(MutationError::Commit(error)) => {
                                tracing::error!(
                                    "truncate-on-open of {} failed: {error}",
                                    watched.display()
                                );
                                reply.error(Errno::EIO);
                                return;
                            }
                        }
                    }
                    let access = if needs_write {
                        Access::Write
                    } else {
                        Access::Read
                    };
                    let fh = shared.register_handle(OpenHandle {
                        access,
                        can_read: needs_read,
                    });
                    reply.opened(FileHandle(fh), FopenFlags::FOPEN_DIRECT_IO);
                }
                None => reply.error(Errno::EACCES),
            }
        });
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        // An unknown fh was never authorized; a write-only handle may not read.
        match self.shared.handles.lock().unwrap().get(&fh.0) {
            Some(h) if h.can_read => {}
            Some(_) | None => {
                reply.error(Errno::EACCES);
                return;
            }
        }

        let content = self.shared.content.lock().unwrap();
        reply.data(slice_content(&content.bytes, offset, size));
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        match self.apply_write(fh.0, offset, data) {
            Ok(written) => reply.written(written),
            Err(MutationError::Invalid(error)) => reply.error(error),
            Err(MutationError::Commit(error)) => {
                tracing::error!(
                    "write of {} failed to commit: {error}",
                    self.watched_path.display()
                );
                reply.error(Errno::EIO);
            }
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        if !self.uid_permitted(req.uid()) {
            reply.error(Errno::EACCES);
            return;
        }
        if mode.is_some()
            || uid.is_some()
            || gid.is_some()
            || atime.is_some()
            || mtime.is_some()
            || ctime.is_some()
            || crtime.is_some()
            || chgtime.is_some()
            || bkuptime.is_some()
            || flags.is_some()
        {
            reply.error(Errno::EOPNOTSUPP);
            return;
        }

        if let Some(new_size) = size {
            let authorized = match fh {
                Some(handle) => self
                    .shared
                    .handles
                    .lock()
                    .unwrap()
                    .get(&handle.0)
                    .is_some_and(|state| state.access == Access::Write),
                None => self.authorize(req, Access::Write).is_some(),
            };
            if !authorized {
                reply.error(Errno::EACCES);
                return;
            }
            match self.apply_truncate(new_size) {
                Ok(()) => {}
                Err(MutationError::Invalid(error)) => {
                    reply.error(error);
                    return;
                }
                Err(MutationError::Commit(error)) => {
                    tracing::error!(
                        "truncate of {} failed: {error}",
                        self.watched_path.display()
                    );
                    reply.error(Errno::EIO);
                    return;
                }
            }
        }

        reply.attr(
            &default_ttl(),
            &build_file_attr(self.current_size(), &self.presentation),
        );
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        self.shared.handles.lock().unwrap().remove(&fh.0);
        reply.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Settings};
    use crate::logging::AccessLogger;
    use crate::policy::engine::PolicyEngine;
    use crate::prompt::PromptClient;
    use crate::store::testing::{MemoryStore, mount_intent_record};
    use crate::store::{FinalizationRecord, RecordVersion, StoreError, StoreResult};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn slice_content_bounds() {
        let c = b"hello world";
        assert_eq!(slice_content(c, 0, 5), b"hello");
        assert_eq!(slice_content(c, 6, 100), b"world"); // size past end clamps
        assert_eq!(slice_content(c, 11, 10), b""); // at end
        assert_eq!(slice_content(c, 100, 10), b""); // past end
        assert_eq!(slice_content(c, 0, 0), b""); // zero size
    }

    /// `fuser::Errno` has no `PartialEq`; compare via its libc code instead.
    fn code<T>(r: Result<T, Errno>) -> Result<T, i32> {
        r.map_err(|e| e.code())
    }

    fn mutation_code<T>(result: Result<T, MutationError>) -> Result<T, i32> {
        result.map_err(|error| match error {
            MutationError::Invalid(errno) => errno.code(),
            MutationError::Commit(error) => panic!("unexpected commit error: {error}"),
        })
    }

    #[test]
    fn checked_write_end_rejects_overflow_and_cap() {
        assert_eq!(code(checked_write_end(0, 5)), Ok(5));
        assert_eq!(
            code(checked_write_end(MAX_CONTENT_LEN - 3, 3)),
            Ok(MAX_CONTENT_LEN as usize)
        );
        assert_eq!(
            code(checked_write_end(MAX_CONTENT_LEN, 1)),
            Err(libc::EFBIG)
        );
        assert_eq!(code(checked_write_end(u64::MAX, 1)), Err(libc::EFBIG));
        assert_eq!(code(checked_write_end(1 << 50, 0)), Err(libc::EFBIG)); // huge sparse offset
    }

    fn credential_fs(
        watched: PathBuf,
        store: Arc<dyn BackingStore>,
    ) -> (CredentialFs, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let config = Config {
            settings: toml::from_str::<Settings>("default_action = \"deny\"").unwrap(),
            watch: vec![],
            rule: vec![],
        };
        let policy = Arc::new(PolicyEngine::new(
            &config,
            Arc::new(PromptClient::new(
                PathBuf::from("/nonexistent.sock"),
                Duration::from_millis(50),
                0,
            )),
        ));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let fs = CredentialFs::new(watched, store, policy, logger, rt.handle().clone()).unwrap();
        (fs, rt)
    }

    fn fixture(
        initial: &[u8],
    ) -> (
        CredentialFs,
        PathBuf,
        Arc<MemoryStore>,
        tokio::runtime::Runtime,
    ) {
        let watched = PathBuf::from("/credential");
        let store = Arc::new(MemoryStore::with_record(
            watched.clone(),
            mount_intent_record(&watched, initial),
        ));
        let (fs, rt) = credential_fs(watched.clone(), store.clone());
        (fs, watched, store, rt)
    }

    struct FaultStore {
        inner: MemoryStore,
        fail_before_commit: AtomicBool,
        fail_after_commit: AtomicBool,
    }

    impl FaultStore {
        fn new(path: &Path, contents: &[u8], before: bool, after: bool) -> Self {
            Self {
                inner: MemoryStore::with_record(
                    path.to_path_buf(),
                    mount_intent_record(path, contents),
                ),
                fail_before_commit: AtomicBool::new(before),
                fail_after_commit: AtomicBool::new(after),
            }
        }

        fn contents(&self, path: &Path) -> Vec<u8> {
            self.inner.contents(path)
        }
    }

    impl BackingStore for FaultStore {
        fn load(&self, file_id: &Path) -> StoreResult<Entry> {
            self.inner.load(file_id)
        }

        fn commit(
            &self,
            file_id: &Path,
            expected: Option<&RecordVersion>,
            next: &SnapshotRecord,
        ) -> StoreResult<RecordVersion> {
            if self.fail_before_commit.swap(false, Ordering::SeqCst) {
                return Err(StoreError::Io(std::io::Error::other(
                    "injected pre-commit failure",
                )));
            }
            let version = self.inner.commit(file_id, expected, next)?;
            if self.fail_after_commit.swap(false, Ordering::SeqCst) {
                return Err(StoreError::Indeterminate(
                    "injected post-commit failure".to_string(),
                ));
            }
            Ok(version)
        }

        fn begin_finalization(
            &self,
            file_id: &Path,
            expected: &RecordVersion,
            marker: &FinalizationRecord,
        ) -> StoreResult<RecordVersion> {
            self.inner.begin_finalization(file_id, expected, marker)
        }

        fn finish_finalization(&self, file_id: &Path, expected: &RecordVersion) -> StoreResult<()> {
            self.inner.finish_finalization(file_id, expected)
        }

        fn list(&self) -> StoreResult<Vec<Entry>> {
            self.inner.list()
        }
    }

    fn write_handle(fs: &CredentialFs) -> u64 {
        fs.shared.register_handle(OpenHandle {
            access: Access::Write,
            can_read: false,
        })
    }

    /// Two concurrent write handles editing disjoint regions: with a shared
    /// content buffer, both edits survive — the previous per-handle-buffer model
    /// lost the first writer's bytes (last-writer-wins whole-file overwrite).
    #[test]
    fn concurrent_disjoint_writes_preserve_both_edits() {
        let (fs, watched, store, _rt) = fixture(&[b'x'; 200]);
        let p1 = write_handle(&fs);
        let p2 = write_handle(&fs);

        fs.apply_write(p1, 0, b"AAA").unwrap();
        fs.apply_write(p2, 100, b"BBB").unwrap();

        let got = store.contents(&watched);
        assert_eq!(&got[0..3], b"AAA");
        assert_eq!(&got[100..103], b"BBB");
        assert_eq!(got.len(), 200);
    }

    /// A truncate is not reverted by another open write handle that never saw it
    /// (the original corruption class), because the buffer is shared.
    #[test]
    fn truncate_not_reverted_by_sibling_handle() {
        let (fs, watched, store, _rt) = fixture(b"OLD-LONG-SECRET");
        let sibling = write_handle(&fs);
        fs.apply_write(sibling, 0, b"OLD-LONG-SECRET").unwrap();

        fs.apply_truncate(3).unwrap();

        assert_eq!(store.contents(&watched), b"OLD");
    }

    /// O_TRUNC-at-open empties the shared file even with no following write.
    #[test]
    fn otrunc_open_then_close_persists_empty() {
        let (fs, watched, store, _rt) = fixture(b"SECRET");
        fs.shared.truncate_on_open(&fs.manager).unwrap();
        assert_eq!(store.contents(&watched), b"");
    }

    /// A write at a huge offset is rejected with EFBIG, not attempted as a
    /// multi-terabyte allocation that would abort the daemon.
    #[test]
    fn write_at_huge_offset_is_efbig() {
        let (fs, _watched, _store, _rt) = fixture(b"");
        let fh = write_handle(&fs);
        assert_eq!(
            mutation_code(fs.apply_write(fh, 1 << 50, b"x")),
            Err(libc::EFBIG)
        );
        assert_eq!(fs.current_size(), 0); // nothing allocated/grown
    }

    /// A sparse write past EOF zero-fills the gap and grows the file.
    #[test]
    fn sparse_write_zero_fills_gap() {
        let (fs, watched, store, _rt) = fixture(b"ab");
        let fh = write_handle(&fs);
        fs.apply_write(fh, 5, b"Z").unwrap();
        assert_eq!(store.contents(&watched), b"ab\0\0\0Z");
    }

    #[test]
    fn failed_write_is_never_published_or_retried() {
        let watched = PathBuf::from("/credential");
        let store = Arc::new(FaultStore::new(&watched, b"abc", true, false));
        let (fs, _rt) = credential_fs(watched.clone(), store.clone());
        let fh = write_handle(&fs);

        assert!(matches!(
            fs.apply_write(fh, 0, b"X"),
            Err(MutationError::Commit(_))
        ));
        assert_eq!(fs.shared.content.lock().unwrap().bytes, b"abc");
        assert_eq!(store.contents(&watched), b"abc");

        fs.apply_write(fh, 1, b"Z").unwrap();
        assert_eq!(store.contents(&watched), b"aZc");
    }

    #[test]
    fn indeterminate_committed_write_is_reloaded_before_publication() {
        let watched = PathBuf::from("/credential");
        let store = Arc::new(FaultStore::new(&watched, b"abc", false, true));
        let (fs, _rt) = credential_fs(watched.clone(), store.clone());
        let fh = write_handle(&fs);

        assert_eq!(fs.apply_write(fh, 0, b"X").unwrap(), 1);
        assert_eq!(fs.shared.content.lock().unwrap().bytes, b"Xbc");
        assert_eq!(store.contents(&watched), b"Xbc");
    }

    #[test]
    fn uid_gate_uses_captured_parent_owner() {
        let watched = PathBuf::from("/credential");
        let mut record = mount_intent_record(&watched, b"secret");
        record.header.parent.uid = 1234;
        if let crate::store::OriginalState::Present { metadata, .. } = &mut record.header.original {
            metadata.uid = 5678;
        }
        let store: Arc<dyn BackingStore> =
            Arc::new(MemoryStore::with_record(watched.clone(), record));
        let (fs, _rt) = credential_fs(watched, store);

        assert_eq!(fs.owner_uid, 1234);
        assert!(fs.uid_permitted(1234));
        assert!(!fs.uid_permitted(5678));
    }

    /// An unknown fh and a non-write handle are both refused by apply_write.
    #[test]
    fn write_rejects_unknown_and_read_handle() {
        let (fs, _watched, _store, _rt) = fixture(b"");
        assert_eq!(
            mutation_code(fs.apply_write(999, 0, b"x")),
            Err(libc::EACCES)
        );
        let read_fh = fs.shared.register_handle(OpenHandle {
            access: Access::Read,
            can_read: true,
        });
        assert_eq!(
            mutation_code(fs.apply_write(read_fh, 0, b"x")),
            Err(libc::EACCES)
        );
    }

    /// Construction surfaces a genuine store read error (existing entry that
    /// fails to read) instead of silently serving an empty file.
    #[test]
    fn new_propagates_store_read_error() {
        struct FailingStore;
        impl BackingStore for FailingStore {
            fn load(&self, _: &Path) -> crate::store::StoreResult<Entry> {
                Err(crate::store::StoreError::Io(std::io::Error::other(
                    "disk on fire",
                )))
            }
            fn commit(
                &self,
                _: &Path,
                _: Option<&crate::store::RecordVersion>,
                _: &SnapshotRecord,
            ) -> crate::store::StoreResult<crate::store::RecordVersion> {
                unreachable!()
            }
            fn begin_finalization(
                &self,
                _: &Path,
                _: &crate::store::RecordVersion,
                _: &crate::store::FinalizationRecord,
            ) -> crate::store::StoreResult<crate::store::RecordVersion> {
                unreachable!()
            }
            fn finish_finalization(
                &self,
                _: &Path,
                _: &crate::store::RecordVersion,
            ) -> crate::store::StoreResult<()> {
                unreachable!()
            }
            fn list(&self) -> crate::store::StoreResult<Vec<Entry>> {
                unreachable!()
            }
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        let config = Config {
            settings: toml::from_str::<Settings>("default_action = \"deny\"").unwrap(),
            watch: vec![],
            rule: vec![],
        };
        let policy = Arc::new(PolicyEngine::new(
            &config,
            Arc::new(PromptClient::new(
                PathBuf::from("/x.sock"),
                Duration::from_millis(50),
                0,
            )),
        ));
        let logger = Arc::new(AccessLogger::new("stdout").unwrap());
        let err = CredentialFs::new(
            PathBuf::from("/credential"),
            Arc::new(FailingStore),
            policy,
            logger,
            rt.handle().clone(),
        );
        assert!(
            err.is_err(),
            "a failing read of an existing entry must not be served as empty"
        );
    }
}
