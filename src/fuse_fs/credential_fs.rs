use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, INodeNo,
    LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite,
    Request, TimeOrNow, WriteFlags,
};

use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::policy::rule::{Access, Decision};
use crate::process::identify::ProcessInfo;
use crate::store::BackingStore;

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

fn build_file_attr(file_size: u64) -> FileAttr {
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
        // Writable: the mount now accepts gated writes (each write-open is
        // authorized like a read).
        perm: 0o644,
        nlink: 1,
        uid: 0,
        gid: 0,
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
    /// Differs from the backing store and must be persisted on flush/release.
    dirty: bool,
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

pub struct CredentialFs {
    watched_path: PathBuf,
    store: Arc<dyn BackingStore>,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    rt_handle: tokio::runtime::Handle,
    /// Expected requester uid (the owner of the guarded file's directory). When
    /// set, only that uid — or root — may access the mount, even though
    /// `allow_other` makes it reachable by any local user.
    owner_uid: Option<u32>,
    content: Mutex<Content>,
    handles: Mutex<HashMap<u64, OpenHandle>>,
    next_fh: AtomicU64,
}

impl CredentialFs {
    pub fn new(
        watched_path: PathBuf,
        store: Arc<dyn BackingStore>,
        policy: Arc<PolicyEngine>,
        logger: Arc<AccessLogger>,
        rt_handle: tokio::runtime::Handle,
        owner_uid: Option<u32>,
    ) -> anyhow::Result<Self> {
        // Load the authoritative content once. `exists()` distinguishes "not
        // stored yet" (serve empty) from a genuine read failure on an existing
        // entry, which must surface rather than masquerade as an empty file.
        let bytes = if store.exists(&watched_path) {
            store.read(&watched_path)?
        } else {
            Vec::new()
        };

        Ok(Self {
            watched_path,
            store,
            policy,
            logger,
            rt_handle,
            owner_uid,
            content: Mutex::new(Content {
                bytes,
                dirty: false,
            }),
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
        })
    }

    /// Identify the calling process, evaluate policy for `access`, and return
    /// the process info iff allowed. A foreign uid is rejected before policy is
    /// even consulted.
    fn authorize(&self, req: &Request, access: Access) -> Option<ProcessInfo> {
        let info = match crate::process::identify::identify(req.pid()) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("failed to identify pid {}: {e}", req.pid());
                return None;
            }
        };

        // Reject a foreign uid before consulting policy: `allow_other` makes the
        // root mount reachable by any local user, but only the owning user (or
        // root) may access another user's credential.
        if let Some(owner) = self.owner_uid {
            let uid = req.uid();
            if uid != owner && uid != 0 {
                tracing::warn!(
                    "denying uid {uid} access to {} (owner uid {owner})",
                    self.watched_path.display()
                );
                self.logger
                    .log(&info, &self.watched_path, access, &Decision::DenyOnce, None);
                return None;
            }
        }

        let decision =
            self.rt_handle
                .block_on(self.policy.evaluate(&info, &self.watched_path, access));
        self.logger
            .log(&info, &self.watched_path, access, &decision, None);

        decision.is_allowed().then_some(info)
    }

    fn register_handle(&self, handle: OpenHandle) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().unwrap().insert(fh, handle);
        fh
    }

    /// Apply a write into the shared content at `offset`, growing (and
    /// zero-filling any gap) as needed. Rejects an unknown/non-write handle
    /// (`EACCES`) and an out-of-bounds extent (`EFBIG`).
    fn apply_write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        match self.handles.lock().unwrap().get(&fh) {
            Some(h) if h.access == Access::Write => {}
            Some(_) | None => return Err(Errno::EACCES),
        }

        let end = checked_write_end(offset, data.len())?;
        let start = offset as usize;

        let mut content = self.content.lock().unwrap();
        if content.bytes.len() < end {
            content.bytes.resize(end, 0); // sparse gap zero-filled
        }
        content.bytes[start..end].copy_from_slice(data);
        content.dirty = true;
        Ok(data.len() as u32)
    }

    /// Resize the shared content to `new_size` (zero-filling on grow), rejecting
    /// an oversized truncate. Acts on the single shared buffer, so no open
    /// handle can later resurrect the dropped tail.
    fn apply_truncate(&self, new_size: u64) -> Result<(), Errno> {
        if new_size > MAX_CONTENT_LEN {
            return Err(Errno::EFBIG);
        }
        let mut content = self.content.lock().unwrap();
        content.bytes.resize(new_size as usize, 0);
        content.dirty = true;
        Ok(())
    }

    /// Empty the shared content (an `O_TRUNC` open), marking it dirty so the
    /// truncation persists even if the handle is closed without a write.
    fn truncate_on_open(&self) {
        let mut content = self.content.lock().unwrap();
        content.bytes.clear();
        content.dirty = true;
    }

    /// Persist the shared content to the store if dirty. The content lock is
    /// held across the store write so a concurrent write/truncate can neither
    /// interleave into a half-persisted state nor have its dirty flag cleared
    /// without being written; on failure `dirty` stays set for a later retry.
    fn persist(&self) -> anyhow::Result<()> {
        let mut content = self.content.lock().unwrap();
        if !content.dirty {
            return Ok(());
        }
        self.store.store(&self.watched_path, &content.bytes)?;
        content.dirty = false;
        Ok(())
    }

    fn current_size(&self) -> u64 {
        self.content.lock().unwrap().bytes.len() as u64
    }
}

impl Filesystem for CredentialFs {
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.attr(&default_ttl(), &build_file_attr(self.current_size()));
    }

    fn lookup(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEntry) {
        reply.error(Errno::ENOENT);
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let flags = flags.0;
        let accmode = flags & libc::O_ACCMODE;
        let access = Access::from_open_flags(flags);

        if self.authorize(req, access).is_none() {
            reply.error(Errno::EACCES);
            return;
        }

        // O_RDWR can both read and write. `from_open_flags` classifies it as a
        // write; it must *additionally* pass read authorization, otherwise a
        // write-only grant could open O_RDWR and read the secret out of the
        // shared buffer via read().
        let can_read = accmode == libc::O_RDONLY || accmode == libc::O_RDWR;
        if accmode == libc::O_RDWR && self.authorize(req, Access::Read).is_none() {
            reply.error(Errno::EACCES);
            return;
        }

        // O_TRUNC empties the shared file immediately, even if the handle is
        // closed without a subsequent write.
        if access == Access::Write && (flags & libc::O_TRUNC) != 0 {
            self.truncate_on_open();
        }

        let fh = self.register_handle(OpenHandle { access, can_read });
        reply.opened(FileHandle(fh), FopenFlags::FOPEN_DIRECT_IO);
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
        match self.handles.lock().unwrap().get(&fh.0) {
            Some(h) if h.can_read => {}
            Some(_) | None => {
                reply.error(Errno::EACCES);
                return;
            }
        }

        let content = self.content.lock().unwrap();
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
            Err(e) => reply.error(e),
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        // The only attribute we enforce is size (truncate) — it is a write and
        // the easiest write-bypass to miss. An already-authorized write handle
        // passes; a handle-less truncate is gated against the calling process.
        if let Some(new_size) = size {
            let authorized = match fh.and_then(|h| {
                self.handles
                    .lock()
                    .unwrap()
                    .get(&h.0)
                    .map(|s| s.access == Access::Write)
            }) {
                Some(true) => true,
                Some(false) => false, // a read handle may not resize
                None => self.authorize(req, Access::Write).is_some(),
            };
            if !authorized {
                reply.error(Errno::EACCES);
                return;
            }
            if let Err(e) = self.apply_truncate(new_size) {
                reply.error(e);
                return;
            }
            // A truncate is a durable operation on its own (a handle-less
            // truncate(2) has no later flush/release), so persist immediately.
            if let Err(e) = self.persist() {
                tracing::error!("truncate of {} failed: {e}", self.watched_path.display());
                reply.error(Errno::EIO);
                return;
            }
        }

        reply.attr(&default_ttl(), &build_file_attr(self.current_size()));
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
        match self.persist() {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!("flush of {} failed: {e}", self.watched_path.display());
                reply.error(Errno::EIO);
            }
        }
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
        match self.persist() {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!("fsync of {} failed: {e}", self.watched_path.display());
                reply.error(Errno::EIO);
            }
        }
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

        let persisted = self.persist();
        self.handles.lock().unwrap().remove(&fh.0);

        match persisted {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!(
                    "release persist of {} failed: {e}",
                    self.watched_path.display()
                );
                reply.error(Errno::EIO);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Settings};
    use crate::logging::AccessLogger;
    use crate::policy::engine::PolicyEngine;
    use crate::prompt::PromptClient;
    use std::collections::HashMap as StdHashMap;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;

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

    #[test]
    fn checked_write_end_rejects_overflow_and_cap() {
        assert_eq!(code(checked_write_end(0, 5)), Ok(5));
        assert_eq!(
            code(checked_write_end(MAX_CONTENT_LEN - 3, 3)),
            Ok(MAX_CONTENT_LEN as usize)
        );
        assert_eq!(code(checked_write_end(MAX_CONTENT_LEN, 1)), Err(libc::EFBIG));
        assert_eq!(code(checked_write_end(u64::MAX, 1)), Err(libc::EFBIG));
        assert_eq!(code(checked_write_end(1 << 50, 0)), Err(libc::EFBIG)); // huge sparse offset
    }

    struct MemStore(StdMutex<StdHashMap<PathBuf, Vec<u8>>>);

    impl BackingStore for MemStore {
        fn read(&self, id: &Path) -> anyhow::Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not stored"))
        }
        fn store(&self, id: &Path, contents: &[u8]) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(id.to_path_buf(), contents.to_vec());
            Ok(())
        }
        fn delete(&self, id: &Path) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
        fn list(&self) -> anyhow::Result<Vec<PathBuf>> {
            Ok(self.0.lock().unwrap().keys().cloned().collect())
        }
        fn exists(&self, id: &Path) -> bool {
            self.0.lock().unwrap().contains_key(id)
        }
    }

    /// A `CredentialFs` over an in-memory store seeded with `initial`. The
    /// policy/logger are never exercised by the content-level methods under test.
    fn fixture(initial: &[u8]) -> (CredentialFs, PathBuf, Arc<MemStore>, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let watched = PathBuf::from("/credential");
        let store = Arc::new(MemStore(StdMutex::new(
            [(watched.clone(), initial.to_vec())].into_iter().collect(),
        )));
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
        let fs = CredentialFs::new(
            watched.clone(),
            store.clone() as Arc<dyn BackingStore>,
            policy,
            logger,
            rt.handle().clone(),
            None,
        )
        .unwrap();
        (fs, watched, store, rt)
    }

    fn write_handle(fs: &CredentialFs) -> u64 {
        fs.register_handle(OpenHandle {
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
        fs.persist().unwrap();

        let got = store.read(&watched).unwrap();
        assert_eq!(&got[0..3], b"AAA");
        assert_eq!(&got[100..103], b"BBB");
        assert_eq!(got.len(), 200);
    }

    /// A truncate is not reverted by another open write handle that never saw it
    /// (the original corruption class), because the buffer is shared.
    #[test]
    fn truncate_not_reverted_by_sibling_handle() {
        let (fs, watched, store, _rt) = fixture(b"OLD-LONG-SECRET");
        let sibling = write_handle(&fs); // open, dirty, holds no private copy now
        fs.apply_write(sibling, 0, b"OLD-LONG-SECRET").unwrap();

        fs.apply_truncate(3).unwrap();
        fs.persist().unwrap(); // sibling's later persist sees the same 3-byte content

        assert_eq!(store.read(&watched).unwrap(), b"OLD");
    }

    /// O_TRUNC-at-open empties the shared file even with no following write.
    #[test]
    fn otrunc_open_then_close_persists_empty() {
        let (fs, watched, store, _rt) = fixture(b"SECRET");
        fs.truncate_on_open();
        fs.persist().unwrap();
        assert_eq!(store.read(&watched).unwrap(), b"");
    }

    /// A write at a huge offset is rejected with EFBIG, not attempted as a
    /// multi-terabyte allocation that would abort the daemon.
    #[test]
    fn write_at_huge_offset_is_efbig() {
        let (fs, _watched, _store, _rt) = fixture(b"");
        let fh = write_handle(&fs);
        assert_eq!(code(fs.apply_write(fh, 1 << 50, b"x")), Err(libc::EFBIG));
        assert_eq!(fs.current_size(), 0); // nothing allocated/grown
    }

    /// A sparse write past EOF zero-fills the gap and grows the file.
    #[test]
    fn sparse_write_zero_fills_gap() {
        let (fs, watched, store, _rt) = fixture(b"ab");
        let fh = write_handle(&fs);
        fs.apply_write(fh, 5, b"Z").unwrap();
        fs.persist().unwrap();
        assert_eq!(store.read(&watched).unwrap(), b"ab\0\0\0Z");
    }

    /// An unknown fh and a non-write handle are both refused by apply_write.
    #[test]
    fn write_rejects_unknown_and_read_handle() {
        let (fs, _watched, _store, _rt) = fixture(b"");
        assert_eq!(code(fs.apply_write(999, 0, b"x")), Err(libc::EACCES));
        let read_fh = fs.register_handle(OpenHandle {
            access: Access::Read,
            can_read: true,
        });
        assert_eq!(code(fs.apply_write(read_fh, 0, b"x")), Err(libc::EACCES));
    }

    /// Construction surfaces a genuine store read error (existing entry that
    /// fails to read) instead of silently serving an empty file.
    #[test]
    fn new_propagates_store_read_error() {
        struct FailingStore;
        impl BackingStore for FailingStore {
            fn read(&self, _: &Path) -> anyhow::Result<Vec<u8>> {
                anyhow::bail!("disk on fire")
            }
            fn store(&self, _: &Path, _: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn delete(&self, _: &Path) -> anyhow::Result<()> {
                Ok(())
            }
            fn list(&self) -> anyhow::Result<Vec<PathBuf>> {
                Ok(vec![])
            }
            fn exists(&self, _: &Path) -> bool {
                true // entry "exists" but read fails
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
            None,
        );
        assert!(err.is_err(), "a failing read of an existing entry must not be served as empty");
    }
}
