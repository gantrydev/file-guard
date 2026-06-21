use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    FUSE_ROOT_ID, FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyWrite, Request, TimeOrNow,
};

use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::policy::rule::Access;
use crate::process::identify::ProcessInfo;
use crate::store::BackingStore;

fn default_ttl() -> Duration {
    Duration::from_secs(1)
}

fn build_file_attr(file_size: u64) -> FileAttr {
    let now = SystemTime::now();

    FileAttr {
        ino: FUSE_ROOT_ID,
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

fn slice_content(content: &[u8], offset: i64, size: u32) -> &[u8] {
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

/// Per-open-handle state. A write handle keeps a working copy of the file's
/// content (`buf`) which is persisted to the backing store on flush/release;
/// read handles serve directly from the store and keep `buf` empty.
struct HandleState {
    access: Access,
    buf: Vec<u8>,
    dirty: bool,
}

pub struct CredentialFs {
    watched_path: PathBuf,
    store: Arc<dyn BackingStore>,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    rt_handle: tokio::runtime::Handle,
    handles: Mutex<HashMap<u64, HandleState>>,
    next_fh: AtomicU64,
    /// Live file size reported by `getattr`, updated as writes/truncates land.
    current_size: Mutex<u64>,
}

impl CredentialFs {
    pub fn new(
        watched_path: PathBuf,
        store: Arc<dyn BackingStore>,
        policy: Arc<PolicyEngine>,
        logger: Arc<AccessLogger>,
        rt_handle: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        // Tolerate an absent store entry (the watched file may not exist yet):
        // serve an empty file and let an authorized writer populate it.
        let file_size = store
            .read(&watched_path)
            .map(|c| c.len() as u64)
            .unwrap_or(0);

        Ok(Self {
            watched_path,
            store,
            policy,
            logger,
            rt_handle,
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            current_size: Mutex::new(file_size),
        })
    }

    /// Identify the calling process, evaluate policy for `access`, and return
    /// the process info iff allowed.
    fn authorize(&self, pid: u32, access: Access) -> Option<ProcessInfo> {
        let info = match crate::process::identify::identify(pid) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("failed to identify pid {pid}: {e}");
                return None;
            }
        };

        let decision =
            self.rt_handle
                .block_on(self.policy.evaluate(&info, &self.watched_path, access));
        self.logger
            .log(&info, &self.watched_path, access, &decision, None);

        decision.is_allowed().then_some(info)
    }

    fn read_store_or_empty(&self) -> Vec<u8> {
        // A read error here is, in practice, "not stored yet" (new file) - serve
        // empty. Genuine IO errors on the root-owned store are surfaced by the
        // write path (store() errors map to EIO).
        self.store.read(&self.watched_path).unwrap_or_default()
    }

    fn set_size(&self, size: u64) {
        *self.current_size.lock().unwrap() = size;
    }

    fn grow_size_to(&self, size: u64) {
        let mut current = self.current_size.lock().unwrap();
        if size > *current {
            *current = size;
        }
    }

    fn register_handle(&self, state: HandleState) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().unwrap().insert(fh, state);
        fh
    }

    fn handle_access(&self, fh: u64) -> Option<Access> {
        self.handles.lock().unwrap().get(&fh).map(|s| s.access)
    }

    /// Persist a write handle's buffer to the store if dirty. Clones the buffer
    /// before releasing the lock so the store write doesn't block other ops; on
    /// failure `dirty` stays set so a later flush/release retries.
    fn persist_handle(&self, fh: u64) -> anyhow::Result<()> {
        let buf = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh) {
                Some(s) if s.access == Access::Write && s.dirty => s.buf.clone(),
                _ => return Ok(()),
            }
        };

        self.store.store(&self.watched_path, &buf)?;

        let mut handles = self.handles.lock().unwrap();
        if let Some(s) = handles.get_mut(&fh) {
            s.dirty = false;
        }
        self.set_size(buf.len() as u64);
        Ok(())
    }

    /// Apply a truncate, either against an open write handle's buffer or, when
    /// there is none, directly against the store.
    fn apply_truncate(&self, fh: Option<u64>, new_size: u64) -> anyhow::Result<()> {
        let n = new_size as usize;

        if let Some(h) = fh {
            let mut handles = self.handles.lock().unwrap();
            if let Some(state) = handles.get_mut(&h)
                && state.access == Access::Write
            {
                state.buf.resize(n, 0);
                state.dirty = true;
                drop(handles);
                self.set_size(new_size);
                return Ok(());
            }
        }

        // Standalone truncate(path) with no write handle: apply to the store.
        let mut content = self.read_store_or_empty();
        content.resize(n, 0);
        self.store.store(&self.watched_path, &content)?;
        self.set_size(new_size);
        Ok(())
    }
}

impl Filesystem for CredentialFs {
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }
        let attr = build_file_attr(*self.current_size.lock().unwrap());
        reply.attr(&default_ttl(), &attr);
    }

    fn lookup(&mut self, _req: &Request, _parent: u64, _name: &OsStr, reply: ReplyEntry) {
        reply.error(libc::ENOENT);
    }

    fn open(&mut self, req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }

        let access = Access::from_open_flags(flags);
        if self.authorize(req.pid(), access).is_none() {
            reply.error(libc::EACCES);
            return;
        }

        let truncating = (flags & libc::O_TRUNC) != 0;
        let buf = if access == Access::Write {
            if truncating || (flags & libc::O_CREAT) != 0 {
                Vec::new()
            } else {
                self.read_store_or_empty()
            }
        } else {
            Vec::new()
        };

        // O_TRUNC empties the file immediately, even if the handle is closed
        // without a subsequent write - mark dirty so that empties is persisted.
        let dirty = access == Access::Write && truncating;
        if dirty {
            self.set_size(0);
        }

        let fh = self.register_handle(HandleState { access, buf, dirty });
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }

        // A write handle reads back its own working buffer; a read handle reads
        // the store. An unknown fh was never authorized → EACCES.
        let from_buf = {
            let handles = self.handles.lock().unwrap();
            match handles.get(&fh) {
                None => {
                    reply.error(libc::EACCES);
                    return;
                }
                Some(s) if s.access == Access::Write => Some(s.buf.clone()),
                Some(_) => None,
            }
        };

        let content = from_buf.unwrap_or_else(|| self.read_store_or_empty());
        reply.data(slice_content(&content, offset, size));
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }

        let new_len = {
            let mut handles = self.handles.lock().unwrap();
            let Some(state) = handles.get_mut(&fh) else {
                reply.error(libc::EACCES);
                return;
            };
            if state.access != Access::Write {
                reply.error(libc::EACCES);
                return;
            }

            let start = offset as usize;
            let end = start + data.len();
            if state.buf.len() < end {
                state.buf.resize(end, 0); // sparse gap zero-filled
            }
            state.buf[start..end].copy_from_slice(data);
            state.dirty = true;
            state.buf.len() as u64
        };

        self.grow_size_to(new_len);
        reply.written(data.len() as u32);
    }

    fn setattr(
        &mut self,
        req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }

        // The only attribute we enforce is size (truncate) - it is a write and
        // the easiest write-bypass to miss. An already-authorized write handle
        // passes; otherwise gate the truncate against the calling process.
        if let Some(new_size) = size {
            let authorized = match fh.and_then(|h| self.handle_access(h)) {
                Some(Access::Write) => true,
                Some(_) => false, // a read handle may not resize
                _ => self.authorize(req.pid(), Access::Write).is_some(),
            };
            if !authorized {
                reply.error(libc::EACCES);
                return;
            }
            if let Err(e) = self.apply_truncate(fh, new_size) {
                tracing::error!("truncate of {} failed: {e}", self.watched_path.display());
                reply.error(libc::EIO);
                return;
            }
        }

        let attr = build_file_attr(*self.current_size.lock().unwrap());
        reply.attr(&default_ttl(), &attr);
    }

    fn flush(&mut self, _req: &Request, ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }
        match self.persist_handle(fh) {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!("flush of {} failed: {e}", self.watched_path.display());
                reply.error(libc::EIO);
            }
        }
    }

    fn fsync(&mut self, _req: &Request, ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }
        match self.persist_handle(fh) {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!("fsync of {} failed: {e}", self.watched_path.display());
                reply.error(libc::EIO);
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if ino != FUSE_ROOT_ID {
            reply.error(libc::ENOENT);
            return;
        }

        let persisted = self.persist_handle(fh);
        self.handles.lock().unwrap().remove(&fh);

        match persisted {
            Ok(()) => reply.ok(),
            Err(e) => {
                tracing::error!(
                    "release persist of {} failed: {e}",
                    self.watched_path.display()
                );
                reply.error(libc::EIO);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::slice_content;

    #[test]
    fn slice_content_bounds() {
        let c = b"hello world";
        assert_eq!(slice_content(c, 0, 5), b"hello");
        assert_eq!(slice_content(c, 6, 100), b"world"); // size past end clamps
        assert_eq!(slice_content(c, 11, 10), b""); // at end
        assert_eq!(slice_content(c, 100, 10), b""); // past end
        assert_eq!(slice_content(c, 0, 0), b""); // zero size
    }
}
