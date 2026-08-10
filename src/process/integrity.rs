//! Content hashing for binary-identity pinning.
//!
//! Persistent "always" rules pin the calling binary's sha256 so a replaced
//! binary re-prompts instead of inheriting a prior grant. Hashing sits on the
//! access hot path, so results are cached.
//!
//! The cache is bounded: once it reaches `MAX_CACHE_ENTRIES` the entire cache
//! is flushed. On a long-running daemon with Nix or similar (where every
//! package upgrade produces a new /nix/store path), this prevents unbounded
//! growth. Session grants are lost on restart anyway, so re-hashing is
//! acceptable.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Maximum number of cached hashes before the entire cache is flushed. See
/// module-level docs for rationale.
const MAX_CACHE_ENTRIES: usize = 1000;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    ctime: i64,
    ctime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}

impl Stamp {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            len: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
        }
    }

    fn cacheable(self) -> bool {
        self.uid == 0 && self.mode & 0o022 == 0
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
enum CacheKey {
    Path(PathBuf),
    Object { device: u64, inode: u64 },
}

fn cache() -> &'static Mutex<HashMap<CacheKey, (Stamp, String)>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<CacheKey, (Stamp, String)>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// sha256 (hex) of a stable file descriptor's contents.
///
/// The returned hash always describes the opened object. A post-open path stat
/// rejects replacement during resolution; replacement afterward cannot change
/// the object held by the file descriptor.
pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("open {} for hashing: {e}", path.display()))?;
    let fd_metadata = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("stat {} via fd: {e}", path.display()))?;

    if !fd_metadata.is_file() {
        anyhow::bail!("{} is not a regular file", path.display())
    }
    let path_metadata = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("re-stat {} for verification: {e}", path.display()))?;
    if fd_metadata.dev() != path_metadata.dev() || fd_metadata.ino() != path_metadata.ino() {
        anyhow::bail!("{} was replaced during open", path.display())
    }

    hash_opened(file, CacheKey::Path(path.to_path_buf()), path)
}

pub struct CapturedExecutable {
    pub path: PathBuf,
    pub sha256: String,
}

pub fn capture_process_executable(pid: u32, start_time: u64) -> anyhow::Result<CapturedExecutable> {
    if crate::process::start_time(pid)? != start_time {
        anyhow::bail!("pid {pid} was recycled before executable capture");
    }
    let proc_path = PathBuf::from(format!("/proc/{pid}/exe"));
    let file = std::fs::File::open(&proc_path)
        .map_err(|error| anyhow::anyhow!("open {}: {error}", proc_path.display()))?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        anyhow::bail!(
            "{} does not reference a regular executable",
            proc_path.display()
        );
    }
    let binary_path = std::fs::read_link(&proc_path)?;
    let current = std::fs::metadata(&proc_path)?;
    if opened.dev() != current.dev() || opened.ino() != current.ino() {
        anyhow::bail!("pid {pid} changed executable during capture");
    }
    let key = CacheKey::Object {
        device: opened.dev(),
        inode: opened.ino(),
    };
    let sha256 = hash_opened(file, key, &proc_path)?;
    if crate::process::start_time(pid)? != start_time {
        anyhow::bail!("pid {pid} exited or was recycled during executable capture");
    }
    let after = std::fs::metadata(&proc_path)?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || std::fs::read_link(&proc_path)? != binary_path
    {
        anyhow::bail!("pid {pid} changed executable during capture");
    }
    Ok(CapturedExecutable {
        path: binary_path,
        sha256,
    })
}

fn hash_opened(
    mut file: std::fs::File,
    key: CacheKey,
    display_path: &Path,
) -> anyhow::Result<String> {
    let fd_metadata = file.metadata()?;
    if !fd_metadata.is_file() {
        anyhow::bail!("{} is not a regular file", display_path.display());
    }

    let before = Stamp::from(&fd_metadata);

    if before.cacheable()
        && let Some((cached, hash)) = cache().lock().unwrap().get(&key)
        && *cached == before
    {
        let after = Stamp::from(&file.metadata()?);
        if after == before {
            return Ok(hash.clone());
        }
    }

    let hash = hash_contents(&mut file)?;
    let after = Stamp::from(&file.metadata()?);
    if after != before {
        anyhow::bail!(
            "{} changed while it was being hashed",
            display_path.display()
        )
    }
    let mut cache = cache().lock().unwrap();
    if after.cacheable() {
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(key.clone(), (after, hash.clone()));
    } else {
        cache.remove(&key);
    }
    Ok(hash)
}

fn hash_contents(file: &mut std::fs::File) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "file-guard-integrity-{tag}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn hashes_and_caches() {
        let tmp = temp_path("cache");
        std::fs::File::create(&tmp)
            .unwrap()
            .write_all(b"hello")
            .unwrap();

        let h1 = hash_file(&tmp).unwrap();
        let h2 = hash_file(&tmp).unwrap();
        assert_eq!(h1, h2);
        // sha256("hello")
        assert_eq!(
            h1,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn same_length_rewrite_with_restored_mtime_invalidates_cache() {
        let tmp = temp_path("restored-mtime");
        std::fs::write(&tmp, b"hello").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();
        let original_mtime = std::fs::metadata(&tmp).unwrap().modified().unwrap();
        let original_hash = hash_file(&tmp).unwrap();

        std::fs::write(&tmp, b"jello").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();

        assert_ne!(hash_file(&tmp).unwrap(), original_hash);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn hashes_hardlinks_and_symlink_paths_by_opened_identity() {
        let original = temp_path("linked-original");
        let hardlink = temp_path("hardlink");
        let symlink = temp_path("symlink");
        std::fs::write(&original, b"linked-content").unwrap();
        std::fs::hard_link(&original, &hardlink).unwrap();
        std::os::unix::fs::symlink(&original, &symlink).unwrap();

        let expected = hash_file(&original).unwrap();
        assert_eq!(hash_file(&hardlink).unwrap(), expected);
        assert_eq!(hash_file(&symlink).unwrap(), expected);

        std::fs::remove_file(&symlink).ok();
        std::fs::remove_file(&hardlink).ok();
        std::fs::remove_file(&original).ok();
    }

    #[test]
    fn process_hash_uses_the_running_executable_object() {
        let pid = std::process::id();
        let start_time = crate::process::start_time(pid).unwrap();
        let process = capture_process_executable(pid, start_time).unwrap();
        let executable = std::env::current_exe().unwrap();
        assert_eq!(process.path, executable);
        assert_eq!(process.sha256, hash_file(&executable).unwrap());
    }
}
