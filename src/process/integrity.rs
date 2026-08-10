//! Content hashing for binary-identity pinning.
//!
//! Persistent "always" rules pin the calling binary's sha256 so a replaced
//! binary re-prompts instead of inheriting a prior grant. Hashing sits on the
//! access hot path, so results are cached.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
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

fn cache() -> &'static Mutex<HashMap<PathBuf, (Stamp, String)>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, (Stamp, String)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// sha256 (hex) of a stable file descriptor's contents.
pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("open {} for hashing: {e}", path.display()))?;
    let before_metadata = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("stat {} for hashing: {e}", path.display()))?;
    if !before_metadata.is_file() {
        anyhow::bail!("{} is not a regular file", path.display())
    }
    let before = Stamp::from(&before_metadata);

    if before.cacheable()
        && let Some((cached, hash)) = cache().lock().unwrap().get(path)
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
        anyhow::bail!("{} changed while it was being hashed", path.display())
    }
    let mut cache = cache().lock().unwrap();
    if after.cacheable() {
        cache.insert(path.to_path_buf(), (after, hash.clone()));
    } else {
        cache.remove(path);
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
}
