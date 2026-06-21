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

/// Cache validity stamp. `(mtime, len)` is sufficient in practice: an in-place
/// edit bumps mtime, and Nix never mutates a store path in place - a rebuild
/// lands at a *new* path, so the old cache key is simply never hit again.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    mtime: i64,
    mtime_nsec: i64,
    len: u64,
}

fn cache() -> &'static Mutex<HashMap<PathBuf, (Stamp, String)>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, (Stamp, String)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// sha256 (hex) of a file's contents, cached by `(path, mtime, len)`.
pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("stat {} for hashing: {e}", path.display()))?;
    let stamp = Stamp {
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        len: meta.len(),
    };

    if let Some((cached, hash)) = cache().lock().unwrap().get(path)
        && *cached == stamp
    {
        return Ok(hash.clone());
    }

    let hash = hash_contents(path)?;
    cache()
        .lock()
        .unwrap()
        .insert(path.to_path_buf(), (stamp, hash.clone()));
    Ok(hash)
}

fn hash_contents(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("open {} for hashing: {e}", path.display()))?;
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
    use std::io::Write;

    #[test]
    fn hashes_and_caches() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("file-guard-integrity-{}", std::process::id()));
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
}
