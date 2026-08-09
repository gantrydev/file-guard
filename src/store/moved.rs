use crate::store::BackingStore;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Disambiguates concurrent temp files written during atomic `store`.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Simplest backing store: originals moved to a directory the guarded user
/// cannot read.
///
/// SECURITY: this only protects against same-uid malware if the store is owned
/// by a *different* uid than the guarded user. In the supported privileged
/// deployment the daemon runs as root and the store
/// lives at `/var/lib/file-guard/store` (root:root, 0700), set via
/// `FILE_GUARD_STORE_DIR`. Running as your own user puts the plaintext at
/// `~/.local/share/file-guard/store`, readable by the very malware this tool
/// defends against - that mode is for development only.
pub struct MovedStore {
    store_dir: PathBuf,
}

impl MovedStore {
    pub fn new() -> anyhow::Result<Self> {
        let store_dir = match std::env::var_os("FILE_GUARD_STORE_DIR") {
            Some(dir) => PathBuf::from(dir),
            None if is_root() => PathBuf::from("/var/lib/file-guard/store"),
            None => dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("~/.local/share"))
                .join("file-guard")
                .join("store"),
        };

        if !store_dir.exists() {
            std::fs::create_dir_all(&store_dir)?;
            // Set directory permissions to 0700
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }

        Ok(Self { store_dir })
    }

    /// Map a watched file path to its store location, e.g.
    /// `/home/a/.aws/credentials` → `store_dir/home%2Fa%2F.aws%2Fcredentials`.
    ///
    /// The key is a percent-encoding of the absolute path (only `/` and `%` are
    /// escaped), which is *injective*: distinct paths never collide. A prior
    /// `/`→`--` scheme could both collide (`/a-/b` and `/a/-b` mapped to the same
    /// file, silently clobbering one credential with another) and round-trip
    /// wrong for any path already containing `--`.
    fn store_path(&self, file_id: &Path) -> PathBuf {
        self.store_dir.join(encode_key(file_id))
    }
}

/// Percent-encode an absolute path into a single, collision-free filename.
/// Bytes outside `[A-Za-z0-9._-]` (notably `/` and `%`) become `%XX`.
fn encode_key(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// Inverse of `encode_key`, for `list()`.
///
/// Operates on raw bytes with an explicit ASCII-hex check: slicing the `&str`
/// at `%`-relative offsets could panic on a non-char-boundary, and
/// `from_str_radix` would wrongly accept a leading `+`.
fn decode_key(name: &str) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let hex = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'A'..=b'F' => Some(b - b'A' + 10),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(hi * 16 + lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    PathBuf::from(std::ffi::OsStr::from_bytes(&out))
}

impl BackingStore for MovedStore {
    fn read(&self, file_id: &Path) -> anyhow::Result<Vec<u8>> {
        let path = self.store_path(file_id);
        std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("failed to read backing store {}: {e}", path.display()))
    }

    fn store(&self, file_id: &Path, contents: &[u8]) -> anyhow::Result<()> {
        use std::io::Write;
        let path = self.store_path(file_id);

        // Write the new contents to a sibling temp file, fsync it, then rename
        // it over the target. A crash at any point leaves either the old file or
        // the complete new one — never a torn, half-written credential (which is
        // the sole copy). std::fs::write's truncate-in-place gave no such
        // guarantee. The temp lives in the same dir so the rename is atomic.
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .store_dir
            .join(format!(".tmp.{}.{seq}", std::process::id()));

        let write_tmp = || -> std::io::Result<()> {
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut f = opts.open(&tmp)?;
            f.write_all(contents)?;
            f.sync_all() // durable before the rename
        };

        if let Err(e) = write_tmp() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }

        // fsync the directory so the rename (the metadata change) is itself
        // durable across a power loss, not just the file data.
        if let Ok(dir) = std::fs::File::open(&self.store_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn delete(&self, file_id: &Path) -> anyhow::Result<()> {
        let path = self.store_path(file_id);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn exists(&self, file_id: &Path) -> bool {
        self.store_path(file_id).exists()
    }

    fn list(&self) -> anyhow::Result<Vec<PathBuf>> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(&self.store_dir)? {
            let entry = entry?;
            let raw = entry.file_name();
            let raw = raw.to_string_lossy();
            // Skip in-flight/orphaned atomic-write temp files (.tmp.<pid>.<seq>).
            if raw.starts_with(".tmp.") {
                continue;
            }
            result.push(decode_key(&raw));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_encodes_separators() {
        let store = MovedStore {
            store_dir: PathBuf::from("/var/lib/file-guard/store"),
        };
        assert_eq!(
            store.store_path(Path::new("/home/alice/.aws/credentials")),
            PathBuf::from("/var/lib/file-guard/store/%2Fhome%2Falice%2F.aws%2Fcredentials"),
        );
    }

    #[test]
    fn encoding_is_injective_and_round_trips() {
        // The two paths that collided under the old `/`→`--` scheme.
        assert_ne!(
            encode_key(Path::new("/a-/b")),
            encode_key(Path::new("/a/-b"))
        );
        for p in [
            "/home/u/.aws/credentials",
            "/a-/b",
            "/a/-b",
            "/weird--dir/x",
        ] {
            assert_eq!(decode_key(&encode_key(Path::new(p))), PathBuf::from(p));
        }
    }

    #[test]
    fn store_round_trips_at_0600_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("fg-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = MovedStore {
            store_dir: dir.clone(),
        };
        let id = Path::new("/home/u/.config/cred");

        store.store(id, b"v1-secret").unwrap();
        store.store(id, b"v2").unwrap(); // overwrite path is also atomic
        assert_eq!(store.read(id).unwrap(), b"v2");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.store_path(id))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "stored credential must be 0600");
        }

        // No temp files left behind, and list() ignores any that might be.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "atomic store left a temp file behind");
        assert_eq!(store.list().unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
