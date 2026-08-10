use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, Dir, Gid, Mode, OFlags, RenameFlags, Stat, Uid, XattrFlags};

use crate::store::{
    ExtendedAttribute, MAX_CREDENTIAL_SIZE, ObjectIdentity, OriginalState, RestoreMetadata,
    Timestamp, sha256,
};

#[derive(Debug)]
pub struct CapturedSource {
    pub contents: Vec<u8>,
    pub original: OriginalState,
}

pub struct ResolvedPath {
    path: PathBuf,
    parent_path: PathBuf,
    parent: OwnedFd,
    name: CString,
}

pub struct StagingArea {
    path: PathBuf,
    directory: File,
}

impl ResolvedPath {
    pub fn new(path: &Path) -> io::Result<Self> {
        let path = absolute_lexical(path)?;
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?
            .to_path_buf();
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path must name a file"))?;
        let name = cstring(name)?;
        let parent = resolve_directory(&parent_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "refusing to resolve {} through a symlink or inaccessible directory: {error}",
                    path.display()
                ),
            )
        })?;
        Ok(Self {
            path,
            parent_path,
            parent,
            name,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn parent_path(&self) -> &Path {
        &self.parent_path
    }

    pub fn parent_identity(&self) -> io::Result<ObjectIdentity> {
        object_identity(&stat_fd(self.parent.as_raw_fd())?)
    }

    pub fn verify_parent_binding(&self) -> io::Result<()> {
        let current = File::from(resolve_directory(&self.parent_path)?);
        let held = object_identity(&stat_fd(self.parent.as_raw_fd())?)?;
        let current = object_identity(&stat_fd(current.as_raw_fd())?)?;
        if !same_object(&held, &current) {
            return Err(io::Error::other(format!(
                "parent directory for {} was renamed or replaced",
                self.path.display()
            )));
        }
        Ok(())
    }

    pub fn observe(&self) -> io::Result<Option<ObjectIdentity>> {
        self.verify_parent_binding()?;
        observe_at(self.parent.as_raw_fd(), &self.name)
    }

    pub fn verify_restoration(
        &self,
        contents: &[u8],
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        self.verify_parent_binding()?;
        let (actual_contents, identity, actual_metadata) =
            read_file_at(self.parent.as_raw_fd(), &self.name)?;
        self.verify_parent_binding()?;
        if actual_contents != contents
            || actual_metadata.uid != metadata.uid
            || actual_metadata.gid != metadata.gid
            || actual_metadata.mode != metadata.mode
            || actual_metadata.mtime != metadata.mtime
            || actual_metadata.xattrs != metadata.xattrs
        {
            return Err(io::Error::other(format!(
                "{} is not the committed restoration file",
                self.path.display()
            )));
        }
        Ok(identity)
    }

    pub fn verify_finalization(
        &self,
        content_length: u64,
        content_sha256: &str,
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        self.verify_parent_binding()?;
        let (contents, identity, actual_metadata) =
            read_file_at(self.parent.as_raw_fd(), &self.name)?;
        self.verify_parent_binding()?;
        verify_finalization_data(
            &contents,
            &actual_metadata,
            content_length,
            content_sha256,
            metadata,
        )?;
        Ok(identity)
    }

    pub fn capture(&self) -> io::Result<CapturedSource> {
        let parent = stat_fd(self.parent.as_raw_fd())?;
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        #[cfg(target_os = "linux")]
        {
            flags |= libc::O_NOATIME;
        }
        let file = match open_at(self.parent.as_raw_fd(), &self.name, flags, 0) {
            Ok(file) => Some(File::from(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };

        let Some(mut file) = file else {
            return Ok(CapturedSource {
                contents: Vec::new(),
                original: OriginalState::Absent {
                    presentation: RestoreMetadata {
                        uid: parent.st_uid,
                        gid: parent.st_gid,
                        mode: 0o600,
                        atime: stat_atime(&parent),
                        mtime: stat_mtime(&parent),
                        xattrs: Vec::new(),
                    },
                },
            });
        };

        let before = stat_fd(file.as_raw_fd())?;
        validate_regular(&before, true)?;
        if before.st_size < 0 || before.st_size as usize > MAX_CREDENTIAL_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is {} bytes; maximum credential size is {MAX_CREDENTIAL_SIZE}",
                    self.path.display(),
                    before.st_size
                ),
            ));
        }
        let metadata = restore_metadata(file.as_raw_fd(), &before)?;
        let mut contents = Vec::with_capacity(before.st_size as usize);
        file.read_to_end(&mut contents)?;
        let after = stat_fd(file.as_raw_fd())?;
        let before_identity = object_identity(&before)?;
        let after_identity = object_identity(&after)?;
        if before_identity != after_identity || contents.len() != after.st_size as usize {
            return Err(io::Error::other(format!(
                "{} changed while it was being captured",
                self.path.display()
            )));
        }

        Ok(CapturedSource {
            contents,
            original: OriginalState::Present {
                identity: after_identity,
                metadata,
            },
        })
    }

    #[cfg(target_os = "linux")]
    pub fn exchange_with(&self, staging: &StagingArea, staging_name: &str) -> io::Result<()> {
        self.verify_parent_binding()?;
        let staging_name = entry_name(staging_name)?;
        let result = rename_exchange(
            staging.directory.as_raw_fd(),
            &staging_name,
            self.parent.as_raw_fd(),
            &self.name,
        );
        self.verify_parent_binding()?;
        result
    }

    #[cfg(target_os = "linux")]
    pub fn install_absent(&self, staging: &StagingArea, staging_name: &str) -> io::Result<()> {
        self.verify_parent_binding()?;
        let staging_name = entry_name(staging_name)?;
        let result = rename_noreplace(
            staging.directory.as_raw_fd(),
            &staging_name,
            self.parent.as_raw_fd(),
            &self.name,
        );
        self.verify_parent_binding()?;
        result
    }

    #[cfg(target_os = "linux")]
    pub fn move_to_staging(&self, staging: &StagingArea, staging_name: &str) -> io::Result<()> {
        self.verify_parent_binding()?;
        let staging_name = entry_name(staging_name)?;
        let result = rename_noreplace(
            self.parent.as_raw_fd(),
            &self.name,
            staging.directory.as_raw_fd(),
            &staging_name,
        );
        self.verify_parent_binding()?;
        result
    }

    pub fn sync_with(&self, staging: &StagingArea) -> io::Result<()> {
        self.verify_parent_binding()?;
        sync_namespaces(&staging.directory, self.parent.as_raw_fd())?;
        self.verify_parent_binding()
    }
}

impl StagingArea {
    pub fn planned_path(root: &Path, generation: &str) -> io::Result<PathBuf> {
        validate_token(generation)?;
        Ok(absolute_lexical(root)?.join(generation))
    }

    pub fn create(root: &Path, generation: &str, expected_device: u64) -> io::Result<Self> {
        validate_token(generation)?;
        let root = absolute_lexical(root)?;
        validate_trusted_ancestors(&root)?;
        let root_file = create_private_directory(&root)?;
        validate_private_directory(&root, &root_file, expected_device)?;

        let path = root.join(generation);
        let generation = entry_name(generation)?;
        let created = match mkdir_at(root_file.as_raw_fd(), &generation, 0o700) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error),
        };
        if created {
            root_file.sync_all()?;
        }
        let directory = File::from(open_directory(root_file.as_raw_fd(), &generation)?);
        if created {
            set_mode(directory.as_raw_fd(), 0o700)?;
            directory.sync_all()?;
            root_file.sync_all()?;
        }
        validate_private_directory(&path, &directory, expected_device)?;
        Ok(Self { path, directory })
    }

    pub fn open(path: &Path, expected_device: u64) -> io::Result<Self> {
        let path = absolute_lexical(path)?;
        validate_trusted_ancestors(&path)?;
        let directory = File::from(resolve_directory(&path)?);
        validate_private_directory(&path, &directory, expected_device)?;
        Ok(Self { path, directory })
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn observe(&self, name: &str) -> io::Result<Option<ObjectIdentity>> {
        observe_at(self.directory.as_raw_fd(), &entry_name(name)?)
    }

    pub fn create_placeholder(
        &self,
        name: &str,
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        self.create_file(name, &[], metadata, false)
    }

    pub fn create_restoration(
        &self,
        name: &str,
        contents: &[u8],
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        self.create_file(name, contents, metadata, true)
    }

    pub fn verify_snapshot(
        &self,
        name: &str,
        contents: &[u8],
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        let (actual_contents, identity, actual_metadata) = self.read_file(name)?;
        if actual_contents != contents
            || actual_metadata.uid != metadata.uid
            || actual_metadata.gid != metadata.gid
            || actual_metadata.mode != metadata.mode
            || actual_metadata.mtime != metadata.mtime
            || actual_metadata.xattrs != metadata.xattrs
        {
            return Err(io::Error::other(format!(
                "staging entry {name:?} no longer matches the captured snapshot"
            )));
        }
        Ok(identity)
    }

    pub fn verify_placeholder(
        &self,
        name: &str,
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        let (contents, identity, actual) = self.read_file(name)?;
        if !contents.is_empty()
            || actual.uid != metadata.uid
            || actual.gid != metadata.gid
            || actual.mode != metadata.mode
        {
            return Err(io::Error::other(format!(
                "staging entry {name:?} is not the prepared placeholder"
            )));
        }
        Ok(identity)
    }

    pub fn verify_restoration(
        &self,
        name: &str,
        contents: &[u8],
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        let (actual_contents, identity, actual_metadata) = self.read_file(name)?;
        if actual_contents != contents || actual_metadata != *metadata {
            return Err(io::Error::other(format!(
                "staging entry {name:?} is not the committed restoration file"
            )));
        }
        Ok(identity)
    }

    pub fn verify_finalization(
        &self,
        name: &str,
        content_length: u64,
        content_sha256: &str,
        metadata: &RestoreMetadata,
    ) -> io::Result<ObjectIdentity> {
        let (contents, identity, actual_metadata) = self.read_file(name)?;
        verify_finalization_data(
            &contents,
            &actual_metadata,
            content_length,
            content_sha256,
            metadata,
        )?;
        Ok(identity)
    }

    pub fn remove_verified(&self, name: &str, expected: &ObjectIdentity) -> io::Result<()> {
        let name = entry_name(name)?;
        let actual = observe_at(self.directory.as_raw_fd(), &name)?;
        if actual.as_ref() != Some(expected) {
            return Err(io::Error::other(format!(
                "refusing to remove staging entry {name:?}: identity mismatch"
            )));
        }
        unlink_at(self.directory.as_raw_fd(), &name)?;
        self.directory.sync_all()
    }

    pub fn discard_uncommitted(&self, name: &str) -> io::Result<()> {
        self.discard_entry(&entry_name(name)?)
    }

    pub fn discard_construction(&self, name: &str) -> io::Result<()> {
        self.discard_entry(&construction_entry_name(&entry_name(name)?)?)
    }

    pub fn sync(&self) -> io::Result<()> {
        self.directory.sync_all()
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        directory_is_empty(self.directory.as_raw_fd())
    }

    pub fn contains_only(&self, names: &[&str]) -> io::Result<bool> {
        let mut expected = names
            .iter()
            .map(|name| Ok(entry_name(name)?.to_bytes().to_vec()))
            .collect::<io::Result<Vec<_>>>()?;
        expected.sort();
        Ok(directory_entries(self.directory.as_raw_fd())? == expected)
    }

    pub fn remove_if_empty(self) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("staging directory has no parent"))?
            .to_path_buf();
        let name = self
            .path
            .file_name()
            .ok_or_else(|| io::Error::other("staging directory has no name"))?;
        let parent = File::from(resolve_directory(&parent)?);
        let name = cstring(name)?;
        if !directory_is_empty(self.directory.as_raw_fd())? {
            return Err(io::Error::new(
                io::ErrorKind::DirectoryNotEmpty,
                "staging directory is not empty",
            ));
        }
        let identity = object_identity(&stat_fd(self.directory.as_raw_fd())?)?;
        if observe_at(parent.as_raw_fd(), &name)?.as_ref() != Some(&identity) {
            return Err(io::Error::other(
                "staging directory identity changed before removal",
            ));
        }
        remove_directory_at(parent.as_raw_fd(), &name)?;
        parent.sync_all()
    }

    fn create_file(
        &self,
        name: &str,
        contents: &[u8],
        metadata: &RestoreMetadata,
        restore_exact_metadata: bool,
    ) -> io::Result<ObjectIdentity> {
        if contents.len() > MAX_CREDENTIAL_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "credential exceeds maximum size",
            ));
        }
        let name = entry_name(name)?;
        let construction_name = construction_entry_name(&name)?;
        self.discard_entry(&construction_name)?;
        let fd = open_at(
            self.directory.as_raw_fd(),
            &construction_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        let mut file = File::from(fd);
        let result = (|| -> io::Result<ObjectIdentity> {
            file.write_all(contents)?;
            apply_ownership_and_mode(file.as_raw_fd(), metadata)?;
            if restore_exact_metadata {
                apply_xattrs(file.as_raw_fd(), &metadata.xattrs)?;
                apply_times(file.as_raw_fd(), &metadata.atime, &metadata.mtime)?;
            }
            file.sync_all()?;
            let before_rename = object_identity(&stat_fd(file.as_raw_fd())?)?;
            self.directory.sync_all()?;
            let operation = rename_noreplace(
                self.directory.as_raw_fd(),
                &construction_name,
                self.directory.as_raw_fd(),
                &name,
            );
            let constructed = observe_at(self.directory.as_raw_fd(), &construction_name)?;
            let installed = observe_at(self.directory.as_raw_fd(), &name)?;
            let Some(installed) = installed.filter(|actual| {
                constructed.is_none() && same_file_after_rename(&before_rename, actual)
            }) else {
                return match operation {
                    Ok(()) => Err(io::Error::other(
                        "constructed staging file was not atomically installed",
                    )),
                    Err(error) => Err(error),
                };
            };
            self.directory.sync_all()?;
            Ok(installed)
        })();
        if result.is_err() {
            drop(file);
            let _ = self.discard_entry(&construction_name);
        }
        result
    }

    fn discard_entry(&self, name: &CStr) -> io::Result<()> {
        if observe_at(self.directory.as_raw_fd(), name)?.is_none() {
            return Ok(());
        }
        unlink_at(self.directory.as_raw_fd(), name)?;
        self.directory.sync_all()
    }

    fn read_file(&self, name: &str) -> io::Result<(Vec<u8>, ObjectIdentity, RestoreMetadata)> {
        let name = entry_name(name)?;
        read_file_at(self.directory.as_raw_fd(), &name)
    }
}

fn verify_finalization_data(
    contents: &[u8],
    actual: &RestoreMetadata,
    content_length: u64,
    content_sha256: &str,
    expected: &RestoreMetadata,
) -> io::Result<()> {
    if contents.len() as u64 != content_length
        || sha256(contents) != content_sha256
        || actual.uid != expected.uid
        || actual.gid != expected.gid
        || actual.mode != expected.mode
        || actual.mtime != expected.mtime
        || actual.xattrs != expected.xattrs
    {
        return Err(io::Error::other(
            "file does not match the finalization marker",
        ));
    }
    Ok(())
}

pub fn default_staging_root(target: &ResolvedPath) -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("FILE_GUARD_STAGING_DIR") {
        return Ok(PathBuf::from(path));
    }
    let expected_device = target.parent_identity()?.device;
    let conventional = PathBuf::from("/var/lib/file-guard/staging-v2");
    if conventional
        .parent()
        .and_then(|parent| std::fs::metadata(parent).ok())
        .is_some_and(|metadata| metadata.dev() == expected_device)
    {
        return Ok(conventional);
    }
    let root = filesystem_root(target.parent_path(), expected_device)?;
    Ok(root.join(".file-guard-staging-v2"))
}

pub fn same_object(left: &ObjectIdentity, right: &ObjectIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && (left.mode & libc::S_IFMT) == (right.mode & libc::S_IFMT)
}

pub fn same_file_after_rename(before: &ObjectIdentity, after: &ObjectIdentity) -> bool {
    same_object(before, after)
        && before.mtime == after.mtime
        && before.size == after.size
        && before.links == after.links
        && before.mode == after.mode
        && before.uid == after.uid
        && before.gid == after.gid
}

fn filesystem_root(start: &Path, device: u64) -> io::Result<PathBuf> {
    let mut current = absolute_lexical(start)?;
    loop {
        let Some(parent) = current.parent() else {
            return Ok(current);
        };
        if parent == current {
            return Ok(current);
        }
        let directory = File::from(resolve_directory(parent)?);
        if directory.metadata()?.dev() != device {
            return Ok(current);
        }
        current = parent.to_path_buf();
    }
}

fn restore_metadata(fd: RawFd, stat: &Stat) -> io::Result<RestoreMetadata> {
    Ok(RestoreMetadata {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode & 0o7777,
        atime: stat_atime(stat),
        mtime: stat_mtime(stat),
        xattrs: read_xattrs(fd)?,
    })
}

fn object_identity(stat: &Stat) -> io::Result<ObjectIdentity> {
    if stat.st_size < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem returned a negative object size",
        ));
    }
    Ok(ObjectIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        ctime: stat_ctime(stat),
        mtime: stat_mtime(stat),
        size: stat.st_size as u64,
        links: stat.st_nlink,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
    })
}

#[cfg(target_os = "linux")]
fn read_xattrs(fd: RawFd) -> io::Result<Vec<ExtendedAttribute>> {
    let mut names = vec![0u8; 64 * 1024];
    let length = with_borrowed_fd(fd, |fd| {
        rustix::fs::flistxattr(fd, &mut names).map_err(io::Error::from)
    })?;
    names.truncate(length);

    let mut attributes = Vec::new();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = CString::new(name)?;
        let mut value = vec![0u8; 64 * 1024];
        let length = with_borrowed_fd(fd, |fd| {
            rustix::fs::fgetxattr(fd, &name, &mut value).map_err(io::Error::from)
        })?;
        value.truncate(length);
        attributes.push(ExtendedAttribute {
            name_hex: hex::encode(name.as_bytes()),
            value_hex: hex::encode(value),
        });
    }
    attributes.sort_by(|left, right| left.name_hex.cmp(&right.name_hex));
    Ok(attributes)
}

#[cfg(not(target_os = "linux"))]
fn read_xattrs(_fd: RawFd) -> io::Result<Vec<ExtendedAttribute>> {
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
fn apply_xattrs(fd: RawFd, attributes: &[ExtendedAttribute]) -> io::Result<()> {
    for attribute in attributes {
        let name = hex::decode(&attribute.name_hex)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let value = hex::decode(&attribute.value_hex)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let name = CString::new(name)?;
        with_borrowed_fd(fd, |fd| {
            rustix::fs::fsetxattr(fd, &name, &value, XattrFlags::empty()).map_err(io::Error::from)
        })?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_xattrs(_fd: RawFd, attributes: &[ExtendedAttribute]) -> io::Result<()> {
    if attributes.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "extended-attribute restoration is unsupported on this platform",
        ))
    }
}

fn apply_ownership_and_mode(fd: RawFd, metadata: &RestoreMetadata) -> io::Result<()> {
    if metadata.uid == u32::MAX || metadata.gid == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "restore ownership contains the reserved unchanged value",
        ));
    }
    with_borrowed_fd(fd, |fd| {
        rustix::fs::fchown(
            fd,
            Some(Uid::from_raw(metadata.uid)),
            Some(Gid::from_raw(metadata.gid)),
        )
        .map_err(io::Error::from)?;
        rustix::fs::fchmod(fd, Mode::from_raw_mode(metadata.mode & 0o7777)).map_err(io::Error::from)
    })
}

fn apply_times(fd: RawFd, atime: &Timestamp, mtime: &Timestamp) -> io::Result<()> {
    let times = rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: atime.seconds,
            tv_nsec: atime.nanoseconds,
        },
        last_modification: rustix::fs::Timespec {
            tv_sec: mtime.seconds,
            tv_nsec: mtime.nanoseconds,
        },
    };
    with_borrowed_fd(fd, |fd| {
        rustix::fs::futimens(fd, &times).map_err(io::Error::from)
    })
}

#[cfg(target_os = "linux")]
fn stat_atime(stat: &Stat) -> Timestamp {
    Timestamp {
        seconds: stat.st_atime,
        nanoseconds: stat.st_atime_nsec as i64,
    }
}

#[cfg(target_os = "linux")]
fn stat_mtime(stat: &Stat) -> Timestamp {
    Timestamp {
        seconds: stat.st_mtime,
        nanoseconds: stat.st_mtime_nsec as i64,
    }
}

#[cfg(target_os = "linux")]
fn stat_ctime(stat: &Stat) -> Timestamp {
    Timestamp {
        seconds: stat.st_ctime,
        nanoseconds: stat.st_ctime_nsec as i64,
    }
}

#[cfg(target_os = "macos")]
fn stat_atime(stat: &Stat) -> Timestamp {
    Timestamp {
        seconds: stat.st_atimespec.tv_sec,
        nanoseconds: stat.st_atimespec.tv_nsec,
    }
}

#[cfg(target_os = "macos")]
fn stat_mtime(stat: &Stat) -> Timestamp {
    Timestamp {
        seconds: stat.st_mtimespec.tv_sec,
        nanoseconds: stat.st_mtimespec.tv_nsec,
    }
}

#[cfg(target_os = "macos")]
fn stat_ctime(stat: &Stat) -> Timestamp {
    Timestamp {
        seconds: stat.st_ctimespec.tv_sec,
        nanoseconds: stat.st_ctimespec.tv_nsec,
    }
}

fn absolute_lexical(path: &Path) -> io::Result<PathBuf> {
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "path escapes the filesystem root",
                    ));
                }
            }
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported path prefix",
                ));
            }
        }
    }
    Ok(output)
}

fn resolve_directory(path: &Path) -> io::Result<OwnedFd> {
    let mut directory = open_directory(libc::AT_FDCWD, c"/")?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = open_directory(directory.as_raw_fd(), &cstring(name)?)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path is not normalized",
                ));
            }
        }
    }
    Ok(directory)
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn entry_name(value: &str) -> io::Result<CString> {
    if value.is_empty() || value == "." || value == ".." || value.as_bytes().contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid staging entry name",
        ));
    }
    CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "entry contains a NUL byte"))
}

fn construction_entry_name(name: &CStr) -> io::Result<CString> {
    let mut value = b".building-".to_vec();
    value.extend_from_slice(name.to_bytes());
    CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "entry contains a NUL byte"))
}

fn validate_token(value: &str) -> io::Result<()> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transaction token must contain 32 hexadecimal characters",
        ));
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> io::Result<File> {
    let parent_path = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "directory has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "directory has no name"))?;
    let parent = File::from(resolve_directory(parent_path)?);
    let name = cstring(name)?;
    let created = match mkdir_at(parent.as_raw_fd(), &name, 0o700) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    let directory = File::from(open_directory(parent.as_raw_fd(), &name)?);
    if created {
        set_mode(directory.as_raw_fd(), 0o700)?;
        directory.sync_all()?;
        parent.sync_all()?;
    }
    Ok(directory)
}

fn validate_trusted_ancestors(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "staging path has no parent"))?;
    let effective_uid = unsafe { libc::geteuid() };
    let mut directory = File::from(open_at(
        libc::AT_FDCWD,
        c"/",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?);
    validate_trusted_ancestor(Path::new("/"), &directory, effective_uid)?;
    let mut traversed = PathBuf::from("/");
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                let name = cstring(name)?;
                directory = File::from(open_directory(directory.as_raw_fd(), &name)?);
                traversed.push(OsStr::from_bytes(name.to_bytes()));
                validate_trusted_ancestor(&traversed, &directory, effective_uid)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "staging path is not normalized",
                ));
            }
        }
    }
    Ok(())
}

fn validate_trusted_ancestor(path: &Path, directory: &File, effective_uid: u32) -> io::Result<()> {
    let metadata = directory.metadata()?;
    #[cfg(test)]
    if path == Path::new("/") && metadata.is_dir() {
        return Ok(());
    }
    let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == effective_uid;
    let writable = metadata.mode() & 0o022 != 0;
    let root_sticky = metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0;
    if !metadata.is_dir() || !owner_is_trusted || (writable && !root_sticky) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "staging ancestor {} must be owned by root or uid {}, and must not be group/world-writable unless it is a root-owned sticky directory",
                path.display(),
                effective_uid
            ),
        ));
    }
    Ok(())
}

fn validate_private_directory(path: &Path, file: &File, expected_device: u64) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.dev() != expected_device
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "staging directory {} must be a mode-0700 directory owned by uid {} on device {}",
                path.display(),
                unsafe { libc::geteuid() },
                expected_device
            ),
        ));
    }
    Ok(())
}

fn read_file_at(
    parent: RawFd,
    name: &CStr,
) -> io::Result<(Vec<u8>, ObjectIdentity, RestoreMetadata)> {
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    #[cfg(target_os = "linux")]
    {
        flags |= libc::O_NOATIME;
    }
    let mut file = File::from(open_at(parent, name, flags, 0)?);
    let before = stat_fd(file.as_raw_fd())?;
    validate_regular(&before, true)?;
    if before.st_size < 0 || before.st_size as usize > MAX_CREDENTIAL_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential has an invalid size",
        ));
    }
    let mut contents = Vec::with_capacity(before.st_size as usize);
    file.read_to_end(&mut contents)?;
    let after = stat_fd(file.as_raw_fd())?;
    let before_identity = object_identity(&before)?;
    let after_identity = object_identity(&after)?;
    if before_identity != after_identity || contents.len() != after.st_size as usize {
        return Err(io::Error::other("credential changed while being verified"));
    }
    let metadata = restore_metadata(file.as_raw_fd(), &after)?;
    Ok((contents, after_identity, metadata))
}

fn open_directory(parent: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    )
}

fn open_at(parent: RawFd, name: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let flags = OFlags::from_bits_retain(flags as _);
    let mode = Mode::from_raw_mode(mode);
    if parent == libc::AT_FDCWD {
        rustix::fs::openat(rustix::fs::CWD, name, flags, mode).map_err(io::Error::from)
    } else {
        with_borrowed_fd(parent, |parent| {
            rustix::fs::openat(parent, name, flags, mode).map_err(io::Error::from)
        })
    }
}

fn stat_fd(fd: RawFd) -> io::Result<Stat> {
    with_borrowed_fd(fd, |fd| rustix::fs::fstat(fd).map_err(io::Error::from))
}

fn observe_at(parent: RawFd, name: &CStr) -> io::Result<Option<ObjectIdentity>> {
    match with_borrowed_fd(parent, |parent| {
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
    }) {
        Ok(stat) => object_identity(&stat).map(Some),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn validate_regular(stat: &Stat, reject_hardlinks: bool) -> io::Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential path is not a regular file",
        ));
    }
    if reject_hardlinks && stat.st_nlink != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential file has hard-link aliases; refusing to guard it",
        ));
    }
    Ok(())
}

fn mkdir_at(parent: RawFd, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    with_borrowed_fd(parent, |parent| {
        rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(mode)).map_err(io::Error::from)
    })
}

fn set_mode(fd: RawFd, mode: libc::mode_t) -> io::Result<()> {
    with_borrowed_fd(fd, |fd| {
        rustix::fs::fchmod(fd, Mode::from_raw_mode(mode)).map_err(io::Error::from)
    })
}

fn unlink_at(parent: RawFd, name: &CStr) -> io::Result<()> {
    with_borrowed_fd(parent, |parent| {
        rustix::fs::unlinkat(parent, name, AtFlags::empty()).map_err(io::Error::from)
    })
}

fn remove_directory_at(parent: RawFd, name: &CStr) -> io::Result<()> {
    with_borrowed_fd(parent, |parent| {
        rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(io::Error::from)
    })
}

fn directory_is_empty(fd: RawFd) -> io::Result<bool> {
    Ok(directory_entries(fd)?.is_empty())
}

fn directory_entries(fd: RawFd) -> io::Result<Vec<Vec<u8>>> {
    let directory = with_borrowed_fd(fd, |fd| Dir::read_from(fd).map_err(io::Error::from))?;
    let mut names = Vec::new();
    for entry in directory {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    names.sort();
    Ok(names)
}

fn sync_fd(fd: RawFd) -> io::Result<()> {
    with_borrowed_fd(fd, |fd| rustix::fs::fsync(fd).map_err(io::Error::from))
}

fn sync_namespaces(staging: &File, parent: RawFd) -> io::Result<()> {
    staging.sync_all()?;
    sync_fd(parent)
}

#[cfg(target_os = "linux")]
fn rename_exchange(
    old_parent: RawFd,
    old_name: &CStr,
    new_parent: RawFd,
    new_name: &CStr,
) -> io::Result<()> {
    with_borrowed_fd(old_parent, |old_parent| {
        with_borrowed_fd(new_parent, |new_parent| {
            rustix::fs::renameat_with(
                old_parent,
                old_name,
                new_parent,
                new_name,
                RenameFlags::EXCHANGE,
            )
            .map_err(io::Error::from)
        })
    })
}

#[cfg(target_os = "linux")]
fn rename_noreplace(
    old_parent: RawFd,
    old_name: &CStr,
    new_parent: RawFd,
    new_name: &CStr,
) -> io::Result<()> {
    with_borrowed_fd(old_parent, |old_parent| {
        with_borrowed_fd(new_parent, |new_parent| {
            rustix::fs::renameat_with(
                old_parent,
                old_name,
                new_parent,
                new_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)
        })
    })
}

fn with_borrowed_fd<T>(fd: RawFd, operation: impl for<'fd> FnOnce(BorrowedFd<'fd>) -> T) -> T {
    operation(unsafe { BorrowedFd::borrow_raw(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fixture(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "file-guard-secure-{tag}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let watched = root.join("watched");
        let staging = root.join("staging");
        std::fs::create_dir_all(&watched).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (root, watched.join("credential"), staging)
    }

    #[test]
    fn capture_rejects_hardlinks_and_symlinked_parents() {
        let (root, path, _) = fixture("validation");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::hard_link(&path, root.join("alias")).unwrap();
        assert_eq!(
            ResolvedPath::new(&path)
                .unwrap()
                .capture()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.join("linked")).unwrap();
        assert!(ResolvedPath::new(&root.join("linked/file")).is_err());

        std::fs::remove_file(root.join("alias")).unwrap();
        std::fs::remove_file(&path).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"target-secret").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ResolvedPath::new(&path).unwrap().capture().is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn protected_exchange_preserves_the_detached_inode() {
        let (root, path, staging_root) = fixture("exchange");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let resolved = ResolvedPath::new(&path).unwrap();
        let captured = resolved.capture().unwrap();
        let parent = resolved.parent_identity().unwrap();
        let staging = StagingArea::create(
            &staging_root,
            "00112233445566778899aabbccddeeff",
            parent.device,
        )
        .unwrap();
        let placeholder = staging
            .create_placeholder("swap", captured.original.metadata())
            .unwrap();
        resolved.exchange_with(&staging, "swap").unwrap();

        assert!(same_file_after_rename(
            &placeholder,
            &resolved.observe().unwrap().unwrap()
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        assert_eq!(
            std::fs::read(staging.path().join("swap")).unwrap(),
            b"secret"
        );
        let OriginalState::Present { identity, .. } = captured.original else {
            panic!("fixture should be present")
        };
        assert!(same_file_after_rename(
            &identity,
            &staging.observe("swap").unwrap().unwrap()
        ));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn restoration_preserves_promised_metadata_and_xattrs() {
        let (root, path, staging_root) = fixture("restore");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let resolved = ResolvedPath::new(&path).unwrap();
        let captured = resolved.capture().unwrap();
        let parent = resolved.parent_identity().unwrap();
        let staging = StagingArea::create(
            &staging_root,
            "00112233445566778899aabbccddeeff",
            parent.device,
        )
        .unwrap();
        staging
            .create_placeholder("swap", captured.original.metadata())
            .unwrap();
        resolved.exchange_with(&staging, "swap").unwrap();
        let restored = staging
            .create_restoration("restore", &captured.contents, captured.original.metadata())
            .unwrap();
        resolved.exchange_with(&staging, "restore").unwrap();
        assert!(same_file_after_rename(
            &restored,
            &resolved.observe().unwrap().unwrap()
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o640);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn construction_debris_is_replaced_before_atomic_installation() {
        let (root, path, staging_root) = fixture("construction-debris");
        std::fs::write(&path, b"complete-secret").unwrap();
        let resolved = ResolvedPath::new(&path).unwrap();
        let captured = resolved.capture().unwrap();
        let parent = resolved.parent_identity().unwrap();
        let staging = StagingArea::create(
            &staging_root,
            "00112233445566778899aabbccddeeff",
            parent.device,
        )
        .unwrap();
        let construction = staging.path().join(".building-restore");
        std::fs::write(&construction, b"partial").unwrap();

        staging
            .create_restoration("restore", &captured.contents, captured.original.metadata())
            .unwrap();

        assert!(!construction.exists());
        staging
            .verify_restoration("restore", &captured.contents, captured.original.metadata())
            .unwrap();
        std::fs::remove_dir_all(root).ok();
    }
}
