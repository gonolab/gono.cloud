//! Object operations: reads and writes by client path for callers that are not dav-server, such
//! as the S3 API.
//!
//! dav-server and the chunked upload reach the tree through DAV paths. An S3 request names a
//! bucket, which is a mount of the request's [`Identity`], and a key; together they are a client
//! path. The operations here take that client path, apply the same scope and path checks as
//! every WebDAV request, and add S3's rules:
//!
//! - **No folders in S3**: a write creates its missing parent folders, each recorded in the
//!   MetaStore. Parents are checked and created under a lock per account, so a file is never
//!   recorded below a folder whose own record is still to come (recording a folder clears stale
//!   rows below it, which would take the file's S3 metadata along). A WebDAV `MKCOL` of the same
//!   new folder at the same instant does not take that lock; the file's row is then adopted
//!   again on the next lookup, without its S3 metadata.
//! - **Keys name files**: writing where a folder is, or below a file, is refused
//!   ([`ObjectError::IsFolder`], [`ObjectError::ParentIsFile`]). Deleting removes only the file;
//!   folders that become empty stay, because they may be the WebDAV user's own.
//! - **Conditional writes** ([`WriteCondition`]): `CreateOnly` installs with `link(2)`, which
//!   fails atomically when the name is taken, by any writer. `IfMatch` compares the S3 ETag and
//!   installs under a lock per path, which makes it atomic against the other writes here; WebDAV
//!   writes do not take that lock.
//! - **S3 metadata of one version**: [`ScopedFs::object`] returns the stored [`ObjectMeta`] only
//!   while the file on disk is still the version it was written with.
//! - Every write runs to completion even if the request is dropped, like every other write.
//!
//! WebDAV locks are the caller's concern ([`crate::locks::write_conflict`]), as for the chunked
//! upload.

use std::{
    hash::{DefaultHasher, Hash as _, Hasher as _},
    io,
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

use dav_server::fs::FsError;
use gono_server_core::{
    RelPath,
    meta::{DiskStat, ObjectMeta},
    storage::lstat_beneath,
};
use http::Method;
use rand::RngExt as _;
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::{
    ctx::{Ctx, RequestInfo},
    fs::{ScopedFs, disk_stat},
    identity::Identity,
    metadata::Entry,
    resolve::{self, Location},
};

/// Locks per path striped over this many mutexes; so are the locks per account.
const STRIPES: usize = 64;

/// Why an object operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectError {
    /// Nothing is there, or the path is outside the identity's mounts.
    NotFound,
    /// The identity may not write there, or the path is a mount root.
    Forbidden,
    /// The path is a folder.
    IsFolder,
    /// A parent of the path is a file.
    ParentIsFile,
    /// The [`WriteCondition`] does not hold.
    PreconditionFailed,
    /// The file system is full.
    InsufficientStorage,
    /// Anything else; logged where it happened.
    Failed,
}

impl std::fmt::Display for ObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "not found",
            Self::Forbidden => "forbidden",
            Self::IsFolder => "the path is a folder",
            Self::ParentIsFile => "a parent of the path is a file",
            Self::PreconditionFailed => "precondition failed",
            Self::InsufficientStorage => "insufficient storage",
            Self::Failed => "failed",
        })
    }
}

impl std::error::Error for ObjectError {}

impl From<FsError> for ObjectError {
    fn from(err: FsError) -> Self {
        match err {
            FsError::NotFound => Self::NotFound,
            FsError::Forbidden => Self::Forbidden,
            FsError::InsufficientStorage => Self::InsufficientStorage,
            _ => Self::Failed,
        }
    }
}

fn object_io_error(err: io::Error) -> ObjectError {
    match err.kind() {
        io::ErrorKind::NotFound => ObjectError::NotFound,
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => {
            ObjectError::InsufficientStorage
        }
        _ => {
            tracing::error!(error = %err, "object operation failed");
            ObjectError::Failed
        }
    }
}

fn object_db_error(err: gono_server_core::Error) -> ObjectError {
    tracing::error!(error = %err, "metadata update failed");
    ObjectError::Failed
}

/// When a write may happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteCondition {
    /// Always.
    Always,
    /// Only if nothing is at the path (`If-None-Match: *`).
    CreateOnly,
    /// Only if a file is at the path and its S3 ETag (without quotes) is this one (`If-Match`).
    IfMatch(String),
}

/// The mutexes behind the locks per path and per account.
#[derive(Debug)]
pub(crate) struct ObjectLocks {
    paths: Vec<Arc<Mutex<()>>>,
    accounts: Vec<Arc<Mutex<()>>>,
}

impl ObjectLocks {
    pub(crate) fn new() -> Self {
        let stripes = || (0..STRIPES).map(|_| Arc::new(Mutex::new(()))).collect();
        Self {
            paths: stripes(),
            accounts: stripes(),
        }
    }

    /// The lock of `owner`'s path `rel`. Taken before the account's lock, never after it.
    async fn path(&self, owner: i64, rel: &RelPath) -> OwnedMutexGuard<()> {
        let mut hasher = DefaultHasher::new();
        owner.hash(&mut hasher);
        rel.as_str().hash(&mut hasher);
        let stripe = usize::try_from(hasher.finish() % STRIPES as u64).unwrap_or(0);
        self.paths[stripe].clone().lock_owned().await
    }

    /// The lock of `owner`'s folder creation.
    async fn account(&self, owner: i64) -> OwnedMutexGuard<()> {
        let stripe = usize::try_from(owner.rem_euclid(STRIPES as i64)).unwrap_or(0);
        self.accounts[stripe].clone().lock_owned().await
    }
}

/// Runs blocking code on the blocking thread pool.
async fn blocking<T, F>(f: F) -> Result<T, ObjectError>
where
    F: FnOnce() -> Result<T, ObjectError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ObjectError::Failed)?
}

/// Runs `future` to completion even if the request that started it is dropped.
async fn detached<T, F>(future: F) -> Result<T, ObjectError>
where
    F: Future<Output = Result<T, ObjectError>> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(future)
        .await
        .map_err(|_| ObjectError::Failed)?
}

/// A resolved write target.
struct Target {
    ctx: Ctx,
    location: Location,
    owner: i64,
    /// The path inside the owner's storage.
    storage: RelPath,
    /// The storage path of the target's mount: parents are created below it, never above.
    mount_root: RelPath,
}

impl ScopedFs {
    /// The file at client path `client` and its S3 metadata. The metadata is `None` when the
    /// version was not written through S3, and also when the file changed on disk behind the
    /// server's back since (it described other content then).
    pub async fn object(
        &self,
        identity: Arc<Identity>,
        client: &RelPath,
    ) -> Result<(Arc<Entry>, Option<ObjectMeta>), ObjectError> {
        let entry = self.stat(identity.clone(), client).await?;
        if entry.is_dir() {
            return Err(ObjectError::IsFolder);
        }
        let meta = self.version_meta(identity.user_id, &entry).await?;
        Ok((entry, meta))
    }

    /// The S3 metadata of the file version `entry` describes, while it is the recorded version.
    async fn version_meta(
        &self,
        owner: i64,
        entry: &Entry,
    ) -> Result<Option<ObjectMeta>, ObjectError> {
        let file_id = entry.file_id.ok_or(ObjectError::Failed)?;
        // A file changed behind the server's back gets an ETag derived from the disk, never the
        // recorded one (see `ScopedFs::storage_entry`).
        let recorded = self
            .meta()
            .get_by_id(owner, file_id)
            .await
            .map_err(object_db_error)?
            .is_some_and(|row| row.etag == entry.etag);
        if !recorded {
            return Ok(None);
        }
        self.meta()
            .object_meta(file_id)
            .await
            .map_err(object_db_error)
    }

    /// Installs `temp` as the file at client path `client` with the S3 metadata `object`, if
    /// `condition` holds, creating missing parent folders.
    ///
    /// `temp` must be a complete, synced file on the data directory's file system (in `tmp/`).
    /// On error it is left for the caller to remove.
    pub async fn put_object(
        &self,
        identity: Arc<Identity>,
        client: &RelPath,
        temp: PathBuf,
        object: ObjectMeta,
        condition: WriteCondition,
    ) -> Result<Arc<Entry>, ObjectError> {
        let target = self.object_target(identity, client, Method::PUT).await?;
        let fs = self.clone();
        detached(async move { fs.install_object(target, temp, object, condition).await }).await
    }

    /// Copies the file at client path `from` to client path `to` with the S3 metadata `object`,
    /// if `condition` holds, creating missing parent folders of `to`. The copy is a new version:
    /// its modification time is `modified`, or now.
    pub async fn copy_object(
        &self,
        identity: Arc<Identity>,
        from: &RelPath,
        to: &RelPath,
        object: ObjectMeta,
        condition: WriteCondition,
        modified: Option<SystemTime>,
    ) -> Result<Arc<Entry>, ObjectError> {
        let source = self.stat(identity.clone(), from).await?;
        if source.is_dir() {
            return Err(ObjectError::IsFolder);
        }
        let source = source
            .location
            .storage()
            .cloned()
            .ok_or(ObjectError::NotFound)?;
        let target = self.object_target(identity, to, Method::PUT).await?;
        let root = self.user_root(target.owner);
        let tmp_dir = self.layout().tmp_dir();
        let fs = self.clone();
        detached(async move {
            let temp = blocking(move || {
                let meta = lstat_beneath(&root, &source)
                    .map_err(object_io_error)?
                    .ok_or(ObjectError::NotFound)?;
                if !meta.is_file() {
                    return Err(ObjectError::NotFound);
                }
                let temp = tmp_dir.join(format!("{:032x}.part", rand::rng().random::<u128>()));
                let copied = std::fs::copy(source.to_fs_path(&root), &temp).and_then(|_| {
                    let file = std::fs::OpenOptions::new().write(true).open(&temp)?;
                    file.set_modified(modified.unwrap_or_else(SystemTime::now))?;
                    file.sync_all()
                });
                if let Err(err) = copied {
                    let _ = std::fs::remove_file(&temp);
                    return Err(object_io_error(err));
                }
                Ok(temp)
            })
            .await?;
            let result = fs
                .install_object(target, temp.clone(), object, condition)
                .await;
            if result.is_err() {
                let _ = tokio::fs::remove_file(&temp).await;
            }
            result
        })
        .await
    }

    /// Creates the folder at client path `client` and its missing parents (an S3 folder
    /// marker, a key ending in `/` with an empty body). An existing folder is fine.
    pub async fn put_folder(
        &self,
        identity: Arc<Identity>,
        client: &RelPath,
    ) -> Result<Arc<Entry>, ObjectError> {
        let location = resolve::resolve_client(&identity, client.clone())?;
        if !location.writable(&identity) {
            return Err(ObjectError::Forbidden);
        }
        let mount_root = location
            .mount(&identity)
            .map(|mount| mount.storage_path.clone())
            .ok_or(ObjectError::Forbidden)?;
        let storage = location.storage().cloned().ok_or(ObjectError::Forbidden)?;
        let owner = identity.user_id;
        self.ensure_user(owner).await?;
        let fs = self.clone();
        let ctx = Ctx::new(identity.clone(), RequestInfo::new(Method::PUT));
        detached(async move {
            fs.create_folders(owner, &mount_root, &storage, true)
                .await?;
            Ok(fs.lookup(&ctx, &location).await?)
        })
        .await
    }

    /// Opens the file at client path `client` for reading, with its S3 metadata as
    /// [`Self::object`] returns it. The last path component is opened without following
    /// symbolic links, like a WebDAV `GET`.
    pub async fn open_object(
        &self,
        identity: Arc<Identity>,
        client: &RelPath,
    ) -> Result<(Arc<Entry>, Option<ObjectMeta>, std::fs::File), ObjectError> {
        let (entry, meta) = self.object(identity.clone(), client).await?;
        let storage = entry
            .location
            .storage()
            .cloned()
            .ok_or(ObjectError::NotFound)?;
        let path = storage.to_fs_path(&self.user_root(identity.user_id));
        let file = blocking(move || {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
            options.open(path).map_err(object_io_error)
        })
        .await?;
        Ok((entry, meta, file))
    }

    /// Removes the folder at client path `client` with its subfolders if no file is left
    /// below it (deleting an S3 bucket, or an S3 folder marker). Returns `false`, and removes
    /// nothing, when there is no folder there or files are left. A mount root is refused.
    pub async fn remove_empty_folder(
        &self,
        identity: Arc<Identity>,
        client: &RelPath,
    ) -> Result<bool, ObjectError> {
        let target = self.object_target(identity, client, Method::DELETE).await?;
        let fs = self.clone();
        detached(async move {
            let _path = fs.object_locks().path(target.owner, &target.storage).await;
            // Folder creation of uploads takes this lock too, so none starts filling the
            // folder while it is checked and removed.
            let _account = fs.object_locks().account(target.owner).await;
            let root = fs.user_root(target.owner);
            let rel = target.storage.clone();
            let removed = blocking(move || {
                match lstat_beneath(&root, &rel).map_err(object_io_error)? {
                    Some(meta) if meta.is_dir() => {}
                    _ => return Ok(false),
                }
                let path = rel.to_fs_path(&root);
                if holds_files(&path).map_err(object_io_error)? {
                    return Ok(false);
                }
                std::fs::remove_dir_all(&path).map_err(object_io_error)?;
                Ok(true)
            })
            .await?;
            if removed {
                fs.meta()
                    .record_delete(target.owner, &target.storage)
                    .await
                    .map_err(object_db_error)?;
                target.ctx.forget(&target.storage);
            }
            Ok(removed)
        })
        .await
    }

    /// Deletes the file at client path `client`. Returns `false` when there is no file there
    /// (nothing, or a folder): deleting a missing object succeeds in S3. Parent folders stay.
    pub async fn delete_object(
        &self,
        identity: Arc<Identity>,
        client: &RelPath,
    ) -> Result<bool, ObjectError> {
        let target = self.object_target(identity, client, Method::DELETE).await?;
        let fs = self.clone();
        detached(async move {
            let _path = fs.object_locks().path(target.owner, &target.storage).await;
            let root = fs.user_root(target.owner);
            let rel = target.storage.clone();
            let removed = blocking(move || {
                match lstat_beneath(&root, &rel).map_err(object_io_error)? {
                    Some(meta) if meta.is_file() => {}
                    _ => return Ok(false),
                }
                match std::fs::remove_file(rel.to_fs_path(&root)) {
                    Ok(()) => Ok(true),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
                    Err(err) => Err(object_io_error(err)),
                }
            })
            .await?;
            if removed {
                fs.meta()
                    .record_delete(target.owner, &target.storage)
                    .await
                    .map_err(object_db_error)?;
                target.ctx.forget(&target.storage);
            }
            Ok(removed)
        })
        .await
    }

    /// Resolves the target of a write or delete: a writable path inside a mount, not the mount
    /// root itself.
    async fn object_target(
        &self,
        identity: Arc<Identity>,
        client: &RelPath,
        method: Method,
    ) -> Result<Target, ObjectError> {
        let location = resolve::resolve_client(&identity, client.clone())?;
        if !location.writable(&identity) || location.is_mount_root(&identity) {
            return Err(ObjectError::Forbidden);
        }
        let mount_root = location
            .mount(&identity)
            .map(|mount| mount.storage_path.clone())
            .ok_or(ObjectError::Forbidden)?;
        let storage = location.storage().cloned().ok_or(ObjectError::Forbidden)?;
        let owner = identity.user_id;
        self.ensure_user(owner).await?;
        Ok(Target {
            ctx: Ctx::new(identity, RequestInfo::new(method)),
            location,
            owner,
            storage,
            mount_root,
        })
    }

    /// The body of [`Self::put_object`] and [`Self::copy_object`], run detached.
    async fn install_object(
        &self,
        target: Target,
        temp: PathBuf,
        object: ObjectMeta,
        condition: WriteCondition,
    ) -> Result<Arc<Entry>, ObjectError> {
        let Target {
            ctx,
            location,
            owner,
            storage,
            mount_root,
        } = target;
        let _path = self.object_locks().path(owner, &storage).await;
        if let Some(parent) = storage.parent() {
            self.create_folders(owner, &mount_root, &parent, true)
                .await?;
        }
        if let WriteCondition::IfMatch(expected) = &condition {
            let current = match self.lookup(&ctx, &location).await {
                Ok(entry) => entry,
                Err(FsError::NotFound) => return Err(ObjectError::PreconditionFailed),
                Err(err) => return Err(err.into()),
            };
            if current.is_dir() {
                return Err(ObjectError::PreconditionFailed);
            }
            let meta = self.version_meta(owner, &current).await?;
            let etag = meta
                .as_ref()
                .map_or(current.etag.as_str(), |meta| meta.etag_or(&current.etag));
            if etag != expected {
                return Err(ObjectError::PreconditionFailed);
            }
            ctx.forget(&storage);
        }
        let root = self.user_root(owner);
        let rel = storage.clone();
        let create_only = condition == WriteCondition::CreateOnly;
        let stat = blocking(move || {
            match lstat_beneath(&root, &rel).map_err(object_io_error)? {
                Some(meta) if meta.is_dir() => return Err(ObjectError::IsFolder),
                Some(_) if create_only => return Err(ObjectError::PreconditionFailed),
                _ => {}
            }
            let path = rel.to_fs_path(&root);
            if create_only {
                // Unlike rename(2), link(2) never replaces what another writer put there since.
                match std::fs::hard_link(&temp, &path) {
                    Ok(()) => {
                        let _ = std::fs::remove_file(&temp);
                    }
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(ObjectError::PreconditionFailed);
                    }
                    Err(err) => return Err(object_io_error(err)),
                }
            } else {
                std::fs::rename(&temp, &path).map_err(|err| match err.kind() {
                    // A folder appeared there since the check above.
                    io::ErrorKind::IsADirectory
                    | io::ErrorKind::DirectoryNotEmpty
                    | io::ErrorKind::AlreadyExists => ObjectError::IsFolder,
                    _ => object_io_error(err),
                })?;
            }
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)
                    .and_then(|dir| dir.sync_all())
                    .map_err(object_io_error)?;
            }
            Ok(disk_stat(
                &std::fs::symlink_metadata(&path).map_err(object_io_error)?,
            ))
        })
        .await?;
        let row = self
            .meta()
            .record_object_write(owner, &storage, stat, &object)
            .await
            .map_err(object_db_error)?;
        Ok(self.remember_row(&ctx, location, &row, stat))
    }

    /// Makes sure `dir` and its ancestors below `mount_root` are folders (only `dir`'s
    /// ancestors when `include_dir` is false), creating and recording the missing ones under the
    /// account's lock.
    async fn create_folders(
        &self,
        owner: i64,
        mount_root: &RelPath,
        dir: &RelPath,
        include_dir: bool,
    ) -> Result<(), ObjectError> {
        let mut wanted: Vec<RelPath> = dir
            .ancestors()
            .into_iter()
            .filter(|ancestor| ancestor.starts_with(mount_root) && ancestor != mount_root)
            .collect();
        if include_dir && dir != mount_root {
            wanted.push(dir.clone());
        }
        if wanted.is_empty() {
            return Ok(());
        }
        let _account = self.object_locks().account(owner).await;
        for folder in wanted {
            let root = self.user_root(owner);
            let rel = folder.clone();
            let created: Option<DiskStat> = blocking(move || {
                match lstat_beneath(&root, &rel).map_err(object_io_error)? {
                    Some(meta) if meta.is_dir() => return Ok(None),
                    Some(_) => return Err(ObjectError::ParentIsFile),
                    None => {}
                }
                let path = rel.to_fs_path(&root);
                match std::fs::create_dir(&path) {
                    Ok(()) => {}
                    // Created by a writer that does not take the account's lock.
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                        return match lstat_beneath(&root, &rel).map_err(object_io_error)? {
                            Some(meta) if meta.is_dir() => Ok(None),
                            _ => Err(ObjectError::ParentIsFile),
                        };
                    }
                    Err(err) => return Err(object_io_error(err)),
                }
                Ok(Some(disk_stat(
                    &std::fs::symlink_metadata(&path).map_err(object_io_error)?,
                )))
            })
            .await?;
            if let Some(stat) = created {
                self.meta()
                    .record_mkdir(owner, &folder, stat.mtime_ns)
                    .await
                    .map_err(object_db_error)?;
            }
        }
        Ok(())
    }
}

/// Whether anything but folders lies below the folder `dir` (symbolic links and special files
/// count, so they are never removed by accident).
fn holds_files(dir: &std::path::Path) -> io::Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if !kind.is_dir() || holds_files(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}
