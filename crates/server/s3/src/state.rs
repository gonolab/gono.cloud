//! What every S3 request shares.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use gono_server_core::{db::Pool, locks::LockStore, sealing::Key};
use gono_server_dav::ScopedFs;

/// The settings of `[s3]` the API needs.
#[derive(Debug, Clone)]
pub struct S3Settings {
    /// The region clients sign for.
    pub region: String,
    /// The folder of each user's tree that holds the buckets created through the API.
    pub bucket_folder: String,
    /// Whether buckets may publish anything to anonymous requests.
    pub allow_anonymous: bool,
    /// Lifetime of a multipart upload, in seconds.
    pub multipart_ttl_secs: u64,
    /// The domain of virtual-hosted-style addressing (`<bucket>.<domain>`), if enabled.
    pub virtual_host_domain: Option<String>,
    /// The domain of static websites (`<bucket>.<domain>`), if enabled.
    pub website_domain: Option<String>,
}

/// The shared state of the S3 API. Cheap to clone.
#[derive(Clone)]
pub struct S3State {
    inner: Arc<Inner>,
}

struct Inner {
    pool: Pool,
    fs: ScopedFs,
    locks: LockStore,
    sealing: Key,
    settings: S3Settings,
    /// Multipart uploads being completed: their parts must not change meanwhile.
    completing: Mutex<HashSet<String>>,
}

/// Marks a multipart upload as being completed until it is dropped.
pub(crate) struct Completing {
    state: S3State,
    upload_id: String,
}

impl Drop for Completing {
    fn drop(&mut self) {
        self.state
            .inner
            .completing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.upload_id);
    }
}

impl std::fmt::Debug for S3State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3State")
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

impl S3State {
    /// The state over the server's database, file system, WebDAV locks and key file.
    pub fn new(
        pool: Pool,
        fs: ScopedFs,
        locks: LockStore,
        sealing: Key,
        settings: S3Settings,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                pool,
                fs,
                locks,
                sealing,
                settings,
                completing: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// The database.
    pub fn pool(&self) -> &Pool {
        &self.inner.pool
    }

    /// The users' trees.
    pub fn fs(&self) -> &ScopedFs {
        &self.inner.fs
    }

    /// The WebDAV locks.
    pub fn locks(&self) -> &LockStore {
        &self.inner.locks
    }

    /// The key secrets are sealed with.
    pub fn sealing(&self) -> &Key {
        &self.inner.sealing
    }

    /// The `[s3]` settings.
    pub fn settings(&self) -> &S3Settings {
        &self.inner.settings
    }

    /// Marks `upload_id` as being completed; `None` if it is already.
    pub(crate) fn begin_completion(&self, upload_id: &str) -> Option<Completing> {
        let fresh = self
            .inner
            .completing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(upload_id.to_owned());
        fresh.then(|| Completing {
            state: self.clone(),
            upload_id: upload_id.to_owned(),
        })
    }

    /// Whether `upload_id` is being completed.
    pub(crate) fn is_completing(&self, upload_id: &str) -> bool {
        self.inner
            .completing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(upload_id)
    }
}
