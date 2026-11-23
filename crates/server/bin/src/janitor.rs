//! Background cleanup of expired state.
//!
//! Requests never clean up after other requests; one task does it for the whole server, right
//! after startup and then every [`INTERVAL`]:
//!
//! - expired chunked upload sessions with their chunks, and chunk directories that belong to
//!   no session ([`ChunkedUploads::purge`]);
//! - expired Login Flow v2 sign-ins ([`login_flows::purge_expired`]);
//! - expired browser sessions ([`web_sessions::purge_expired`]);
//! - expired direct download links ([`direct_downloads::purge_expired`]);
//! - one-time codes of email addresses that ended (expired, used, replaced or tried too often)
//!   a day after they were made: until then the limit of codes per day counts them
//!   ([`email::purge`]);
//! - expired WeChat bind tickets and mini program sessions ([`wechat::purge_expired`]),
//!   whether or not `[wechat]` is on, and expired pending identities, the signup tokens of the
//!   mini program among them ([`identities::purge_expired`]);
//! - expired S3 multipart uploads with their parts, and part directories that belong to no
//!   upload ([`gono_server_s3::multipart::purge`]), when the S3 API is on;
//! - the lifecycle rules of S3 buckets ([`gono_server_s3::lifecycle::apply`]), when the S3 API
//!   is on;
//! - the accounts whose cooling-off period after asking for their deletion ended
//!   ([`users::due_deletions`]): deleted as an administrator's deletion would, their files
//!   moved to `deleted/`.
//!
//! Every pass is independent: a failure is logged and the next pass tries again.

use std::time::Duration;

use gono_server_core::{
    db, direct_downloads, email, identities, login_flows, storage::DataLayout, users, web_sessions,
    wechat,
};
use gono_server_nextcloud::chunking::ChunkedUploads;
use gono_server_s3::S3State;
use tokio::task::JoinHandle;

/// Time between two cleanup passes.
pub const INTERVAL: Duration = Duration::from_secs(10 * 60);

/// What the janitor cleans.
#[derive(Debug, Clone)]
pub struct Janitor {
    /// The database.
    pub db: db::Pool,
    /// Chunked uploads.
    pub uploads: ChunkedUploads,
    /// The S3 API, when it is on.
    pub s3: Option<S3State>,
    /// The data directory, where the files of deleted accounts are moved away.
    pub layout: DataLayout,
}

impl Janitor {
    /// Runs one cleanup pass.
    pub async fn run_once(&self) {
        match self.uploads.purge().await {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "removed expired chunked uploads"),
            Err(err) => tracing::warn!(error = %err, "cannot clean up chunked uploads"),
        }
        let now = db::unix_now();
        match login_flows::purge_expired(&self.db, now).await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "removed expired Login Flow v2 sign-ins"),
            Err(err) => tracing::warn!(error = %err, "cannot clean up Login Flow v2 sign-ins"),
        }
        match web_sessions::purge_expired(&self.db, now).await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "removed expired browser sessions"),
            Err(err) => tracing::warn!(error = %err, "cannot clean up browser sessions"),
        }
        match direct_downloads::purge_expired(&self.db, now).await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "removed expired direct download links"),
            Err(err) => tracing::warn!(error = %err, "cannot clean up direct download links"),
        }
        match email::purge(&self.db, now).await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "removed old email codes"),
            Err(err) => tracing::warn!(error = %err, "cannot clean up email codes"),
        }
        match wechat::purge_expired(&self.db, now).await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "removed expired WeChat tickets and sessions"),
            Err(err) => tracing::warn!(error = %err, "cannot clean up WeChat tickets and sessions"),
        }
        match identities::purge_expired(&self.db, now).await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "removed expired pending identities"),
            Err(err) => tracing::warn!(error = %err, "cannot clean up pending identities"),
        }
        self.delete_due_accounts(now).await;
        if let Some(s3) = &self.s3 {
            match gono_server_s3::multipart::purge(s3).await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(removed, "removed expired S3 multipart uploads"),
                Err(err) => tracing::warn!(error = %err, "cannot clean up S3 multipart uploads"),
            }
            if let Err(err) = gono_server_s3::lifecycle::apply(s3, db::unix_now()).await {
                tracing::warn!(error = %err, "cannot apply S3 lifecycle rules");
            }
        }
    }

    /// Deletes the accounts whose deletion is due at `now`.
    async fn delete_due_accounts(&self, now: i64) {
        let due = match users::due_deletions(&self.db, now).await {
            Ok(due) => due,
            Err(err) => {
                tracing::warn!(error = %err, "cannot look for accounts to delete");
                return;
            }
        };
        for user in due {
            match users::delete(&self.db, &user.username).await {
                Ok(deleted) => {
                    match self
                        .layout
                        .retire_user(deleted.id, deleted.username.as_str(), now)
                    {
                        Ok(files) => {
                            tracing::info!(user = %deleted.username, files = ?files, "account deleted after its cooling-off period");
                        }
                        Err(err) => {
                            tracing::warn!(user = %deleted.username, error = %err, "account deleted, but its files could not be moved to deleted/");
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(user = %user.username, error = %err, "cannot delete an account whose deletion is due");
                }
            }
        }
    }

    /// Starts the background task. It runs until the runtime shuts down.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                self.run_once().await;
            }
        })
    }
}
