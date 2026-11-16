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
//! - expired S3 multipart uploads with their parts, and part directories that belong to no
//!   upload ([`gono_server_s3::multipart::purge`]), when the S3 API is on.
//!
//! Every pass is independent: a failure is logged and the next pass tries again.

use std::time::Duration;

use gono_server_core::{db, direct_downloads, login_flows, web_sessions};
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
        if let Some(s3) = &self.s3 {
            match gono_server_s3::multipart::purge(s3).await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(removed, "removed expired S3 multipart uploads"),
                Err(err) => tracing::warn!(error = %err, "cannot clean up S3 multipart uploads"),
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
