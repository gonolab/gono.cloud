//! The secret behind an access key, for s3s to check signatures with.
//!
//! s3s computes and compares the signature itself; this only looks the key up. Keys that do not
//! exist, expired, belong to a disabled account or whose secret no longer opens (the key file
//! was replaced) all answer `InvalidAccessKeyId`. A database failure answers `ServiceUnavailable`,
//! which clients retry, never a credential error.

use gono_server_core::{app_passwords, db, s3};
use s3s::{
    S3Result,
    auth::{S3Auth, SecretKey},
    s3_error,
};
use secrecy::ExposeSecret as _;

use crate::state::S3State;

/// Minimum time between two `last_used_at` updates of one key, in seconds (as for app
/// passwords).
const LAST_USED_GRANULARITY: i64 = 300;

/// The [`S3Auth`] of the API.
pub(crate) struct Auth {
    state: S3State,
}

impl Auth {
    pub(crate) fn new(state: S3State) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl S3Auth for Auth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        let now = db::unix_now();
        let key = s3::signing_key(self.state.pool(), self.state.sealing(), access_key, now)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "cannot look up an S3 access key");
                s3_error!(ServiceUnavailable, "Please try again later")
            })?
            .ok_or_else(|| s3_error!(InvalidAccessKeyId))?;
        if key
            .last_used_at
            .is_none_or(|at| now - at >= LAST_USED_GRANULARITY)
        {
            let pool = self.state.pool().clone();
            let id = key.id;
            tokio::spawn(async move {
                if let Err(err) = app_passwords::record_use(&pool, id, now).await {
                    tracing::warn!(error = %err, "cannot record the use of an S3 access key");
                }
            });
        }
        Ok(SecretKey::from(key.secret.expose_secret()))
    }
}
