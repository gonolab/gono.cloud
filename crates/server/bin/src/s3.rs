//! The S3 API's listener (`s3.bind`), next to the HTTP server, and what the browser pages
//! know of the S3 API ([`S3Ui`]).
//!
//! The API itself is [`gono_server_s3`]; this adapts its service to axum, so that it is served
//! with the same accept loop (`TCP_NODELAY`) and graceful shutdown as the main listener.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
};
use gono_server_core::{
    audit::{self, Record},
    config::S3Config,
    db,
    s3::{Bucket, S3Key},
};
use gono_server_s3::S3State;
use ipnet::IpNet;
use serde_json::json;
use url::Url;

use crate::{client_ip::client_ip, request_log::redact};

/// The settings of `[s3]` that the account page and the admin UI show and follow. The pages
/// get one only while the S3 API is enabled; without it, they show nothing of S3.
#[derive(Debug, Clone)]
pub struct S3Ui {
    /// `s3.public_url`: the endpoint clients are configured with.
    pub public_url: Option<Url>,
    /// `s3.region`.
    pub region: String,
    /// `s3.bucket_folder`: where new buckets get their folders.
    pub bucket_folder: String,
    /// `s3.allow_anonymous`: whether bucket owners may allow anonymous reads and listings.
    pub allow_anonymous: bool,
}

impl S3Ui {
    /// What the pages need of `config`, or `None` when the S3 API is off.
    pub fn from_config(config: &S3Config) -> Option<Self> {
        config.enabled.then(|| Self {
            public_url: config.public_url.clone(),
            region: config.region.clone(),
            bucket_folder: config.bucket_folder.clone(),
            allow_anonymous: config.allow_anonymous,
        })
    }

    /// The endpoint without a trailing `/`, as clients are configured with it.
    pub fn endpoint(&self) -> Option<String> {
        self.public_url
            .as_ref()
            .map(|url| url.as_str().trim_end_matches('/').to_owned())
    }
}

/// Writes `record` of an S3 change (a key created or revoked, a bucket created, removed or
/// with new anonymous access) to the audit log. The change is made already, so a record that
/// cannot be written is logged instead of failing the request.
pub async fn audit(pool: &db::Pool, record: Record) {
    if let Err(err) = audit::record(pool, &record, db::unix_now()).await {
        tracing::warn!(kind = record.kind, error = %err, "cannot write an audit record");
    }
}

/// The details of an `s3.key.created` record: the key, its label, what it reaches (bucket
/// names, `null` for every bucket) and its expiry.
pub fn key_details(key: &S3Key, buckets: &[Bucket]) -> serde_json::Value {
    let grants: Vec<serde_json::Value> = key
        .grants
        .iter()
        .map(|grant| {
            let bucket = grant.bucket_id.map(|id| {
                buckets
                    .iter()
                    .find(|bucket| bucket.id == id)
                    .map_or_else(|| format!("#{id}"), |bucket| bucket.name.clone())
            });
            json!({ "bucket": bucket, "permission": grant.permission.as_str() })
        })
        .collect();
    json!({
        "access_key_id": key.access_key_id,
        "label": key.label,
        "grants": grants,
        "expires_at": key.expires_at,
    })
}

/// The router of the S3 listener: every request goes to the S3 API, and one log line per
/// request records it (presigned URLs lose their signatures there, like every query value).
pub fn router(state: S3State, trusted_proxies: Arc<Vec<IpNet>>) -> Router {
    let service = gono_server_s3::service(state);
    let handler = move |request: Request<Body>| {
        let mut service = service.clone();
        async move {
            match tower_service::Service::call(&mut service, request).await {
                Ok(response) => response.map(Body::new),
                // s3s answers protocol errors itself; what reaches here failed below it.
                Err(err) => {
                    tracing::error!(error = ?err, "S3 request failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
    };
    Router::new()
        .fallback(handler)
        .layer(middleware::from_fn_with_state(
            trusted_proxies,
            log_requests,
        ))
}

/// Logs method, redacted target, status, duration and client address of an S3 request.
async fn log_requests(
    State(trusted_proxies): State<Arc<Vec<IpNet>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let target = redact(request.uri());
    let client = client_ip(peer.ip(), request.headers(), &trusted_proxies);
    let response = next.run(request).await;
    tracing::info!(
        %method,
        %target,
        status = response.status().as_u16(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        %client,
        "s3 request"
    );
    response
}
