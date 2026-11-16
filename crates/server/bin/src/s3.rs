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
    RelPath,
    audit::{self, Record},
    config::S3Config,
    db,
    s3::{Anonymous, Bucket, S3Key},
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
    /// `s3.virtual_host_domain`: buckets are also `<bucket>.<domain>`.
    pub virtual_host_domain: Option<String>,
    /// `s3.website_domain`: buckets with a website configuration are `<bucket>.<domain>`.
    pub website_domain: Option<String>,
}

impl S3Ui {
    /// What the pages need of `config`, or `None` when the S3 API is off.
    pub fn from_config(config: &S3Config) -> Option<Self> {
        config.enabled.then(|| Self {
            public_url: config.public_url.clone(),
            region: config.region.clone(),
            bucket_folder: config.bucket_folder.clone(),
            allow_anonymous: config.allow_anonymous,
            virtual_host_domain: config.virtual_host_domain.clone(),
            website_domain: config.website_domain.clone(),
        })
    }

    /// The endpoint without a trailing `/`, as clients are configured with it.
    pub fn endpoint(&self) -> Option<String> {
        self.public_url
            .as_ref()
            .map(|url| url.as_str().trim_end_matches('/').to_owned())
    }

    /// The origin of `bucket` in virtual-hosted style, `<scheme>://<bucket>.<domain>[:<port>]`
    /// with the scheme and port of the endpoint; `None` without `s3.virtual_host_domain`.
    pub fn virtual_host_origin(&self, bucket: &str) -> Option<String> {
        Some(self.origin(bucket, self.virtual_host_domain.as_deref()?))
    }

    /// The website of `bucket`, `<scheme>://<bucket>.<domain>[:<port>]/` with the scheme and
    /// port of the endpoint (websites are served by the same listener); `None` without
    /// `s3.website_domain`.
    pub fn website_url(&self, bucket: &str) -> Option<String> {
        let domain = self.website_domain.as_deref()?;
        Some(format!("{}/", self.origin(bucket, domain)))
    }

    /// `<scheme>://<bucket>.<domain>[:<port>]` with the scheme and port of the endpoint.
    fn origin(&self, bucket: &str, domain: &str) -> String {
        let scheme = self.public_url.as_ref().map_or("https", Url::scheme);
        let port = self
            .public_url
            .as_ref()
            .and_then(Url::port)
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        format!("{scheme}://{bucket}.{domain}{port}")
    }
}

/// What the file UI needs for its "copy public link" action: the endpoint and the account's
/// buckets that publish something right now.
#[derive(Debug, Clone)]
pub struct PublicLinks {
    ui: Arc<S3Ui>,
    /// The buckets whose mode is `acl` or `public-read`.
    buckets: Vec<Bucket>,
}

impl PublicLinks {
    /// The public links of `owner`'s files: `None` while the S3 API or anonymous access is off,
    /// the endpoint is unknown, or no bucket of `owner` publishes anything.
    pub async fn load(ui: Option<&Arc<S3Ui>>, pool: &db::Pool, owner: i64) -> Option<Self> {
        let ui = ui?;
        if !ui.allow_anonymous || ui.public_url.is_none() {
            return None;
        }
        let buckets = match gono_server_core::s3::buckets_of(pool, owner).await {
            Ok(buckets) => buckets,
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the buckets for public links");
                return None;
            }
        };
        let buckets: Vec<Bucket> = buckets
            .into_iter()
            .filter(|bucket| bucket.owner_enabled && bucket.anonymous != Anonymous::Private)
            .collect();
        (!buckets.is_empty()).then(|| Self {
            ui: ui.clone(),
            buckets,
        })
    }

    /// The buckets whose folder holds `rel`, innermost first.
    fn holding(&self, rel: &RelPath) -> Vec<&Bucket> {
        let mut holding: Vec<&Bucket> = self
            .buckets
            .iter()
            .filter(|bucket| rel.starts_with(&bucket.folder) && *rel != bucket.folder)
            .collect();
        holding.sort_by_key(|bucket| std::cmp::Reverse(bucket.folder.as_str().len()));
        holding
    }

    /// Whether the file at `rel` is published only if it has the `public-read` ACL, so that
    /// [`Self::url`] needs to know.
    pub fn needs_acl(&self, rel: &RelPath) -> bool {
        let holding = self.holding(rel);
        !holding.is_empty()
            && holding
                .iter()
                .all(|bucket| bucket.anonymous == Anonymous::Acl)
    }

    /// The URL anyone can download the file at `rel` from, if one of the buckets holding it
    /// publishes it: every file of a `public-read` bucket, and in an `acl` bucket the files
    /// whose current version has the `public-read` ACL (`public_acl`). Virtual-hosted style when
    /// it is enabled, which gives each bucket an origin of its own.
    pub fn url(&self, rel: &RelPath, spelled: Option<&str>, public_acl: bool) -> Option<String> {
        let bucket = self.holding(rel).into_iter().find(|bucket| {
            bucket.anonymous == Anonymous::PublicRead
                || (bucket.anonymous == Anonymous::Acl && public_acl)
        })?;
        // The key as S3 spelled it (keys need not be in NFC; the tree's names are), which is
        // the only one the file answers to.
        let below = rel.strip_prefix(&bucket.folder)?;
        let key = spelled
            .and_then(|spelled| spelled.strip_prefix(bucket.folder.as_str()))
            .and_then(|rest| rest.strip_prefix('/'))
            .unwrap_or(below.as_str());
        if key.len() > gono_server_s3::keys::MAX_KEY_BYTES {
            return None;
        }
        let key = gono_server_s3::keys::url_encode(key);
        Some(match self.ui.virtual_host_origin(&bucket.name) {
            Some(origin) => format!("{origin}/{key}"),
            None => format!("{}/{}/{key}", self.ui.endpoint()?, bucket.name),
        })
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
        let service = service.clone();
        async move {
            match service.call(request).await {
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

/// Logs method, redacted target, status, duration, client address and request id (the
/// `x-amz-request-id` the client got) of an S3 request.
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
    let request_id = response
        .headers()
        .get("x-amz-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-");
    tracing::info!(
        %method,
        %target,
        status = response.status().as_u16(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        %client,
        request_id,
        "s3 request"
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ui(public_url: &str, domain: Option<&str>) -> S3Ui {
        S3Ui {
            public_url: Some(Url::parse(public_url).unwrap()),
            region: "us-east-1".to_owned(),
            bucket_folder: "Buckets".to_owned(),
            allow_anonymous: false,
            virtual_host_domain: domain.map(str::to_owned),
            website_domain: None,
        }
    }

    fn bucket(id: i64, name: &str, folder: &str, anonymous: Anonymous) -> Bucket {
        Bucket {
            id,
            name: name.to_owned(),
            owner_id: 1,
            owner_name: gono_server_core::Username::new("alice").unwrap(),
            owner_display_name: "Alice".to_owned(),
            owner_enabled: true,
            root_file_id: 100 + id,
            folder: RelPath::parse(folder).unwrap(),
            anonymous,
            anonymous_list: false,
            cors: None,
            tags: None,
            lifecycle: None,
            website: None,
            created_at: 0,
        }
    }

    #[test]
    fn public_links_name_the_bucket_that_publishes_a_file() {
        let links = PublicLinks {
            ui: Arc::new(ui("https://s3.example.com", None)),
            buckets: vec![
                bucket(1, "media", "Buckets/media", Anonymous::Acl),
                bucket(2, "site", "Sites/site", Anonymous::PublicRead),
                bucket(3, "inner", "Sites/site/inner", Anonymous::Acl),
            ],
        };
        let path = |rel: &str| RelPath::parse(rel).unwrap();
        // An `acl` bucket publishes only files with the public-read ACL.
        assert!(links.needs_acl(&path("Buckets/media/a b.jpg")));
        assert_eq!(links.url(&path("Buckets/media/a b.jpg"), None, false), None);
        assert_eq!(
            links
                .url(&path("Buckets/media/2026/a b+c.jpg"), None, true)
                .as_deref(),
            Some("https://s3.example.com/media/2026/a%20b%2Bc.jpg")
        );
        // A public-read bucket publishes everything, also below a nested acl bucket.
        assert!(!links.needs_acl(&path("Sites/site/index.html")));
        assert_eq!(
            links
                .url(&path("Sites/site/index.html"), None, false)
                .as_deref(),
            Some("https://s3.example.com/site/index.html")
        );
        assert!(!links.needs_acl(&path("Sites/site/inner/x.txt")));
        assert_eq!(
            links
                .url(&path("Sites/site/inner/x.txt"), None, false)
                .as_deref(),
            Some("https://s3.example.com/site/inner/x.txt")
        );
        assert_eq!(
            links
                .url(&path("Sites/site/inner/x.txt"), None, true)
                .as_deref(),
            Some("https://s3.example.com/inner/x.txt"),
            "the innermost bucket that publishes it"
        );
        // Outside every bucket, or the bucket's folder itself: nothing.
        assert!(!links.needs_acl(&path("Documents/a.txt")));
        assert_eq!(links.url(&path("Documents/a.txt"), None, true), None);
        assert_eq!(links.url(&path("Buckets/media"), None, true), None);

        let virtual_links = PublicLinks {
            ui: Arc::new(ui("https://s3.example.com", Some("s3.example.com"))),
            ..links
        };
        assert_eq!(
            virtual_links
                .url(&path("Sites/site/index.html"), None, false)
                .as_deref(),
            Some("https://site.s3.example.com/index.html")
        );
        // A key that S3 spelled otherwise (here in NFD) is linked as spelled, the only spelling
        // the file answers to.
        assert_eq!(
            virtual_links
                .url(
                    &path("Sites/site/Caf\u{e9}/a.txt"),
                    Some("Sites/site/Cafe\u{301}/a.txt"),
                    false
                )
                .as_deref(),
            Some("https://site.s3.example.com/Cafe%CC%81/a.txt")
        );
    }

    #[test]
    fn virtual_host_origins_keep_the_endpoints_scheme_and_port() {
        assert_eq!(
            ui("https://s3.example.com/", Some("s3.example.com"))
                .virtual_host_origin("photos")
                .as_deref(),
            Some("https://photos.s3.example.com")
        );
        assert_eq!(
            ui("http://s3.localhost:9000", Some("s3.localhost"))
                .virtual_host_origin("media")
                .as_deref(),
            Some("http://media.s3.localhost:9000")
        );
        assert_eq!(
            ui("https://s3.example.com", None).virtual_host_origin("photos"),
            None
        );
    }

    #[test]
    fn website_urls_keep_the_endpoints_scheme_and_port() {
        let mut local = ui("http://s3.localhost:9000", None);
        assert_eq!(local.website_url("site"), None);
        local.website_domain = Some("web.localhost".to_owned());
        assert_eq!(
            local.website_url("site").as_deref(),
            Some("http://site.web.localhost:9000/")
        );
    }
}
