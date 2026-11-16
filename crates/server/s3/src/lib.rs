//! The S3-compatible API of Gono Cloud, built on [`s3s`].
//!
//! s3s speaks the protocol: SigV4 in headers, presigned URLs and browser form uploads (POST
//! policies), `aws-chunked` bodies with their chunk signatures and trailers, the XML of every
//! operation, and error responses. This crate maps it onto the users' trees:
//!
//! - A **bucket** is a folder of its owner's tree ([`gono_server_core::s3`]); its objects are
//!   the files below it, and a key is a path relative to the folder ([`keys`]). Every write goes
//!   through [`gono_server_dav::ScopedFs`] and the MetaStore, so WebDAV, the Nextcloud clients
//!   and notify_push see S3 changes, and S3 sees theirs.
//! - **Addressing**: path style (`/<bucket>/<key>`) always, and virtual-hosted style
//!   (`<bucket>.<domain>`) when `s3.virtual_host_domain` is set ([`host`]).
//! - **Who may do what** is decided once per request, before the operation runs ([`access`]):
//!   requests signed with an access key act within the key's grants; unsigned requests may
//!   only read what a bucket publishes, and only while `s3.allow_anonymous` is on.
//! - **Operations** ([`ops`]) cover buckets, listings, objects with their metadata, ACLs and
//!   conditional requests, and multipart uploads ([`multipart`]). Everything else answers
//!   `NotImplemented`, the default of the s3s trait.
//! - **CORS** ([`cors`]): the rules of each bucket answer preflight requests, which s3s does
//!   not route, and add their headers to s3s's responses.
//! - **Request ids**: every response carries one in `x-amz-request-id`, and every error document
//!   in `RequestId`, as from S3 (s3s writes neither); the request log records it.
//!
//! [`service`] builds the [`Service`] the server binds to `s3.bind`.

mod access;
mod auth;
mod checksums;
mod cors;
mod error;
mod form;
mod host;
pub mod keys;
pub mod lifecycle;
pub mod multipart;
mod ops;
mod policy;
mod state;
mod tags;
mod upload;

pub use state::{S3Settings, S3State};

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use gono_server_core::s3 as buckets;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use rand::RngExt as _;
use s3s::{
    Body, HttpError, HttpResponse, S3Error,
    config::{S3Config, StaticConfigProvider},
    s3_error,
    service::{S3Service, S3ServiceBuilder},
};

/// The S3 API, ready to serve: s3s, with CORS handled around it. Cheap to clone.
#[derive(Clone)]
pub struct Service {
    s3: S3Service,
    state: S3State,
    hosts: Option<Arc<host::VirtualHosts>>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").finish_non_exhaustive()
    }
}

/// The S3 API over `state`.
pub fn service(state: S3State) -> Service {
    let mut builder = S3ServiceBuilder::new(ops::GonoS3::new(state.clone()));
    builder.set_auth(auth::Auth::new(state.clone()));
    builder.set_access(access::Access::new(state.clone()));
    let hosts = state
        .settings()
        .virtual_host_domain
        .as_deref()
        .map(|domain| Arc::new(host::VirtualHosts::new(domain)));
    if let Some(hosts) = &hosts {
        builder.set_host(host::Shared(hosts.clone()));
    }
    let mut config = S3Config::default();
    // Clients that sign for another region get the error from which the AWS SDKs learn the
    // right one.
    config.expected_region = state.settings().region.parse().ok();
    // Browser form uploads, signed with a policy; unsigned forms are anonymous writes, which
    // the access check refuses.
    config.allow_post_signature = true;
    builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(config))));
    Service {
        s3: builder.build(),
        state,
        hosts,
    }
}

/// The response of `err`.
fn error_response(err: S3Error) -> HttpResponse {
    err.to_http_response().unwrap_or_else(|_| {
        let mut response = HttpResponse::new(Body::empty());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    })
}

/// A new request id: 16 hexadecimal digits, like S3's.
fn new_request_id() -> String {
    format!("{:016X}", rand::rng().random::<u64>())
}

/// Gives `response` the request id `id`: in `x-amz-request-id`, and in an error document that
/// is held in memory (every one s3s and this crate write; a multipart completion's error after
/// its keep-alive has started is streamed and keeps its document as it is).
fn stamp_request_id(response: &mut HttpResponse, id: &str) {
    let Ok(value) = HeaderValue::from_str(id) else {
        return;
    };
    response
        .headers_mut()
        .insert(s3s::header::X_AMZ_REQUEST_ID, value);
    if response.status().is_success() {
        return;
    }
    let Some(stamped) = response
        .body()
        .bytes()
        .and_then(|body| with_request_id(&body, id))
    else {
        return;
    };
    if response.headers().contains_key(header::CONTENT_LENGTH) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(stamped.len()));
    }
    *response.body_mut() = Body::from(stamped);
}

/// `document`, an S3 error document without a `RequestId`, with `<RequestId>id</RequestId>` as
/// the last element of `Error`; `None` for anything else.
fn with_request_id(document: &[u8], id: &str) -> Option<Vec<u8>> {
    const END: &[u8] = b"</Error>";
    if document.windows(11).any(|window| window == b"<RequestId>") {
        return None;
    }
    let end = document
        .windows(END.len())
        .rposition(|window| window == END)?;
    let element = format!("<RequestId>{id}</RequestId>");
    let mut stamped = Vec::with_capacity(document.len() + element.len());
    stamped.extend_from_slice(&document[..end]);
    stamped.extend_from_slice(element.as_bytes());
    stamped.extend_from_slice(&document[end..]);
    Some(stamped)
}

/// Whether `headers` describe a form upload (`multipart/form-data`).
fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("multipart/form-data")
        })
}

impl Service {
    /// Answers `request`.
    ///
    /// # Errors
    ///
    /// What s3s reports for failures below the protocol (S3 errors are responses).
    pub async fn call<B>(&self, request: Request<B>) -> Result<HttpResponse, HttpError>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let id = new_request_id();
        let mut response = self.answer(request).await?;
        stamp_request_id(&mut response, &id);
        Ok(response)
    }

    /// Answers `request`: form uploads are prepared for s3s first.
    async fn answer<B>(&self, request: Request<B>) -> Result<HttpResponse, HttpError>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        if request.method() == Method::POST && is_form(request.headers()) {
            // s3s reads a form upload's file into memory to learn its size when the request
            // does not say it, and does so before the access check; browsers always say it.
            if !request.headers().contains_key(header::CONTENT_LENGTH) {
                return Ok(error_response(s3_error!(MissingContentLength)));
            }
            if let Some(boundary) = form::boundary(request.headers()) {
                let (parts, body) = request.into_parts();
                let (acl, body) = form::read_acl(body, boundary).await;
                let mut request = Request::from_parts(parts, body);
                if let Some(acl) = acl {
                    request.extensions_mut().insert(acl);
                }
                return self.respond(request).await;
            }
        }
        self.respond(request).await
    }

    /// Answers `request` with s3s, or itself for a preflight request, and adds the CORS
    /// headers.
    async fn respond<B>(&self, request: Request<B>) -> Result<HttpResponse, HttpError>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        if request.method() == Method::OPTIONS {
            // Only the headers are held across the lookup: a request body need not be `Sync`.
            let bucket = self.bucket_name(&request);
            return Ok(self.preflight(request.headers(), bucket).await);
        }
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let Some(origin) = origin else {
            return self.forward(request).await;
        };
        let method = request.method().clone();
        let bucket = self.bucket_name(&request);
        let mut response = self.forward(request).await?;
        if let Some(bucket) = bucket
            && let Some(rules) = self.rules(&bucket).await.ok().flatten()
            && let Some(rule) = cors::find(&rules, &origin, method.as_str(), &[])
        {
            cors::add_headers(response.headers_mut(), rule, &origin, None);
        }
        Ok(response)
    }

    async fn forward<B>(&self, request: Request<B>) -> Result<HttpResponse, HttpError>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let mut s3 = self.s3.clone();
        tower_service::Service::call(&mut s3, request).await
    }

    /// The bucket a request names, the way s3s finds it: in the host name (virtual-hosted
    /// style, never for an IP address), else in the first path segment.
    fn bucket_name<B>(&self, request: &Request<B>) -> Option<String> {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| request.uri().authority().map(http::uri::Authority::as_str));
        if let (Some(hosts), Some(host)) = (&self.hosts, host)
            && host.parse::<SocketAddr>().is_err()
            && host.parse::<IpAddr>().is_err()
            && let Some(bucket) = hosts.bucket_of(host)
        {
            return Some(bucket);
        }
        let first = request
            .uri()
            .path()
            .trim_start_matches('/')
            .split('/')
            .next()?;
        (!first.is_empty()).then(|| first.to_owned())
    }

    /// The CORS rules of `bucket`: `None` if it does not exist, belongs to a disabled account
    /// or has none.
    async fn rules(&self, bucket: &str) -> Result<Option<Vec<cors::Rule>>, S3Error> {
        let bucket = buckets::bucket(self.state.pool(), bucket)
            .await
            .map_err(error::database)?;
        Ok(bucket
            .filter(|bucket| bucket.owner_enabled)
            .and_then(|bucket| bucket.cors)
            .map(|stored| cors::from_stored(&stored)))
    }

    /// Answers a preflight request to `bucket` (see [`cors`]).
    async fn preflight(&self, headers: &HeaderMap, bucket: Option<String>) -> HttpResponse {
        let text = |name| headers.get(name).and_then(|value| value.to_str().ok());
        let (Some(origin), Some(method)) = (
            text(header::ORIGIN),
            text(header::ACCESS_CONTROL_REQUEST_METHOD),
        ) else {
            return error_response(s3_error!(
                InvalidRequest,
                "Insufficient information. Origin and Access-Control-Request-Method are needed."
            ));
        };
        let Some(bucket) = bucket else {
            return error_response(cors::forbidden());
        };
        let rules = match self.rules(&bucket).await {
            Ok(rules) => rules.unwrap_or_default(),
            Err(err) => return error_response(err),
        };
        let requested = cors::requested_headers(headers);
        let Some(rule) = cors::find(&rules, origin, method, &requested) else {
            return error_response(cors::forbidden());
        };
        let mut response = HttpResponse::new(Body::empty());
        cors::add_headers(response.headers_mut(), rule, origin, Some(&requested));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_documents_get_the_request_id() {
        let document =
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code></Error>";
        assert_eq!(
            with_request_id(document, "ABC").unwrap(),
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><RequestId>ABC</RequestId></Error>"
        );
        assert_eq!(
            with_request_id(b"<Error><RequestId>X</RequestId></Error>", "ABC"),
            None
        );
        assert_eq!(with_request_id(b"", "ABC"), None);
        assert_eq!(with_request_id(b"<ListBucketResult/>", "ABC"), None);
    }

    #[test]
    fn responses_get_the_request_id() {
        let mut error = error_response(s3_error!(NoSuchBucket));
        stamp_request_id(&mut error, "0123456789ABCDEF");
        assert_eq!(error.headers()["x-amz-request-id"], "0123456789ABCDEF");
        let body = String::from_utf8(error.body().bytes().unwrap().to_vec()).unwrap();
        assert!(
            body.ends_with("<RequestId>0123456789ABCDEF</RequestId></Error>"),
            "{body}"
        );
        let mut ok = HttpResponse::new(Body::from("<ListAllMyBucketsResult/>".to_owned()));
        stamp_request_id(&mut ok, "0123456789ABCDEF");
        assert_eq!(ok.headers()["x-amz-request-id"], "0123456789ABCDEF");
        assert_eq!(
            ok.body().bytes().unwrap(),
            Bytes::from_static(b"<ListAllMyBucketsResult/>")
        );
        assert_eq!(new_request_id().len(), 16);
    }
}
