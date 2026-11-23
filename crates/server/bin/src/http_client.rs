//! The outgoing HTTPS of the server: WeChat's `jscode2session` (`[wechat]`) and the OAuth
//! providers of `[oauth.*]` (Google, GitHub).
//!
//! Every client is reqwest with rustls on ring and the Mozilla roots of `webpki-roots`, as every
//! other TLS client of the workspace, nothing from the platform: HTTP/1.1 only, no proxy, no
//! redirects (a URL may carry a secret, which must go to its host and nowhere else), and
//! timeouts, so that a slow provider cannot hold a request for long.

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;

/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one request may take in all.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The TLS client configuration: ring, TLS 1.2 and 1.3, the Mozilla roots of `webpki-roots`,
/// and HTTP/1.1 only (reqwest is built without HTTP/2).
fn tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// A client as the module documentation describes it.
pub fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(concat!("gono-cloud/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("set up the outgoing HTTPS client")
}

/// A reqwest error for the log: without the URL (which may hold a secret), with its causes.
/// `what` names the other side.
pub fn describe(what: &str, err: reqwest::Error) -> String {
    let err = err.without_url();
    if err.is_timeout() {
        return format!("{what} did not answer in time");
    }
    let mut text = format!("cannot reach {what}: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// The body of `response`, at most `limit` bytes; `Err` says why not (for the log).
pub async fn read_body(
    what: &str,
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let too_large = || format!("{what}'s answer is larger than {limit} bytes");
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| describe(what, err))? {
        if body.len() + chunk.len() > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
