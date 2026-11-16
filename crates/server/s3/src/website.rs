//! Static website hosting.
//!
//! A bucket with a website configuration (`PutBucketWebsite`, stored as JSON in
//! `s3_buckets.website`) is served as a website at `<bucket>.<s3.website_domain>`, a host name of
//! its own as in S3, while the S3 API stays as it is. Website requests are anonymous `GET` and
//! `HEAD` requests and read only what anonymous requests may read (the bucket's anonymous
//! access). On top of that, as in S3:
//!
//! - `/` and every path ending in `/` serve the index document of that folder;
//! - a path whose object is missing while `<path>/<index document>` exists redirects to `<path>/`;
//! - routing rules redirect by key prefix and by the error a request would get;
//! - errors answer the error document (with the error's status), or a small HTML page;
//! - `RedirectAllRequestsTo` sends every request to another host.

use std::future::Future;

use http::{HeaderValue, Method, StatusCode, header};
use s3s::{Body, HttpResponse, S3Error, S3ErrorCode, S3Result, dto};
use serde::{Deserialize, Serialize};

/// Most routing rules, as in S3.
const MAX_ROUTING_RULES: usize = 50;

/// A website configuration as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Website {
    index_suffix: Option<String>,
    error_key: Option<String>,
    redirect_all: Option<Target>,
    #[serde(default)]
    rules: Vec<RoutingRule>,
}

/// Where a redirect goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Target {
    host: Option<String>,
    protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RoutingRule {
    key_prefix_equals: Option<String>,
    error_code_equals: Option<u16>,
    target: Target,
    replace_key_prefix_with: Option<String>,
    replace_key_with: Option<String>,
    code: Option<u16>,
}

fn invalid(message: &str) -> S3Error {
    S3Error::with_message(S3ErrorCode::InvalidArgument, message.to_owned())
}

fn protocol(value: Option<dto::Protocol>) -> S3Result<Option<String>> {
    match value.as_ref().map(dto::Protocol::as_str) {
        None => Ok(None),
        Some(protocol @ ("http" | "https")) => Ok(Some(protocol.to_owned())),
        Some(_) => Err(invalid("Protocol is http or https")),
    }
}

/// The website configuration of a `PutBucketWebsite`, checked.
pub(crate) fn from_config(config: dto::WebsiteConfiguration) -> S3Result<Website> {
    if let Some(all) = config.redirect_all_requests_to {
        if config.index_document.is_some()
            || config.error_document.is_some()
            || config.routing_rules.is_some()
        {
            return Err(invalid(
                "RedirectAllRequestsTo cannot be combined with other website settings",
            ));
        }
        return Ok(Website {
            index_suffix: None,
            error_key: None,
            redirect_all: Some(Target {
                host: Some(all.host_name),
                protocol: protocol(all.protocol)?,
            }),
            rules: Vec::new(),
        });
    }
    let suffix = config
        .index_document
        .map(|index| index.suffix)
        .ok_or_else(|| invalid("A website configuration needs an IndexDocument"))?;
    if suffix.is_empty() || suffix.contains('/') {
        return Err(invalid(
            "The IndexDocument Suffix must not be empty or contain '/'",
        ));
    }
    let rules = config.routing_rules.unwrap_or_default();
    if rules.len() > MAX_ROUTING_RULES {
        return Err(invalid("At most 50 routing rules are allowed"));
    }
    let rules = rules
        .into_iter()
        .map(|rule| {
            let condition = rule.condition.unwrap_or_default();
            let redirect = rule.redirect;
            if redirect.replace_key_prefix_with.is_some() && redirect.replace_key_with.is_some() {
                return Err(invalid(
                    "A redirect has ReplaceKeyPrefixWith or ReplaceKeyWith, not both",
                ));
            }
            let code = |value: Option<String>, valid: &dyn Fn(u16) -> bool| {
                value
                    .map(|value| {
                        value
                            .parse::<u16>()
                            .ok()
                            .filter(|code| valid(*code))
                            .ok_or_else(|| invalid("An HTTP code is not valid here"))
                    })
                    .transpose()
            };
            Ok(RoutingRule {
                key_prefix_equals: condition.key_prefix_equals,
                error_code_equals: code(condition.http_error_code_returned_equals, &|code| {
                    (400..600).contains(&code)
                })?,
                target: Target {
                    host: redirect.host_name,
                    protocol: protocol(redirect.protocol)?,
                },
                replace_key_prefix_with: redirect.replace_key_prefix_with,
                replace_key_with: redirect.replace_key_with,
                code: code(redirect.http_redirect_code, &|code| {
                    (300..400).contains(&code)
                })?,
            })
        })
        .collect::<S3Result<Vec<_>>>()?;
    Ok(Website {
        index_suffix: Some(suffix),
        error_key: config.error_document.map(|error| error.key),
        redirect_all: None,
        rules,
    })
}

/// `website` as `GetBucketWebsite` answers it.
pub(crate) fn to_config(website: &Website) -> dto::GetBucketWebsiteOutput {
    let protocol = |value: &Option<String>| value.clone().map(dto::Protocol::from);
    dto::GetBucketWebsiteOutput {
        index_document: website
            .index_suffix
            .clone()
            .map(|suffix| dto::IndexDocument { suffix }),
        error_document: website
            .error_key
            .clone()
            .map(|key| dto::ErrorDocument { key }),
        redirect_all_requests_to: website.redirect_all.as_ref().map(|all| {
            dto::RedirectAllRequestsTo {
                host_name: all.host.clone().unwrap_or_default(),
                protocol: protocol(&all.protocol),
            }
        }),
        routing_rules: (!website.rules.is_empty()).then(|| {
            website
                .rules
                .iter()
                .map(|rule| dto::RoutingRule {
                    condition: (rule.key_prefix_equals.is_some()
                        || rule.error_code_equals.is_some())
                    .then(|| dto::Condition {
                        key_prefix_equals: rule.key_prefix_equals.clone(),
                        http_error_code_returned_equals: rule
                            .error_code_equals
                            .map(|code| code.to_string()),
                    }),
                    redirect: dto::Redirect {
                        host_name: rule.target.host.clone(),
                        protocol: protocol(&rule.target.protocol),
                        replace_key_prefix_with: rule.replace_key_prefix_with.clone(),
                        replace_key_with: rule.replace_key_with.clone(),
                        http_redirect_code: rule.code.map(|code| code.to_string()),
                    },
                })
                .collect()
        }),
    }
}

/// The configuration as stored.
pub(crate) fn to_stored(website: &Website) -> String {
    serde_json::to_string(website).unwrap_or_else(|_| "{}".to_owned())
}

/// The configuration of a bucket as stored, if it has one that can be read.
pub(crate) fn from_stored(stored: Option<&str>) -> Option<Website> {
    stored.and_then(|stored| serde_json::from_str(stored).ok())
}

/// The bucket a website host name `host` (port ignored) names below `domain`.
pub(crate) fn bucket_of(host: &str, domain: &str) -> Option<String> {
    let host = host.rsplit_once(':').map_or(host, |(name, port)| {
        if port.bytes().all(|byte| byte.is_ascii_digit()) {
            name
        } else {
            host
        }
    });
    let host = host.to_ascii_lowercase();
    let bucket = host.strip_suffix(domain)?.strip_suffix('.')?;
    (!bucket.is_empty() && !bucket.contains('.')).then(|| bucket.to_owned())
}

/// Percent-decodes a request path into a key (without its leading `/`).
fn key_of(path: &str) -> Option<String> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            decoded.push(u8::from_str_radix(path.get(index + 1..index + 3)?, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// Percent-encodes a key for a URL path, keeping `/`.
pub(crate) fn encode_key(key: &str) -> String {
    let mut encoded = String::with_capacity(key.len());
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// The answer for a website host whose bucket has no website configuration (or does not
/// exist): S3's `NoSuchWebsiteConfiguration`, as a page.
pub(crate) fn not_a_website() -> HttpResponse {
    plain(
        StatusCode::NOT_FOUND,
        "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1>\
         <p>Code: NoSuchWebsiteConfiguration</p></body></html>"
            .to_owned(),
    )
}

/// A plain response.
fn plain(status: StatusCode, body: String) -> HttpResponse {
    let mut response = HttpResponse::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

fn redirect(status: StatusCode, location: &str) -> HttpResponse {
    let mut response = plain(status, String::new());
    if let Ok(location) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

/// The location a redirect to `target` with `key` goes to; relative when it names no host.
fn location(target: &Target, request_host: &str, key: &str) -> String {
    match &target.host {
        Some(host) => format!(
            "{}://{host}/{}",
            target.protocol.as_deref().unwrap_or("http"),
            encode_key(key)
        ),
        None if target.protocol.is_some() => format!(
            "{}://{request_host}/{}",
            target.protocol.as_deref().unwrap_or("http"),
            encode_key(key)
        ),
        None => format!("/{}", encode_key(key)),
    }
}

impl RoutingRule {
    /// The redirect of this rule for `key`, which got the error `status` (`None`: before
    /// reading it).
    fn applies(&self, key: &str, status: Option<StatusCode>) -> bool {
        let prefix = self
            .key_prefix_equals
            .as_deref()
            .is_none_or(|prefix| key.starts_with(prefix));
        let error = match (self.error_code_equals, status) {
            (None, _) => true,
            (Some(code), Some(status)) => status.as_u16() == code,
            (Some(_), None) => false,
        };
        prefix && error && (self.key_prefix_equals.is_some() || self.error_code_equals.is_some())
    }

    fn redirect(&self, key: &str, request_host: &str) -> HttpResponse {
        let new_key = match (&self.replace_key_with, &self.replace_key_prefix_with) {
            (Some(replacement), _) => replacement.clone(),
            (None, Some(replacement)) => {
                let rest = self
                    .key_prefix_equals
                    .as_deref()
                    .and_then(|prefix| key.strip_prefix(prefix))
                    .unwrap_or(key);
                format!("{replacement}{rest}")
            }
            (None, None) => key.to_owned(),
        };
        let status = self
            .code
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::MOVED_PERMANENTLY);
        redirect(status, &location(&self.target, request_host, &new_key))
    }
}

/// Answers a website request for `path` of a bucket with `website`, reading objects with
/// `fetch(key, method)` (an anonymous `GET` or `HEAD` of the S3 API). `request_host` is the
/// request's host, for redirects that keep it.
pub(crate) async fn serve<F, Fut>(
    website: &Website,
    method: &Method,
    path: &str,
    request_host: &str,
    fetch: F,
) -> HttpResponse
where
    F: Fn(String, Method) -> Fut,
    Fut: Future<Output = HttpResponse>,
{
    if method != Method::GET && method != Method::HEAD {
        let mut response = plain(
            StatusCode::METHOD_NOT_ALLOWED,
            "<html><body><h1>405 Method Not Allowed</h1></body></html>".to_owned(),
        );
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    if let Some(all) = &website.redirect_all {
        let key = key_of(path).unwrap_or_default();
        return redirect(
            StatusCode::MOVED_PERMANENTLY,
            &location(all, request_host, &key),
        );
    }
    let Some(key) = key_of(path) else {
        return plain(
            StatusCode::BAD_REQUEST,
            "<html><body><h1>400 Bad Request</h1></body></html>".to_owned(),
        );
    };
    if let Some(rule) = website
        .rules
        .iter()
        .find(|rule| rule.error_code_equals.is_none() && rule.applies(&key, None))
    {
        return rule.redirect(&key, request_host);
    }
    let suffix = website.index_suffix.as_deref().unwrap_or("index.html");
    let object = if key.is_empty() || key.ends_with('/') {
        format!("{key}{suffix}")
    } else {
        key.clone()
    };
    let response = fetch(object.clone(), method.clone()).await;
    let status = response.status();
    if status.is_success() || status == StatusCode::NOT_MODIFIED || status.is_redirection() {
        return response;
    }
    if status == StatusCode::RANGE_NOT_SATISFIABLE || status == StatusCode::PRECONDITION_FAILED {
        return response;
    }
    // A folder without its slash: redirect when its index document exists.
    if !key.is_empty() && !key.ends_with('/') {
        let index = fetch(format!("{key}/{suffix}"), Method::HEAD).await;
        if index.status().is_success() {
            return redirect(StatusCode::FOUND, &format!("/{}/", encode_key(&key)));
        }
    }
    let error = if status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND {
        status
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    if let Some(rule) = website
        .rules
        .iter()
        .find(|rule| rule.error_code_equals.is_some() && rule.applies(&key, Some(error)))
    {
        return rule.redirect(&key, request_host);
    }
    if let Some(error_key) = &website.error_key {
        let mut document = fetch(error_key.clone(), method.clone()).await;
        if document.status().is_success() {
            *document.status_mut() = error;
            return document;
        }
    }
    let reason = error.canonical_reason().unwrap_or("Error");
    plain(
        error,
        format!(
            "<html><head><title>{code} {reason}</title></head><body><h1>{code} {reason}</h1>\
             </body></html>",
            code = error.as_u16()
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(xml: dto::WebsiteConfiguration) -> Website {
        from_config(xml).unwrap()
    }

    fn site() -> Website {
        config(dto::WebsiteConfiguration {
            index_document: Some(dto::IndexDocument {
                suffix: "index.html".into(),
            }),
            error_document: Some(dto::ErrorDocument {
                key: "404.html".into(),
            }),
            redirect_all_requests_to: None,
            routing_rules: Some(vec![dto::RoutingRule {
                condition: Some(dto::Condition {
                    key_prefix_equals: Some("old/".into()),
                    http_error_code_returned_equals: None,
                }),
                redirect: dto::Redirect {
                    replace_key_prefix_with: Some("new/".into()),
                    ..Default::default()
                },
            }]),
        })
    }

    /// Serves `path` of `site` from `objects` (key → body).
    async fn get(site: &Website, path: &str, objects: &[(&str, &str)]) -> (u16, String, String) {
        let objects: HashMap<String, String> = objects
            .iter()
            .map(|(key, body)| ((*key).to_owned(), (*body).to_owned()))
            .collect();
        let response = serve(site, &Method::GET, path, "site.example.org", |key, _| {
            let body = objects.get(&key).cloned();
            async move {
                match body {
                    Some(body) => HttpResponse::new(Body::from(body)),
                    None => {
                        let mut response = HttpResponse::new(Body::empty());
                        *response.status_mut() = StatusCode::FORBIDDEN;
                        response
                    }
                }
            }
        })
        .await;
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let body = response
            .body()
            .bytes()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        (response.status().as_u16(), location, body)
    }

    #[tokio::test]
    async fn folders_serve_their_index_and_errors_the_error_document() {
        let site = site();
        let objects = [
            ("index.html", "home"),
            ("docs/index.html", "docs"),
            ("docs/a.txt", "a"),
            ("404.html", "missing"),
        ];
        assert_eq!(
            get(&site, "/", &objects).await,
            (200, String::new(), "home".into())
        );
        assert_eq!(get(&site, "/docs/", &objects).await.2, "docs");
        assert_eq!(get(&site, "/docs/a.txt", &objects).await.2, "a");
        assert_eq!(
            get(&site, "/docs", &objects).await,
            (302, "/docs/".into(), String::new())
        );
        assert_eq!(
            get(&site, "/nothing", &objects).await,
            (403, String::new(), "missing".into())
        );
        assert_eq!(
            get(&site, "/old/page.html", &objects).await,
            (301, "/new/page.html".into(), String::new())
        );
        // Without an error document, a small page.
        let (status, _, body) = get(&site, "/nothing", &objects[..3]).await;
        assert_eq!(status, 403);
        assert!(body.contains("403 Forbidden"), "{body}");
        assert_eq!(
            get(&site, "/caf%C3%A9.txt", &[("café.txt", "c")]).await.2,
            "c"
        );
    }

    #[tokio::test]
    async fn every_request_can_go_elsewhere() {
        let all = config(dto::WebsiteConfiguration {
            redirect_all_requests_to: Some(dto::RedirectAllRequestsTo {
                host_name: "www.example.org".into(),
                protocol: Some(dto::Protocol::from_static(dto::Protocol::HTTPS)),
            }),
            ..Default::default()
        });
        assert_eq!(
            get(&all, "/a b", &[]).await,
            (301, "https://www.example.org/a%20b".into(), String::new())
        );
    }

    #[test]
    fn configurations_are_checked_and_answered_as_given() {
        let site = site();
        assert_eq!(from_stored(Some(&to_stored(&site))), Some(site.clone()));
        let answered = to_config(&site);
        assert_eq!(answered.index_document.unwrap().suffix, "index.html");
        assert_eq!(answered.routing_rules.unwrap().len(), 1);
        let refused = |config: dto::WebsiteConfiguration| from_config(config).is_err();
        assert!(
            refused(dto::WebsiteConfiguration::default()),
            "no index document"
        );
        assert!(refused(dto::WebsiteConfiguration {
            index_document: Some(dto::IndexDocument {
                suffix: "a/b.html".into()
            }),
            ..Default::default()
        }));
        assert!(refused(dto::WebsiteConfiguration {
            index_document: Some(dto::IndexDocument {
                suffix: "index.html".into()
            }),
            redirect_all_requests_to: Some(dto::RedirectAllRequestsTo {
                host_name: "x".into(),
                protocol: None,
            }),
            ..Default::default()
        }));
    }

    #[test]
    fn website_hosts_name_their_bucket() {
        assert_eq!(
            bucket_of("photos.web.example.org", "web.example.org").as_deref(),
            Some("photos")
        );
        assert_eq!(
            bucket_of("Photos.WEB.example.org:8443", "web.example.org").as_deref(),
            Some("photos")
        );
        assert_eq!(bucket_of("web.example.org", "web.example.org"), None);
        assert_eq!(bucket_of("a.b.web.example.org", "web.example.org"), None);
        assert_eq!(bucket_of("photos.example.org", "web.example.org"), None);
    }
}
