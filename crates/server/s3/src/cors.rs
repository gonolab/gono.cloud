//! CORS: the rules of a bucket (`PutBucketCors`) and the answers browsers get.
//!
//! The rules follow S3:
//!
//! - A rule allows a request when its origin matches one of `AllowedOrigin` (each with at most one
//!   `*`), its method is one of `AllowedMethod` (`GET`, `PUT`, `HEAD`, `POST`, `DELETE`), and, for
//!   a preflight request, every header in `Access-Control-Request-Headers` matches one of
//!   `AllowedHeader` (each with at most one `*`, compared without regard to case). The first
//!   rule that allows a request answers it.
//! - A preflight request (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) never
//!   reaches s3s, which does not route `OPTIONS`: it is answered here, `200` with the allowed
//!   origin, methods and headers, or `403 AccessForbidden`. It needs no signature, and it
//!   reveals no more than the rules.
//! - An actual request with `Origin` gets the CORS headers of the rule that allows it added to
//!   s3s's response, error responses included, so that the page can read them.
//!
//! CORS grants nothing: a browser may read a response only if the request itself was allowed
//! (signed with a key, or anonymous and published by the bucket).
//!
//! Rules are stored with the bucket as a JSON array ([`Rule`]).

use http::{HeaderMap, HeaderName, HeaderValue, header};
use s3s::{S3Error, S3ErrorCode, S3Result, dto, s3_error};
use serde::{Deserialize, Serialize};

/// Most rules of a bucket, as in S3.
pub(crate) const MAX_RULES: usize = 100;

/// Longest stored configuration, in bytes (S3 allows 64 KB).
const MAX_STORED_BYTES: usize = 64 * 1024;

/// The methods a rule may allow.
const METHODS: [&str; 5] = ["GET", "PUT", "HEAD", "POST", "DELETE"];

/// One CORS rule, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Rule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<String>,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) allowed_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) expose_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_age_seconds: Option<i32>,
}

fn invalid(message: String) -> S3Error {
    S3Error::with_message(S3ErrorCode::InvalidRequest, message)
}

/// Whether `value` is a token of RFC 9110 (a header name), with `*` allowed if `wildcard`.
fn is_token(value: &str, wildcard: bool) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"!#$%&'+-.^_`|~".contains(&b) || (wildcard && b == b'*')
        })
}

/// The rules of a `PutBucketCors` body, checked as S3 checks them.
pub(crate) fn rules_from_dto(config: dto::CORSConfiguration) -> S3Result<Vec<Rule>> {
    let rules = config.cors_rules;
    if rules.is_empty() {
        return Err(s3_error!(
            MalformedXML,
            "A CORS configuration needs at least one rule"
        ));
    }
    if rules.len() > MAX_RULES {
        return Err(invalid(format!(
            "A CORS configuration has at most {MAX_RULES} rules"
        )));
    }
    let mut checked = Vec::with_capacity(rules.len());
    for rule in rules {
        if rule.allowed_origins.is_empty() || rule.allowed_methods.is_empty() {
            return Err(s3_error!(
                MalformedXML,
                "Every CORS rule needs an AllowedOrigin and an AllowedMethod"
            ));
        }
        for method in &rule.allowed_methods {
            if !METHODS.contains(&method.as_str()) {
                return Err(invalid(format!(
                    "Found unsupported HTTP method in CORS config. Unsupported method is {method}"
                )));
            }
        }
        for origin in &rule.allowed_origins {
            if origin.is_empty() || !origin.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(invalid(format!("AllowedOrigin {origin:?} is not valid")));
            }
            if origin.matches('*').count() > 1 {
                return Err(invalid(format!(
                    "AllowedOrigin \"{origin}\" can not have more than one wildcard."
                )));
            }
        }
        let allowed_headers = rule.allowed_headers.unwrap_or_default();
        for name in &allowed_headers {
            if !is_token(name, true) || name.matches('*').count() > 1 {
                return Err(invalid(format!("AllowedHeader {name:?} is not valid")));
            }
        }
        let expose_headers = rule.expose_headers.unwrap_or_default();
        for name in &expose_headers {
            if !is_token(name, false) {
                return Err(invalid(format!("ExposeHeader {name:?} is not valid")));
            }
        }
        if rule.id.as_ref().is_some_and(|id| id.len() > 255) {
            return Err(invalid(
                "The ID of a CORS rule has at most 255 characters".into(),
            ));
        }
        if rule.max_age_seconds.is_some_and(|age| age < 0) {
            return Err(invalid("MaxAgeSeconds must not be negative".into()));
        }
        checked.push(Rule {
            id: rule.id,
            allowed_origins: rule.allowed_origins,
            allowed_methods: rule.allowed_methods,
            allowed_headers,
            expose_headers,
            max_age_seconds: rule.max_age_seconds,
        });
    }
    Ok(checked)
}

/// The rules as `GetBucketCors` returns them.
pub(crate) fn rules_to_dto(rules: Vec<Rule>) -> Vec<dto::CORSRule> {
    rules
        .into_iter()
        .map(|rule| dto::CORSRule {
            allowed_headers: (!rule.allowed_headers.is_empty()).then_some(rule.allowed_headers),
            allowed_methods: rule.allowed_methods,
            allowed_origins: rule.allowed_origins,
            expose_headers: (!rule.expose_headers.is_empty()).then_some(rule.expose_headers),
            id: rule.id,
            max_age_seconds: rule.max_age_seconds,
        })
        .collect()
}

/// `rules` as stored; refused if larger than S3 allows.
pub(crate) fn to_stored(rules: &[Rule]) -> S3Result<String> {
    let stored = serde_json::to_string(rules)
        .map_err(|_| s3_error!(InternalError, "cannot store the CORS rules"))?;
    if stored.len() > MAX_STORED_BYTES {
        return Err(invalid(
            "The CORS configuration is larger than 64 KB".to_owned(),
        ));
    }
    Ok(stored)
}

/// The stored rules of a bucket. Only this module writes them; an unreadable value (a damaged
/// database) allows nothing.
pub(crate) fn from_stored(stored: &str) -> Vec<Rule> {
    serde_json::from_str(stored).unwrap_or_else(|err| {
        tracing::warn!(error = %err, "stored CORS rules cannot be read; they allow nothing");
        Vec::new()
    })
}

/// Whether `value` matches `pattern`, which holds at most one `*` standing for any text.
fn wildcard_matches(pattern: &str, value: &str, ignore_case: bool) -> bool {
    let eq = |a: &str, b: &str| {
        if ignore_case {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    };
    match pattern.split_once('*') {
        None => eq(pattern, value),
        Some((prefix, suffix)) => {
            value.len() >= prefix.len() + suffix.len()
                && value.is_char_boundary(prefix.len())
                && value.is_char_boundary(value.len() - suffix.len())
                && eq(prefix, &value[..prefix.len()])
                && eq(suffix, &value[value.len() - suffix.len()..])
        }
    }
}

impl Rule {
    /// The `AllowedOrigin` that `origin` matches, if any.
    fn origin_pattern(&self, origin: &str) -> Option<&str> {
        self.allowed_origins
            .iter()
            .map(String::as_str)
            .find(|pattern| wildcard_matches(pattern, origin, false))
    }

    /// Whether the rule allows `method` from `origin` with the request `headers` (lowercase).
    fn allows(&self, origin: &str, method: &str, headers: &[String]) -> bool {
        self.origin_pattern(origin).is_some()
            && self.allowed_methods.iter().any(|allowed| allowed == method)
            && headers.iter().all(|name| {
                self.allowed_headers
                    .iter()
                    .any(|pattern| wildcard_matches(pattern, name, true))
            })
    }
}

/// The first rule that allows `method` from `origin` with the request `headers` (lowercase).
pub(crate) fn find<'a>(
    rules: &'a [Rule],
    origin: &str,
    method: &str,
    headers: &[String],
) -> Option<&'a Rule> {
    rules
        .iter()
        .find(|rule| rule.allows(origin, method, headers))
}

/// The headers `Access-Control-Request-Headers` names, in lowercase.
pub(crate) fn requested_headers(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Adds the CORS headers of `rule` for a request from `origin` to `headers`. `preflight` holds
/// the requested headers of a preflight request.
pub(crate) fn add_headers(
    headers: &mut HeaderMap,
    rule: &Rule,
    origin: &str,
    preflight: Option<&[String]>,
) {
    let mut set = |name: HeaderName, value: String| {
        if let Ok(value) = HeaderValue::try_from(value) {
            headers.insert(name, value);
        }
    };
    // A rule for every origin answers `*`; one for named origins repeats the origin, which
    // a browser then also accepts for requests with credentials.
    let any = rule.origin_pattern(origin) == Some("*");
    set(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        if any {
            "*".to_owned()
        } else {
            origin.to_owned()
        },
    );
    if !any {
        set(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".to_owned());
    }
    set(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        rule.allowed_methods.join(", "),
    );
    if let Some(requested) = preflight
        && !requested.is_empty()
    {
        set(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.join(", "));
    }
    if !rule.expose_headers.is_empty() {
        set(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            rule.expose_headers.join(", "),
        );
    }
    if let Some(age) = rule.max_age_seconds {
        set(header::ACCESS_CONTROL_MAX_AGE, age.to_string());
    }
    let vary = if preflight.is_some() {
        "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"
    } else {
        "Origin"
    };
    headers.append(header::VARY, HeaderValue::from_static(vary));
}

/// The refusal of a preflight request that no rule allows.
pub(crate) fn forbidden() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("AccessForbidden".into()),
        "CORSResponse: This CORS request is not allowed. This is usually because the \
         evaluation of Origin, request method / Access-Control-Request-Method or \
         Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.",
    );
    err.set_status_code(http::StatusCode::FORBIDDEN);
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(origins: &[&str], methods: &[&str], headers: &[&str]) -> Rule {
        Rule {
            id: None,
            allowed_origins: origins.iter().map(|&o| o.to_owned()).collect(),
            allowed_methods: methods.iter().map(|&m| m.to_owned()).collect(),
            allowed_headers: headers.iter().map(|&h| h.to_owned()).collect(),
            expose_headers: vec!["ETag".into()],
            max_age_seconds: Some(600),
        }
    }

    fn dto_rule(origins: &[&str], methods: &[&str]) -> dto::CORSRule {
        dto::CORSRule {
            allowed_headers: Some(vec!["*".into()]),
            allowed_methods: methods.iter().map(|&m| m.to_owned()).collect(),
            allowed_origins: origins.iter().map(|&o| o.to_owned()).collect(),
            expose_headers: None,
            id: Some("uploads".into()),
            max_age_seconds: None,
        }
    }

    fn config(rules: Vec<dto::CORSRule>) -> dto::CORSConfiguration {
        dto::CORSConfiguration { cors_rules: rules }
    }

    #[test]
    fn wildcards_stand_for_any_text_once() {
        assert!(wildcard_matches("*", "https://a.example", false));
        assert!(wildcard_matches(
            "https://*.example.com",
            "https://app.example.com",
            false
        ));
        assert!(!wildcard_matches(
            "https://*.example.com",
            "https://example.com",
            false
        ));
        assert!(!wildcard_matches(
            "https://app.example.com",
            "https://APP.example.com",
            false
        ));
        assert!(wildcard_matches("x-amz-*", "X-Amz-Date", true));
        assert!(!wildcard_matches("x-amz-*", "content-type", true));
        assert!(!wildcard_matches("ab*ba", "aba", false));
        assert!(wildcard_matches("ab*ba", "abba", false));
    }

    #[test]
    fn the_first_rule_that_allows_a_request_answers_it() {
        let rules = [
            rule(
                &["https://app.example"],
                &["PUT", "POST"],
                &["content-type"],
            ),
            rule(&["*"], &["GET", "HEAD"], &[]),
        ];
        let headers = |names: &[&str]| names.iter().map(|&n| n.to_owned()).collect::<Vec<_>>();
        let put = find(
            &rules,
            "https://app.example",
            "PUT",
            &headers(&["content-type"]),
        );
        assert_eq!(put, Some(&rules[0]));
        assert_eq!(
            find(
                &rules,
                "https://app.example",
                "PUT",
                &headers(&["x-amz-date"])
            ),
            None,
            "a header no rule allows"
        );
        assert_eq!(find(&rules, "https://other.example", "PUT", &[]), None);
        assert_eq!(
            find(&rules, "https://other.example", "GET", &[]),
            Some(&rules[1])
        );
        assert_eq!(find(&rules, "https://app.example", "DELETE", &[]), None);
    }

    #[test]
    fn allowed_requests_get_the_rules_headers() {
        let named = rule(&["https://app.example"], &["PUT", "POST"], &["*"]);
        let mut headers = HeaderMap::new();
        let requested = vec!["content-type".to_owned(), "x-amz-date".to_owned()];
        add_headers(
            &mut headers,
            &named,
            "https://app.example",
            Some(&requested),
        );
        assert_eq!(
            headers["access-control-allow-origin"],
            "https://app.example"
        );
        assert_eq!(headers["access-control-allow-credentials"], "true");
        assert_eq!(headers["access-control-allow-methods"], "PUT, POST");
        assert_eq!(
            headers["access-control-allow-headers"],
            "content-type, x-amz-date"
        );
        assert_eq!(headers["access-control-expose-headers"], "ETag");
        assert_eq!(headers["access-control-max-age"], "600");
        assert!(headers["vary"].to_str().unwrap().starts_with("Origin"));

        let any = rule(&["*"], &["GET"], &[]);
        let mut headers = HeaderMap::new();
        add_headers(&mut headers, &any, "https://other.example", None);
        assert_eq!(headers["access-control-allow-origin"], "*");
        assert!(!headers.contains_key("access-control-allow-credentials"));
        assert!(!headers.contains_key("access-control-allow-headers"));
        assert_eq!(headers["vary"], "Origin");
    }

    #[test]
    fn configurations_are_checked_like_s3_checks_them() {
        let rules = rules_from_dto(config(vec![dto_rule(
            &["https://*.example.com"],
            &["PUT", "GET"],
        )]))
        .unwrap();
        assert_eq!(rules[0].allowed_headers, ["*"]);
        assert_eq!(rules[0].id.as_deref(), Some("uploads"));
        let stored = to_stored(&rules).unwrap();
        assert_eq!(from_stored(&stored), rules);
        assert_eq!(
            rules_to_dto(rules.clone())[0].allowed_methods,
            ["PUT", "GET"]
        );
        assert!(from_stored("not json").is_empty());

        let code =
            |rules: Vec<dto::CORSRule>| rules_from_dto(config(rules)).unwrap_err().code().clone();
        assert_eq!(code(vec![]), S3ErrorCode::MalformedXML);
        assert_eq!(
            code(vec![dto_rule(&[], &["GET"])]),
            S3ErrorCode::MalformedXML
        );
        assert_eq!(code(vec![dto_rule(&["*"], &[])]), S3ErrorCode::MalformedXML);
        assert_eq!(
            code(vec![dto_rule(&["*"], &["PATCH"])]),
            S3ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(vec![dto_rule(&["https://*.*.example"], &["GET"])]),
            S3ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(vec![dto_rule(&["https://a example"], &["GET"])]),
            S3ErrorCode::InvalidRequest
        );
        let mut bad_header = dto_rule(&["*"], &["GET"]);
        bad_header.allowed_headers = Some(vec!["x-*-*".into()]);
        assert_eq!(code(vec![bad_header]), S3ErrorCode::InvalidRequest);
        let mut bad_expose = dto_rule(&["*"], &["GET"]);
        bad_expose.expose_headers = Some(vec!["ETag, x".into()]);
        assert_eq!(code(vec![bad_expose]), S3ErrorCode::InvalidRequest);
        assert_eq!(
            code(vec![dto_rule(&["*"], &["GET"]); MAX_RULES + 1]),
            S3ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn requested_headers_are_split_and_lowercased() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static("Content-Type, X-Amz-Date,,authorization"),
        );
        assert_eq!(
            requested_headers(&headers),
            ["content-type", "x-amz-date", "authorization"]
        );
    }
}
