//! Virtual-hosted-style addressing: `<bucket>.<domain>` (`s3.virtual_host_domain`).
//!
//! s3s asks an [`S3Host`] which bucket a request's `Host` names, except for hosts that are IP
//! addresses (always path style). The host is matched against the configured domain without
//! regard to ASCII case or port:
//!
//! - the domain itself names no bucket: the request is path style (`/<bucket>/<key>`);
//! - `<bucket>.<domain>` names the bucket `<bucket>`, in lowercase; the path is then the key;
//! - every other host is path style too. s3s's own `SingleDomain` would take an unknown host for
//!   a bucket name (CNAME style), which this server does not offer.
//!
//! Bucket names have no dots, so a host with more labels than one below the domain names a
//! bucket that cannot exist, and s3s refuses it.

use std::borrow::Cow;

use s3s::{
    S3Result,
    host::{S3Host, VirtualHost},
};

/// The [`S3Host`] of the API when `s3.virtual_host_domain` is set.
#[derive(Debug)]
pub(crate) struct VirtualHosts {
    /// The domain, in lowercase.
    domain: String,
}

impl VirtualHosts {
    pub(crate) fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_ascii_lowercase(),
        }
    }

    /// The bucket that `host` names, if any; `None` for path style.
    fn bucket_of(&self, host: &str) -> Option<String> {
        let host = strip_port(host).to_ascii_lowercase();
        let below = host.strip_suffix(&self.domain)?.strip_suffix('.')?;
        (!below.is_empty()).then(|| below.to_owned())
    }
}

/// `host` without a `:<port>` suffix (bracketed IPv6 literals stay as they are).
fn strip_port(host: &str) -> &str {
    if host.ends_with(']') {
        return host;
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.parse::<u16>().is_ok() => name,
        _ => host,
    }
}

impl S3Host for VirtualHosts {
    fn parse_host_header<'a>(&'a self, host: &'a str) -> S3Result<VirtualHost<'a>> {
        Ok(match self.bucket_of(host) {
            Some(bucket) => VirtualHost::new(self.domain.as_str()).with_bucket(Cow::Owned(bucket)),
            None => VirtualHost::new(host),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_named_by_the_label_below_the_domain() {
        let hosts = VirtualHosts::new("s3.example.com");
        let bucket = |host: &str| hosts.bucket_of(host);
        assert_eq!(bucket("photos.s3.example.com").as_deref(), Some("photos"));
        assert_eq!(
            bucket("Photos.S3.Example.com:8443").as_deref(),
            Some("photos")
        );
        // Dotted names are not bucket names; s3s refuses them.
        assert_eq!(bucket("a.b.s3.example.com").as_deref(), Some("a.b"));
        for path_style in [
            "s3.example.com",
            "S3.EXAMPLE.COM:443",
            "localhost:16104",
            "example.com",
            "xs3.example.com",
            ".s3.example.com",
            "other.example.org",
            "[::1]",
        ] {
            assert_eq!(bucket(path_style), None, "{path_style}");
        }
    }

    #[test]
    fn the_parser_reports_the_bucket_to_s3s() {
        let hosts = VirtualHosts::new("s3.localhost");
        let parsed = hosts.parse_host_header("media.s3.localhost:9000").unwrap();
        assert_eq!(parsed.bucket(), Some("media"));
        assert_eq!(parsed.domain(), "s3.localhost");
        let parsed = hosts.parse_host_header("s3.localhost:9000").unwrap();
        assert_eq!(parsed.bucket(), None);
    }
}
