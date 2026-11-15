//! The server origin a device talks to, and the checks that bind every URL the server names and
//! every statement the device signs to it (protocol 2.1, 3 and 4.3; threat model C16).
//!
//! - **TLS.** An origin is `https`, or `http` on a loopback host (`localhost`, 127.0.0.0/8,
//!   `::1`) for tests, the same rule the server applies to `server.base_url` (protocol 3).
//! - **Same origin.** The login, poll and WebSocket URLs must have the origin's scheme (`wss`
//!   for `https`, `ws` for loopback `http`), host and port. A server cannot send the device's
//!   credential or its proofs anywhere else, and never over plain TCP to a remote host.
//! - **Statements** name the origin the device is talking to, in the serialization of
//!   protocol 2.1, never the `server` value an answer carries: a server whose `discovery.server`
//!   or `Registered.server` differs is refused.

use gono_protocol::connect::{Discovery, VERSION};
use url::{Host, Url};

use crate::{Error, Result};

/// A checked server origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Origin {
    /// `scheme://host[:port]/`, without path, query or user information.
    url: Url,
    /// `scheme://host[:port]`: what statements name.
    serialized: String,
}

/// Whether `url` names a loopback host, on which plain `http` is allowed for tests.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

impl Origin {
    /// Parses and normalizes an origin the user entered or a credential names, for example
    /// `https://cloud.example.com`. A path, query or user information is dropped.
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let url = Url::parse(input.trim()).map_err(|err| Error::Url(format!("{input}: {err}")))?;
        if url.host().is_none() {
            return Err(Error::Url(format!("{input} has no host")));
        }
        match url.scheme() {
            "https" => {}
            "http" if is_loopback(&url) => {}
            "http" => {
                return Err(Error::Url(format!(
                    "{input} uses plain http; only https is allowed, or http on a loopback host"
                )));
            }
            _ => return Err(Error::Url(format!("{input} is not an https origin"))),
        }
        let serialized = url.origin().ascii_serialization();
        let url = Url::parse(&serialized).map_err(|err| Error::Url(err.to_string()))?;
        Ok(Self { url, serialized })
    }

    /// The origin as statements name it: `https://cloud.example.com`.
    pub(crate) fn as_str(&self) -> &str {
        &self.serialized
    }

    /// The URL of `path` on this origin.
    pub(crate) fn join(&self, path: &str) -> Url {
        let mut url = self.url.clone();
        url.set_path(path);
        url
    }

    /// Checks that `url`, which the server named as its `what` URL, is on this origin: the same
    /// host and port, with the origin's scheme, or for a WebSocket its counterpart (`https` ↔
    /// `wss`, `http` ↔ `ws`).
    pub(crate) fn check_url(&self, what: &str, url: &str, websocket: bool) -> Result<Url> {
        let parsed =
            Url::parse(url).map_err(|err| Error::Url(format!("the {what} URL {url}: {err}")))?;
        let scheme = match (self.url.scheme(), websocket) {
            ("https", false) => "https",
            ("https", true) => "wss",
            (_, false) => "http",
            (_, true) => "ws",
        };
        if parsed.scheme() != scheme
            || parsed.host() != self.url.host()
            || parsed.port_or_known_default() != self.url.port_or_known_default()
        {
            return Err(Error::Url(format!(
                "the {what} URL {url} is not on {}",
                self.serialized
            )));
        }
        Ok(parsed)
    }

    /// Checks that the server calls itself by this origin (`discovery.server`,
    /// `Registered.server`).
    pub(crate) fn check_server(&self, found: &str) -> Result<()> {
        if found == self.serialized {
            Ok(())
        } else {
            Err(Error::WrongServer {
                expected: self.serialized.clone(),
                found: found.to_owned(),
            })
        }
    }

    /// Checks a discovery document fetched from this origin (protocol 3): the version, the
    /// server it names, and its login and WebSocket URLs. Returns the WebSocket URL.
    pub(crate) fn check_discovery(&self, discovery: &Discovery) -> Result<Url> {
        if discovery.version != VERSION {
            return Err(Error::UnsupportedVersion(discovery.version));
        }
        self.check_server(&discovery.server)?;
        self.check_url("login", &discovery.login, false)?;
        self.check_url("websocket", &discovery.websocket, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery(origin: &str, websocket: &str) -> Discovery {
        Discovery {
            version: VERSION,
            server: origin.to_owned(),
            login: format!("{origin}/gono/v1/login"),
            websocket: websocket.to_owned(),
            relay_url: "https://relay.example.com/".to_owned(),
            two_factor_required: true,
        }
    }

    #[test]
    fn origins_are_https_or_loopback_http() {
        for good in [
            "https://cloud.example.com",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.4.5.6",
            "http://[::1]:8080",
        ] {
            assert!(Origin::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "http://cloud.example.com",
            "http://192.168.1.10:8080",
            "http://[2001:db8::1]",
            "ftp://cloud.example.com",
            "wss://cloud.example.com",
            "not a url",
            "https://",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn origins_are_normalized() {
        let origin = Origin::parse(" HTTPS://kim:pw@Cloud.Example.COM:443/path?x=1 ").unwrap();
        assert_eq!(origin.as_str(), "https://cloud.example.com");
        assert_eq!(
            origin.join("/gono/v1/connect").as_str(),
            "https://cloud.example.com/gono/v1/connect"
        );
        assert_eq!(
            Origin::parse("https://cloud.example.com:8443/")
                .unwrap()
                .as_str(),
            "https://cloud.example.com:8443"
        );
    }

    #[test]
    fn urls_must_be_on_the_origin() {
        let origin = Origin::parse("https://cloud.example.com").unwrap();
        assert!(
            origin
                .check_url("login", "https://cloud.example.com/gono/v1/login", false)
                .is_ok()
        );
        assert!(
            origin
                .check_url("login", "https://cloud.example.com:443/x", false)
                .is_ok()
        );
        assert!(
            origin
                .check_url("websocket", "wss://cloud.example.com/gono/v1/ws", true)
                .is_ok()
        );
        for (url, websocket) in [
            ("http://cloud.example.com/gono/v1/login", false),
            ("https://evil.example.com/gono/v1/login", false),
            ("https://cloud.example.com:8443/gono/v1/login", false),
            ("wss://cloud.example.com/gono/v1/login", false),
            ("ws://cloud.example.com/gono/v1/ws", true),
            ("https://cloud.example.com/gono/v1/ws", true),
            ("wss://evil.example.com/gono/v1/ws", true),
            ("not a url", false),
        ] {
            assert!(origin.check_url("x", url, websocket).is_err(), "{url}");
        }
        let local = Origin::parse("http://127.0.0.1:8080").unwrap();
        assert!(
            local
                .check_url("websocket", "ws://127.0.0.1:8080/gono/v1/ws", true)
                .is_ok()
        );
        assert!(
            local
                .check_url("websocket", "ws://127.0.0.1:8081/gono/v1/ws", true)
                .is_err()
        );
    }

    #[test]
    fn discovery_must_name_this_origin_and_version() {
        let origin = Origin::parse("https://cloud.example.com").unwrap();
        let good = discovery(
            "https://cloud.example.com",
            "wss://cloud.example.com/gono/v1/ws",
        );
        assert_eq!(
            origin.check_discovery(&good).unwrap().as_str(),
            "wss://cloud.example.com/gono/v1/ws"
        );

        let mut newer = good.clone();
        newer.version = VERSION + 1;
        assert!(matches!(
            origin.check_discovery(&newer),
            Err(Error::UnsupportedVersion(version)) if version == VERSION + 1
        ));
        let other = discovery(
            "https://other.example.com",
            "wss://cloud.example.com/gono/v1/ws",
        );
        assert!(matches!(
            origin.check_discovery(&other),
            Err(Error::WrongServer { .. })
        ));
        let plain = discovery(
            "https://cloud.example.com",
            "ws://cloud.example.com/gono/v1/ws",
        );
        assert!(matches!(origin.check_discovery(&plain), Err(Error::Url(_))));
        let mut login = good;
        login.login = "https://evil.example.com/gono/v1/login".to_owned();
        assert!(matches!(origin.check_discovery(&login), Err(Error::Url(_))));
    }
}
