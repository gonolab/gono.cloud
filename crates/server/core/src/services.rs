//! The services an account may use.
//!
//! Every account has five switches, all off until an admin turns them on (the web admin UI or
//! `gono-cloud user services`); a new account, the first admin included, can only sign in to
//! the web pages, change its password and display name and set up two-step verification. Each
//! request path checks the switch of its service next to the account's `enabled` flag:
//!
//! - [`Service::Files`]: the web file UI (`/apps/files/`).
//! - [`Service::Webdav`]: everything Nextcloud clients use: WebDAV, chunked uploads, OCS,
//!   notify_push, direct links and the Login Flow v2 grants of app passwords.
//! - [`Service::S3`]: the S3 API with the account's access keys, and anonymous reads of its
//!   buckets.
//! - [`Service::Direct`]: remote access for devices ("direct connections"): registering them,
//!   the directory, connection requests and addresses, pairing, and the relay at the limited
//!   rate, enough for handshakes and for finding a direct path.
//! - [`Service::Relay`]: the relay at the full rate. It needs [`Service::Direct`]: turning it
//!   on turns that on as well ([`Services::normalized`]), and the schema refuses a row with
//!   relay but not direct connections.
//!
//! The switches are columns of `users` (`service_files`, ...). [`Services`] reads them with
//! `#[sqlx(flatten)]` from the columns of [`COLUMNS`] (or [`USER_COLUMNS`] for a query that
//! joins `users` as `u`).

use std::{fmt, str::FromStr};

use sqlx::FromRow;

use crate::db::Flag;

/// One of the five services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Service {
    /// The web file UI.
    Files,
    /// WebDAV and the rest of the Nextcloud protocol surface.
    Webdav,
    /// The S3 API.
    S3,
    /// Remote access for devices, with the relay at the limited rate.
    Direct,
    /// The relay at the full rate.
    Relay,
}

impl Service {
    /// Every service, in the order they are shown.
    pub const ALL: [Self; 5] = [
        Self::Files,
        Self::Webdav,
        Self::S3,
        Self::Direct,
        Self::Relay,
    ];

    /// The name used in the CLI, URLs and the protocol: `files`, `webdav`, `s3`, `direct`,
    /// `relay`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Webdav => "webdav",
            Self::S3 => "s3",
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

impl Service {
    /// Its column in `users`: `service_files`, `service_webdav`, ...
    pub const fn column(self) -> &'static str {
        match self {
            Self::Files => "service_files",
            Self::Webdav => "service_webdav",
            Self::S3 => "service_s3",
            Self::Direct => "service_direct",
            Self::Relay => "service_relay",
        }
    }

    /// The service's name in English messages: "web files", "WebDAV", "S3", "direct
    /// connections", "relay".
    pub const fn label(self) -> &'static str {
        match self {
            Self::Files => "web files",
            Self::Webdav => "WebDAV",
            Self::S3 => "S3",
            Self::Direct => "direct connections",
            Self::Relay => "relay",
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Service {
    type Err = UnknownService;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|service| service.as_str() == value)
            .ok_or_else(|| UnknownService(value.to_owned()))
    }
}

/// A name that is not one of [`Service::ALL`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown service {0:?}; the services are files, webdav, s3, direct and relay")]
pub struct UnknownService(pub String);

/// The switches of one account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, FromRow)]
pub struct Services {
    /// [`Service::Files`].
    #[sqlx(rename = "service_files", try_from = "Flag")]
    pub files: bool,
    /// [`Service::Webdav`].
    #[sqlx(rename = "service_webdav", try_from = "Flag")]
    pub webdav: bool,
    /// [`Service::S3`].
    #[sqlx(rename = "service_s3", try_from = "Flag")]
    pub s3: bool,
    /// [`Service::Direct`].
    #[sqlx(rename = "service_direct", try_from = "Flag")]
    pub direct: bool,
    /// [`Service::Relay`].
    #[sqlx(rename = "service_relay", try_from = "Flag")]
    pub relay: bool,
}

/// The service columns of `users`, for a query on `users` itself.
pub const COLUMNS: &str =
    "service_files, service_webdav, service_s3, service_direct, service_relay";

/// The service columns of `users` joined as `u`.
pub const USER_COLUMNS: &str =
    "u.service_files, u.service_webdav, u.service_s3, u.service_direct, u.service_relay";

impl Services {
    /// No service: the state of every new account.
    pub const NONE: Self = Self {
        files: false,
        webdav: false,
        s3: false,
        direct: false,
        relay: false,
    };

    /// Every service.
    pub const ALL: Self = Self {
        files: true,
        webdav: true,
        s3: true,
        direct: true,
        relay: true,
    };

    /// Whether `service` is on.
    pub const fn has(self, service: Service) -> bool {
        match service {
            Service::Files => self.files,
            Service::Webdav => self.webdav,
            Service::S3 => self.s3,
            Service::Direct => self.direct,
            Service::Relay => self.relay,
        }
    }

    /// These switches with `service` set to `on`, normalized.
    #[must_use]
    pub const fn with(mut self, service: Service, on: bool) -> Self {
        match service {
            Service::Files => self.files = on,
            Service::Webdav => self.webdav = on,
            Service::S3 => self.s3 = on,
            Service::Direct => {
                self.direct = on;
                // Without direct connections there is no full-rate relay either.
                if !on {
                    self.relay = false;
                }
            }
            Service::Relay => self.relay = on,
        }
        self.normalized()
    }

    /// The switches as stored: the relay needs direct connections, so relay turns them on.
    #[must_use]
    pub const fn normalized(mut self) -> Self {
        if self.relay {
            self.direct = true;
        }
        self
    }

    /// The services that are on, in the order of [`Service::ALL`].
    pub fn enabled(self) -> impl Iterator<Item = Service> {
        Service::ALL
            .into_iter()
            .filter(move |service| self.has(*service))
    }

    /// Whether no service is on.
    pub fn is_none(self) -> bool {
        self.enabled().next().is_none()
    }
}

impl fmt::Display for Services {
    /// The services that are on, separated by commas (`webdav,s3`), or `none`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            return f.write_str("none");
        }
        for (index, service) in self.enabled().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            f.write_str(service.as_str())?;
        }
        Ok(())
    }
}

/// Parses a comma-separated list of service names (`webdav,s3`); `all` names every service and
/// `none` (or an empty list) none.
pub fn parse_list(value: &str) -> Result<Vec<Service>, UnknownService> {
    let mut services = Vec::new();
    for name in value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        match name {
            "all" => services.extend(Service::ALL),
            "none" => {}
            _ => services.push(name.parse()?),
        }
    }
    services.sort_unstable();
    services.dedup();
    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for service in Service::ALL {
            assert_eq!(service.as_str().parse::<Service>().unwrap(), service);
        }
        assert!("ftp".parse::<Service>().is_err());
    }

    #[test]
    fn the_relay_needs_direct_connections() {
        let relay = Services::NONE.with(Service::Relay, true);
        assert!(relay.relay && relay.direct);
        let off = relay.with(Service::Direct, false);
        assert!(!off.relay && !off.direct);
        // Turning the relay off keeps direct connections.
        let direct = relay.with(Service::Relay, false);
        assert!(direct.direct && !direct.relay);
    }

    #[test]
    fn lists_parse_and_print() {
        assert_eq!(
            parse_list("s3, webdav,s3").unwrap(),
            [Service::Webdav, Service::S3]
        );
        assert_eq!(parse_list("all").unwrap(), Service::ALL);
        assert!(parse_list("none").unwrap().is_empty());
        assert!(parse_list("webdav,ftp").is_err());
        assert_eq!(Services::NONE.to_string(), "none");
        assert_eq!(
            Services::NONE
                .with(Service::Webdav, true)
                .with(Service::Relay, true)
                .to_string(),
            "webdav,direct,relay"
        );
    }
}
