//! The configuration file.
//!
//! The configuration is a TOML file (see `config.example.toml` in the repository root). Loading
//! happens in three steps, all performed by [`Config::load`]:
//!
//! 1. **Parse.** Every table uses `deny_unknown_fields`, so a misspelled key is an error instead
//!    of a silently ignored setting.
//! 2. **Resolve paths.** Relative paths are resolved against the directory that contains the
//!    config file, so the result does not depend on the working directory of the process.
//! 3. **Validate.** [`Config::validate`] checks values that the type system cannot express
//!    (loopback-only bind address, the shape of `base_url`, non-zero intervals, ...) and reports
//!    every problem at once.

use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de::Error as _};
use url::Url;

use crate::error::{ConfigError, ValidationIssue};

/// Default listen address. Loopback only: a reverse proxy terminates HTTPS in front of us.
pub const DEFAULT_BIND: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 16102);

/// Default address of the relay's plain-HTTP listener, next to [`DEFAULT_BIND`]. Loopback only:
/// the reverse proxy terminates HTTPS for the relay's host name.
pub const DEFAULT_RELAY_BIND: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 16103);

/// Default address of the S3 API's plain-HTTP listener, next to [`DEFAULT_RELAY_BIND`].
/// Loopback only: the reverse proxy terminates HTTPS for the S3 host name.
pub const DEFAULT_S3_BIND: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 16104);

/// Default of `s3.multipart_ttl_secs`: a week.
pub const DEFAULT_MULTIPART_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// UDP port of QUIC address discovery that iroh devices use unless told otherwise.
pub const DEFAULT_QAD_PORT: u16 = 7842;

/// Root of the configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[server]`: listener and public origin.
    pub server: ServerConfig,
    /// `[storage]`: where user files live.
    pub storage: StorageConfig,
    /// `[db]`: the SQLite metadata database.
    pub db: DbConfig,
    /// `[webdav]`: WebDAV protocol limits.
    #[serde(default)]
    pub webdav: WebdavConfig,
    /// `[logging]`: log level and destination.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// `[notify_push]`: real-time change notifications.
    #[serde(default)]
    pub notify_push: NotifyPushConfig,
    /// `[admin]`: the web admin UI.
    #[serde(default)]
    pub admin: AdminConfig,
    /// `[files_ui]`: the web file UI.
    #[serde(default)]
    pub files_ui: FilesUiConfig,
    /// `[relay]`: the relay through which devices reach each other.
    #[serde(default)]
    pub relay: RelayConfig,
    /// `[s3]`: the S3-compatible API.
    #[serde(default)]
    pub s3: S3Config,
    /// `[two_factor]`: two-step verification of web sign-ins.
    #[serde(default)]
    pub two_factor: TwoFactorConfig,
}

/// `[server]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address of the plain-HTTP listener, `IP:port`.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,

    /// Allows `bind` to be a non-loopback address, for example inside a container where the
    /// reverse proxy runs in another network namespace.
    #[serde(default)]
    pub allow_non_loopback_bind: bool,

    /// Public origin of the server as clients see it, for example `https://cloud.example.com`.
    ///
    /// Used to build absolute URLs (Login Flow v2, capabilities, `Location` headers). It is
    /// never inferred from request headers.
    pub base_url: Url,

    /// Reverse proxies whose forwarding headers (`X-Forwarded-For`, `Forwarded`) are trusted.
    ///
    /// Each entry is an IP address or a CIDR block. Requests from any other peer are attributed
    /// to the peer address and their forwarding headers are ignored.
    #[serde(default, deserialize_with = "deserialize_networks")]
    pub trusted_proxies: Vec<IpNet>,
}

/// `[storage]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Directory that holds user files. It belongs to the server; changes made behind its back
    /// are only picked up by `gono-cloud rescan`.
    pub data_dir: PathBuf,
}

/// `[db]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    /// Path of the SQLite database file.
    pub path: PathBuf,

    /// Upper bound of the connection pool.
    #[serde(default = "default_db_max_connections")]
    pub max_connections: u32,

    /// How long a connection waits for a writer of another process (the CLI) before giving
    /// up, in seconds. The server's own writers queue at the write gate instead
    /// ([`crate::db::begin_immediate`]).
    #[serde(default = "default_db_busy_timeout_secs")]
    pub busy_timeout_secs: u64,
}

/// Highest accepted value of `db.max_connections`. SQLite serializes writers anyway; a large
/// pool only adds contention.
pub const MAX_DB_CONNECTIONS: u32 = 64;

/// `[webdav]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebdavConfig {
    /// Longest lifetime of a WebDAV lock, in seconds. Requests for longer locks, including
    /// `Timeout: Infinite`, are clamped to it, so locks of vanished clients always expire.
    pub max_lock_timeout_secs: u64,
}

impl Default for WebdavConfig {
    fn default() -> Self {
        Self {
            max_lock_timeout_secs: 3600,
        }
    }
}

/// Highest accepted value of `webdav.max_lock_timeout_secs` (one week).
pub const MAX_LOCK_TIMEOUT_SECS: u64 = 7 * 24 * 3600;

/// `[logging]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum level of Gono Cloud's own log events. Dependencies log at `warn` and above.
    pub level: LogLevel,

    /// Log file to append to. When unset, `serve` logs to stdout.
    pub file: Option<PathBuf>,
}

/// Log level accepted by `logging.level`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Normal operational messages.
    #[default]
    Info,
    /// Verbose diagnostics.
    Debug,
    /// Everything.
    Trace,
}

impl LogLevel {
    /// Name as used in `tracing` filter directives.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// `[notify_push]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyPushConfig {
    /// Advertise and serve the notify_push WebSocket endpoint.
    pub enabled: bool,

    /// Interval between WebSocket pings, in seconds. A connection that has sent nothing (not
    /// even the pong) by the next ping is closed, and every ping also re-checks that the
    /// connection's app password is still valid.
    pub ping_interval_secs: u64,

    /// Time a freshly opened WebSocket has to authenticate, in seconds.
    pub auth_timeout_secs: u64,

    /// Lifetime of a pre-auth token handed out by the pre-auth endpoint, in seconds.
    pub pre_auth_ttl_secs: u64,

    /// Debounce interval of change notifications, in seconds: two notifications of the same
    /// kind on one connection are at least this far apart, every change in between is merged
    /// into the next one, and no change waits longer than this before it is announced.
    pub debounce_secs: u64,

    /// Maximum number of concurrent WebSocket connections per user.
    pub max_connections_per_user: u32,
}

impl Default for NotifyPushConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ping_interval_secs: 30,
            auth_timeout_secs: 15,
            pre_auth_ttl_secs: 15,
            debounce_secs: 5,
            max_connections_per_user: 64,
        }
    }
}

/// `[admin]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Serve the web admin UI. Admins sign in with their web login password; app passwords
    /// cannot access it.
    pub enabled: bool,

    /// URL path of the admin UI, for example `/apps/manage`.
    pub path: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: DEFAULT_ADMIN_PATH.to_owned(),
        }
    }
}

/// `[files_ui]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesUiConfig {
    /// Serve the web file UI at `/apps/files/`, with the sign-in page at `/login` and the
    /// account page at `/apps/account/`. Users sign in with their web login password; app
    /// passwords cannot access it.
    pub enabled: bool,
}

impl Default for FilesUiConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// `[two_factor]` table: two-step verification (TOTP) of web sign-ins.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TwoFactorConfig {
    /// The key the TOTP secrets are encrypted with: 32 random bytes (or 64 hex digits) in a file
    /// outside the database directory, readable by the service. Relative paths are resolved
    /// against the configuration file's directory. `init` and the install script create it.
    pub key_file: PathBuf,
    /// The configuration file's directory, where the key belongs, once
    /// [`Config::resolve_relative_paths`] has run.
    #[serde(skip)]
    config_dir: Option<PathBuf>,
}

impl Default for TwoFactorConfig {
    fn default() -> Self {
        Self {
            key_file: crate::two_factor::default_key_file(),
            config_dir: None,
        }
    }
}

/// `[relay]` table: the iroh relay through which devices (Input Show and later products) reach
/// each other across the internet when they cannot connect directly. It forwards end-to-end
/// encrypted packets only and never sees their content.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayConfig {
    /// Run the relay: `serve` runs it next to the HTTP server, `gono-cloud relay` runs it alone.
    pub enabled: bool,

    /// Public URL of the relay as devices see it, for example `https://relay.example.com`.
    ///
    /// The relay needs a host name of its own: it cannot run below a path, so it cannot share
    /// `server.base_url`. Required when the relay is enabled.
    pub public_url: Option<Url>,

    /// Socket address of the relay's plain-HTTP listener. The reverse proxy terminates TLS for
    /// `public_url` and forwards the relay's WebSocket (`/relay`) and its probes (`/ping`,
    /// `/generate_204`) to it. Loopback only unless `server.allow_non_loopback_bind`.
    pub bind: SocketAddr,

    /// Public UDP socket of QUIC address discovery (QAD), through which devices learn their
    /// public address, for example `[::]:7842`. Needs `tls_cert` and `tls_key`. Off when unset.
    pub qad_bind: Option<SocketAddr>,

    /// PEM certificate chain for the host of `public_url`, used by QAD.
    pub tls_cert: Option<PathBuf>,

    /// PEM private key of `tls_cert`.
    pub tls_key: Option<PathBuf>,

    /// Interval at which `tls_cert` and `tls_key` are read again, in seconds, so that a renewed
    /// certificate takes effect without a restart.
    pub tls_reload_interval_secs: u64,

    /// Devices that may use the relay, by device id (the iroh endpoint id): 64 hex digits each.
    /// Every other device is refused.
    pub allowed_endpoints: Vec<String>,

    /// Most bytes per second the relay reads from one device connection. Unlimited when unset.
    pub max_client_bytes_per_sec: Option<u32>,

    /// Largest burst the relay reads from one device connection at once, in bytes. Needs
    /// `max_client_bytes_per_sec`.
    pub max_client_burst_bytes: Option<u32>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            public_url: None,
            bind: DEFAULT_RELAY_BIND,
            qad_bind: None,
            tls_cert: None,
            tls_key: None,
            tls_reload_interval_secs: 3600,
            allowed_endpoints: Vec::new(),
            max_client_bytes_per_sec: None,
            max_client_burst_bytes: None,
        }
    }
}

/// `[s3]` table: the S3-compatible API. Buckets are folders of their owners' trees, so files
/// uploaded through S3 are WebDAV files as well.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct S3Config {
    /// Serve the S3 API.
    pub enabled: bool,

    /// Public URL of the S3 API, for example `https://s3.example.com`.
    ///
    /// It needs a host name of its own: S3 clients address buckets right below the root, and
    /// objects published for anonymous download must never run as part of the site's origin.
    /// Required when the S3 API is enabled.
    pub public_url: Option<Url>,

    /// Socket address of the S3 API's plain-HTTP listener. Loopback only unless
    /// `server.allow_non_loopback_bind`.
    pub bind: SocketAddr,

    /// The region clients sign their requests for. Most clients default to `us-east-1`.
    pub region: String,

    /// The folder, in each user's tree, that holds the buckets created through the S3 API: one
    /// path segment.
    pub bucket_folder: String,

    /// Whether bucket owners may allow anonymous downloads and listings. While false, every
    /// bucket answers as private, whatever its stored settings.
    pub allow_anonymous: bool,

    /// Multipart uploads that are neither completed nor aborted within this many seconds are
    /// removed.
    pub multipart_ttl_secs: u64,

    /// The domain below which buckets are addressed by host name (virtual-hosted style):
    /// `<bucket>.<domain>`, for example `photos.s3.example.com` for `s3.example.com`. Needs
    /// wildcard DNS and a wildcard certificate for `*.<domain>`. Path style keeps working.
    /// `None` (the default): path style only.
    pub virtual_host_domain: Option<String>,

    /// The domain below which buckets with a website configuration are served as static
    /// websites, `<bucket>.<domain>`, to anonymous `GET` and `HEAD` requests. A domain of its
    /// own (as S3's website endpoints): wildcard DNS and certificate for `*.<domain>`,
    /// forwarded to `bind`. `None` (the default): no websites.
    pub website_domain: Option<String>,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            public_url: None,
            bind: DEFAULT_S3_BIND,
            region: "us-east-1".to_owned(),
            bucket_folder: "Buckets".to_owned(),
            allow_anonymous: false,
            multipart_ttl_secs: DEFAULT_MULTIPART_TTL_SECS,
            virtual_host_domain: None,
            website_domain: None,
        }
    }
}

/// Whether `domain` is a DNS name in lowercase: labels of 1 to 63 letters, digits and `-`, not
/// starting or ending with `-`, at most 253 characters, no trailing dot, not an IP address.
fn is_domain(domain: &str) -> bool {
    (1..=253).contains(&domain.len())
        && domain.parse::<IpAddr>().is_err()
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // A name of digits and dots only is an IPv4 address in some notation.
        && !domain.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// Whether `host` lies strictly below `domain` (`a.example.com` below `example.com`).
fn is_below(host: &str, domain: &str) -> bool {
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// Whether `region` is an AWS-style region name: lowercase letters, digits and `-`, starting
/// with a letter, at most 63 characters.
fn is_region(region: &str) -> bool {
    (1..=63).contains(&region.len())
        && region.starts_with(|c: char| c.is_ascii_lowercase())
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `id` is a device id as the relay expects it: 64 hex digits, the 32 bytes of an
/// Ed25519 public key.
pub fn is_endpoint_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Default of `admin.path`, next to the web file UI (`/apps/files/`) and the account page
/// (`/apps/account/`).
pub const DEFAULT_ADMIN_PATH: &str = "/apps/manage";

/// First path segments the server uses itself; `admin.path` must not start with one of them,
/// except that it may be [`DEFAULT_ADMIN_PATH`].
const RESERVED_SEGMENTS: &[&str] = &[
    "204",
    "apps",
    "healthz",
    "index.php",
    "login",
    "ocs",
    "push",
    "remote.php",
    "status.php",
];

/// `admin.path` is `/` followed by one or more segments of unreserved URL characters, without a
/// trailing slash, and outside the paths the server serves itself. The default lies below
/// `/apps`, which is otherwise reserved: the server serves nothing else under `/apps/manage`.
fn check_admin_path(path: &str) -> Result<(), String> {
    if path == DEFAULT_ADMIN_PATH {
        return Ok(());
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err("must start with '/'".to_owned());
    };
    if rest.is_empty() || rest.ends_with('/') {
        return Err("must name a path below '/' without a trailing slash".to_owned());
    }
    for segment in rest.split('/') {
        let valid = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        if !valid {
            return Err(format!(
                "segment {segment:?} must consist of letters, digits, '-', '.', '_' and '~'"
            ));
        }
    }
    let first = rest.split('/').next().unwrap_or_default();
    if RESERVED_SEGMENTS
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(first))
    {
        return Err(format!("/{first} is used by the server itself"));
    }
    Ok(())
}

const fn default_bind() -> SocketAddr {
    DEFAULT_BIND
}

const fn default_db_max_connections() -> u32 {
    8
}

const fn default_db_busy_timeout_secs() -> u64 {
    5
}

/// Accepts both bare IP addresses (`"10.0.0.1"`, treated as a single host) and CIDR blocks
/// (`"10.0.0.0/8"`).
fn deserialize_networks<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<IpNet>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|entry| parse_network(entry).map_err(D::Error::custom))
        .collect()
}

/// Parses an IP address or CIDR block. A bare address becomes a host-sized network (`/32` or
/// `/128`).
pub fn parse_network(entry: &str) -> Result<IpNet, String> {
    let entry = entry.trim();
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    entry
        .parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| format!("{entry:?} is neither an IP address nor a CIDR block"))
}

impl Config {
    /// Reads, parses and validates the config file at `path`.
    ///
    /// Relative paths inside the file are resolved against the directory containing it.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let read_error = |source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        };
        let raw = fs::read_to_string(path).map_err(read_error)?;
        let mut config = Self::from_toml(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;

        let absolute = std::path::absolute(path).map_err(read_error)?;
        if let Some(base_dir) = absolute.parent() {
            config.resolve_relative_paths(base_dir);
        }

        config.validate()?;
        Ok(config)
    }

    /// Parses a config document without resolving paths or validating values.
    ///
    /// Prefer [`Config::load`]; this exists for tests and tooling.
    pub fn from_toml(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }

    /// Makes every relative path absolute by joining it onto `base_dir`.
    ///
    /// Empty paths are left alone so that [`Config::validate`] can reject them.
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        let resolve = |path: &mut PathBuf| {
            if !path.as_os_str().is_empty() && path.is_relative() {
                *path = base_dir.join(&*path);
            }
        };
        resolve(&mut self.storage.data_dir);
        resolve(&mut self.db.path);
        resolve(&mut self.two_factor.key_file);
        self.two_factor.config_dir = Some(base_dir.to_path_buf());
        for file in [
            self.logging.file.as_mut(),
            self.relay.tls_cert.as_mut(),
            self.relay.tls_key.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            resolve(file);
        }
    }

    /// Checks every value that parsing alone cannot guarantee.
    ///
    /// All problems are collected and returned together in [`ConfigError::Invalid`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut issues = Vec::new();
        let mut reject = |key: &'static str, message: String| {
            issues.push(ValidationIssue { key, message });
        };

        // [server]
        let server = &self.server;
        if !server.bind.ip().is_loopback() && !server.allow_non_loopback_bind {
            reject(
                "server.bind",
                format!(
                    "{} is not a loopback address; Gono Cloud serves plain HTTP and expects a \
                     reverse proxy in front of it. Bind to 127.0.0.1 or ::1, or set \
                     server.allow_non_loopback_bind = true if the proxy cannot reach loopback",
                    server.bind.ip()
                ),
            );
        }
        if let Err(message) = check_base_url(&server.base_url) {
            reject("server.base_url", message);
        }
        for net in &server.trusted_proxies {
            if *net != net.trunc() {
                reject(
                    "server.trusted_proxies",
                    format!("{net} has host bits set; did you mean {}?", net.trunc()),
                );
            }
        }

        // [storage]
        if self.storage.data_dir.as_os_str().is_empty() {
            reject("storage.data_dir", "must not be empty".to_owned());
        }

        // [db]
        if self.db.path.as_os_str().is_empty() {
            reject("db.path", "must not be empty".to_owned());
        }
        if !(1..=MAX_DB_CONNECTIONS).contains(&self.db.max_connections) {
            reject(
                "db.max_connections",
                format!("must be between 1 and {MAX_DB_CONNECTIONS}"),
            );
        }
        if self.db.busy_timeout_secs == 0 {
            reject("db.busy_timeout_secs", "must be greater than 0".to_owned());
        }

        // [webdav]
        if !(1..=MAX_LOCK_TIMEOUT_SECS).contains(&self.webdav.max_lock_timeout_secs) {
            reject(
                "webdav.max_lock_timeout_secs",
                format!("must be between 1 and {MAX_LOCK_TIMEOUT_SECS} (one week)"),
            );
        }

        // [logging]
        if self
            .logging
            .file
            .as_ref()
            .is_some_and(|file| file.as_os_str().is_empty())
        {
            reject(
                "logging.file",
                "must not be empty; remove the key to log to stdout".to_owned(),
            );
        }

        // [notify_push]
        let push = &self.notify_push;
        for (key, value) in [
            ("notify_push.ping_interval_secs", push.ping_interval_secs),
            ("notify_push.auth_timeout_secs", push.auth_timeout_secs),
            ("notify_push.pre_auth_ttl_secs", push.pre_auth_ttl_secs),
            ("notify_push.debounce_secs", push.debounce_secs),
            (
                "notify_push.max_connections_per_user",
                u64::from(push.max_connections_per_user),
            ),
        ] {
            if value == 0 {
                reject(key, "must be greater than 0".to_owned());
            }
        }

        // [admin]
        if let Err(message) = check_admin_path(&self.admin.path) {
            reject("admin.path", message);
        }

        // [relay]
        self.validate_relay(&mut reject);

        // [s3]
        self.validate_s3(&mut reject);

        if issues.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(issues))
        }
    }

    /// Checks the `[relay]` table. Values that are set are always checked, so that a mistake
    /// shows before the relay is switched on; what the relay needs to run is only required once
    /// it is enabled.
    fn validate_relay(&self, reject: &mut impl FnMut(&'static str, String)) {
        let relay = &self.relay;
        match &relay.public_url {
            Some(url) => {
                if let Err(message) = check_base_url(url) {
                    reject("relay.public_url", message);
                } else if url.origin() == self.server.base_url.origin() {
                    reject(
                        "relay.public_url",
                        "must differ from server.base_url: the relay cannot run below a path, so \
                         it needs a host name of its own, for example https://relay.example.com"
                            .to_owned(),
                    );
                }
            }
            None if relay.enabled => {
                reject(
                    "relay.public_url",
                    "is required when the relay is enabled".to_owned(),
                );
            }
            None => {}
        }
        if relay.enabled {
            if !relay.bind.ip().is_loopback() && !self.server.allow_non_loopback_bind {
                reject(
                    "relay.bind",
                    format!(
                        "{} is not a loopback address; the relay serves plain HTTP behind the \
                         reverse proxy. Bind to 127.0.0.1 or ::1, or set \
                         server.allow_non_loopback_bind = true if the proxy cannot reach \
                         loopback",
                        relay.bind.ip()
                    ),
                );
            }
            if relay.bind == self.server.bind {
                reject("relay.bind", "must differ from server.bind".to_owned());
            }
        }

        for (key, path) in [
            ("relay.tls_cert", relay.tls_cert.as_ref()),
            ("relay.tls_key", relay.tls_key.as_ref()),
        ] {
            match (path, relay.qad_bind) {
                (Some(path), _) if path.as_os_str().is_empty() => {
                    reject(key, "must not be empty".to_owned());
                }
                (Some(_), None) => reject(
                    key,
                    "is only used by QUIC address discovery; set relay.qad_bind too, or remove it"
                        .to_owned(),
                ),
                (None, Some(_)) => reject(key, "is required with relay.qad_bind".to_owned()),
                _ => {}
            }
        }
        if relay.tls_reload_interval_secs == 0 {
            reject(
                "relay.tls_reload_interval_secs",
                "must be greater than 0".to_owned(),
            );
        }

        for id in &relay.allowed_endpoints {
            if !is_endpoint_id(id) {
                reject(
                    "relay.allowed_endpoints",
                    format!("{id:?} is not a device id: expected 64 hex digits"),
                );
            }
        }

        for (key, value) in [
            (
                "relay.max_client_bytes_per_sec",
                relay.max_client_bytes_per_sec,
            ),
            ("relay.max_client_burst_bytes", relay.max_client_burst_bytes),
        ] {
            if value == Some(0) {
                reject(
                    key,
                    "must be greater than 0; remove it for no limit".to_owned(),
                );
            }
        }
        if relay.max_client_burst_bytes.is_some() && relay.max_client_bytes_per_sec.is_none() {
            reject(
                "relay.max_client_burst_bytes",
                "needs relay.max_client_bytes_per_sec".to_owned(),
            );
        }
    }

    /// Checks the `[s3]` table. Values that are set are always checked; what the S3 API needs
    /// to run is only required once it is enabled.
    fn validate_s3(&self, reject: &mut impl FnMut(&'static str, String)) {
        let s3 = &self.s3;
        match &s3.public_url {
            Some(url) => {
                let host = url.host_str();
                if let Err(message) = check_base_url(url) {
                    reject("s3.public_url", message);
                } else if host == self.server.base_url.host_str() {
                    reject(
                        "s3.public_url",
                        "must have a host name other than server.base_url's, for example \
                         https://s3.example.com: S3 clients address buckets right below the root, \
                         and files published for anonymous download must never share the \
                         site's host"
                            .to_owned(),
                    );
                } else if self
                    .relay
                    .public_url
                    .as_ref()
                    .is_some_and(|relay| relay.host_str() == host)
                {
                    reject(
                        "s3.public_url",
                        "must have a host name other than relay.public_url's".to_owned(),
                    );
                }
            }
            None if s3.enabled => {
                reject(
                    "s3.public_url",
                    "is required when the S3 API is enabled".to_owned(),
                );
            }
            None => {}
        }
        if s3.enabled {
            if !s3.bind.ip().is_loopback() && !self.server.allow_non_loopback_bind {
                reject(
                    "s3.bind",
                    format!(
                        "{} is not a loopback address; the S3 API serves plain HTTP behind the \
                         reverse proxy. Bind to 127.0.0.1 or ::1, or set \
                         server.allow_non_loopback_bind = true if the proxy cannot reach \
                         loopback",
                        s3.bind.ip()
                    ),
                );
            }
            if s3.bind == self.server.bind || (self.relay.enabled && s3.bind == self.relay.bind) {
                reject(
                    "s3.bind",
                    "must differ from server.bind and relay.bind".to_owned(),
                );
            }
        }
        if !is_region(&s3.region) {
            reject(
                "s3.region",
                format!(
                    "{:?} is not a region name: lowercase letters, digits and '-', starting \
                     with a letter",
                    s3.region
                ),
            );
        }
        if crate::path::normalize_segment(s3.bucket_folder.as_bytes())
            .ok()
            .as_deref()
            != Some(s3.bucket_folder.as_str())
        {
            reject(
                "s3.bucket_folder",
                format!(
                    "{:?} is not a folder name: one path segment in Unicode NFC, without '/'",
                    s3.bucket_folder
                ),
            );
        }
        if s3.multipart_ttl_secs == 0 {
            reject("s3.multipart_ttl_secs", "must be greater than 0".to_owned());
        }
        if let Some(domain) = &s3.virtual_host_domain {
            self.validate_virtual_host_domain(domain, reject);
        }
        if let Some(domain) = &s3.website_domain {
            self.validate_website_domain(domain, reject);
        }
    }

    /// Checks `s3.website_domain`: a DNS name of its own, below which no other host of this
    /// server lies and which is neither the virtual-hosted domain nor below or above it.
    fn validate_website_domain(&self, domain: &str, reject: &mut impl FnMut(&'static str, String)) {
        if !is_domain(domain) {
            reject(
                "s3.website_domain",
                format!(
                    "{domain:?} is not a domain name: lowercase letters, digits, '-' and '.', \
                     without a scheme, a port or a trailing dot, for example \"web.example.com\""
                ),
            );
            return;
        }
        let site = self.server.base_url.host_str();
        let relay = self.relay.public_url.as_ref().and_then(Url::host_str);
        let s3 = self.s3.public_url.as_ref().and_then(Url::host_str);
        for (name, host) in [
            ("server.base_url", site),
            ("relay.public_url", relay),
            ("s3.public_url", s3),
        ] {
            if let Some(host) = host
                && (host.eq_ignore_ascii_case(domain)
                    || is_below(&host.to_ascii_lowercase(), domain))
            {
                reject(
                    "s3.website_domain",
                    format!(
                        "{name}'s host {host} is or lies below {domain}; websites need a domain \
                         of their own, such as web.example.com"
                    ),
                );
            }
        }
        if let Some(virtual_hosts) = &self.s3.virtual_host_domain
            && (virtual_hosts == domain
                || is_below(domain, virtual_hosts)
                || is_below(virtual_hosts, domain))
        {
            reject(
                "s3.website_domain",
                format!(
                    "{domain} and s3.virtual_host_domain {virtual_hosts} would name the same \
                     hosts; use a domain apart from it"
                ),
            );
        }
    }

    /// Checks `s3.virtual_host_domain`: a DNS name below which no other host of this server
    /// lies, since such a host would read as a bucket name.
    fn validate_virtual_host_domain(
        &self,
        domain: &str,
        reject: &mut impl FnMut(&'static str, String),
    ) {
        if !is_domain(domain) {
            reject(
                "s3.virtual_host_domain",
                format!(
                    "{domain:?} is not a domain name: lowercase letters, digits, '-' and '.', \
                     without a scheme, a port or a trailing dot, for example \"s3.example.com\""
                ),
            );
            return;
        }
        let site = self.server.base_url.host_str();
        let relay = self.relay.public_url.as_ref().and_then(Url::host_str);
        for (name, host) in [("server.base_url", site), ("relay.public_url", relay)] {
            if let Some(host) = host
                && (host.eq_ignore_ascii_case(domain)
                    || is_below(&host.to_ascii_lowercase(), domain))
            {
                reject(
                    "s3.virtual_host_domain",
                    format!(
                        "{name}'s host {host} is or lies below {domain}; it would read as a \
                         bucket name. Use a domain of its own, such as s3.example.com"
                    ),
                );
            }
        }
        if let Some(host) = self.s3.public_url.as_ref().and_then(Url::host_str)
            && is_below(&host.to_ascii_lowercase(), domain)
        {
            reject(
                "s3.virtual_host_domain",
                format!(
                    "s3.public_url's host {host} lies below {domain}, so path-style requests \
                     would read as requests to a bucket; use {host} itself or a domain that \
                     does not contain it"
                ),
            );
        }
    }

    /// Settings that are valid but probably not what the operator wants in production.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let key = &self.two_factor.key_file;
        if !self.storage.data_dir.as_os_str().is_empty() && key.starts_with(&self.storage.data_dir)
        {
            warnings.push(format!(
                "two_factor.key_file {} lies in the data directory: a copy of it would give the \
                 second factor of every account away; keep it in the configuration directory",
                key.display()
            ));
        } else if let Some(db_dir) = self.db.path.parent().filter(|dir| {
            // A database kept in the configuration directory itself (as in the example
            // configuration) shares it with the key by design: that directory is backed up
            // as the configuration, which the key belongs to.
            !dir.as_os_str().is_empty() && self.two_factor.config_dir.as_deref() != Some(*dir)
        }) && key.starts_with(db_dir)
        {
            warnings.push(format!(
                "two_factor.key_file {} lies in the directory of the database: a copy of that \
                 directory would give the second factor of every account away; keep the key in \
                 the configuration directory",
                key.display()
            ));
        }
        let url = &self.server.base_url;
        if url.scheme() == "http" && !is_local_host(url) {
            warnings.push(format!(
                "server.base_url {url} uses plain http; passwords and app passwords will cross \
                 the network unencrypted"
            ));
        }
        if !self.server.bind.ip().is_loopback() {
            warnings.push(format!(
                "server.bind {} is reachable from outside this host; make sure only the reverse \
                 proxy can connect to it",
                self.server.bind
            ));
        }

        let relay = &self.relay;
        if relay.enabled {
            // An empty relay.allowed_endpoints is normal: `serve` admits the devices registered
            // for remote access. `gono-cloud relay` on a host of its own warns about it.
            if relay.qad_bind.is_none() {
                warnings.push(
                    "relay.qad_bind is not set: devices cannot learn their public address from \
                     the relay (QUIC address discovery), so fewer of them connect directly"
                        .to_owned(),
                );
            }
            if let Some(url) = relay
                .public_url
                .as_ref()
                .filter(|url| url.scheme() == "http" && !is_local_host(url))
            {
                warnings.push(format!(
                    "relay.public_url {url} uses plain http; device ids and traffic metadata \
                     cross the network unencrypted"
                ));
            }
            if !relay.bind.ip().is_loopback() {
                warnings.push(format!(
                    "relay.bind {} is reachable from outside this host; make sure only the \
                     reverse proxy can connect to it",
                    relay.bind
                ));
            }
        }
        warnings
    }
}

/// `base_url` must be a bare origin: `http(s)://host[:port]` with an optional trailing slash.
fn check_base_url(url: &Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme must be http or https, got {:?}",
            url.scheme()
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("must include a host".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials".to_owned());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not contain a query string or fragment".to_owned());
    }
    if url.path() != "/" {
        return Err(format!(
            "must not contain a path (got {:?}); serving under a sub-path is not supported",
            url.path()
        ));
    }
    Ok(())
}

fn is_local_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [server]
        base_url = "https://cloud.example.com"

        [storage]
        data_dir = "data"

        [db]
        path = "gono-cloud.db"
    "#;

    fn parse(raw: &str) -> Config {
        Config::from_toml(raw).expect("config should parse")
    }

    /// Parses `MINIMAL` with `extra` appended to the `[server]` table.
    fn with_server(extra: &str) -> Config {
        parse(&MINIMAL.replace("[server]\n", &format!("[server]\n{extra}\n")))
    }

    fn issue_keys(config: &Config) -> Vec<&'static str> {
        match config.validate() {
            Ok(()) => Vec::new(),
            Err(ConfigError::Invalid(issues)) => issues.into_iter().map(|i| i.key).collect(),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let config = parse(MINIMAL);
        config.validate().expect("minimal config should be valid");

        assert_eq!(config.server.bind, "127.0.0.1:16102".parse().unwrap());
        assert!(!config.server.allow_non_loopback_bind);
        assert!(config.server.trusted_proxies.is_empty());
        assert_eq!(config.db.max_connections, 8);
        assert_eq!(config.db.busy_timeout_secs, 5);
        assert_eq!(config.webdav.max_lock_timeout_secs, 3600);
        assert_eq!(config.logging.level, LogLevel::Info);
        assert_eq!(config.logging.file, None, "logs go to stdout by default");
        assert!(config.notify_push.enabled);
        assert!(config.admin.enabled);
        assert!(config.files_ui.enabled);
        assert_eq!(config.admin.path, "/apps/manage");
        assert!(config.warnings().is_empty());
    }

    #[test]
    fn required_keys_are_required() {
        for (table, key) in [
            ("server", "base_url"),
            ("storage", "data_dir"),
            ("db", "path"),
        ] {
            let raw: String = MINIMAL
                .lines()
                .filter(|line| !line.trim_start().starts_with(key))
                .collect::<Vec<_>>()
                .join("\n");
            let err = Config::from_toml(&raw).expect_err(key).to_string();
            assert!(err.contains(key), "[{table}] {key}: {err}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for raw in [
            format!("{MINIMAL}\nunknown = 1"),
            MINIMAL.replace("[server]\n", "[server]\nbase_ulr = \"x\"\n"),
            format!("{MINIMAL}\n[logging]\nloglevel = \"info\""),
            format!("{MINIMAL}\n[notify_push]\npath = \"/push\""),
            format!("{MINIMAL}\n[sync]\nretention_days = 30"),
        ] {
            let err = Config::from_toml(&raw).expect_err(&raw).to_string();
            assert!(err.contains("unknown"), "{err}");
        }
    }

    #[test]
    fn bind_must_be_loopback_unless_allowed() {
        let public = MINIMAL.replace("[server]\n", "[server]\nbind = \"0.0.0.0:16102\"\n");
        assert_eq!(issue_keys(&parse(&public)), ["server.bind"]);

        let allowed = public.replace("[server]\n", "[server]\nallow_non_loopback_bind = true\n");
        let config = parse(&allowed);
        assert!(issue_keys(&config).is_empty());
        assert_eq!(config.warnings().len(), 1);

        for loopback in ["127.0.0.1:8080", "[::1]:8080", "127.0.0.2:0"] {
            let config = with_server(&format!("bind = \"{loopback}\""));
            assert!(issue_keys(&config).is_empty(), "{loopback}");
        }
    }

    #[test]
    fn bind_must_be_a_socket_address() {
        for bind in ["localhost:16102", "127.0.0.1", "16102"] {
            let raw = MINIMAL.replace("[server]\n", &format!("[server]\nbind = \"{bind}\"\n"));
            assert!(Config::from_toml(&raw).is_err(), "{bind}");
        }
    }

    #[test]
    fn base_url_must_be_a_bare_http_origin() {
        for good in [
            "https://cloud.example.com",
            "https://cloud.example.com/",
            "https://cloud.example.com:8443",
            "http://127.0.0.1:16102",
            "http://[::1]:16102",
        ] {
            let config = parse(&MINIMAL.replace("https://cloud.example.com", good));
            assert!(issue_keys(&config).is_empty(), "{good}");
        }

        for bad in [
            "ftp://cloud.example.com",
            "https://cloud.example.com/nextcloud",
            "https://cloud.example.com/?a=b",
            "https://cloud.example.com/#top",
            "https://user:secret@cloud.example.com",
            "file:///srv/cloud",
        ] {
            let config = parse(&MINIMAL.replace("https://cloud.example.com", bad));
            assert_eq!(issue_keys(&config), ["server.base_url"], "{bad}");
        }

        for unparsable in ["cloud.example.com", "", "https://"] {
            let raw = MINIMAL.replace("https://cloud.example.com", unparsable);
            assert!(Config::from_toml(&raw).is_err(), "{unparsable:?}");
        }
    }

    #[test]
    fn plain_http_on_a_public_host_warns() {
        let config = parse(&MINIMAL.replace("https://", "http://"));
        assert!(issue_keys(&config).is_empty());
        assert_eq!(config.warnings().len(), 1);

        let local = parse(&MINIMAL.replace("https://cloud.example.com", "http://localhost:16102"));
        assert!(local.warnings().is_empty());
    }

    #[test]
    fn trusted_proxies_accept_addresses_and_cidr_blocks() {
        let config =
            with_server(r#"trusted_proxies = ["127.0.0.1", "::1", "10.0.0.0/8", "fd00::/8"]"#);
        assert!(issue_keys(&config).is_empty());
        let proxies: Vec<String> = config
            .server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            proxies,
            ["127.0.0.1/32", "::1/128", "10.0.0.0/8", "fd00::/8"]
        );
    }

    #[test]
    fn trusted_proxies_reject_garbage() {
        for bad in ["proxy.local", "10.0.0.0/33", "300.1.1.1", "10.0.0.0/"] {
            let raw = MINIMAL.replace(
                "[server]\n",
                &format!("[server]\ntrusted_proxies = [\"{bad}\"]\n"),
            );
            let err = Config::from_toml(&raw).expect_err(bad).to_string();
            assert!(err.contains("trusted_proxies"), "{bad}: {err}");
        }
    }

    #[test]
    fn trusted_proxies_reject_host_bits() {
        let config = with_server(r#"trusted_proxies = ["10.1.2.3/8"]"#);
        match config.validate() {
            Err(ConfigError::Invalid(issues)) => {
                assert_eq!(issues.len(), 1);
                assert_eq!(issues[0].key, "server.trusted_proxies");
                assert!(issues[0].message.contains("10.0.0.0/8"));
            }
            other => panic!("expected an invalid config, got {other:?}"),
        }
    }

    #[test]
    fn intervals_must_be_positive() {
        let raw = format!(
            "{MINIMAL}
            [notify_push]
            ping_interval_secs = 0
            auth_timeout_secs = 0
            pre_auth_ttl_secs = 0
            debounce_secs = 0
            max_connections_per_user = 0
            "
        )
        .replace(
            "path = \"gono-cloud.db\"",
            "path = \"gono-cloud.db\"\nbusy_timeout_secs = 0",
        );
        assert_eq!(
            issue_keys(&parse(&raw)),
            [
                "db.busy_timeout_secs",
                "notify_push.ping_interval_secs",
                "notify_push.auth_timeout_secs",
                "notify_push.pre_auth_ttl_secs",
                "notify_push.debounce_secs",
                "notify_push.max_connections_per_user",
            ]
        );
    }

    #[test]
    fn negative_intervals_do_not_parse() {
        let raw = format!("{MINIMAL}\n[notify_push]\nping_interval_secs = -1");
        assert!(Config::from_toml(&raw).is_err());
    }

    #[test]
    fn db_pool_size_is_bounded() {
        for (value, ok) in [(0, false), (1, true), (64, true), (65, false)] {
            let raw = MINIMAL.replace(
                "path = \"gono-cloud.db\"",
                &format!("path = \"gono-cloud.db\"\nmax_connections = {value}"),
            );
            assert_eq!(issue_keys(&parse(&raw)).is_empty(), ok, "{value}");
        }
    }

    #[test]
    fn empty_paths_are_rejected() {
        let raw = MINIMAL
            .replace("data_dir = \"data\"", "data_dir = \"\"")
            .replace("path = \"gono-cloud.db\"", "path = \"\"");
        let raw = format!("{raw}\n[logging]\nfile = \"\"");
        let mut config = parse(&raw);
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            issue_keys(&config),
            ["storage.data_dir", "db.path", "logging.file"]
        );
    }

    #[test]
    fn admin_path_is_validated() {
        for good in [
            "/apps/manage",
            "/gono-admin",
            "/admin",
            "/ops/admin",
            "/a.b_c~d",
        ] {
            let raw = format!("{MINIMAL}\n[admin]\npath = \"{good}\"");
            assert!(issue_keys(&parse(&raw)).is_empty(), "{good}");
        }
        for bad in [
            "",
            "/",
            "admin",
            "/admin/",
            "/a//b",
            "/a b",
            "/%2e",
            "/../x",
            "/ocs",
            "/push/x",
            "/remote.php",
            "/Index.php",
            "/login",
            // Only the default itself may lie below /apps.
            "/apps",
            "/apps/files",
            "/apps/assets",
            "/apps/manage/x",
            "/Apps/manage",
        ] {
            let raw = format!("{MINIMAL}\n[admin]\npath = \"{bad}\"");
            assert_eq!(issue_keys(&parse(&raw)), ["admin.path"], "{bad:?}");
        }
    }

    /// A device id: 64 hex digits.
    const DEVICE: &str = "6f6e8a2a5c1d0b9e7f3a4c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f";

    /// A complete `[relay]` table that runs the relay with QUIC address discovery.
    const RELAY: &str = r#"
        enabled = true
        public_url = "https://relay.example.com"
        qad_bind = "[::]:7842"
        tls_cert = "relay-tls/fullchain.pem"
        tls_key = "relay-tls/privkey.pem"
    "#;

    /// `MINIMAL` with a `[relay]` table.
    fn with_relay(table: &str) -> Config {
        parse(&format!("{MINIMAL}\n[relay]\n{table}"))
    }

    /// [`RELAY`] with `extra` keys and the given allowed devices.
    fn complete_relay(extra: &str) -> Config {
        with_relay(&format!(
            "{RELAY}\nallowed_endpoints = [\"{DEVICE}\"]\n{extra}"
        ))
    }

    #[test]
    fn relay_is_off_by_default() {
        let relay = parse(MINIMAL).relay;
        assert!(!relay.enabled);
        assert_eq!(relay.public_url, None);
        assert_eq!(relay.bind, "127.0.0.1:16103".parse().unwrap());
        assert_eq!(relay.qad_bind, None);
        assert_eq!(relay.tls_reload_interval_secs, 3600);
        assert!(relay.allowed_endpoints.is_empty());
        assert_eq!(relay.max_client_bytes_per_sec, None);
    }

    #[test]
    fn complete_relay_is_valid_without_warnings() {
        let config = complete_relay("");
        assert!(issue_keys(&config).is_empty());
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
        assert_eq!(config.relay.qad_bind, Some("[::]:7842".parse().unwrap()));
    }

    #[test]
    fn enabled_relay_needs_a_host_name_of_its_own() {
        assert_eq!(
            issue_keys(&with_relay("enabled = true")),
            ["relay.public_url"]
        );
        for shared in [
            "https://cloud.example.com",
            "https://cloud.example.com:443/",
        ] {
            let config = complete_relay("").relay;
            let mut config = Config {
                relay: RelayConfig {
                    public_url: Some(shared.parse().unwrap()),
                    ..config
                },
                ..parse(MINIMAL)
            };
            assert_eq!(issue_keys(&config), ["relay.public_url"], "{shared}");
            config.relay.public_url = Some("https://cloud.example.com:8443".parse().unwrap());
            assert!(
                issue_keys(&config).is_empty(),
                "another port is another origin"
            );
        }
        for bad in [
            "https://relay.example.com/relay",
            "ftp://relay.example.com",
            "https://user:secret@relay.example.com",
        ] {
            let config = with_relay(&format!("public_url = \"{bad}\""));
            assert_eq!(issue_keys(&config), ["relay.public_url"], "{bad}");
        }
        // A disabled relay needs no URL.
        assert!(issue_keys(&with_relay("enabled = false")).is_empty());
    }

    #[test]
    fn relay_bind_must_be_loopback_unless_allowed() {
        let public = complete_relay("bind = \"0.0.0.0:16103\"");
        assert_eq!(issue_keys(&public), ["relay.bind"]);

        let mut allowed = public;
        allowed.server.allow_non_loopback_bind = true;
        assert!(issue_keys(&allowed).is_empty());
        assert_eq!(allowed.warnings().len(), 1, "{:?}", allowed.warnings());

        let clash = complete_relay("bind = \"127.0.0.1:16102\"");
        assert_eq!(issue_keys(&clash), ["relay.bind"]);
    }

    #[test]
    fn qad_and_its_certificate_come_together() {
        let without_certificate = with_relay("qad_bind = \"[::]:7842\"");
        assert_eq!(
            issue_keys(&without_certificate),
            ["relay.tls_cert", "relay.tls_key"]
        );

        let without_qad = with_relay("tls_cert = \"cert.pem\"\ntls_key = \"key.pem\"");
        assert_eq!(
            issue_keys(&without_qad),
            ["relay.tls_cert", "relay.tls_key"]
        );

        let empty = complete_relay("").relay;
        let config = Config {
            relay: RelayConfig {
                tls_cert: Some(PathBuf::new()),
                tls_reload_interval_secs: 0,
                ..empty
            },
            ..parse(MINIMAL)
        };
        assert_eq!(
            issue_keys(&config),
            ["relay.tls_cert", "relay.tls_reload_interval_secs"]
        );
    }

    #[test]
    fn allowed_endpoints_are_device_ids() {
        let upper = DEVICE.to_ascii_uppercase();
        let config = with_relay(&format!("allowed_endpoints = [\"{DEVICE}\", \"{upper}\"]"));
        assert!(issue_keys(&config).is_empty());

        for bad in [
            DEVICE[1..].to_owned(),
            format!("{DEVICE}0"),
            DEVICE.replace('a', "g"),
            "alice".to_owned(),
            String::new(),
        ] {
            let config = with_relay(&format!("allowed_endpoints = [\"{bad}\"]"));
            assert_eq!(issue_keys(&config), ["relay.allowed_endpoints"], "{bad:?}");
        }
    }

    #[test]
    fn client_rate_limits_are_checked() {
        let ok =
            complete_relay("max_client_bytes_per_sec = 1048576\nmax_client_burst_bytes = 65536");
        assert!(issue_keys(&ok).is_empty());

        let zero = complete_relay("max_client_bytes_per_sec = 0\nmax_client_burst_bytes = 0");
        assert_eq!(
            issue_keys(&zero),
            [
                "relay.max_client_bytes_per_sec",
                "relay.max_client_burst_bytes"
            ]
        );

        let burst_alone = complete_relay("max_client_burst_bytes = 65536");
        assert_eq!(issue_keys(&burst_alone), ["relay.max_client_burst_bytes"]);

        let too_large = format!("{MINIMAL}\n[relay]\nmax_client_bytes_per_sec = 4294967296");
        assert!(Config::from_toml(&too_large).is_err());
    }

    #[test]
    fn enabled_relay_warns_about_what_it_lacks() {
        let bare = with_relay("enabled = true\npublic_url = \"http://relay.example.com\"");
        assert!(issue_keys(&bare).is_empty());
        let warnings = bare.warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("relay.qad_bind"));
        assert!(warnings[1].contains("plain http"));

        // A disabled relay warns about nothing.
        assert!(
            with_relay("public_url = \"http://relay.example.com\"")
                .warnings()
                .is_empty()
        );
    }

    #[test]
    fn the_two_factor_key_lives_next_to_the_config_file() {
        let mut config = parse(MINIMAL);
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            config.two_factor.key_file,
            Path::new("/etc/gono-cloud/two-factor.key")
        );
        assert!(
            config.warnings().iter().all(|w| !w.contains("two_factor")),
            "{:?}",
            config.warnings()
        );
        config.two_factor.key_file = config.storage.data_dir.join("two-factor.key");
        assert!(
            config
                .warnings()
                .iter()
                .any(|w| w.contains("two_factor.key_file"))
        );

        // Next to a database outside the configuration directory: warned about.
        let raw = MINIMAL.replace(
            "path = \"gono-cloud.db\"",
            "path = \"/var/lib/gono-cloud/gono-cloud.db\"",
        );
        let mut config = parse(&raw);
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert!(config.warnings().iter().all(|w| !w.contains("two_factor")));
        config.two_factor.key_file = PathBuf::from("/var/lib/gono-cloud/two-factor.key");
        let warnings = config.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("two_factor.key_file") && w.contains("database")),
            "{warnings:?}"
        );
        // Not when the database lives in the configuration directory, next to the key.
        config.db.path = PathBuf::from("/etc/gono-cloud/gono-cloud.db");
        config.two_factor.key_file = PathBuf::from("/etc/gono-cloud/two-factor.key");
        assert!(config.warnings().iter().all(|w| !w.contains("two_factor")));
    }

    #[test]
    fn relay_certificate_paths_resolve_against_the_config_directory() {
        let mut config = complete_relay("");
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            config.relay.tls_cert.as_deref(),
            Some(Path::new("/etc/gono-cloud/relay-tls/fullchain.pem"))
        );
        assert_eq!(
            config.relay.tls_key.as_deref(),
            Some(Path::new("/etc/gono-cloud/relay-tls/privkey.pem"))
        );
    }

    #[test]
    fn lock_timeout_is_bounded() {
        for (value, ok) in [(0, false), (1, true), (604_800, true), (604_801, false)] {
            let raw = format!("{MINIMAL}\n[webdav]\nmax_lock_timeout_secs = {value}");
            assert_eq!(issue_keys(&parse(&raw)).is_empty(), ok, "{value}");
        }
    }

    #[test]
    fn logging_level_is_restricted() {
        let ok = parse(&format!("{MINIMAL}\n[logging]\nlevel = \"debug\""));
        assert_eq!(ok.logging.level, LogLevel::Debug);

        for bad in ["verbose", "WARN", "warning", "info,sqlx=debug"] {
            let raw = format!("{MINIMAL}\n[logging]\nlevel = \"{bad}\"");
            assert!(Config::from_toml(&raw).is_err(), "{bad}");
        }
    }

    #[test]
    fn relative_paths_resolve_against_the_config_directory() {
        let raw = format!(
            "{}\n[logging]\nfile = \"logs/gono-cloud.log\"",
            MINIMAL.replace(
                "path = \"gono-cloud.db\"",
                "path = \"/var/lib/gono/gono.db\""
            )
        );
        let mut config = parse(&raw);
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));

        assert_eq!(config.storage.data_dir, Path::new("/etc/gono-cloud/data"));
        assert_eq!(config.db.path, Path::new("/var/lib/gono/gono.db"));
        assert_eq!(
            config.logging.file.as_deref(),
            Some(Path::new("/etc/gono-cloud/logs/gono-cloud.log"))
        );
    }

    #[test]
    fn load_reports_all_issues_with_the_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            MINIMAL
                .replace("[server]\n", "[server]\nbind = \"0.0.0.0:1\"\n")
                .replace("https://cloud.example.com", "https://cloud.example.com/sub"),
        )
        .unwrap();

        let err = Config::load(&path).expect_err("config should be rejected");
        let message = err.to_string();
        assert!(message.contains("server.bind"), "{message}");
        assert!(message.contains("server.base_url"), "{message}");
    }

    #[test]
    fn load_resolves_paths_next_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, MINIMAL).unwrap();

        let config = Config::load(&path).expect("config should load");
        let base = std::path::absolute(dir.path()).unwrap();
        assert_eq!(config.storage.data_dir, base.join("data"));
        assert_eq!(config.db.path, base.join("gono-cloud.db"));
    }

    #[test]
    fn load_reports_missing_files() {
        let err = Config::load(Path::new("/nonexistent/gono-cloud/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
    }

    #[test]
    fn example_config_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../config.example.toml");
        let config = Config::load(&path).expect("config.example.toml should be valid");
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
    }

    /// Parses `MINIMAL` with an `[s3]` table holding `body`.
    fn with_s3(body: &str) -> Config {
        parse(&format!("{MINIMAL}\n[s3]\n{body}\n"))
    }

    #[test]
    fn s3_is_off_by_default() {
        let s3 = parse(MINIMAL).s3;
        assert!(!s3.enabled);
        assert_eq!(s3.public_url, None);
        assert_eq!(s3.bind, "127.0.0.1:16104".parse().unwrap());
        assert_eq!(s3.region, "us-east-1");
        assert_eq!(s3.bucket_folder, "Buckets");
        assert!(!s3.allow_anonymous);
        assert_eq!(s3.multipart_ttl_secs, 7 * 24 * 60 * 60);
        assert_eq!(s3.virtual_host_domain, None);
        assert!(issue_keys(&parse(MINIMAL)).is_empty());
    }

    #[test]
    fn website_domains_are_checked() {
        let enabled = "enabled = true\npublic_url = \"https://s3.example.com\"\n\
                       virtual_host_domain = \"s3.example.com\"";
        let website = |value: &str| {
            let mut keys = issue_keys(&with_s3(&format!(
                "{enabled}\nwebsite_domain = \"{value}\""
            )));
            keys.dedup();
            keys
        };
        assert!(website("web.example.org").is_empty());
        for invalid in [
            "https://web.example.org",
            "web.example.org:443",
            "Web.example.org",
        ] {
            assert_eq!(website(invalid), ["s3.website_domain"], "{invalid}");
        }
        // The S3 host, its virtual hosts and the site's host are not websites.
        for clash in ["s3.example.com", "x.s3.example.com", "example.com"] {
            assert_eq!(website(clash), ["s3.website_domain"], "{clash}");
        }
        assert_eq!(parse(MINIMAL).s3.website_domain, None);
    }

    #[test]
    fn virtual_host_domains_are_checked() {
        let enabled = "enabled = true\npublic_url = \"https://s3.example.com\"";
        let domain = |value: &str| {
            let mut keys = issue_keys(&with_s3(&format!(
                "{enabled}\nvirtual_host_domain = \"{value}\""
            )));
            // "example.com" is above both the site's host and the endpoint's.
            keys.dedup();
            keys
        };
        for valid in [
            "s3.example.com",
            "files.example.org",
            "s3.localhost",
            "localhost",
        ] {
            assert!(domain(valid).is_empty(), "{valid}");
        }
        for invalid in [
            "",
            "S3.example.com",
            "s3.example.com.",
            "https://s3.example.com",
            "s3.example.com:9000",
            "s3..example.com",
            "-s3.example.com",
            "s3_example.com",
            "127.0.0.1",
            "1.2",
            "::1",
            // The site's host, or a domain above it: cloud.example.com would read as a bucket.
            "cloud.example.com",
            "example.com",
        ] {
            assert_eq!(domain(invalid), ["s3.virtual_host_domain"], "{invalid}");
        }
        // The endpoint itself below the domain: path-style requests would name a bucket.
        let nested = with_s3(
            "enabled = true\npublic_url = \"https://s3.files.example.org\"\n\
             virtual_host_domain = \"files.example.org\"",
        );
        assert_eq!(issue_keys(&nested), ["s3.virtual_host_domain"]);
        let mut relay = with_s3(&format!("{enabled}\nvirtual_host_domain = \"example.net\""));
        relay.relay.public_url = Some(Url::parse("https://relay.example.net").unwrap());
        assert_eq!(issue_keys(&relay), ["s3.virtual_host_domain"]);
    }

    #[test]
    fn enabled_s3_needs_a_host_name_of_its_own() {
        assert_eq!(issue_keys(&with_s3("enabled = true")), ["s3.public_url"]);
        let valid = with_s3("enabled = true\npublic_url = \"https://s3.example.com\"");
        assert!(issue_keys(&valid).is_empty());
        for shared in [
            "https://cloud.example.com",
            // Another port is another origin, but cookies are shared by host name.
            "https://cloud.example.com:9000",
            "https://s3.example.com/s3",
        ] {
            assert_eq!(
                issue_keys(&with_s3(&format!(
                    "enabled = true\npublic_url = \"{shared}\""
                ))),
                ["s3.public_url"],
                "{shared}"
            );
        }
        let mut relay = with_s3("enabled = true\npublic_url = \"https://relay.example.com\"");
        relay.relay.public_url = Some(Url::parse("https://relay.example.com").unwrap());
        assert_eq!(issue_keys(&relay), ["s3.public_url"]);
    }

    #[test]
    fn s3_values_are_checked() {
        let enabled = "enabled = true\npublic_url = \"https://s3.example.com\"";
        for (extra, key) in [
            ("bind = \"0.0.0.0:16104\"", "s3.bind"),
            ("bind = \"127.0.0.1:16102\"", "s3.bind"),
            ("region = \"US East\"", "s3.region"),
            ("region = \"\"", "s3.region"),
            ("bucket_folder = \"a/b\"", "s3.bucket_folder"),
            ("bucket_folder = \"..\"", "s3.bucket_folder"),
            ("bucket_folder = \"\"", "s3.bucket_folder"),
            ("bucket_folder = \"Cafe\u{0301}\"", "s3.bucket_folder"),
            ("multipart_ttl_secs = 0", "s3.multipart_ttl_secs"),
        ] {
            assert_eq!(
                issue_keys(&with_s3(&format!("{enabled}\n{extra}"))),
                [key],
                "{extra}"
            );
        }
        let mut open = with_s3(&format!("{enabled}\nbind = \"0.0.0.0:16104\""));
        open.server.allow_non_loopback_bind = true;
        assert!(issue_keys(&open).is_empty());
        assert!(
            issue_keys(&with_s3(
                "region = \"eu-central-1\"\nbucket_folder = \"S3\""
            ))
            .is_empty()
        );
    }
}
