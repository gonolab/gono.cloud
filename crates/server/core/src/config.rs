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

use crate::{
    db::Backend,
    error::{ConfigError, ValidationIssue},
};

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
    /// `[db]`: the metadata database (SQLite or MySQL).
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
    /// `[connect]`: remote access of devices (`docs/connect-protocol.md`).
    #[serde(default)]
    pub connect: ConnectConfig,
    /// `[s3]`: the S3-compatible API.
    #[serde(default)]
    pub s3: S3Config,
    /// `[two_factor]`: two-step verification of web sign-ins.
    #[serde(default)]
    pub two_factor: TwoFactorConfig,
    /// `[smtp]`: the mail server that sends the codes of email addresses and password resets.
    #[serde(default)]
    pub smtp: SmtpConfig,
    /// `[wechat]`: the WeChat mini program whose users bind and sign in to their accounts.
    #[serde(default)]
    pub wechat: WeChatConfig,
    /// `[oauth.google]`, `[oauth.github]`: sign-in with Google and GitHub.
    #[serde(default)]
    pub oauth: OAuthConfig,
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
    /// The database system: `sqlite` (built in, the default) or `mysql` (MySQL 5.7.44 or
    /// later).
    #[serde(default)]
    pub backend: Backend,

    /// SQLite only: path of the database file.
    #[serde(default)]
    pub path: PathBuf,

    /// MySQL only: the server and the database, for example
    /// `mysql://gono@127.0.0.1:3306/gono_cloud`, without a password (that goes into
    /// `password_file`). Query parameters such as `ssl-mode=verify_identity` and `ssl-ca` set up
    /// TLS.
    #[serde(default)]
    pub url: Option<Url>,

    /// MySQL only: a file holding the password of the MySQL account, read at every start.
    /// Without it the account must not need a password.
    #[serde(default)]
    pub password_file: Option<PathBuf>,

    /// Upper bound of the connection pool.
    #[serde(default = "default_db_max_connections")]
    pub max_connections: u32,

    /// How long a writer waits for a writer of another process (the CLI) before giving up, in
    /// seconds: SQLite's busy timeout, MySQL's `innodb_lock_wait_timeout`. The server's own
    /// writers queue at the write gate instead ([`crate::db::begin_immediate`]).
    #[serde(default = "default_db_busy_timeout_secs")]
    pub busy_timeout_secs: u64,
}

impl DbConfig {
    /// A SQLite database at `path`, with the default pool settings.
    pub fn sqlite(path: impl Into<PathBuf>) -> Self {
        Self {
            backend: Backend::Sqlite,
            path: path.into(),
            url: None,
            password_file: None,
            max_connections: default_db_max_connections(),
            busy_timeout_secs: default_db_busy_timeout_secs(),
        }
    }

    /// The MySQL database at `url`, with the default pool settings and no password file.
    pub fn mysql(url: Url) -> Self {
        Self {
            backend: Backend::MySql,
            path: PathBuf::new(),
            url: Some(url),
            password_file: None,
            max_connections: default_db_max_connections(),
            busy_timeout_secs: default_db_busy_timeout_secs(),
        }
    }

    /// The database for people: the SQLite file, or the MySQL URL (which carries no password).
    pub fn describe(&self) -> String {
        match (self.backend, &self.url) {
            (Backend::MySql, Some(url)) => format!("MySQL {url}"),
            (Backend::MySql, None) => "MySQL (no db.url)".to_owned(),
            (Backend::Sqlite, _) => format!("SQLite {}", self.path.display()),
        }
    }

    fn validate(&self, reject: &mut impl FnMut(&'static str, String)) {
        match self.backend {
            Backend::Sqlite => {
                if self.path.as_os_str().is_empty() {
                    reject("db.path", "must not be empty".to_owned());
                }
                if self.url.is_some() {
                    reject("db.url", "is for backend = \"mysql\" only".to_owned());
                }
                if self.password_file.is_some() {
                    reject(
                        "db.password_file",
                        "is for backend = \"mysql\" only".to_owned(),
                    );
                }
            }
            Backend::MySql => {
                if !self.path.as_os_str().is_empty() {
                    reject(
                        "db.path",
                        "is for backend = \"sqlite\" only; MySQL is configured by db.url"
                            .to_owned(),
                    );
                }
                match &self.url {
                    None => reject(
                        "db.url",
                        "is required with backend = \"mysql\", for example \
                         mysql://gono@127.0.0.1:3306/gono_cloud"
                            .to_owned(),
                    ),
                    Some(url) => {
                        if let Err(message) = check_mysql_url(url) {
                            reject("db.url", message);
                        }
                    }
                }
                if self
                    .password_file
                    .as_ref()
                    .is_some_and(|file| file.as_os_str().is_empty())
                {
                    reject("db.password_file", "must not be empty".to_owned());
                }
            }
        }
        if !(1..=MAX_DB_CONNECTIONS).contains(&self.max_connections) {
            reject(
                "db.max_connections",
                format!("must be between 1 and {MAX_DB_CONNECTIONS}"),
            );
        }
        if self.busy_timeout_secs == 0 {
            reject("db.busy_timeout_secs", "must be greater than 0".to_owned());
        }
        if self.busy_timeout_secs > MAX_DB_BUSY_TIMEOUT_SECS {
            reject(
                "db.busy_timeout_secs",
                format!("must be at most {MAX_DB_BUSY_TIMEOUT_SECS} (one day)"),
            );
        }
    }
}

/// Checks the shape of `db.url`: a `mysql://` URL with a host and one database, without a
/// password.
fn check_mysql_url(url: &Url) -> Result<(), String> {
    if url.scheme() != "mysql" {
        return Err(format!("{url} must start with mysql://"));
    }
    if url.password().is_some() {
        return Err(
            "must not contain a password; put the password into a file and name it in \
             db.password_file"
                .to_owned(),
        );
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("{url} names no host"));
    }
    let database = url.path().trim_start_matches('/');
    if database.is_empty() || database.contains('/') {
        return Err(format!(
            "{url} must name exactly one database, as in mysql://gono@127.0.0.1:3306/gono_cloud"
        ));
    }
    if url.fragment().is_some() {
        return Err(format!("{url} must not have a fragment"));
    }
    Ok(())
}

/// Whether a MySQL URL names this host. `mysql://` is not a special scheme to the URL parser,
/// so IPv4 addresses come back as names.
fn mysql_host_is_local(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether a MySQL URL insists on TLS (`ssl-mode` of `required`, `verify_ca` or
/// `verify_identity`); sqlx's default, `preferred`, falls back to plain TCP.
fn mysql_requires_tls(url: &Url) -> bool {
    url.query_pairs().any(|(key, value)| {
        matches!(&*key, "ssl-mode" | "sslmode")
            && ["required", "verify_ca", "verify_identity"]
                .iter()
                .any(|mode| value.replace('-', "_").eq_ignore_ascii_case(mode))
    })
}

/// Highest accepted value of `db.max_connections`. SQLite serializes writers anyway; a large
/// pool only adds contention.
pub const MAX_DB_CONNECTIONS: u32 = 64;

/// Highest accepted value of `db.busy_timeout_secs`: MySQL's `innodb_lock_wait_timeout` stops
/// at a year, but a writer that waits for a day is stuck anyway.
pub const MAX_DB_BUSY_TIMEOUT_SECS: u64 = 24 * 60 * 60;

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

    /// URL path of the admin UI, for example `/manage`.
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
    /// account page at `/account/`. Users sign in with their web login password; app
    /// passwords cannot access it.
    pub enabled: bool,
}

impl Default for FilesUiConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// `[connect]` table: remote access of devices (`docs/connect-protocol.md`), served by `serve`
/// when the relay is enabled.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnectConfig {
    /// Whether remote access needs two-step verification on the account (protocol 13): granting
    /// a device registration, `connect`, `lookup` and pairing on the control channel, and
    /// admission to the relay. True keeps all of these to accounts with two-step verification.
    ///
    /// **Temporary.** It defaults to false only while remote control is in development, so that
    /// test accounts need no authenticator; two-step verification still works for the accounts
    /// that turn it on. The default must become true before remote control is released (a
    /// release gate of the plan, R10), and [`Config::warnings`] reports false while the relay
    /// is enabled.
    pub require_two_factor: bool,
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

    /// Most bytes per second the relay reads from one connection of a device with full relay
    /// access (the full tier, which the devices of `allowed_endpoints` have). Unlimited when
    /// unset.
    pub max_client_bytes_per_sec: Option<u32>,

    /// Largest burst the relay reads at once from one connection of a device with full relay
    /// access, in bytes. Needs `max_client_bytes_per_sec`.
    pub max_client_burst_bytes: Option<u32>,

    /// Most bytes per second the relay reads from one connection of a device that may connect
    /// directly but not relay (the limited tier): enough for the handshakes and the
    /// hole-punching coordination that set up a direct connection. At most
    /// `max_client_bytes_per_sec`.
    pub limited_bytes_per_sec: u32,

    /// Largest burst the relay reads at once from one connection of a device of the limited
    /// tier, in bytes. At most `max_client_burst_bytes`.
    pub limited_burst_bytes: u32,
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
            limited_bytes_per_sec: 16_384,
            limited_burst_bytes: 32_768,
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

/// How the connection to `smtp.host` is protected (`smtp.security`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurity {
    /// TLS from the first byte ("implicit TLS", SMTPS), usually on port 465.
    #[default]
    Tls,
    /// Plain SMTP upgraded with STARTTLS, usually on port 587. A server that does not offer
    /// STARTTLS is refused before anything is sent, so a man in the middle cannot strip it.
    Starttls,
    /// Plain SMTP without encryption. Accepted only for a relay on this host (`host` is a
    /// loopback address or `localhost`), such as a local Postfix, and for tests.
    None,
}

impl SmtpSecurity {
    /// `tls`, `starttls` or `none`, as the configuration spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Starttls => "starttls",
            Self::None => "none",
        }
    }
}

/// Default of `smtp.port`: SMTP submission with implicit TLS.
pub const DEFAULT_SMTP_PORT: u16 = 465;

/// `[smtp]` table: the mail server through which `serve` sends the one-time codes that bind an
/// email address to an account and reset a forgotten web login password, and the notices that
/// follow such changes. Without it (the default) accounts have no email addresses to add, and
/// passwords cannot be reset by mail.
///
/// The password of the mail account never goes into the configuration: it is the first line of
/// `password_file`, read when `serve` starts.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpConfig {
    /// Send mail.
    pub enabled: bool,
    /// The mail server's host name or IP address. Required when enabled.
    pub host: Option<String>,
    /// The mail server's port.
    pub port: u16,
    /// How the connection is protected.
    pub security: SmtpSecurity,
    /// The account to authenticate as, with `password_file`. Without both, nothing is
    /// authenticated (a local relay).
    pub username: Option<String>,
    /// A file holding the password of `username`: its first line, without the line break.
    /// Relative paths are resolved against the configuration file's directory.
    pub password_file: Option<PathBuf>,
    /// The sender of every mail: an address with an optional display name, for example
    /// `Gono Cloud <cloud@example.com>`. Required when enabled.
    pub from: Option<String>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: None,
            port: DEFAULT_SMTP_PORT,
            security: SmtpSecurity::default(),
            username: None,
            password_file: None,
            from: None,
        }
    }
}

/// `[wechat]` table: the WeChat mini program whose users bind their WeChat to their accounts
/// on the account page and then sign in with it (`docs/wechat-miniprogram.md`). Off by
/// default: the account page says that the server does not offer it, and the mini program's
/// API under `/gono/v1/wechat/` answers `not_found`.
///
/// The AppSecret never goes into the configuration: it is the first line of `secret_file`, read
/// when `serve` starts.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WeChatConfig {
    /// Serve the mini program's API, the WeChat panel of the account page and the pages of the
    /// QR links.
    pub enabled: bool,
    /// The mini program's AppID: `wx` and 16 letters or digits. Required when enabled.
    pub app_id: Option<String>,
    /// A file holding the mini program's AppSecret: its first line, without the line break.
    /// Relative paths are resolved against the configuration file's directory. Required when
    /// enabled.
    pub secret_file: Option<PathBuf>,
    /// The prefix of the QR links that open the mini program, as configured in its admin
    /// console under "扫普通链接二维码打开小程序" (scan ordinary QR codes to open the mini
    /// program): an `https://` URL ending in `/`, for example `https://cloud.example.com/q/`.
    /// Binding links are `<prefix>bind/<ticket>`. Its host may differ from `server.base_url`'s:
    /// mini programs need a domain with an ICP filing, which another host may front. Required
    /// when enabled.
    pub qr_url_prefix: Option<Url>,
    /// The verification file WeChat gives for the QR link rule, served at `/<its file name>`
    /// with its exact content while enabled. Relative paths are resolved against the
    /// configuration file's directory. Optional.
    pub verify_file: Option<PathBuf>,
}

/// `[oauth.*]` tables: sign-in with Google (OpenID Connect) and GitHub (an OAuth app)
/// (`plan/third-party-sign-in-design.md`). Each is off by default; without either, the sign-in
/// pages offer the password (and WeChat) only.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthConfig {
    /// `[oauth.google]`.
    pub google: OAuthProviderConfig,
    /// `[oauth.github]`.
    pub github: OAuthProviderConfig,
}

/// One `[oauth.<provider>]` table. The client secret never goes into the configuration: it is
/// the first line of `client_secret_file`, read when `serve` starts.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthProviderConfig {
    /// Offer sign-in with the provider.
    pub enabled: bool,
    /// The OAuth client ID from the provider's console. Required when enabled.
    pub client_id: Option<String>,
    /// A file holding the client secret: its first line, without the line break. Relative
    /// paths are resolved against the configuration file's directory. Required when enabled.
    pub client_secret_file: Option<PathBuf>,
    /// Let an identity of the provider that is bound to no account create one. Off by default:
    /// an unbound identity can then only be bound to an existing account.
    pub allow_signup: bool,
}

/// The longest OAuth client ID accepted, in bytes.
pub const MAX_CLIENT_ID_BYTES: usize = 255;

/// The redirect URI of the OAuth provider `provider` (`google`, `github`) on a server whose
/// public origin is `base_url`: what its console must list.
pub fn oauth_redirect_uri(base_url: &Url, provider: &str) -> String {
    format!(
        "{}/login/oauth/{provider}/callback",
        base_url.as_str().trim_end_matches('/')
    )
}

/// The longest `wechat.qr_url_prefix` accepted, in bytes: the QR codes of its links stay easy
/// to scan.
pub const MAX_QR_URL_PREFIX_BYTES: usize = 200;

/// Checks `wechat.qr_url_prefix`: `https`, a host, no credentials, query or fragment, a path
/// that ends with `/`, at most [`MAX_QR_URL_PREFIX_BYTES`].
fn check_qr_url_prefix(url: &Url) -> Result<(), String> {
    if url.scheme() != "https" {
        return Err(format!(
            "must be an https URL (mini programs open https links only), got {:?}",
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
    if !url.path().ends_with('/') {
        return Err(format!(
            "must end with '/', as the rule in the mini program's console does, for example \
             \"https://cloud.example.com/q/\" (got {:?})",
            url.path()
        ));
    }
    if url.as_str().len() > MAX_QR_URL_PREFIX_BYTES {
        return Err(format!(
            "must be at most {MAX_QR_URL_PREFIX_BYTES} bytes long, so that its QR codes stay \
             easy to scan"
        ));
    }
    Ok(())
}

/// The name under which `wechat.verify_file` is served, `/<name>`: the file name, if it is
/// letters, digits, `-`, `_` and `.`, ends with `.txt` and does not start with `.` (WeChat's
/// are `<random>.txt`), so that it can never name another page of the server.
pub fn verify_file_name(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    (name.len() > 4
        && name.len() <= 128
        && name.ends_with(".txt")
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
    .then_some(name)
}

/// Whether `host` names this host: a loopback address or `localhost`.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
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

/// Default of `admin.path`: a path of its own, apart from the pages of every account (the web
/// file UI below `/apps/`, the account page at `/account/`).
pub const DEFAULT_ADMIN_PATH: &str = "/manage";

/// First path segments the server uses itself; `admin.path` must not start with one of them.
const RESERVED_SEGMENTS: &[&str] = &[
    "204",
    "account",
    "apps",
    "gono",
    "healthz",
    "index.php",
    "login",
    "logout",
    "ocs",
    "push",
    "q",
    "remote.php",
    "status.php",
];

/// `admin.path` is `/` followed by one or more segments of unreserved URL characters, without a
/// trailing slash, and outside the paths the server serves itself.
fn check_admin_path(path: &str) -> Result<(), String> {
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
        if let Some(file) = self.db.password_file.as_mut() {
            resolve(file);
        }
        resolve(&mut self.two_factor.key_file);
        self.two_factor.config_dir = Some(base_dir.to_path_buf());
        for file in [
            self.logging.file.as_mut(),
            self.relay.tls_cert.as_mut(),
            self.relay.tls_key.as_mut(),
            self.smtp.password_file.as_mut(),
            self.wechat.secret_file.as_mut(),
            self.wechat.verify_file.as_mut(),
            self.oauth.google.client_secret_file.as_mut(),
            self.oauth.github.client_secret_file.as_mut(),
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
        self.db.validate(&mut reject);

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

        // [smtp]
        self.validate_smtp(&mut reject);

        // [wechat]
        self.validate_wechat(&mut reject);

        // [oauth.*]
        validate_oauth(&self.oauth.google, "google", &mut reject);
        validate_oauth(&self.oauth.github, "github", &mut reject);

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

        // The relay refills a connection's allowance every tenth of a second, a byte at least.
        if relay.limited_bytes_per_sec < 10 {
            reject(
                "relay.limited_bytes_per_sec",
                "must be at least 10".to_owned(),
            );
        } else if let Some(full) = relay
            .max_client_bytes_per_sec
            // 0 is refused above already.
            .filter(|full| *full > 0 && relay.limited_bytes_per_sec > *full)
        {
            reject(
                "relay.limited_bytes_per_sec",
                format!(
                    "must not exceed relay.max_client_bytes_per_sec ({full}): the limited tier \
                     cannot get more than full relay access"
                ),
            );
        }
        if relay.limited_burst_bytes == 0 {
            reject(
                "relay.limited_burst_bytes",
                "must be greater than 0".to_owned(),
            );
        } else if let Some(full) = relay
            .max_client_burst_bytes
            .filter(|full| *full > 0 && relay.limited_burst_bytes > *full)
        {
            reject(
                "relay.limited_burst_bytes",
                format!(
                    "must not exceed relay.max_client_burst_bytes ({full}): the limited tier \
                     cannot get more than full relay access"
                ),
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

    /// Checks the `[smtp]` table. Values that are set are always checked; what sending needs is
    /// only required once it is enabled.
    fn validate_smtp(&self, reject: &mut impl FnMut(&'static str, String)) {
        let smtp = &self.smtp;
        match smtp.host.as_deref() {
            Some(host) => {
                let name = host.to_ascii_lowercase();
                if host.parse::<IpAddr>().is_err() && !is_domain(&name) {
                    reject(
                        "smtp.host",
                        format!(
                            "{host:?} is neither a host name nor an IP address; give the port in \
                             smtp.port"
                        ),
                    );
                } else if smtp.security == SmtpSecurity::None && !is_loopback_host(host) {
                    // Codes that reset passwords must not cross a network in plain text.
                    reject(
                        "smtp.security",
                        format!(
                            "\"none\" sends mail and the password unencrypted, so it is accepted \
                             only for a mail server on this host (a loopback address or \
                             localhost), not {host}; use \"tls\" or \"starttls\""
                        ),
                    );
                }
            }
            None if smtp.enabled => {
                reject("smtp.host", "is required when smtp.enabled".to_owned());
            }
            None => {}
        }
        if smtp.port == 0 {
            reject("smtp.port", "must be between 1 and 65535".to_owned());
        }
        match (&smtp.username, &smtp.password_file) {
            (Some(username), _)
                if username.is_empty() || username.chars().any(char::is_control) =>
            {
                reject(
                    "smtp.username",
                    "must not be empty or contain control characters".to_owned(),
                );
            }
            (_, Some(file)) if file.as_os_str().is_empty() => {
                reject("smtp.password_file", "must not be empty".to_owned());
            }
            (Some(_), None) => reject(
                "smtp.password_file",
                "is required with smtp.username: the file that holds its password".to_owned(),
            ),
            (None, Some(_)) => reject(
                "smtp.username",
                "is required with smtp.password_file: the account the password belongs to"
                    .to_owned(),
            ),
            _ => {}
        }
        match &smtp.from {
            Some(from) => {
                if let Err(message) = crate::email::parse_mailbox(from) {
                    reject(
                        "smtp.from",
                        format!(
                            "{from:?} {message}; expected an address with an optional name, for \
                             example \"Gono Cloud <cloud@example.com>\""
                        ),
                    );
                }
            }
            None if smtp.enabled => {
                reject(
                    "smtp.from",
                    "is required when smtp.enabled, for example \"Gono Cloud <cloud@example.com>\""
                        .to_owned(),
                );
            }
            None => {}
        }
    }

    /// The `[oauth.*]` tables that are enabled, with their provider keys.
    pub fn oauth_providers(&self) -> Vec<(&'static str, &OAuthProviderConfig)> {
        [
            ("google", &self.oauth.google),
            ("github", &self.oauth.github),
        ]
        .into_iter()
        .filter(|(_, provider)| provider.enabled)
        .collect()
    }

    /// Checks the `[wechat]` table. Values that are set are always checked; what the mini
    /// program needs is only required once it is enabled.
    fn validate_wechat(&self, reject: &mut impl FnMut(&'static str, String)) {
        let wechat = &self.wechat;
        match &wechat.app_id {
            Some(app_id) if !crate::wechat::is_app_id(app_id) => reject(
                "wechat.app_id",
                format!(
                    "{app_id:?} is not the AppID of a mini program: \"wx\" and 16 letters or \
                     digits, as its admin console shows it"
                ),
            ),
            None if wechat.enabled => {
                reject(
                    "wechat.app_id",
                    "is required when wechat.enabled".to_owned(),
                );
            }
            _ => {}
        }
        match &wechat.secret_file {
            Some(file) if file.as_os_str().is_empty() => {
                reject("wechat.secret_file", "must not be empty".to_owned());
            }
            None if wechat.enabled => reject(
                "wechat.secret_file",
                "is required when wechat.enabled: the file that holds the mini program's \
                 AppSecret"
                    .to_owned(),
            ),
            _ => {}
        }
        match &wechat.qr_url_prefix {
            Some(url) => {
                if let Err(message) = check_qr_url_prefix(url) {
                    reject("wechat.qr_url_prefix", message);
                }
            }
            None if wechat.enabled => reject(
                "wechat.qr_url_prefix",
                "is required when wechat.enabled, for example \"https://cloud.example.com/q/\""
                    .to_owned(),
            ),
            None => {}
        }
        if let Some(file) = &wechat.verify_file
            && verify_file_name(file).is_none()
        {
            reject(
                "wechat.verify_file",
                format!(
                    "{} is not a verification file of WeChat: its name must be letters, digits, \
                     '-', '_' and '.' ending in .txt, as WeChat names it",
                    file.display()
                ),
            );
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
            // MySQL has no path.
            self.db.backend == Backend::Sqlite &&
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
        if let Some(url) = self
            .db
            .url
            .as_ref()
            .filter(|url| self.db.backend == Backend::MySql && !mysql_requires_tls(url))
            .filter(|url| !mysql_host_is_local(url))
        {
            warnings.push(format!(
                "db.url {url} reaches MySQL on another host without requiring TLS; the password \
                 and every query cross the network unencrypted unless the server offers TLS on \
                 its own. Add ?ssl-mode=verify_identity (and ssl-ca=<file> for a private CA)"
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
            if !self.connect.require_two_factor {
                warnings.push(
                    "connect.require_two_factor is false: remote access (device registration, \
                     the device directory and the relay) is open to accounts without two-step \
                     verification; this is for development only, set it to true before remote \
                     control is released"
                        .to_owned(),
                );
            }
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

        let smtp = &self.smtp;
        if smtp.enabled {
            if !self.files_ui.enabled {
                warnings.push(
                    "smtp.enabled is true, but nothing sends mail: email addresses are added on \
                     the account page and passwords reset from the sign-in page, which belong to \
                     the web file UI that files_ui.enabled turns off"
                        .to_owned(),
                );
            }
            // The usual ports of the other kind of connection: a mismatch fails at the first
            // mail with a confusing TLS or protocol error.
            match (smtp.security, smtp.port) {
                (SmtpSecurity::Tls, 25 | 587) => warnings.push(format!(
                    "smtp.port {} usually expects STARTTLS, but smtp.security is \"tls\" (TLS \
                     from the first byte, usually port 465); set security = \"starttls\" or the \
                     port the server takes TLS on",
                    smtp.port
                )),
                (SmtpSecurity::Starttls, 465) => warnings.push(
                    "smtp.port 465 usually expects TLS from the first byte, but smtp.security is \
                     \"starttls\" (usually port 587); set security = \"tls\" or port = 587"
                        .to_owned(),
                ),
                _ => {}
            }
        }

        for (key, _) in self.oauth_providers() {
            if !self.files_ui.enabled {
                warnings.push(format!(
                    "oauth.{key}.enabled is true, but nobody signs in with it: the sign-in pages \
                     are part of the web file UI that files_ui.enabled turns off"
                ));
            }
            if self.server.base_url.scheme() != "https" && !is_local_host(&self.server.base_url) {
                warnings.push(format!(
                    "oauth.{key}.enabled is true, but server.base_url is not https: the provider \
                     sends the browser back to {} in the clear, and providers refuse plain http \
                     redirect URIs except for localhost",
                    oauth_redirect_uri(&self.server.base_url, key)
                ));
            }
        }

        let wechat = &self.wechat;
        if wechat.enabled {
            if !self.files_ui.enabled {
                warnings.push(
                    "wechat.enabled is true, but nothing binds WeChat to an account: the WeChat \
                     panel is on the account page, part of the web file UI that \
                     files_ui.enabled turns off"
                        .to_owned(),
                );
            }
            if let Some(url) = wechat.qr_url_prefix.as_ref().filter(|url| {
                url.host_str() == self.server.base_url.host_str() && !url.path().starts_with("/q/")
            }) {
                warnings.push(format!(
                    "wechat.qr_url_prefix {url} is on server.base_url's host but outside /q/: a \
                     browser that opens one of its links gets 404 instead of the page that says \
                     to scan the code with WeChat"
                ));
            }
        }
        warnings
    }
}

/// Checks one `[oauth.<provider>]` table. Values that are set are always checked; what sign-in
/// needs is only required once it is enabled.
fn validate_oauth(
    provider: &OAuthProviderConfig,
    key: &'static str,
    reject: &mut impl FnMut(&'static str, String),
) {
    let (id_key, secret_key) = match key {
        "google" => ("oauth.google.client_id", "oauth.google.client_secret_file"),
        _ => ("oauth.github.client_id", "oauth.github.client_secret_file"),
    };
    match &provider.client_id {
        Some(id)
            if id.is_empty()
                || id.len() > MAX_CLIENT_ID_BYTES
                || !id.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            reject(
                id_key,
                format!(
                    "{id:?} is not a client ID: 1 to {MAX_CLIENT_ID_BYTES} visible ASCII \
                     characters, as the provider's console shows it"
                ),
            );
        }
        None if provider.enabled => {
            reject(id_key, format!("is required when oauth.{key}.enabled"));
        }
        _ => {}
    }
    match &provider.client_secret_file {
        Some(file) if file.as_os_str().is_empty() => {
            reject(secret_key, "must not be empty".to_owned());
        }
        None if provider.enabled => reject(
            secret_key,
            format!("is required when oauth.{key}.enabled: the file that holds the client secret"),
        ),
        _ => {}
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
        assert_eq!(config.admin.path, "/manage");
        assert!(config.warnings().is_empty());
    }

    #[test]
    fn required_keys_are_required() {
        for (table, key) in [("server", "base_url"), ("storage", "data_dir")] {
            let raw: String = MINIMAL
                .lines()
                .filter(|line| !line.trim_start().starts_with(key))
                .collect::<Vec<_>>()
                .join("\n");
            let err = Config::from_toml(&raw).expect_err(key).to_string();
            assert!(err.contains(key), "[{table}] {key}: {err}");
        }
        // `db.path` may be missing for MySQL, so validation asks for it.
        let raw = MINIMAL.replace("path = \"gono-cloud.db\"", "");
        assert_eq!(issue_keys(&parse(&raw)), ["db.path"]);
    }

    /// `MINIMAL` with a `[db]` table for MySQL instead of SQLite.
    fn mysql(db: &str) -> Config {
        parse(&MINIMAL.replace("path = \"gono-cloud.db\"", db))
    }

    #[test]
    fn mysql_needs_a_url_without_password() {
        let config = mysql(
            "backend = \"mysql\"\nurl = \"mysql://gono@127.0.0.1:3306/gono_cloud\"\n\
             password_file = \"mysql-password\"",
        );
        assert_eq!(config.db.backend, Backend::MySql);
        assert!(issue_keys(&config).is_empty());
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
        assert_eq!(
            config.db.describe(),
            "MySQL mysql://gono@127.0.0.1:3306/gono_cloud"
        );

        for (db, key) in [
            ("backend = \"mysql\"", "db.url"),
            (
                "backend = \"mysql\"\nurl = \"mysql://gono:secret@127.0.0.1/gono_cloud\"",
                "db.url",
            ),
            (
                "backend = \"mysql\"\nurl = \"mysql://gono@127.0.0.1:3306\"",
                "db.url",
            ),
            (
                "backend = \"mysql\"\nurl = \"mysql://gono@127.0.0.1/a/b\"",
                "db.url",
            ),
            (
                "backend = \"mysql\"\nurl = \"postgres://gono@127.0.0.1/gono\"",
                "db.url",
            ),
            (
                "backend = \"mysql\"\nurl = \"mysql://gono@127.0.0.1/gono\"\npath = \"x.db\"",
                "db.path",
            ),
            (
                "backend = \"mysql\"\nurl = \"mysql://gono@127.0.0.1/gono\"\npassword_file = \"\"",
                "db.password_file",
            ),
            (
                "path = \"gono-cloud.db\"\nurl = \"mysql://gono@127.0.0.1/gono\"",
                "db.url",
            ),
            (
                "path = \"gono-cloud.db\"\npassword_file = \"mysql-password\"",
                "db.password_file",
            ),
        ] {
            assert_eq!(issue_keys(&mysql(db)), [key], "{db}");
        }
        let raw = MINIMAL.replace("path = \"gono-cloud.db\"", "backend = \"postgres\"");
        assert!(Config::from_toml(&raw).is_err());
    }

    #[test]
    fn mysql_password_files_resolve_against_the_config_directory() {
        let mut config = mysql(
            "backend = \"mysql\"\nurl = \"mysql://gono@127.0.0.1/gono\"\n\
             password_file = \"secrets/mysql\"",
        );
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            config.db.password_file.as_deref(),
            Some(Path::new("/etc/gono-cloud/secrets/mysql"))
        );
        // The empty `db.path` of MySQL stays empty.
        assert!(config.db.path.as_os_str().is_empty());
    }

    #[test]
    fn remote_mysql_without_tls_is_warned_about() {
        let warned = |url: &str| {
            mysql(&format!("backend = \"mysql\"\nurl = \"{url}\""))
                .warnings()
                .iter()
                .any(|w| w.contains("db.url"))
        };
        assert!(warned("mysql://gono@db.example.com/gono"));
        assert!(warned("mysql://gono@10.0.0.5:3306/gono?ssl-mode=preferred"));
        assert!(!warned(
            "mysql://gono@db.example.com/gono?ssl-mode=verify_identity"
        ));
        assert!(!warned(
            "mysql://gono@db.example.com/gono?ssl-mode=REQUIRED"
        ));
        assert!(!warned("mysql://gono@127.0.0.1/gono"));
        assert!(!warned("mysql://gono@[::1]:3306/gono"));
        assert!(!warned("mysql://gono@localhost/gono"));
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
        for good in ["/manage", "/gono-admin", "/admin", "/ops/admin", "/a.b_c~d"] {
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
            "/logout",
            "/account",
            "/gono/v1",
            "/q",
            // Nothing below /apps, the pages of every account.
            "/apps",
            "/apps/files",
            "/apps/assets",
            "/apps/manage",
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

    /// `MINIMAL` with a `[relay]` table, and remote access that needs two-step verification
    /// (the warning about it has a test of its own).
    fn with_relay(table: &str) -> Config {
        parse(&format!(
            "{MINIMAL}\n[relay]\n{table}\n[connect]\nrequire_two_factor = true\n"
        ))
    }

    #[test]
    fn remote_access_without_two_step_verification_is_warned_about() {
        // The development default (plan R10): no `[connect]` table.
        let open = parse(&format!("{MINIMAL}\n[relay]\n{RELAY}"));
        assert!(!open.connect.require_two_factor);
        let warnings = open.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("connect.require_two_factor is false")
                && warnings[0].contains("before remote control is released"),
            "{warnings:?}"
        );

        let required = with_relay(RELAY);
        assert!(required.connect.require_two_factor);
        assert!(required.warnings().is_empty(), "{:?}", required.warnings());

        // Without the relay there is no remote access to warn about.
        assert!(!parse(MINIMAL).connect.require_two_factor);
        assert!(parse(MINIMAL).warnings().is_empty());

        let unknown = Config::from_toml(&format!("{MINIMAL}\n[connect]\nrequire_2fa = true\n"));
        assert!(unknown.is_err());
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
        assert_eq!(relay.limited_bytes_per_sec, 16_384);
        assert_eq!(relay.limited_burst_bytes, 32_768);
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
    fn limited_rate_limits_are_checked() {
        let ok = complete_relay("limited_bytes_per_sec = 4096\nlimited_burst_bytes = 8192");
        assert!(issue_keys(&ok).is_empty());
        // The defaults stay below the limits of full relay access.
        let below =
            complete_relay("max_client_bytes_per_sec = 1048576\nmax_client_burst_bytes = 65536");
        assert!(issue_keys(&below).is_empty());

        let zero = complete_relay("limited_bytes_per_sec = 0\nlimited_burst_bytes = 0");
        assert_eq!(
            issue_keys(&zero),
            ["relay.limited_bytes_per_sec", "relay.limited_burst_bytes"]
        );
        let too_slow = complete_relay("limited_bytes_per_sec = 9");
        assert_eq!(issue_keys(&too_slow), ["relay.limited_bytes_per_sec"]);

        let above =
            complete_relay("max_client_bytes_per_sec = 8192\nmax_client_burst_bytes = 16384");
        assert_eq!(
            issue_keys(&above),
            ["relay.limited_bytes_per_sec", "relay.limited_burst_bytes"]
        );
        let equal = complete_relay(
            "max_client_bytes_per_sec = 8192\nmax_client_burst_bytes = 16384\n\
             limited_bytes_per_sec = 8192\nlimited_burst_bytes = 16384",
        );
        assert!(issue_keys(&equal).is_empty());
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

    /// Parses `MINIMAL` with an `[smtp]` table holding `body`.
    fn with_smtp(body: &str) -> Config {
        parse(&format!("{MINIMAL}\n[smtp]\n{body}\n"))
    }

    const SMTP: &str = "enabled = true\nhost = \"smtp.example.com\"\n\
                        from = \"Gono Cloud <cloud@example.com>\"";

    #[test]
    fn smtp_is_off_by_default() {
        let smtp = parse(MINIMAL).smtp;
        assert!(!smtp.enabled);
        assert_eq!(smtp.host, None);
        assert_eq!(smtp.port, 465);
        assert_eq!(smtp.security, SmtpSecurity::Tls);
        assert_eq!(smtp.username, None);
        assert_eq!(smtp.from, None);
        assert!(issue_keys(&with_smtp("")).is_empty());
    }

    #[test]
    fn enabled_smtp_needs_a_host_and_a_sender() {
        let mut keys = issue_keys(&with_smtp("enabled = true"));
        keys.sort_unstable();
        assert_eq!(keys, ["smtp.from", "smtp.host"]);
        let config = with_smtp(SMTP);
        assert!(issue_keys(&config).is_empty());
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
        for (extra, key) in [("port = 0", "smtp.port"), ("security = \"ssl\"", "")] {
            let raw = format!("{MINIMAL}\n[smtp]\n{SMTP}\n{extra}\n");
            match Config::from_toml(&raw) {
                Ok(config) => assert_eq!(issue_keys(&config), [key], "{extra}"),
                Err(err) => assert!(key.is_empty(), "{extra}: {err}"),
            }
        }
    }

    #[test]
    fn smtp_hosts_and_senders_are_checked() {
        let host = |value: &str| issue_keys(&with_smtp(&SMTP.replace("smtp.example.com", value)));
        for valid in [
            "mail.example.com",
            "Mail.Example.COM",
            "192.0.2.25",
            "::1",
            "localhost",
        ] {
            assert!(host(valid).is_empty(), "{valid}");
        }
        for invalid in [
            "",
            "smtp.example.com:465",
            "smtps://smtp.example.com",
            "[::1]",
            "mail example.com",
        ] {
            assert_eq!(host(invalid), ["smtp.host"], "{invalid}");
        }
        let from = |value: &str| {
            issue_keys(&with_smtp(&format!(
                "enabled = true\nhost = \"smtp.example.com\"\nfrom = {value:?}"
            )))
        };
        for valid in [
            "cloud@example.com",
            "Gono Cloud <cloud@example.com>",
            "\"Gono Cloud\" <Cloud@Example.com>",
            "<cloud@example.com>",
            "云盘 <cloud@example.com>",
        ] {
            assert!(from(valid).is_empty(), "{valid}");
        }
        for invalid in [
            "",
            "Gono Cloud",
            "cloud@",
            "Gono <cloud@example.com",
            "a <b> <cloud@example.com>",
            "Gono\nCloud <cloud@example.com>",
            "cloud@example.com, other@example.com",
        ] {
            assert_eq!(from(invalid), ["smtp.from"], "{invalid}");
        }
    }

    #[test]
    fn plain_smtp_is_for_a_relay_on_this_host_only() {
        let plain = |host: &str| {
            issue_keys(&with_smtp(&format!(
                "{}\nsecurity = \"none\"\nport = 25",
                SMTP.replace("smtp.example.com", host)
            )))
        };
        for local in ["127.0.0.1", "::1", "localhost", "LOCALHOST", "127.0.0.53"] {
            assert!(plain(local).is_empty(), "{local}");
        }
        for remote in ["smtp.example.com", "192.0.2.25", "localhost.example.com"] {
            assert_eq!(plain(remote), ["smtp.security"], "{remote}");
        }
        let starttls = with_smtp(&format!("{SMTP}\nsecurity = \"starttls\"\nport = 587"));
        assert_eq!(starttls.smtp.security, SmtpSecurity::Starttls);
        assert!(issue_keys(&starttls).is_empty());
        assert!(starttls.warnings().is_empty(), "{:?}", starttls.warnings());
    }

    #[test]
    fn smtp_credentials_come_together() {
        let both = with_smtp(&format!(
            "{SMTP}\nusername = \"cloud@example.com\"\npassword_file = \"smtp-password\""
        ));
        assert!(issue_keys(&both).is_empty());
        for (extra, key) in [
            ("username = \"cloud@example.com\"", "smtp.password_file"),
            ("password_file = \"smtp-password\"", "smtp.username"),
            (
                "username = \"\"\npassword_file = \"smtp-password\"",
                "smtp.username",
            ),
            (
                "username = \"a\"\npassword_file = \"\"",
                "smtp.password_file",
            ),
        ] {
            assert_eq!(
                issue_keys(&with_smtp(&format!("{SMTP}\n{extra}"))),
                [key],
                "{extra}"
            );
        }
        let mut config = both;
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            config.smtp.password_file.as_deref(),
            Some(Path::new("/etc/gono-cloud/smtp-password"))
        );
    }

    #[test]
    fn smtp_warns_about_mismatched_ports_and_a_missing_file_ui() {
        let warned = |extra: &str| with_smtp(&format!("{SMTP}\n{extra}")).warnings();
        assert!(warned("port = 2465").is_empty());
        assert_eq!(warned("port = 587").len(), 1);
        assert_eq!(warned("security = \"starttls\"").len(), 1);
        let mut config = with_smtp(SMTP);
        config.files_ui.enabled = false;
        let warnings = config.warnings();
        assert!(
            warnings.len() == 1 && warnings[0].contains("files_ui.enabled"),
            "{warnings:?}"
        );
        // Off, nothing is warned about.
        let mut off = with_smtp("port = 587");
        off.files_ui.enabled = false;
        assert!(off.warnings().is_empty());
    }

    /// Parses `MINIMAL` with a `[wechat]` table holding `body`.
    fn with_wechat(body: &str) -> Config {
        parse(&format!("{MINIMAL}\n[wechat]\n{body}\n"))
    }

    const WECHAT: &str = "enabled = true\napp_id = \"wxd930ea5d5a258f4f\"\n\
                          secret_file = \"wechat-secret\"\n\
                          qr_url_prefix = \"https://cloud.example.com/q/\"";

    #[test]
    fn wechat_is_off_by_default() {
        let wechat = parse(MINIMAL).wechat;
        assert!(!wechat.enabled);
        assert_eq!(wechat.app_id, None);
        assert_eq!(wechat.secret_file, None);
        assert_eq!(wechat.qr_url_prefix, None);
        assert_eq!(wechat.verify_file, None);
        assert!(issue_keys(&with_wechat("")).is_empty());
    }

    #[test]
    fn enabled_wechat_needs_an_app_id_a_secret_and_a_prefix() {
        let mut keys = issue_keys(&with_wechat("enabled = true"));
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "wechat.app_id",
                "wechat.qr_url_prefix",
                "wechat.secret_file"
            ]
        );
        let config = with_wechat(WECHAT);
        assert!(issue_keys(&config).is_empty());
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
        // Unknown keys are refused, the secret itself among them.
        assert!(
            Config::from_toml(&format!("{MINIMAL}\n[wechat]\n{WECHAT}\nsecret = \"x\"\n")).is_err()
        );
    }

    #[test]
    fn wechat_values_are_checked() {
        let app_id =
            |value: &str| issue_keys(&with_wechat(&WECHAT.replace("wxd930ea5d5a258f4f", value)));
        assert!(app_id("wx0123456789ABCDEF").is_empty());
        for invalid in ["", "wx123", "wxd930ea5d5a258f4f0", "gh_d930ea5d5a25"] {
            assert_eq!(app_id(invalid), ["wechat.app_id"], "{invalid}");
        }
        let prefix = |value: &str| {
            issue_keys(&with_wechat(
                &WECHAT.replace("https://cloud.example.com/q/", value),
            ))
        };
        for valid in [
            "https://mp.example.cn/q/",
            "https://cloud.example.com/",
            "https://cloud.example.com:8443/q/open/",
        ] {
            assert!(prefix(valid).is_empty(), "{valid}");
        }
        let long = format!("https://cloud.example.com/{}/", "a".repeat(200));
        for invalid in [
            "http://cloud.example.com/q/",
            "https://cloud.example.com/q",
            "https://user@cloud.example.com/q/",
            "https://cloud.example.com/q/?a=b",
            "https://cloud.example.com/q/#x",
            &long,
        ] {
            assert_eq!(prefix(invalid), ["wechat.qr_url_prefix"], "{invalid}");
        }
        let verify =
            |value: &str| issue_keys(&with_wechat(&format!("{WECHAT}\nverify_file = {value:?}")));
        for valid in ["AbC123.txt", "/etc/gono-cloud/x_y-z.1.txt"] {
            assert!(verify(valid).is_empty(), "{valid}");
        }
        for invalid in [
            "",
            "verify.html",
            ".txt",
            ".hidden.txt",
            "a b.txt",
            "a%2F.txt",
        ] {
            assert_eq!(verify(invalid), ["wechat.verify_file"], "{invalid}");
        }
        assert_eq!(
            verify_file_name(Path::new("/etc/gono-cloud/MP_verify_abc.txt")),
            Some("MP_verify_abc.txt")
        );
        // Values are checked also while the mini program is off.
        assert_eq!(
            issue_keys(&with_wechat("app_id = \"wx1\"")),
            ["wechat.app_id"]
        );
    }

    #[test]
    fn wechat_files_resolve_against_the_config_directory() {
        let mut config = with_wechat(&format!("{WECHAT}\nverify_file = \"abc.txt\""));
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            config.wechat.secret_file.as_deref(),
            Some(Path::new("/etc/gono-cloud/wechat-secret"))
        );
        assert_eq!(
            config.wechat.verify_file.as_deref(),
            Some(Path::new("/etc/gono-cloud/abc.txt"))
        );
    }

    #[test]
    fn wechat_warns_about_a_missing_file_ui_and_links_outside_q() {
        let mut config = with_wechat(WECHAT);
        config.files_ui.enabled = false;
        let warnings = config.warnings();
        assert!(
            warnings.len() == 1 && warnings[0].contains("files_ui.enabled"),
            "{warnings:?}"
        );
        let outside = with_wechat(&WECHAT.replace("/q/", "/open/"));
        let warnings = outside.warnings();
        assert!(
            warnings.len() == 1 && warnings[0].contains("/q/"),
            "{warnings:?}"
        );
        // Another host serves its own pages.
        let fronted = with_wechat(&WECHAT.replace("cloud.example.com/q/", "mp.example.cn/open/"));
        assert!(fronted.warnings().is_empty(), "{:?}", fronted.warnings());
        // Off, nothing is warned about.
        let mut off = with_wechat(&WECHAT.replace("enabled = true", "enabled = false"));
        off.files_ui.enabled = false;
        assert!(off.warnings().is_empty());
    }

    const GOOGLE: &str = "enabled = true\nclient_id = \"1234-abc.apps.googleusercontent.com\"\n\
                          client_secret_file = \"google-secret\"";

    /// Parses `MINIMAL` with an `[oauth.<provider>]` table holding `body`.
    fn with_oauth(provider: &str, body: &str) -> Config {
        parse(&format!("{MINIMAL}\n[oauth.{provider}]\n{body}\n"))
    }

    #[test]
    fn oauth_is_off_by_default_and_needs_a_client_when_on() {
        let config = parse(MINIMAL);
        assert!(!config.oauth.google.enabled && !config.oauth.github.enabled);
        assert!(config.oauth_providers().is_empty());
        let mut keys = issue_keys(&with_oauth("github", "enabled = true"));
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["oauth.github.client_id", "oauth.github.client_secret_file"]
        );
        let google = with_oauth("google", GOOGLE);
        assert!(issue_keys(&google).is_empty());
        assert!(!google.oauth.google.allow_signup);
        assert_eq!(google.oauth_providers().len(), 1);
        for invalid in ["", "a b", "\\u0007"] {
            let config = with_oauth(
                "google",
                &GOOGLE.replace("1234-abc.apps.googleusercontent.com", invalid),
            );
            assert_eq!(
                issue_keys(&config),
                ["oauth.google.client_id"],
                "{invalid:?}"
            );
        }
        // The secret never goes into the file.
        assert!(
            Config::from_toml(&format!(
                "{MINIMAL}\n[oauth.google]\n{GOOGLE}\nclient_secret = \"x\"\n"
            ))
            .is_err()
        );
        let mut config = with_oauth("google", GOOGLE);
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            config.oauth.google.client_secret_file.as_deref(),
            Some(Path::new("/etc/gono-cloud/google-secret"))
        );
        assert_eq!(
            oauth_redirect_uri(&config.server.base_url, "google"),
            "https://cloud.example.com/login/oauth/google/callback"
        );
    }

    #[test]
    fn oauth_warns_about_plain_http_and_a_missing_file_ui() {
        let mut config = with_oauth("github", &GOOGLE.replace("google", "github"));
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
        config.files_ui.enabled = false;
        config.server.base_url = Url::parse("http://cloud.example.com").unwrap();
        let warnings = config.warnings();
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings[1].contains("files_ui.enabled"), "{warnings:?}");
        assert!(
            warnings[2].contains("http://cloud.example.com/login/oauth/github/callback"),
            "{warnings:?}"
        );
        // A test installation on this host may use plain http.
        config.files_ui.enabled = true;
        config.server.base_url = Url::parse("http://127.0.0.1:8080").unwrap();
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
    }
}
