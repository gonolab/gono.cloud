//! Remote connectivity: the control protocol of `docs/connect-protocol.md` (version 1).
//!
//! - [`DeviceId`]: a device's key in its wire form.
//! - [`statement`]: the statements devices sign, and [`Signed`], their wire form.
//! - [`message`]: the control channel's messages.
//! - The HTTP documents: [`Discovery`] (protocol 3), [`LoginStart`] / [`LoginStarted`]
//!   (4.1), [`PollRequest`] / [`Registered`] (4.3).
//! - [`paths`], [`close`], [`features`] and [`limits`]: the constants of the protocol.

mod id;
pub mod message;
pub mod statement;

pub use id::{DeviceId, InvalidDeviceId};
pub use message::{ClientMessage, DeviceEntry, ErrorCode, ServerMessage};
use serde::{Deserialize, Serialize};
pub use statement::{Signed, Statement, StatementError};

/// The protocol version this crate speaks.
pub const VERSION: u32 = 1;

/// HTTP paths (protocol 3, 4, 5, 9.4).
pub mod paths {
    /// The discovery document.
    pub const DISCOVERY: &str = "/gono/v1/connect";
    /// Starting a registration.
    pub const LOGIN: &str = "/gono/v1/login";
    /// Polling a registration.
    pub const LOGIN_POLL: &str = "/gono/v1/login/poll";
    /// The control channel.
    pub const WEBSOCKET: &str = "/gono/v1/ws";
    /// Signing out (`DELETE`).
    pub const DEVICE: &str = "/gono/v1/device";
}

/// WebSocket close codes (protocol 5.4).
pub mod close {
    /// The handshake failed.
    pub const HANDSHAKE_FAILED: u16 = 4000;
    /// Replaced by a newer connection of the same device.
    pub const REPLACED: u16 = 4001;
    /// Timed out.
    pub const TIMED_OUT: u16 = 4002;
    /// The device was revoked.
    pub const REVOKED: u16 = 4003;
    /// The account was disabled.
    pub const ACCOUNT_DISABLED: u16 = 4004;
    /// Protocol violation.
    pub const PROTOCOL: u16 = 4008;
    /// Rate limited.
    pub const RATE_LIMITED: u16 = 4029;
}

/// Optional features (protocol 2.4).
pub mod features {
    /// Account-vouched pairing (protocol 8).
    pub const PAIRING: &str = "pairing";
    /// Session reports (protocol 12.2).
    pub const SESSION_REPORTS: &str = "session-reports";
    /// Every feature of version 1.
    pub const ALL: &[&str] = &[PAIRING, SESSION_REPORTS];
}

/// Limits (protocol 15).
pub mod limits {
    /// Largest frame or body, in bytes.
    pub const MAX_FRAME_BYTES: usize = 64 * 1024;
    /// Largest statement, in bytes.
    pub const MAX_STATEMENT_BYTES: usize = 16 * 1024;
    /// Seconds a device has to send `hello`.
    pub const HELLO_TIMEOUT_SECS: u64 = 10;
    /// Seconds between pings.
    pub const PING_INTERVAL_SECS: u64 = 30;
    /// Requests per second per connection.
    pub const REQUESTS_PER_SECOND: u32 = 10;
    /// Burst of requests per connection.
    pub const REQUEST_BURST: u32 = 100;
    /// Direct addresses per `publish`.
    pub const MAX_DIRECT_ADDRESSES: usize = 16;
    /// `connect` per device per minute.
    pub const CONNECTS_PER_MINUTE: u32 = 30;
    /// `lookup` per device per minute.
    pub const LOOKUPS_PER_MINUTE: u32 = 120;
    /// Session reports per device per minute.
    pub const SESSIONS_PER_MINUTE: u32 = 60;
    /// How long after `connect` a `lookup` of the same target is allowed, in seconds.
    pub const LOOKUP_WINDOW_SECS: u64 = 600;
    /// Lifetime of a pairing request, in seconds.
    pub const PAIR_REQUEST_TTL_SECS: i64 = 600;
    /// Pairing requests per account per hour.
    pub const PAIR_REQUESTS_PER_HOUR: usize = 5;
    /// Longest validity of an approval, in seconds.
    pub const MAX_APPROVAL_SECS: i64 = 30 * 24 * 60 * 60;
    /// Devices in one approval's `introduced`.
    pub const MAX_INTRODUCED: usize = 50;
    /// Logged events per `welcome`.
    pub const MAX_WELCOME_EVENTS: i64 = 1000;
}

/// The discovery document (protocol 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    /// [`VERSION`].
    pub version: u32,
    /// The server origin that statements name.
    pub server: String,
    /// Where registrations start.
    pub login: String,
    /// The control channel.
    pub websocket: String,
    /// The relay devices must use, and no other.
    pub relay_url: String,
    /// Remote access needs two-step verification on the account.
    pub two_factor_required: bool,
}

/// `POST /gono/v1/login` (protocol 4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStart {
    /// The device's key.
    pub endpoint_id: DeviceId,
    /// `input-show`, ...
    pub product: String,
    /// `macos`, ...
    pub platform: String,
    /// Its name.
    pub name: String,
    /// Product version.
    #[serde(default)]
    pub version: String,
}

/// Where and how to poll. `Debug` leaves the token out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollEndpoint {
    /// The poll URL.
    pub endpoint: String,
    /// The poll token. Secret.
    pub token: String,
}

/// The answer to [`LoginStart`]. `Debug` leaves the poll token out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStarted {
    /// The URL to open in a browser.
    pub login_url: String,
    /// Where to poll.
    pub poll: PollEndpoint,
    /// 32 random bytes to sign in the `login` statement, base64url.
    pub challenge: String,
    /// When the flow expires.
    pub expires_at: i64,
}

/// `POST /gono/v1/login/poll` (protocol 4.3). `Debug` leaves the token out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollRequest {
    /// The poll token. Secret.
    pub token: String,
    /// The signed `login` statement.
    #[serde(default)]
    pub proof: Option<Signed>,
}

/// A completed registration (protocol 4.3). `Debug` leaves the app password out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    /// `registered`.
    pub status: String,
    /// The server origin.
    pub server: String,
    /// The account's username.
    pub username: String,
    /// The device's app password, returned once. Secret.
    pub app_password: String,
    /// Its directory entry.
    pub device: DeviceEntry,
    /// The device may send pairing requests until then.
    #[serde(default)]
    pub pairing_open_until: Option<i64>,
}

/// What `Debug` shows in place of a secret.
const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for PollEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PollEndpoint")
            .field("endpoint", &self.endpoint)
            .field("token", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for PollRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PollRequest")
            .field("token", &REDACTED)
            .field("proof", &self.proof)
            .finish()
    }
}

impl std::fmt::Debug for Registered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered")
            .field("status", &self.status)
            .field("server", &self.server)
            .field("username", &self.username)
            .field("app_password", &REDACTED)
            .field("device", &self.device)
            .field("pairing_open_until", &self.pairing_open_until)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_leaves_secrets_out() {
        let poll = PollEndpoint {
            endpoint: "https://cloud.example.com/gono/v1/login/poll".to_owned(),
            token: "poll-token-secret".to_owned(),
        };
        let started = LoginStarted {
            login_url: "https://cloud.example.com/login/v2/flow/x".to_owned(),
            poll: poll.clone(),
            challenge: "c".to_owned(),
            expires_at: 1,
        };
        let request = PollRequest {
            token: "poll-token-secret".to_owned(),
            proof: None,
        };
        let registered = Registered {
            status: "registered".to_owned(),
            server: "https://cloud.example.com".to_owned(),
            username: "kim".to_owned(),
            app_password: "app-password-secret".to_owned(),
            device: DeviceEntry {
                endpoint_id: iroh_base::SecretKey::from_bytes(&[1; 32]).public().into(),
                name: "Home PC".to_owned(),
                product: "input-show".to_owned(),
                platform: "linux".to_owned(),
                version: String::new(),
                registered_at: 0,
                online: false,
                last_seen_at: None,
                accept_remote: false,
                unattended: false,
                services: Vec::new(),
                revoked_at: None,
            },
            pairing_open_until: None,
        };
        for text in [
            format!("{poll:?}"),
            format!("{started:?}"),
            format!("{request:?}"),
            format!("{registered:?}"),
        ] {
            assert!(!text.contains("secret"), "{text}");
            assert!(text.contains(REDACTED), "{text}");
        }
        assert!(format!("{registered:?}").contains("kim"));
    }
}
