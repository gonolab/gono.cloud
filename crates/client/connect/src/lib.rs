//! Remote connectivity for Gono products: the client side of `docs/connect-protocol.md`.
//!
//! - [`endpoint::bind`]: the one iroh configuration of plan 3.5. Products never configure
//!   iroh themselves.
//! - [`Server`]: discovery and device registration through the browser (protocol 3 and 4).
//! - [`ControlChannel`]: the control channel (protocol 5): presence, connection requests,
//!   addresses, pairing requests and approvals, revocations. It reconnects on its own and
//!   hands the product its events.
//! - [`ControlLookup`]: iroh's address lookup backed by the control channel (protocol 7).
//! - [`Remote`]: the endpoint and the channel together, with the product API of plan 3.3:
//!   connect to a device, accept connections from trusted keys
//!   ([`Remote::accept_trusted`]), forward network changes.
//! - [`approval`]: the checks of protocol 8.5 on a received approval, and the approver's
//!   statement.
//!
//! The server is bound to the origin the user entered: `https` (plain `http` only on a
//! loopback host), every URL it names on that origin, no redirects, and every statement naming
//! that origin, never a value of the server's (threat model C16). Its answers are checked
//! where they could steer the device: a `connect` or `lookup` answer for another key is
//! refused, and a relay other than the discovery document's is dropped (C15).
//!
//! Trust stays with the product: this crate never decides whether a peer may connect or
//! control anything, and keeps no trust list. It carries the server's messages;
//! [`approval::check`] runs the checks of protocol 8.5 against the product's state and says
//! what to store, and [`Remote::accept_trusted`] applies the product's own predicate.

pub mod approval;
mod channel;
pub mod endpoint;
mod lookup;
mod origin;
mod register;
mod remote;
mod tls;

pub use channel::{ChannelEvent, ChannelOptions, ControlChannel, EndReason};
pub use gono_protocol::connect as protocol;
/// The iroh this crate configures, for its types (`Connection`, `SecretKey`, ...).
pub use iroh;
pub use lookup::ControlLookup;
pub use register::{Credentials, DeviceInfo, PendingRegistration, Server};
pub use remote::{CLOSE_NOT_TRUSTED, Remote, RemoteOptions};

use gono_protocol::connect::{ErrorCode, VERSION};

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server origin or a URL it named is not usable: not `https` (plain `http` only on a
    /// loopback host), or a URL the server named is not on its origin.
    #[error("invalid URL: {0}")]
    Url(String),
    /// The server calls itself by another origin than the one the device talks to
    /// (`discovery.server` or the registration's `server`): its `server.base_url` does not
    /// match the address entered, or it passes another server's answers on.
    #[error("the server at {expected} calls itself {found}")]
    WrongServer {
        /// The origin the device talks to.
        expected: String,
        /// The origin the server named.
        found: String,
    },
    /// The server speaks another version of the connect protocol than this crate.
    #[error(
        "the server speaks version {0} of the connect protocol; this device speaks version {VERSION}"
    )]
    UnsupportedVersion(u32),
    /// The server does not offer remote access (`404` on the discovery document).
    #[error("this server does not offer remote access")]
    NotOffered,
    /// An HTTP request failed before an answer arrived.
    #[error("HTTP request failed: {0}")]
    Http(String),
    /// The server answered with an error document.
    #[error("the server answered {status}: {code}")]
    Server {
        /// The HTTP status.
        status: u16,
        /// The `error` code of the body.
        code: String,
    },
    /// The registration ended without a credential: denied, expired or used.
    #[error("the sign-in was cancelled or has expired")]
    RegistrationGone,
    /// The control channel is not connected, or the connection broke during the request.
    #[error("the control channel is not connected: {0}")]
    Channel(String),
    /// The server refused a request of the control channel.
    #[error("the server refused the request ({code:?}): {message}")]
    Refused {
        /// The error code.
        code: ErrorCode,
        /// For people.
        message: String,
    },
    /// The endpoint could not be bound.
    #[error("cannot bind the endpoint: {0}")]
    Bind(String),
    /// A connection to a peer failed.
    #[error("cannot connect to the device: {0}")]
    Connect(String),
}

/// Result alias of this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Helpers of the unit tests.
#[cfg(test)]
pub(crate) mod tests {
    use gono_protocol::connect::{DeviceEntry, DeviceId};
    use iroh::SecretKey;

    use crate::Credentials;

    /// The device ID of the key made from `seed`.
    pub(crate) fn device_id(seed: u8) -> DeviceId {
        SecretKey::from_bytes(&[seed; 32]).public().into()
    }

    /// The directory entry of the device made from `seed`.
    pub(crate) fn entry(seed: u8) -> DeviceEntry {
        DeviceEntry {
            endpoint_id: device_id(seed),
            name: format!("Device {seed}"),
            product: "input-show".to_owned(),
            platform: "linux".to_owned(),
            version: String::new(),
            registered_at: 0,
            online: true,
            last_seen_at: None,
            accept_remote: false,
            unattended: false,
            services: Vec::new(),
            revoked_at: None,
        }
    }

    /// A credential of the device made from `seed` on `server`.
    pub(crate) fn credentials(server: &str, seed: u8) -> Credentials {
        Credentials {
            server: server.to_owned(),
            username: "kim".to_owned(),
            app_password: "app-password-secret".to_owned(),
            device: entry(seed),
            pairing_open_until: None,
        }
    }
}
