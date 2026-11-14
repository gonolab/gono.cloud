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
//!   connect to a device, accept connections, forward network changes.
//!
//! Trust stays with the product: this crate never decides whether a peer may connect or
//! control anything. It carries the server's messages and checks nothing the product must
//! check itself (the statements of protocol 8.5, the trust list, unattended access).

mod channel;
pub mod endpoint;
mod lookup;
mod register;
mod remote;
mod tls;

pub use channel::{ChannelEvent, ChannelOptions, ControlChannel, EndReason};
pub use gono_protocol::connect as protocol;
/// The iroh this crate configures, for its types (`Connection`, `SecretKey`, ...).
pub use iroh;
pub use lookup::ControlLookup;
pub use register::{Credentials, DeviceInfo, PendingRegistration, Server};
pub use remote::{Remote, RemoteOptions};

use gono_protocol::connect::ErrorCode;

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server origin or a URL it named is not usable.
    #[error("invalid URL: {0}")]
    Url(String),
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
