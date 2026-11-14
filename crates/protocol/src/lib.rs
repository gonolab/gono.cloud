//! Wire types shared by the Gono Cloud server and its clients.
//!
//! - [`connect`]: remote connectivity between devices, the control protocol of
//!   `docs/connect-protocol.md`: the discovery document, device registration, the control
//!   channel's messages, and the statements devices sign.
//!
//! The rules of `docs/repository-layout.md` apply: a released protocol is only ever extended,
//! never changed, and a change here runs both the server's and the clients' checks.

pub mod connect;
