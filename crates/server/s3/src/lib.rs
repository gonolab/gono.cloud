//! The S3-compatible API of Gono Cloud, built on [`s3s`].
//!
//! s3s speaks the protocol: SigV4 in headers and presigned URLs, `aws-chunked` bodies with their
//! chunk signatures and trailers, the XML of every operation, and error responses. This crate
//! maps it onto the users' trees:
//!
//! - A **bucket** is a folder of its owner's tree ([`gono_server_core::s3`]); its objects are
//!   the files below it, and a key is a path relative to the folder ([`keys`]). Every write goes
//!   through [`gono_server_dav::ScopedFs`] and the MetaStore, so WebDAV, the Nextcloud clients
//!   and notify_push see S3 changes, and S3 sees theirs.
//! - **Addressing**: path style (`/<bucket>/<key>`) always, and virtual-hosted style
//!   (`<bucket>.<domain>`) when `s3.virtual_host_domain` is set ([`host`]).
//! - **Who may do what** is decided once per request, before the operation runs ([`access`]):
//!   requests signed with an access key act within the key's grants; unsigned requests may
//!   only read what a bucket publishes, and only while `s3.allow_anonymous` is on.
//! - **Operations** ([`ops`]) cover buckets, listings, objects with their metadata, ACLs and
//!   conditional requests, and multipart uploads ([`multipart`]). Everything else answers
//!   `NotImplemented`, the default of the s3s trait.
//!
//! [`service`] builds the `tower` service the server binds to `s3.bind`.

mod access;
mod auth;
mod error;
mod host;
pub mod keys;
pub mod multipart;
mod ops;
mod state;
mod upload;

pub use state::{S3Settings, S3State};

use std::sync::Arc;

use s3s::{
    config::{S3Config, StaticConfigProvider},
    service::{S3Service, S3ServiceBuilder},
};

/// The S3 API over `state`, ready to serve.
pub fn service(state: S3State) -> S3Service {
    let mut builder = S3ServiceBuilder::new(ops::GonoS3::new(state.clone()));
    builder.set_auth(auth::Auth::new(state.clone()));
    builder.set_access(access::Access::new(state.clone()));
    if let Some(domain) = &state.settings().virtual_host_domain {
        builder.set_host(host::VirtualHosts::new(domain));
    }
    let mut config = S3Config::default();
    // Clients that sign for another region get the error from which the AWS SDKs learn the
    // right one.
    config.expected_region = state.settings().region.parse().ok();
    // Browser form uploads are not supported (yet).
    config.allow_post_signature = false;
    builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(config))));
    builder.build()
}
