//! The TLS client configuration of the server connections: ring, TLS 1.2 and 1.3, the Mozilla
//! roots of `webpki-roots` (the same roots iroh's relay client uses), and nothing from the
//! platform. The device-to-device connections are iroh's and have their own TLS.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

/// A client configuration for HTTPS and `wss://` to the server, advertising `alpn`.
pub(crate) fn client_config(alpn: &[&[u8]]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|alpn| alpn.to_vec()).collect();
    config
}
