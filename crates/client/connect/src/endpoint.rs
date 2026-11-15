//! The one place that configures iroh (plan 3.3 and 3.5).
//!
//! A configured endpoint contacts nobody but its peers and the relay of Gono Cloud:
//! - the `Minimal` preset: a crypto provider (ring) and nothing else, never n0's services;
//! - exactly the relay that the server's discovery document names;
//! - no address lookup but the control channel's ([`crate::ControlLookup`]);
//! - DNS without the public fallback resolvers, or the platform's own resolver
//!   ([`SystemResolver`]) where the app cannot read the network's DNS (HarmonyOS);
//! - both address families bound, on a free port unless the product needs a fixed one;
//! - for the LAN-only endpoint ([`bind_lan`]), no relay and no address lookup at all;
//! - no captive-portal check: iroh would send a plain-HTTP request to port 80 of the relay's
//!   host name (`/generate_204`), whose answer only decides whether the next network report is
//!   a full one. Hosts in mainland China whose domain is not ICP-registered have port 80
//!   intercepted, which reads as a captive portal everywhere; without the check, the relay's
//!   host needs no port 80 for devices. Relay latency still comes from QAD and HTTPS (`/ping`).
//!
//! Incoming connections: iroh 1.4.1 has no builder option for the endpoint's limit of pending
//! connection attempts (noq's `max_incoming`, 65536 by default; `ServerConfigBuilder` only
//! applies to `Incoming::accept_with`, after that limit was checked). Products accept with
//! [`crate::Remote::accept_trusted`], which drains the queue at once, refuses attempts beyond a
//! few concurrent handshakes per source and for the endpoint, and closes keys outside the trust
//! list right after the handshake (threat model C8). iroh's `after_handshake` hook would close
//! them at the same point, so it is not used.
//!
//! Products depend on this crate, never on iroh's configuration directly, so that an iroh
//! upgrade that adds a default changes one file. What a product may tune is limited to what
//! cannot add a contact: the QUIC transport parameters of [`TransportOptions`] (iroh's
//! multipath and hole-punching settings stay as iroh sets them) and the addresses to bind
//! ([`BindAddresses`]).

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh::{
    Endpoint, NetReportConfig, RelayMode, RelayUrl, SecretKey,
    address_lookup::AddressLookup,
    dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData},
    endpoint::{QuicTransportConfig, VarInt, presets},
};
use n0_future::boxed::BoxFuture;

use crate::Error;

/// How the endpoint resolves host names (the relay's).
#[derive(Debug, Clone, Default)]
pub enum Dns {
    /// The system's configured nameservers, without the public fallback resolvers.
    #[default]
    System,
    /// The platform's own resolver (`getaddrinfo`): for HarmonyOS, where the app sees a static
    /// `/etc/resolv.conf` instead of the network's DNS (plan 3.3).
    Platform,
}

/// The addresses the endpoint binds, on [`EndpointOptions::port`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindAddresses {
    /// The IPv4 address: all interfaces by default.
    pub ipv4: Ipv4Addr,
    /// The IPv6 address: all interfaces by default. `None` binds IPv4 alone; otherwise an
    /// IPv6 address that cannot be bound falls back to IPv4 alone, with a warning.
    pub ipv6: Option<Ipv6Addr>,
}

impl Default for BindAddresses {
    fn default() -> Self {
        Self {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: Some(Ipv6Addr::UNSPECIFIED),
        }
    }
}

impl BindAddresses {
    /// Loopback only, for tests.
    pub fn loopback() -> Self {
        Self {
            ipv4: Ipv4Addr::LOCALHOST,
            ipv6: None,
        }
    }
}

/// QUIC transport parameters a product tunes for its protocol, for example Input Show's stream
/// limits, its datagram buffers and the remote profile of plan 3.7. `None` keeps iroh's value.
/// iroh's settings for multipath and hole punching (path keep-alive and idle timeout, paths,
/// NAT-traversal addresses) are not offered: changing them breaks hole punching.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportOptions {
    /// Incoming bidirectional streams open at once (iroh: 100).
    pub max_concurrent_bidi_streams: Option<u32>,
    /// Incoming unidirectional streams open at once (iroh: 100).
    pub max_concurrent_uni_streams: Option<u32>,
    /// Incoming datagram bytes buffered; also the largest datagram the peer may send.
    pub datagram_receive_buffer_size: Option<usize>,
    /// Outgoing datagram bytes buffered; older datagrams are dropped beyond it.
    pub datagram_send_buffer_size: Option<usize>,
    /// The connection's idle timeout. Keep it above the keep-alive interval on both sides.
    pub max_idle_timeout: Option<Duration>,
    /// The connection's keep-alive interval (iroh: 5 s).
    pub keep_alive_interval: Option<Duration>,
}

impl TransportOptions {
    /// iroh's transport configuration with these values applied, or `None` when nothing is
    /// set.
    fn config(&self) -> Result<Option<QuicTransportConfig>, Error> {
        if *self == Self::default() {
            return Ok(None);
        }
        let mut builder = QuicTransportConfig::builder();
        if let Some(streams) = self.max_concurrent_bidi_streams {
            builder = builder.max_concurrent_bidi_streams(VarInt::from_u32(streams));
        }
        if let Some(streams) = self.max_concurrent_uni_streams {
            builder = builder.max_concurrent_uni_streams(VarInt::from_u32(streams));
        }
        if let Some(bytes) = self.datagram_receive_buffer_size {
            builder = builder.datagram_receive_buffer_size(Some(bytes));
        }
        if let Some(bytes) = self.datagram_send_buffer_size {
            builder = builder.datagram_send_buffer_size(bytes);
        }
        if let Some(timeout) = self.max_idle_timeout {
            let timeout = timeout
                .try_into()
                .map_err(|_| Error::Bind(format!("idle timeout {timeout:?} is too long")))?;
            builder = builder.max_idle_timeout(Some(timeout));
        }
        if let Some(interval) = self.keep_alive_interval {
            builder = builder.keep_alive_interval(interval);
        }
        Ok(Some(builder.build()))
    }
}

/// What [`bind`] and [`bind_lan`] need.
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    /// The device's key: its identity on the LAN and remotely.
    pub secret_key: SecretKey,
    /// The relay of the server's discovery document; `None` for an endpoint without a relay,
    /// which [`bind_lan`] requires.
    pub relay_url: Option<RelayUrl>,
    /// The ALPNs the endpoint accepts.
    pub alpns: Vec<Vec<u8>>,
    /// The UDP port of both sockets; 0 picks a free one (stage 1: the LAN endpoint keeps the
    /// product's fixed port).
    pub port: u16,
    /// The addresses to bind.
    pub bind: BindAddresses,
    /// Name resolution.
    pub dns: Dns,
    /// The product's QUIC transport parameters.
    pub transport: TransportOptions,
}

/// Binds the remote endpoint as in plan 3.5, with `lookup` as its only address lookup.
///
/// Both address families are bound unless [`BindAddresses::ipv6`] is `None`. Where the system
/// has no IPv6 (disabled in the kernel or the container), the endpoint binds IPv4 alone and
/// logs that it does.
pub async fn bind(
    options: EndpointOptions,
    lookup: impl AddressLookup + Clone,
) -> Result<Endpoint, Error> {
    bind_with(&options, Some(lookup)).await
}

/// Binds the LAN-only endpoint of plan 3.5: no relay and no address lookup, so it contacts
/// nobody but the peers it dials or that dial it (by mDNS results or typed addresses, which
/// the product passes as `EndpointAddr`s). `options.relay_url` must be `None`.
pub async fn bind_lan(options: EndpointOptions) -> Result<Endpoint, Error> {
    if options.relay_url.is_some() {
        return Err(Error::Bind("the LAN endpoint has no relay".to_owned()));
    }
    bind_with::<crate::ControlLookup>(&options, None).await
}

async fn bind_with<L: AddressLookup + Clone>(
    options: &EndpointOptions,
    lookup: Option<L>,
) -> Result<Endpoint, Error> {
    let Some(ipv6) = options.bind.ipv6 else {
        return bind_families(options, lookup, None).await;
    };
    match bind_families(options, lookup.clone(), Some(ipv6)).await {
        Ok(endpoint) => Ok(endpoint),
        Err(err) => {
            tracing::warn!(error = %err, "cannot bind IPv6; using IPv4 only");
            bind_families(options, lookup, None).await
        }
    }
}

async fn bind_families(
    options: &EndpointOptions,
    lookup: Option<impl AddressLookup>,
    ipv6: Option<Ipv6Addr>,
) -> Result<Endpoint, Error> {
    let dns = match options.dns {
        Dns::System => DnsResolver::builder()
            .with_system_defaults()
            .disable_fallback()
            .build(),
        Dns::Platform => DnsResolver::custom(SystemResolver),
    };
    let mut net_report = NetReportConfig::default();
    net_report.captive_portal_check = false;
    let relay_mode = match &options.relay_url {
        Some(relay_url) => RelayMode::custom([relay_url.clone()]),
        None => RelayMode::Disabled,
    };
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(options.secret_key.clone())
        .alpns(options.alpns.clone())
        .dns_resolver(dns)
        .relay_mode(relay_mode)
        .net_report_config(net_report)
        .clear_address_lookup();
    if let Some(lookup) = lookup {
        builder = builder.address_lookup(lookup);
    }
    if let Some(transport) = options.transport.config()? {
        builder = builder.transport_config(transport);
    }
    // Drops the default sockets of both families; one bind per family follows.
    builder = builder
        .clear_ip_transports()
        .bind_addr(SocketAddr::V4(SocketAddrV4::new(
            options.bind.ipv4,
            options.port,
        )))
        .map_err(|err| Error::Bind(err.to_string()))?;
    if let Some(ipv6) = ipv6 {
        builder = builder
            .bind_addr(SocketAddr::V6(SocketAddrV6::new(ipv6, options.port, 0, 0)))
            .map_err(|err| Error::Bind(err.to_string()))?;
    }
    builder
        .bind()
        .await
        .map_err(|err| Error::Bind(err.to_string()))
}

/// Resolves host names with the platform's resolver (`getaddrinfo`, through
/// [`tokio::net::lookup_host`]). It answers A and AAAA queries only; nothing in this
/// configuration asks for TXT records.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

fn lookup_error(err: std::io::Error) -> DnsError {
    DnsError::from(n0_error::AnyError::from_std(err))
}

impl Resolver for SystemResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(async move {
            let addrs: Vec<Ipv4Addr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(lookup_error)?
                .filter_map(|addr| match addr {
                    SocketAddr::V4(addr) => Some(*addr.ip()),
                    SocketAddr::V6(_) => None,
                })
                .collect();
            Ok(Box::new(addrs.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async move {
            let addrs: Vec<Ipv6Addr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(lookup_error)?
                .filter_map(|addr| match addr {
                    SocketAddr::V6(addr) => Some(*addr.ip()),
                    SocketAddr::V4(_) => None,
                })
                .collect();
            Ok(Box::new(addrs.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<TxtRecordData>) })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPN: &[u8] = b"test/1";

    fn options(seed: u8, transport: TransportOptions) -> EndpointOptions {
        EndpointOptions {
            secret_key: SecretKey::from_bytes(&[seed; 32]),
            relay_url: None,
            alpns: vec![ALPN.to_vec()],
            port: 0,
            bind: BindAddresses::loopback(),
            dns: Dns::System,
            transport,
        }
    }

    #[test]
    fn transport_options_build_only_when_set() {
        assert!(TransportOptions::default().config().unwrap().is_none());
        let options = TransportOptions {
            max_concurrent_bidi_streams: Some(8),
            max_concurrent_uni_streams: Some(4),
            datagram_receive_buffer_size: Some(64 * 1024),
            datagram_send_buffer_size: Some(64 * 1024),
            max_idle_timeout: Some(Duration::from_secs(20)),
            keep_alive_interval: Some(Duration::from_secs(4)),
        };
        assert!(options.config().unwrap().is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lan_endpoint_binds_without_relay_where_it_is_told_and_applies_transport_options() {
        let small = TransportOptions {
            datagram_receive_buffer_size: Some(600),
            ..TransportOptions::default()
        };
        let server = bind_lan(options(1, small)).await.unwrap();
        let client = bind_lan(options(2, TransportOptions::default()))
            .await
            .unwrap();
        for endpoint in [&server, &client] {
            let sockets = endpoint.bound_sockets();
            assert!(!sockets.is_empty());
            assert!(
                sockets.iter().all(|addr| addr.ip().is_loopback()),
                "{sockets:?}"
            );
            assert_eq!(endpoint.addr().relay_urls().count(), 0, "no relay");
        }

        let addr = iroh::EndpointAddr::from_parts(
            server.id(),
            server
                .bound_sockets()
                .into_iter()
                .map(iroh::TransportAddr::Ip),
        );
        let accept = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept().await.unwrap().await.unwrap();
                connection.max_datagram_size()
            }
        });
        let connection = tokio::time::timeout(Duration::from_secs(10), client.connect(addr, ALPN))
            .await
            .unwrap()
            .unwrap();
        // The server's receive buffer limits what the client may send it.
        let towards_server = connection.max_datagram_size().unwrap();
        assert!(towards_server <= 600, "{towards_server}");
        let towards_client = accept.await.unwrap().unwrap();
        assert!(towards_client > 600, "{towards_client}");
        connection.close(0u32.into(), b"done");
        for endpoint in [server, client] {
            endpoint.close().await;
        }
    }

    #[tokio::test]
    async fn a_lan_endpoint_refuses_a_relay() {
        let mut lan = options(3, TransportOptions::default());
        lan.relay_url = Some("https://relay.example.com".parse().unwrap());
        assert!(matches!(bind_lan(lan).await, Err(Error::Bind(_))));
    }
}
