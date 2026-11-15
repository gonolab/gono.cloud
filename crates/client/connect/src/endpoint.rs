//! The one place that configures iroh (plan 3.3 and 3.5).
//!
//! A configured endpoint contacts nobody but its peers and the relay of Gono Cloud:
//! - the `Minimal` preset: a crypto provider (ring) and nothing else, never n0's services;
//! - exactly the relay that the server's discovery document names;
//! - no address lookup but the control channel's ([`crate::ControlLookup`]);
//! - DNS without the public fallback resolvers, or the platform's own resolver
//!   ([`SystemResolver`]) where the app cannot read the network's DNS (HarmonyOS);
//! - both address families bound, on a free port unless the product needs a fixed one;
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
//! few concurrent handshakes per second, and closes keys outside the trust list (threat model
//! C8).
//!
//! Products depend on this crate, never on iroh's configuration directly, so that an iroh
//! upgrade that adds a default changes one file.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use iroh::{
    Endpoint, NetReportConfig, RelayMode, RelayUrl, SecretKey,
    address_lookup::AddressLookup,
    dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData},
    endpoint::presets,
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

/// What [`bind`] needs.
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    /// The device's key: its identity on the LAN and remotely.
    pub secret_key: SecretKey,
    /// The relay of the server's discovery document.
    pub relay_url: RelayUrl,
    /// The ALPNs the endpoint accepts.
    pub alpns: Vec<Vec<u8>>,
    /// The UDP port of both sockets; 0 picks a free one (stage 1: the LAN endpoint keeps the
    /// product's fixed port).
    pub port: u16,
    /// Name resolution.
    pub dns: Dns,
}

/// Binds an endpoint configured as in plan 3.5, with `lookup` as its only address lookup.
///
/// Both address families are bound. Where the system has no IPv6 (disabled in the kernel or the
/// container), the endpoint binds IPv4 alone and logs that it does.
pub async fn bind(
    options: EndpointOptions,
    lookup: impl AddressLookup + Clone,
) -> Result<Endpoint, Error> {
    match bind_families(&options, lookup.clone(), true).await {
        Ok(endpoint) => Ok(endpoint),
        Err(err) => {
            tracing::warn!(error = %err, "cannot bind IPv6; using IPv4 only");
            bind_families(&options, lookup, false).await
        }
    }
}

async fn bind_families(
    options: &EndpointOptions,
    lookup: impl AddressLookup,
    ipv6: bool,
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
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(options.secret_key.clone())
        .alpns(options.alpns.clone())
        .dns_resolver(dns)
        .relay_mode(RelayMode::custom([options.relay_url.clone()]))
        .net_report_config(net_report)
        .clear_address_lookup()
        .address_lookup(lookup)
        // Drops the default sockets of both families; one bind per family follows.
        .clear_ip_transports()
        .bind_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            options.port,
        )))
        .map_err(|err| Error::Bind(err.to_string()))?;
    if ipv6 {
        builder = builder
            .bind_addr(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                options.port,
                0,
                0,
            )))
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
