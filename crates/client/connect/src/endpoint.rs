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
//! - dialing relay first ([`dial`]): the handshake goes over the relay, and iroh's NAT
//!   traversal inside the connection moves it to a direct path. A direct path that works in
//!   one direction only (a host firewall that refuses outbound UDP, an asymmetric filter)
//!   would otherwise hold the handshake until it times out, relay or not, because iroh sends
//!   the Initial on every known path and the peer answers on the first one it heard. The direct
//!   addresses of the control plane are used only when the relay fails (protocol 7.4);
//! - no captive-portal check: iroh would send a plain-HTTP request to port 80 of the relay's
//!   host name (`/generate_204`), whose answer only decides whether the next network report is
//!   a full one. Hosts in mainland China whose domain is not ICP-registered have port 80
//!   intercepted, which reads as a captive portal everywhere; without the check, the relay's
//!   host needs no port 80 for devices. Relay latency still comes from QAD and HTTPS (`/ping`).
//! - on the remote endpoint, short path timers ([`REMOTE_PATH_IDLE_TIMEOUT`],
//!   [`REMOTE_PATH_KEEP_ALIVE_INTERVAL`]): a selected direct path that goes silent is abandoned
//!   after a few seconds instead of iroh's 15, and the connection moves to the relay path,
//!   which stays open beside it (plan V8). The LAN endpoint keeps iroh's timers.
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
//! cannot add a contact: the QUIC transport parameters of [`TransportOptions`] (with the path
//! timers, but not iroh's other multipath and hole-punching settings) and the addresses to
//! bind ([`BindAddresses`]).

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh::{
    Endpoint, EndpointAddr, NetReportConfig, RelayMode, RelayUrl, SecretKey, Watcher as _,
    address_lookup::AddressLookup,
    dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData},
    endpoint::{Connection, QuicTransportConfig, VarInt, presets},
};
use n0_future::boxed::BoxFuture;

use crate::Error;

/// How the endpoint resolves host names (the relay's). The default is [`Dns::Platform`] on
/// HarmonyOS and Android, where an app cannot read the network's DNS servers, and
/// [`Dns::System`] elsewhere, so that a product cannot forget the condition of plan 3.3.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Dns {
    /// The system's configured nameservers, without the public fallback resolvers.
    #[cfg_attr(not(any(target_env = "ohos", target_os = "android")), default)]
    System,
    /// The platform's own resolver (`getaddrinfo`): for HarmonyOS, where the app sees a static
    /// `/etc/resolv.conf` instead of the network's DNS (plan 3.3), and Android.
    #[cfg_attr(any(target_env = "ohos", target_os = "android"), default)]
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

/// How long a path of the remote endpoint may receive nothing before it is abandoned (iroh: 15
/// s). When a selected direct path goes silent (a network that starts dropping UDP, a NAT that
/// forgets the mapping, Wi-Fi gone without a network event), nothing gets through until this
/// timer abandons it: iroh moves the connection to the relay only then, although the relay
/// path is open beside it the whole time (plan V8). Relay paths keep iroh's 30 s, and paths
/// with a long round trip get at least three probe timeouts.
///
/// The price: a working path that receives nothing for this long (a radio gap) is abandoned
/// too, and once a direct path was abandoned, iroh 1.4.1 punches a new one only when an
/// address changes or at its upgrade check, every 60 s. Until then the connection stays on the
/// relay, which still carries it. 3 s abandons the fewest working paths of the values measured
/// (2–3 s); a silent break then reaches the relay about 3.1 s after the drop, longer than
/// Input Show's 2 s key-release timeout, so held keys are released once at the switch.
pub const REMOTE_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(3);

/// How often the remote endpoint pings a path that carries nothing else (iroh: 5 s), so that
/// an idle path outlives [`REMOTE_PATH_IDLE_TIMEOUT`]. It applies to the relay path as well.
pub const REMOTE_PATH_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(1);

/// iroh's path idle timeout and keep-alive interval: what the LAN endpoint keeps, and the
/// largest values iroh accepts.
const IROH_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const IROH_PATH_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// The endpoint a configuration is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    /// [`bind`]: relay and direct paths, with the path timers of plan V8.
    Remote,
    /// [`bind_lan`]: direct paths only, with iroh's path timers.
    Lan,
}

impl Profile {
    /// The path idle timeout and keep-alive interval unless the product sets them.
    fn path_timers(self) -> (Duration, Duration) {
        match self {
            Self::Remote => (REMOTE_PATH_IDLE_TIMEOUT, REMOTE_PATH_KEEP_ALIVE_INTERVAL),
            Self::Lan => (IROH_PATH_IDLE_TIMEOUT, IROH_PATH_KEEP_ALIVE_INTERVAL),
        }
    }
}

/// QUIC transport parameters a product tunes for its protocol, for example Input Show's stream
/// limits, its datagram buffers and the remote profile of plan 3.7. `None` keeps the default:
/// iroh's value, except for the path timers of the remote endpoint.
///
/// The path timers do not touch hole punching: noq opens a direct path only after a NAT
/// traversal probe came back, so a short idle timeout cannot cut a punch short. iroh's other
/// multipath and hole-punching settings (paths, NAT-traversal addresses) are not offered.
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
    /// How long a path may receive nothing before it is abandoned and the connection moves to
    /// another path: [`REMOTE_PATH_IDLE_TIMEOUT`] on the remote endpoint, iroh's 15 s on the
    /// LAN endpoint. At most 15 s. Relay paths keep iroh's 30 s.
    pub path_idle_timeout: Option<Duration>,
    /// How often a path that carries nothing else is pinged:
    /// [`REMOTE_PATH_KEEP_ALIVE_INTERVAL`] on the remote endpoint, iroh's 5 s on the LAN
    /// endpoint. At most 5 s, and at most half the path idle timeout, so that one lost ping
    /// does not end an idle path.
    pub path_keep_alive_interval: Option<Duration>,
}

impl TransportOptions {
    /// The path idle timeout and keep-alive interval for `profile`, checked against each
    /// other and against what iroh accepts (iroh would clamp or ignore larger values with a
    /// warning only).
    fn path_timers(&self, profile: Profile) -> Result<(Duration, Duration), Error> {
        let (idle, keep_alive) = profile.path_timers();
        let idle = self.path_idle_timeout.unwrap_or(idle);
        let keep_alive = self.path_keep_alive_interval.unwrap_or(keep_alive);
        if idle > IROH_PATH_IDLE_TIMEOUT || keep_alive > IROH_PATH_KEEP_ALIVE_INTERVAL {
            return Err(Error::Bind(format!(
                "path timers {idle:?} / {keep_alive:?} exceed iroh's \
                 {IROH_PATH_IDLE_TIMEOUT:?} / {IROH_PATH_KEEP_ALIVE_INTERVAL:?}"
            )));
        }
        if keep_alive.is_zero() || keep_alive * 2 > idle {
            return Err(Error::Bind(format!(
                "path keep-alive {keep_alive:?} must be above zero and at most half the path \
                 idle timeout {idle:?}"
            )));
        }
        Ok((idle, keep_alive))
    }

    /// iroh's transport configuration for `profile` with these values applied, or `None` when
    /// it would be iroh's own.
    fn config(&self, profile: Profile) -> Result<Option<QuicTransportConfig>, Error> {
        let (path_idle, path_keep_alive) = self.path_timers(profile)?;
        if profile == Profile::Lan && *self == Self::default() {
            return Ok(None);
        }
        let mut builder = QuicTransportConfig::builder()
            .default_path_max_idle_timeout(path_idle)
            .default_path_keep_alive_interval(path_keep_alive);
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
    bind_with(&options, Some(lookup), Profile::Remote).await
}

/// Binds the LAN-only endpoint of plan 3.5: no relay and no address lookup, so it contacts
/// nobody but the peers it dials or that dial it (by mDNS results or typed addresses, which
/// the product passes as `EndpointAddr`s). `options.relay_url` must be `None`.
pub async fn bind_lan(options: EndpointOptions) -> Result<Endpoint, Error> {
    if options.relay_url.is_some() {
        return Err(Error::Bind("the LAN endpoint has no relay".to_owned()));
    }
    bind_with::<crate::ControlLookup>(&options, None, Profile::Lan).await
}

async fn bind_with<L: AddressLookup + Clone>(
    options: &EndpointOptions,
    lookup: Option<L>,
    profile: Profile,
) -> Result<Endpoint, Error> {
    let transport = options.transport.config(profile)?;
    let Some(ipv6) = options.bind.ipv6 else {
        return bind_families(options, lookup, transport, None).await;
    };
    match bind_families(options, lookup.clone(), transport.clone(), Some(ipv6)).await {
        Ok(endpoint) => Ok(endpoint),
        Err(err) => {
            tracing::warn!(error = %err, "cannot bind IPv6; using IPv4 only");
            bind_families(options, lookup, transport, None).await
        }
    }
}

async fn bind_families(
    options: &EndpointOptions,
    lookup: Option<impl AddressLookup>,
    transport: Option<QuicTransportConfig>,
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
    if let Some(transport) = transport {
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

/// How long [`dial`] waits for the endpoint's first relay connection, right after the endpoint
/// was bound, before it dials the direct addresses instead. Once a relay connection failed,
/// [`dial`] does not wait.
pub const RELAY_WAIT: Duration = Duration::from_secs(5);

/// How long the handshake over the relay may take before [`dial`] tries the direct addresses.
pub const RELAY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether `endpoint` holds a connection to its home relay.
pub fn relay_connected(endpoint: &Endpoint) -> bool {
    endpoint
        .home_relay_status()
        .get()
        .iter()
        .any(|status| status.is_connected())
}

/// Whether the last attempt to connect to the home relay failed, as in an outage of
/// gono-cloud, whose relay stops with it.
fn relay_failed(endpoint: &Endpoint) -> bool {
    endpoint
        .home_relay_status()
        .get()
        .iter()
        .any(|status| !status.is_connected() && status.last_error().is_some())
}

/// Connects to `addr` for `alpn`, relay first.
///
/// When `addr` names a relay and the endpoint holds its relay connection (waiting up to
/// [`RELAY_WAIT`] for the first one), the handshake goes over the relay alone, and iroh's NAT traversal
/// inside the connection adds a direct path once one works in both directions. The direct
/// addresses of `addr` are dialed only when the relay fails: no relay connection, no relay
/// in `addr`, or no handshake over it within [`RELAY_HANDSHAKE_TIMEOUT`]. A refusal by the peer
/// over a working relay is returned as it is.
///
/// Why not direct first: iroh sends the Initial on every path it knows, and the peer answers
/// on the first copy it receives. If that direct path works one way only, the handshake hangs
/// until it times out, and a relay-only retry fails the same way, because iroh keeps the
/// peer's direct addresses for a minute after the last connection.
pub async fn dial(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    alpn: &[u8],
) -> Result<Connection, Error> {
    if let Some(relay) = addr.relay_urls().next().cloned()
        && (relay_connected(endpoint)
            || (!relay_failed(endpoint)
                && tokio::time::timeout(RELAY_WAIT, endpoint.online())
                    .await
                    .is_ok()))
    {
        let relay_only = EndpointAddr::new(addr.id).with_relay_url(relay);
        match tokio::time::timeout(RELAY_HANDSHAKE_TIMEOUT, endpoint.connect(relay_only, alpn))
            .await
        {
            Ok(Ok(connection)) => return Ok(connection),
            Ok(Err(err)) if relay_connected(endpoint) => {
                return Err(Error::Connect(err.to_string()));
            }
            Ok(Err(err)) => {
                tracing::info!(error = %err, "the relay failed during the handshake; dialing directly");
            }
            Err(_) => tracing::info!(
                "no handshake over the relay within {RELAY_HANDSHAKE_TIMEOUT:?}; dialing directly"
            ),
        }
    }
    endpoint
        .connect(addr, alpn)
        .await
        .map_err(|err| Error::Connect(err.to_string()))
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
    fn the_platform_resolver_is_the_default_where_apps_cannot_read_the_dns_servers() {
        let expected = if cfg!(any(target_env = "ohos", target_os = "android")) {
            Dns::Platform
        } else {
            Dns::System
        };
        assert_eq!(Dns::default(), expected);
    }

    #[test]
    fn transport_options_build_for_the_lan_only_when_set() {
        let lan = TransportOptions::default().config(Profile::Lan).unwrap();
        assert!(lan.is_none(), "the LAN endpoint keeps iroh's configuration");
        let options = TransportOptions {
            max_concurrent_bidi_streams: Some(8),
            max_concurrent_uni_streams: Some(4),
            datagram_receive_buffer_size: Some(64 * 1024),
            datagram_send_buffer_size: Some(64 * 1024),
            max_idle_timeout: Some(Duration::from_secs(20)),
            keep_alive_interval: Some(Duration::from_secs(4)),
            path_idle_timeout: Some(Duration::from_secs(10)),
            path_keep_alive_interval: Some(Duration::from_secs(2)),
        };
        for profile in [Profile::Lan, Profile::Remote] {
            let config = format!("{:?}", options.config(profile).unwrap().unwrap());
            assert!(
                config.contains("default_path_max_idle_timeout: Some(10s)")
                    && config.contains("default_path_keep_alive_interval: Some(2s)"),
                "{config}"
            );
        }
    }

    /// The remote endpoint abandons a silent direct path after a few seconds (plan V8); the
    /// LAN endpoint keeps iroh's 15 s and 5 s.
    #[test]
    fn the_remote_endpoint_has_short_path_timers() {
        let remote = TransportOptions::default().config(Profile::Remote).unwrap();
        let remote = format!(
            "{:?}",
            remote.expect("the remote profile sets the path timers")
        );
        let idle = format!("default_path_max_idle_timeout: Some({REMOTE_PATH_IDLE_TIMEOUT:?})");
        let keep_alive =
            format!("default_path_keep_alive_interval: Some({REMOTE_PATH_KEEP_ALIVE_INTERVAL:?})");
        assert!(
            remote.contains(&idle) && remote.contains(&keep_alive),
            "{remote}"
        );
        // Values the product leaves alone stay iroh's.
        // (noq prints the connection idle timeout in milliseconds.)
        assert!(
            remote.contains(" max_idle_timeout: Some(30000)"),
            "{remote}"
        );
        assert!(
            remote.contains(" keep_alive_interval: Some(5s)"),
            "{remote}"
        );

        let lan = TransportOptions {
            max_concurrent_uni_streams: Some(4),
            ..TransportOptions::default()
        };
        let lan = format!("{:?}", lan.config(Profile::Lan).unwrap().unwrap());
        assert!(
            lan.contains("default_path_max_idle_timeout: Some(15s)")
                && lan.contains("default_path_keep_alive_interval: Some(5s)"),
            "{lan}"
        );
    }

    #[test]
    fn path_timers_iroh_would_clamp_or_that_end_idle_paths_are_refused() {
        let secs = Duration::from_secs;
        for (idle, keep_alive) in [
            (Some(secs(16)), None),
            (None, Some(secs(6))),
            (Some(secs(2)), Some(secs(2))),
            (Some(secs(3)), Some(Duration::from_millis(1600))),
            (None, Some(Duration::ZERO)),
            // The remote default keep-alive is more than half of this.
            (Some(Duration::from_millis(1500)), None),
        ] {
            let options = TransportOptions {
                path_idle_timeout: idle,
                path_keep_alive_interval: keep_alive,
                ..TransportOptions::default()
            };
            assert!(
                matches!(options.config(Profile::Remote), Err(Error::Bind(_))),
                "{idle:?} / {keep_alive:?}"
            );
        }
        // On the LAN, iroh's 5 s keep-alive is more than half of a 9 s idle timeout.
        let lan = TransportOptions {
            path_idle_timeout: Some(secs(9)),
            ..TransportOptions::default()
        };
        assert!(matches!(lan.config(Profile::Lan), Err(Error::Bind(_))));
        assert!(lan.config(Profile::Remote).unwrap().is_some());
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

        let addr = EndpointAddr::from_parts(
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
