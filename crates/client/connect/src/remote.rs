//! The product API of plan 3.3: the endpoint and the control channel together.
//!
//! - [`Remote::start`] binds the endpoint as in plan 3.5, with the server's relay, and opens
//!   the control channel; its events go to the receiver it returns.
//! - [`Remote::connect`] asks the server to connect (`connect`, recorded and announced to the
//!   target) and dials the device by its key, relay first ([`crate::endpoint::dial`]).
//!   [`Remote::connect_for_pairing`] does the same for the approver of a pending pairing
//!   request (protocol 8.2).
//! - [`Remote::accept_trusted_filtered`] is how a product accepts connections: it ignores
//!   relayed attempts from keys the product does not know before any handshake, so that
//!   strangers on the relay get no answer at all (threat model 5.6); it hands out only the
//!   peers whose key the product admits (its trust list, and the key of a pending pairing that
//!   `incoming` announced), closes every other right after the handshake, and limits pending
//!   handshakes and their rate (threat model C8), per source first so that one stranger cannot
//!   keep the user's own devices out. Whether an admitted peer may do anything stays the
//!   product's decision. [`Remote::accept_trusted`] and [`Remote::accept_trusted_with`] do the
//!   same without the filter before the handshake.
//! - [`Remote::network_change`] forwards the platform's network events to the endpoint and the
//!   control channel (plan 3.3; HarmonyOS and Android need it).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use gono_protocol::connect::{DeviceId, Discovery, message::Purpose};
use iroh::{
    Endpoint, EndpointId, RelayUrl, SecretKey,
    endpoint::{Accept, Connection, Incoming, IncomingAddr},
};
use tokio::sync::{Semaphore, mpsc};

use crate::{
    ChannelEvent, ChannelOptions, ControlChannel, ControlLookup, Credentials, Error, Result,
    endpoint::{self, BindAddresses, Dns, EndpointOptions, TransportOptions},
};

/// The QUIC application error code with which [`Remote::accept_trusted`] closes connections
/// from keys the product does not admit.
pub const CLOSE_NOT_TRUSTED: u32 = 403;

/// How many incoming handshakes [`Remote::accept_trusted`] runs at once; more are refused.
const MAX_PENDING_HANDSHAKES: usize = 16;

/// How many incoming handshakes [`Remote::accept_trusted`] starts per second; more are refused.
const HANDSHAKES_PER_SECOND: u32 = 8;

/// How many incoming handshakes of one source run at once; more from it are refused.
const MAX_PENDING_PER_SOURCE: usize = 2;

/// How many incoming handshakes of one source start per second; more from it are refused.
const HANDSHAKES_PER_SOURCE_PER_SECOND: u32 = 2;

/// Sources kept at once. Beyond that, the idle ones are forgotten, and a new source waits
/// until there is room.
const MAX_SOURCES: usize = 1024;

/// How long an incoming handshake may take.
const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What [`Remote::start`] needs. `Debug` leaves the app password and the key out.
#[derive(Debug, Clone)]
pub struct RemoteOptions {
    /// The server's discovery document.
    pub discovery: Discovery,
    /// The device's credential.
    pub credentials: Credentials,
    /// The device's key.
    pub key: SecretKey,
    /// The ALPNs the device accepts. They are also published as its `services` with every
    /// `hello`, unless the channel's settings name `services` themselves.
    pub alpns: Vec<Vec<u8>>,
    /// The UDP port; 0 picks a free one.
    pub port: u16,
    /// The addresses to bind (all interfaces, both families, by default).
    pub bind: BindAddresses,
    /// Name resolution.
    pub dns: Dns,
    /// The product's QUIC transport parameters (plan 3.7: the remote profile).
    pub transport: TransportOptions,
    /// The channel's options beyond the credential: cursor, version, settings, features.
    pub channel: Option<ChannelOptions>,
}

/// See the module documentation.
#[derive(Debug, Clone)]
pub struct Remote {
    endpoint: Endpoint,
    channel: ControlChannel,
    lookup: ControlLookup,
}

/// The channel options of `options`, with the ALPNs as `services` unless the settings name
/// them.
fn channel_options(options: &RemoteOptions) -> ChannelOptions {
    let mut channel = options.channel.clone().unwrap_or_else(|| {
        ChannelOptions::new(
            options.discovery.clone(),
            options.credentials.clone(),
            options.key.clone(),
        )
    });
    let settings = channel.settings.get_or_insert_with(Default::default);
    if settings.services.is_none() {
        settings.services = Some(
            options
                .alpns
                .iter()
                .map(|alpn| String::from_utf8_lossy(alpn).into_owned())
                .collect(),
        );
    }
    channel
}

impl Remote {
    /// Opens the control channel and binds the endpoint. Fails as
    /// [`ControlChannel::start`] does, and when the discovery document's relay URL does not
    /// parse.
    pub async fn start(options: RemoteOptions) -> Result<(Self, mpsc::Receiver<ChannelEvent>)> {
        let relay_url: RelayUrl = options
            .discovery
            .relay_url
            .parse()
            .map_err(|_| Error::Url(options.discovery.relay_url.clone()))?;
        let (channel, events) = ControlChannel::start(channel_options(&options))?;
        let lookup = ControlLookup::new(channel.clone(), relay_url.clone());
        let endpoint = endpoint::bind(
            EndpointOptions {
                secret_key: options.key,
                relay_url: Some(relay_url),
                alpns: options.alpns,
                port: options.port,
                bind: options.bind,
                dns: options.dns,
                transport: options.transport,
            },
            lookup.clone(),
        )
        .await?;
        lookup.watch_relay(&endpoint);
        Ok((
            Self {
                endpoint,
                channel,
                lookup,
            },
            events,
        ))
    }

    /// The iroh endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The control channel.
    pub fn channel(&self) -> &ControlChannel {
        &self.channel
    }

    /// Connects to `device` for `alpn` (protocol 7.2).
    pub async fn connect(&self, device: DeviceId, alpn: &[u8]) -> Result<Connection> {
        self.dial(device, alpn, Purpose::Session, None).await
    }

    /// Connects to the new device of the pending pairing request `request_id` (protocol 8.2,
    /// step 2).
    pub async fn connect_for_pairing(
        &self,
        device: DeviceId,
        alpn: &[u8],
        request_id: String,
    ) -> Result<Connection> {
        self.dial(device, alpn, Purpose::Pair, Some(request_id))
            .await
    }

    async fn dial(
        &self,
        device: DeviceId,
        alpn: &[u8],
        purpose: Purpose,
        request_id: Option<String>,
    ) -> Result<Connection> {
        let service = String::from_utf8_lossy(alpn).into_owned();
        let result = self
            .channel
            .connect_to(device, &service, purpose, request_id)
            .await?;
        let addr = self.lookup.remember(device, &result)?;
        endpoint::dial(&self.endpoint, addr, alpn).await
    }

    /// The next incoming connection attempt, from any key, with no limit.
    ///
    /// Low level: a product accepts with [`Remote::accept_trusted_filtered`] instead, which
    /// ignores relayed strangers, closes unknown keys and limits handshakes (threat model C8).
    /// Do not use both: they take from the same queue.
    pub fn accept(&self) -> Accept<'_> {
        self.endpoint.accept()
    }

    /// Accepts connections in the background and hands out those from keys `allow` admits:
    /// the product's trust list, and the key of a pending pairing that `incoming` announced
    /// (protocol 8.2). Every other connection is closed with [`CLOSE_NOT_TRUSTED`] right after
    /// its handshake. At most a few handshakes run at once and a few start per second; attempts
    /// beyond that are refused before any cryptography (threat model C8).
    ///
    /// `allow` is asked once per connection, after the handshake, so it may read a trust list
    /// that changes. Accepting stops when the endpoint closes or the receiver is dropped.
    ///
    /// Strangers on the relay still complete a handshake here, and with it learn the device's
    /// addresses (threat model 5.6); [`Remote::accept_trusted_filtered`] ignores them first.
    pub fn accept_trusted<F>(&self, allow: F) -> mpsc::Receiver<Connection>
    where
        F: Fn(&EndpointId) -> bool + Send + Sync + 'static,
    {
        self.accept_trusted_with(move |key| {
            if allow(key) {
                Admit::Accept
            } else {
                Admit::not_trusted()
            }
        })
    }

    /// [`Remote::accept_trusted`] with the product's own close codes: `admit` says for each
    /// key whether to hand the connection out, or how to close it (for example a code that
    /// tells a revoked key apart from an unknown one).
    ///
    /// Strangers on the relay still complete a handshake here, and with it learn the device's
    /// addresses (threat model 5.6); [`Remote::accept_trusted_filtered`] ignores them first.
    pub fn accept_trusted_with<F>(&self, admit: F) -> mpsc::Receiver<Connection>
    where
        F: Fn(&EndpointId) -> Admit + Send + Sync + 'static,
    {
        accept_trusted(self.endpoint.clone(), None, Arc::new(admit))
    }

    /// [`Remote::accept_trusted_with`] that first ignores relayed attempts from keys `known`
    /// refuses, before any handshake, and so before any budget (threat model 5.6).
    ///
    /// A relayed attempt names its sender before any cryptography: the relay labels every
    /// frame with the key its sender proved when it connected (protocol 11.1). When `known`
    /// refuses that key, the attempt is ignored: nothing at all goes back, no handshake, no
    /// close and no refusal, so the stranger learns neither the device's addresses nor, with an
    /// ordinary QUIC client, that it is online. (A crafted packet of an unknown QUIC version
    /// still gets noq's version negotiation answer, which says only that.) iroh hands the
    /// device's addresses to every peer that completes a handshake, and probes the addresses
    /// the peer names, before the product can close the connection (threat model 5.6); this
    /// keeps relayed strangers from getting that far.
    ///
    /// **What `known` holds.** Every key the product could admit, or wants to close with a code
    /// of its own; nothing else, because each key in it can learn the device's addresses
    /// (threat model G5):
    /// - a product with a trust list passes the entries the remote endpoint admits (`remote`,
    ///   protocol 8.1) and the key of the device's own pending pairing that `incoming`
    ///   announced (8.2). `known` asks the product's state each time, so a pairing key it
    ///   learns from the channel counts at the dialer's next retransmission, about a second
    ///   later at worst;
    /// - Input Show passes the account's devices, so that each still gets its own close code
    ///   from `admit` (blocked, stale, remote access off).
    ///
    /// **Rules for `known`:**
    /// - it is a pure predicate, cheap and without side effects: it runs on the accept loop for
    ///   every relayed connection attempt, retransmissions included, before any limit, and
    ///   `admit` is still asked once after the handshake for each key it lets through. A
    ///   key-by-key budget belongs in `admit`;
    /// - it says only whether the key may start a handshake. Whether that key may connect now
    ///   (permissions, blocking, staleness) stays with `admit`, which gives each its close code.
    ///
    /// **What it does not cover:**
    /// - direct attempts (from an IP address), which name no key before the handshake: they
    ///   complete it and are closed by `admit` as before (threat model 5.6, plan V9);
    /// - a relay that lies about the sender, which is a compromised server (threat model 5.1,
    ///   5.2): the key proven in the handshake is checked by `admit` as before.
    pub fn accept_trusted_filtered<K, F>(&self, known: K, admit: F) -> mpsc::Receiver<Connection>
    where
        K: Fn(&EndpointId) -> bool + Send + Sync + 'static,
        F: Fn(&EndpointId) -> Admit + Send + Sync + 'static,
    {
        accept_trusted(
            self.endpoint.clone(),
            Some(Arc::new(known)),
            Arc::new(admit),
        )
    }

    /// Tells the endpoint and the control channel that the network changed
    /// ([`ControlChannel::network_changed`]): the channel reconnects at once instead of after
    /// its backoff, so the server sees the device online again as soon as its network is back.
    pub async fn network_change(&self) {
        self.channel.network_changed();
        self.endpoint.network_change().await;
    }

    /// Closes the endpoint. The control channel ends when its last handle is dropped.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// What [`Remote::accept_trusted_with`] does with a connection once its handshake is done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admit {
    /// Hand it to the product.
    Accept,
    /// Close it with this QUIC application error code and reason.
    Close {
        /// The application error code.
        code: u32,
        /// The reason, at most a few bytes the peer may show or log.
        reason: Vec<u8>,
    },
}

impl Admit {
    /// Close with [`CLOSE_NOT_TRUSTED`], as [`Remote::accept_trusted`] does.
    pub fn not_trusted() -> Self {
        Self::Close {
            code: CLOSE_NOT_TRUSTED,
            reason: b"not trusted".to_vec(),
        }
    }
}

/// The product's decision over the remote key.
type Allow = Arc<dyn Fn(&EndpointId) -> Admit + Send + Sync>;

/// The keys the product knows: see [`Remote::accept_trusted_filtered`].
type Known = Arc<dyn Fn(&EndpointId) -> bool + Send + Sync>;

/// At most `limit` events per second, counted in fixed one-second windows.
#[derive(Debug)]
struct Rate {
    limit: u32,
    window: Instant,
    count: u32,
}

impl Rate {
    fn new(limit: u32, now: Instant) -> Self {
        Self {
            limit,
            window: now,
            count: 0,
        }
    }

    /// Whether one more event is allowed at `now`; counts it if so.
    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.count = 0;
        }
        if self.count >= self.limit {
            return false;
        }
        self.count += 1;
        true
    }
}

/// Where an incoming connection attempt comes from, as far as fairness goes (threat model 5.6):
/// the relay's source label for relayed attempts (an honest relay labels frames with the
/// sender's authenticated key; this is a pre-filter, not authentication), and the IP address
/// for direct ones, IPv6 by its /64, which one host usually holds as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Relayed(EndpointId),
    Ipv4([u8; 4]),
    Ipv6([u8; 8]),
    Other,
}

impl Source {
    fn of(addr: &IncomingAddr) -> Self {
        match addr {
            IncomingAddr::Relay { endpoint_id, .. } => Self::Relayed(*endpoint_id),
            IncomingAddr::Ip(addr) => match addr.ip().to_canonical() {
                IpAddr::V4(ip) => Self::Ipv4(ip.octets()),
                IpAddr::V6(ip) => {
                    let mut prefix = [0; 8];
                    prefix.copy_from_slice(&ip.octets()[..8]);
                    Self::Ipv6(prefix)
                }
            },
            _ => Self::Other,
        }
    }
}

/// Handshakes in progress and started per source.
#[derive(Debug)]
struct SourceBudget {
    pending: usize,
    rate: Rate,
}

/// The per-source budgets, shared with the handshake tasks that give their slot back.
#[derive(Debug, Default)]
struct Sources(Mutex<HashMap<Source, SourceBudget>>);

impl Sources {
    /// Takes a slot for `source` at `now`, or says why there is none.
    fn take(&self, source: Source, now: Instant) -> Result<(), &'static str> {
        let mut sources = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !sources.contains_key(&source) && sources.len() >= MAX_SOURCES {
            sources.retain(|_, budget| {
                budget.pending > 0
                    || now.duration_since(budget.rate.window) < Duration::from_secs(1)
            });
            if sources.len() >= MAX_SOURCES {
                return Err("too many sources at once");
            }
        }
        let budget = sources.entry(source).or_insert_with(|| SourceBudget {
            pending: 0,
            rate: Rate::new(HANDSHAKES_PER_SOURCE_PER_SECOND, now),
        });
        if budget.pending >= MAX_PENDING_PER_SOURCE {
            return Err("too many pending handshakes from this source");
        }
        if !budget.rate.allow(now) {
            return Err("too many handshakes per second from this source");
        }
        budget.pending += 1;
        Ok(())
    }

    /// Gives the slot of `source` back once its handshake ended.
    fn give_back(&self, source: Source) {
        let mut sources = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(budget) = sources.get_mut(&source) {
            budget.pending = budget.pending.saturating_sub(1);
        }
    }
}

/// See [`Remote::accept_trusted`] and [`Remote::accept_trusted_filtered`].
fn accept_trusted(
    endpoint: Endpoint,
    known: Option<Known>,
    allow: Allow,
) -> mpsc::Receiver<Connection> {
    let (accepted, receiver) = mpsc::channel(MAX_PENDING_HANDSHAKES);
    tokio::spawn(accept_loop(endpoint, known, allow, accepted));
    receiver
}

/// Takes every connection attempt off the endpoint at once (so noq's own queue of 65536, which
/// iroh 1.4.1 cannot lower, never fills), ignores relayed ones from keys `known` refuses,
/// refuses those beyond the budgets before any cryptography, and runs the rest. The budget of a
/// source is checked before the endpoint's, so that one source refused does not use up the
/// endpoint's rate.
async fn accept_loop(
    endpoint: Endpoint,
    known: Option<Known>,
    allow: Allow,
    accepted: mpsc::Sender<Connection>,
) {
    let handshakes = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let sources = Arc::new(Sources::default());
    let mut rate = Rate::new(HANDSHAKES_PER_SECOND, Instant::now());
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                // The endpoint closed.
                None => return,
            },
            () = accepted.closed() => return,
        };
        let addr = incoming.remote_addr();
        // Before the budgets, so that strangers use up none of them. `ignore`, not `refuse`:
        // a refusal is an answer, and any answer tells the stranger that the device is online.
        // A retransmitted Initial arrives as a new attempt and is asked about again.
        if let (Some(known), IncomingAddr::Relay { endpoint_id, .. }) = (&known, &addr)
            && !known(endpoint_id)
        {
            tracing::debug!(peer = %endpoint_id.fmt_short(), "ignoring a relayed attempt from a key the product does not know");
            incoming.ignore();
            continue;
        }
        let now = Instant::now();
        let source = Source::of(&addr);
        if let Err(reason) = sources.take(source, now) {
            tracing::debug!(?source, "refusing a connection: {reason}");
            incoming.refuse();
            continue;
        }
        let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            sources.give_back(source);
            tracing::debug!("refusing a connection: too many pending handshakes");
            incoming.refuse();
            continue;
        };
        if !rate.allow(now) {
            sources.give_back(source);
            tracing::debug!("refusing a connection: too many handshakes per second");
            incoming.refuse();
            continue;
        }
        let allow = Arc::clone(&allow);
        let accepted = accepted.clone();
        let sources = Arc::clone(&sources);
        tokio::spawn(async move {
            let _permit = permit;
            let connection = handshake(incoming, &allow).await;
            sources.give_back(source);
            if let Some(connection) = connection {
                let _ = accepted.send(connection).await;
            }
        });
    }
}

/// Runs the handshake of `incoming`; returns the connection if `allow` admits its key, and
/// closes it otherwise.
async fn handshake(incoming: Incoming, allow: &Allow) -> Option<Connection> {
    let connection = match tokio::time::timeout(ACCEPT_HANDSHAKE_TIMEOUT, incoming).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "an incoming handshake failed");
            return None;
        }
        Err(_) => {
            tracing::debug!("an incoming handshake timed out");
            return None;
        }
    };
    let remote = connection.remote_id();
    match allow(&remote) {
        Admit::Accept => Some(connection),
        Admit::Close { code, reason } => {
            tracing::info!(peer = %remote.fmt_short(), code, "closing a connection from a key the product does not admit");
            connection.close(code.into(), &reason);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use gono_protocol::connect::{VERSION, message::SettingsChange};

    use super::*;
    use crate::tests::credentials;

    fn options(channel: Option<ChannelOptions>) -> RemoteOptions {
        let discovery = Discovery {
            version: VERSION,
            server: "https://cloud.example.com".to_owned(),
            login: "https://cloud.example.com/gono/v1/login".to_owned(),
            websocket: "wss://cloud.example.com/gono/v1/ws".to_owned(),
            relay_url: "https://relay.example.com/".to_owned(),
            two_factor_required: true,
        };
        RemoteOptions {
            discovery,
            credentials: credentials("https://cloud.example.com", 1),
            key: SecretKey::from_bytes(&[1; 32]),
            alpns: vec![b"inputshow/1".to_vec()],
            port: 0,
            bind: Default::default(),
            dns: Dns::System,
            transport: Default::default(),
            channel,
        }
    }

    #[test]
    fn alpns_are_published_as_services() {
        let published = channel_options(&options(None));
        assert_eq!(
            published.settings.and_then(|settings| settings.services),
            Some(vec!["inputshow/1".to_owned()])
        );

        // Settings of the product keep their own services, and gain the ALPNs otherwise.
        let mut own = channel_options(&options(None));
        own.settings = Some(SettingsChange {
            services: Some(Vec::new()),
            ..SettingsChange::default()
        });
        let kept = channel_options(&options(Some(own.clone())));
        assert_eq!(kept.settings.unwrap().services, Some(Vec::new()));
        own.settings = Some(SettingsChange {
            accept_remote: Some(true),
            ..SettingsChange::default()
        });
        let filled = channel_options(&options(Some(own))).settings.unwrap();
        assert_eq!(filled.accept_remote, Some(true));
        assert_eq!(filled.services, Some(vec!["inputshow/1".to_owned()]));
    }

    #[test]
    fn debug_leaves_secrets_out() {
        let options = options(Some(channel_options(&options(None))));
        let text = format!("{options:?}");
        assert!(!text.contains("secret"), "{text}");
    }

    #[test]
    fn handshakes_are_rate_limited() {
        let start = Instant::now();
        let mut rate = Rate::new(2, start);
        assert!(rate.allow(start));
        assert!(rate.allow(start + Duration::from_millis(10)));
        assert!(!rate.allow(start + Duration::from_millis(20)));
        assert!(rate.allow(start + Duration::from_secs(1)));
    }

    #[test]
    fn one_source_cannot_use_up_the_budget_of_others() {
        let sources = Sources::default();
        let start = Instant::now();
        let stranger = Source::Ipv4([198, 51, 100, 7]);
        assert!(sources.take(stranger, start).is_ok());
        assert!(sources.take(stranger, start).is_ok());
        assert!(
            sources.take(stranger, start).is_err(),
            "two pending at most"
        );
        // Others still get in.
        let relayed = Source::Relayed(SecretKey::from_bytes(&[4; 32]).public());
        assert!(sources.take(relayed, start).is_ok());
        assert!(sources.take(Source::Ipv4([192, 0, 2, 1]), start).is_ok());
        // A slot given back is usable again, within the rate.
        sources.give_back(stranger);
        assert!(
            sources.take(stranger, start).is_err(),
            "two per second at most"
        );
        assert!(
            sources
                .take(stranger, start + Duration::from_secs(1))
                .is_ok()
        );
    }

    #[test]
    fn sources_are_keyed_by_relay_label_ipv4_address_and_ipv6_slash_64() {
        let key = SecretKey::from_bytes(&[5; 32]).public();
        let relayed = IncomingAddr::Relay {
            url: "https://relay.example.com".parse().unwrap(),
            endpoint_id: key,
        };
        assert_eq!(Source::of(&relayed), Source::Relayed(key));
        let ip = |addr: &str| Source::of(&IncomingAddr::Ip(addr.parse().unwrap()));
        assert_eq!(ip("198.51.100.7:1"), ip("198.51.100.7:2"));
        assert_ne!(ip("198.51.100.7:1"), ip("198.51.100.8:1"));
        assert_eq!(ip("[::ffff:198.51.100.7]:1"), ip("198.51.100.7:1"));
        assert_eq!(ip("[2001:db8:1:2::1]:1"), ip("[2001:db8:1:2:ffff::9]:1"));
        assert_ne!(ip("[2001:db8:1:2::1]:1"), ip("[2001:db8:1:3::1]:1"));
    }

    #[test]
    fn idle_sources_are_forgotten_when_the_table_is_full() {
        let sources = Sources::default();
        let start = Instant::now();
        for i in 0..MAX_SOURCES {
            let source = Source::Ipv4((i as u32).to_be_bytes());
            sources.take(source, start).unwrap();
            sources.give_back(source);
        }
        assert!(sources.take(Source::Ipv4([10, 0, 0, 1]), start).is_err());
        let later = start + Duration::from_secs(2);
        assert!(sources.take(Source::Ipv4([10, 0, 0, 1]), later).is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_product_chooses_the_close_code() {
        const ALPN: &[u8] = b"test/1";
        let bind = |seed: u8| {
            Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(SecretKey::from_bytes(&[seed; 32]))
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(iroh::RelayMode::Disabled)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .bind()
        };
        let (server, revoked) = (bind(5).await.unwrap(), bind(6).await.unwrap());
        let _accepted = accept_trusted(
            server.clone(),
            None,
            Arc::new(|_: &EndpointId| Admit::Close {
                code: 4403,
                reason: b"revoked".to_vec(),
            }),
        );
        let addr = iroh::EndpointAddr::from_parts(
            server.id(),
            server
                .bound_sockets()
                .into_iter()
                .map(iroh::TransportAddr::Ip),
        );
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            revoked.connect(addr, ALPN).await.unwrap().closed().await
        })
        .await
        .unwrap();
        assert!(
            matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(close) if close.error_code == 4403u32.into() && close.reason.as_ref() == b"revoked"),
            "{closed:?}"
        );
        for endpoint in [server, revoked] {
            endpoint.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn untrusted_keys_are_closed_after_the_handshake() {
        const ALPN: &[u8] = b"test/1";
        let bind = |seed: u8| {
            Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(SecretKey::from_bytes(&[seed; 32]))
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(iroh::RelayMode::Disabled)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .bind()
        };
        let (server, trusted, stranger) = (
            bind(1).await.unwrap(),
            bind(2).await.unwrap(),
            bind(3).await.unwrap(),
        );
        let trusted_key = trusted.id();
        let mut accepted = accept_trusted(
            server.clone(),
            None,
            Arc::new(move |key| {
                if *key == trusted_key {
                    Admit::Accept
                } else {
                    Admit::not_trusted()
                }
            }),
        );
        let addr = iroh::EndpointAddr::from_parts(
            server.id(),
            server
                .bound_sockets()
                .into_iter()
                .map(iroh::TransportAddr::Ip),
        );

        // The stranger completes its handshake and is closed at once.
        let refused = tokio::time::timeout(Duration::from_secs(10), async {
            stranger
                .connect(addr.clone(), ALPN)
                .await
                .unwrap()
                .closed()
                .await
        })
        .await
        .unwrap();
        assert!(
            matches!(&refused, iroh::endpoint::ConnectionError::ApplicationClosed(close) if close.error_code == CLOSE_NOT_TRUSTED.into()),
            "{refused:?}"
        );
        // The trusted key comes through, and only it.
        let _connection = trusted.connect(addr, ALPN).await.unwrap();
        let incoming = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(incoming.remote_id(), trusted.id());
        assert!(accepted.try_recv().is_err());

        for endpoint in [server, trusted, stranger] {
            endpoint.close().await;
        }
    }

    /// Through the relay: a relay on loopback (as in `examples/udp-paths.rs`), remote
    /// endpoints bound as [`Remote::start`] binds them, and a tap that shows what the device
    /// sends a stranger.
    mod relayed {
        use std::{
            net::{Ipv4Addr, SocketAddr},
            sync::atomic::{AtomicUsize, Ordering},
        };

        use futures_util::{SinkExt, StreamExt};
        use iroh::{EndpointAddr, address_lookup::MemoryLookup, dns::DnsResolver};
        use iroh_relay::{
            client::ClientBuilder,
            protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
            server::{RelayConfig, Server, ServerConfig},
        };
        use tokio::net::UdpSocket;

        use super::*;

        const ALPN: &[u8] = b"test/1";

        /// How long a stranger waits for an answer that must not come. The dialer's first
        /// retransmission comes after about 1 s (noq's initial RTT of 333 ms), so the device
        /// is asked at least twice.
        const SILENCE: Duration = Duration::from_millis(2500);

        async fn relay() -> (Server, RelayUrl) {
            let mut config = ServerConfig::default();
            config.relay = Some(RelayConfig::new(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ));
            let server = Server::spawn(config).await.unwrap();
            let url = format!("http://{}", server.http_addr().unwrap())
                .parse()
                .unwrap();
            (server, url)
        }

        /// A remote endpoint with the relay at `url`, online.
        async fn remote(seed: u8, url: &RelayUrl) -> Endpoint {
            let endpoint = endpoint::bind(
                EndpointOptions {
                    secret_key: SecretKey::from_bytes(&[seed; 32]),
                    relay_url: Some(url.clone()),
                    alpns: vec![ALPN.to_vec()],
                    port: 0,
                    bind: BindAddresses {
                        ipv4: Ipv4Addr::LOCALHOST,
                        ipv6: None,
                    },
                    dns: Dns::System,
                    transport: TransportOptions::default(),
                },
                MemoryLookup::new(),
            )
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(10), endpoint.online())
                .await
                .unwrap();
            endpoint
        }

        /// An endpoint without relay, for dialing through a [`tap`].
        async fn plain(key: &SecretKey) -> Endpoint {
            Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(key.clone())
                .relay_mode(iroh::RelayMode::Disabled)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .bind()
                .await
                .unwrap()
        }

        /// A way to `target` through the relay that counts what comes back. The returned UDP
        /// address stands for `target`: the tap passes each datagram it receives on to
        /// `target` over the relay, as the relay client of `label` (so `target` sees an attempt
        /// relayed from `label`), and passes `target`'s answers back. The counter is the
        /// relay's datagram frames from `target` to `label`: every packet `target` sends back.
        async fn tap(
            url: &RelayUrl,
            label: &SecretKey,
            target: EndpointId,
        ) -> (SocketAddr, Arc<AtomicUsize>) {
            // A plain-HTTP relay uses no TLS, but the client wants a configuration.
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
            let client = ClientBuilder::new(url.clone(), label.clone(), DnsResolver::new())
                .tls_client_config(tls)
                .connect()
                .await
                .unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let answers = Arc::new(AtomicUsize::new(0));
            tokio::spawn({
                let answers = Arc::clone(&answers);
                async move {
                    let (mut from_relay, mut to_relay) = client.split();
                    let mut dialer = None;
                    let mut buf = vec![0; 65536];
                    loop {
                        tokio::select! {
                            received = socket.recv_from(&mut buf) => {
                                let Ok((len, from)) = received else { return };
                                dialer = Some(from);
                                let message = ClientToRelayMsg::Datagrams {
                                    dst_endpoint_id: target,
                                    datagrams: Datagrams::from(&buf[..len]),
                                };
                                if to_relay.send(message).await.is_err() {
                                    return;
                                }
                            }
                            message = from_relay.next() => match message {
                                Some(Ok(RelayToClientMsg::Datagrams {
                                    remote_endpoint_id: sender,
                                    datagrams,
                                })) if sender == target => {
                                    answers.fetch_add(1, Ordering::SeqCst);
                                    let Some(dialer) = dialer else { continue };
                                    // One frame may hold a batch of equal-sized datagrams.
                                    let size = datagrams.segment_size.map(|size| size.get());
                                    let size = size.map_or(datagrams.contents.len(), usize::from);
                                    for datagram in datagrams.contents.chunks(size.max(1)) {
                                        let _ = socket.send_to(datagram, dialer).await;
                                    }
                                }
                                Some(Ok(RelayToClientMsg::Ping(data))) => {
                                    let _ = to_relay.send(ClientToRelayMsg::Pong(data)).await;
                                }
                                Some(Ok(_)) => {}
                                _ => return,
                            },
                        }
                    }
                }
            });
            (addr, answers)
        }

        /// The keys `known` was asked about, and a predicate that records them.
        fn recording(
            known: impl Fn(&EndpointId) -> bool + Send + Sync + 'static,
        ) -> (Arc<Mutex<Vec<EndpointId>>>, Known) {
            let asked = Arc::new(Mutex::new(Vec::new()));
            let record = Arc::clone(&asked);
            let known: Known = Arc::new(move |key: &EndpointId| {
                record.lock().unwrap().push(*key);
                known(key)
            });
            (asked, known)
        }

        fn admit_only(keys: Vec<EndpointId>) -> Allow {
            Arc::new(move |key| {
                if keys.contains(key) {
                    Admit::Accept
                } else {
                    Admit::not_trusted()
                }
            })
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn relayed_strangers_get_no_answer_at_all() {
            let (_relay, url) = relay().await;
            let device = remote(1, &url).await;
            let (stranger, liar) = (
                SecretKey::from_bytes(&[2; 32]),
                SecretKey::from_bytes(&[3; 32]),
            );
            let known_keys = vec![liar.public()];
            let (asked, known) = recording({
                let known_keys = known_keys.clone();
                move |key| known_keys.contains(key)
            });
            let mut accepted = accept_trusted(device.clone(), Some(known), admit_only(known_keys));

            // A stranger dials through the relay: no handshake, no close, no packet of any
            // kind comes back, so no address either; and with no handshake the device never
            // acts on the stranger's NAT-traversal frames, so it probes nothing.
            let (through, answers) = tap(&url, &stranger, device.id()).await;
            let dialer = plain(&stranger).await;
            let dialed = tokio::time::timeout(
                SILENCE,
                dialer.connect(EndpointAddr::new(device.id()).with_ip_addr(through), ALPN),
            )
            .await;
            assert!(dialed.is_err(), "the stranger got an answer: {dialed:?}");
            assert_eq!(
                answers.load(Ordering::SeqCst),
                0,
                "packets back to the stranger"
            );
            let asked_about_stranger = asked
                .lock()
                .unwrap()
                .iter()
                .filter(|key| **key == stranger.public())
                .count();
            assert!(
                asked_about_stranger >= 2,
                "the attempt and its retransmission reach the device and are ignored each time: {asked_about_stranger}"
            );
            assert!(accepted.try_recv().is_err());

            // A relay that lies, labelling the stranger's packets with a key the device
            // knows, gets the stranger through the filter but not past the check after the
            // handshake. (The tap stands for that relay; it also shows that answers would be
            // counted.)
            let (through, answers) = tap(&url, &liar, device.id()).await;
            let dialer = plain(&stranger).await;
            let closed = tokio::time::timeout(Duration::from_secs(10), async {
                dialer
                    .connect(EndpointAddr::new(device.id()).with_ip_addr(through), ALPN)
                    .await
                    .unwrap()
                    .closed()
                    .await
            })
            .await
            .unwrap();
            assert!(
                matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(close) if close.error_code == CLOSE_NOT_TRUSTED.into()),
                "{closed:?}"
            );
            assert!(answers.load(Ordering::SeqCst) > 0);
            assert!(accepted.try_recv().is_err());

            device.close().await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn known_keys_connect_through_the_relay() {
            let (_relay, url) = relay().await;
            let (device, own, pairing) = (
                remote(1, &url).await,
                remote(2, &url).await,
                remote(3, &url).await,
            );
            let (own_key, pairing_key) = (own.id(), pairing.id());
            // The pairing key becomes known only after its first attempt, as when `incoming`
            // reaches the product a moment after the dialer's first packet.
            let (asked, known) = recording({
                let seen = AtomicUsize::new(0);
                move |key| {
                    *key == own_key
                        || (*key == pairing_key && seen.fetch_add(1, Ordering::SeqCst) > 0)
                }
            });
            let mut accepted = accept_trusted(
                device.clone(),
                Some(known),
                admit_only(vec![own_key, pairing_key]),
            );
            let target = EndpointAddr::new(device.id()).with_relay_url(url.clone());

            // A device of the account dials as gono-connect does, relay first.
            let _connection = endpoint::dial(&own, target.clone(), ALPN).await.unwrap();
            let incoming = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(incoming.remote_id(), own_key);
            assert!(
                asked.lock().unwrap().contains(&own_key),
                "the handshake came over the relay"
            );

            // The late key gets in with its retransmission.
            let _connection = endpoint::dial(&pairing, target, ALPN).await.unwrap();
            let incoming = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(incoming.remote_id(), pairing_key);
            let asked_about_pairing = asked
                .lock()
                .unwrap()
                .iter()
                .filter(|key| **key == pairing_key)
                .count();
            assert!(asked_about_pairing >= 2, "{asked_about_pairing}");

            for endpoint in [device, own, pairing] {
                endpoint.close().await;
            }
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn without_known_relayed_strangers_complete_the_handshake_as_before() {
            let (_relay, url) = relay().await;
            let device = remote(1, &url).await;
            let stranger = SecretKey::from_bytes(&[2; 32]);
            let mut accepted = accept_trusted(device.clone(), None, admit_only(Vec::new()));

            let (through, answers) = tap(&url, &stranger, device.id()).await;
            let dialer = plain(&stranger).await;
            let closed = tokio::time::timeout(Duration::from_secs(10), async {
                dialer
                    .connect(EndpointAddr::new(device.id()).with_ip_addr(through), ALPN)
                    .await
                    .unwrap()
                    .closed()
                    .await
            })
            .await
            .unwrap();
            assert!(
                matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(close) if close.error_code == CLOSE_NOT_TRUSTED.into()),
                "{closed:?}"
            );
            assert!(answers.load(Ordering::SeqCst) > 0);
            assert!(accepted.try_recv().is_err());

            device.close().await;
        }

        /// What `ignore` cannot hide: noq answers a packet of an unknown QUIC version with a
        /// version negotiation packet itself, before any connection attempt exists. So a crafted
        /// stranger still learns that the device is online, though nothing else (threat model
        /// 5.6, R7). If this fails, that note can go.
        #[tokio::test(flavor = "multi_thread")]
        async fn version_negotiation_still_answers_relayed_strangers() {
            let (_relay, url) = relay().await;
            let device = remote(1, &url).await;
            let stranger = SecretKey::from_bytes(&[2; 32]);
            let _accepted = accept_trusted(
                device.clone(),
                Some(Arc::new(|_: &EndpointId| false)),
                admit_only(Vec::new()),
            );

            let (through, answers) = tap(&url, &stranger, device.id()).await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            // A long header (form and fixed bits) of the unknown version 0x1a2a3a4a, with
            // 8-byte connection IDs, padded as an Initial must be.
            let mut packet = vec![0; 1200];
            packet[..6].copy_from_slice(&[0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8]);
            packet[6..14].copy_from_slice(&[1; 8]);
            packet[14] = 8;
            packet[15..23].copy_from_slice(&[2; 8]);
            socket.send_to(&packet, through).await.unwrap();
            let mut buf = [0; 1500];
            let (len, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert!(len > 5 && buf[0] & 0x80 != 0, "a long header");
            assert_eq!(buf[1..5], [0; 4], "version 0: version negotiation");
            assert!(answers.load(Ordering::SeqCst) > 0);

            device.close().await;
        }
    }
}
