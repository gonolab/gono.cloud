//! The control channel (protocol 5): one WebSocket to the server, kept open by a background
//! task that reconnects with backoff and hands the product its events.
//!
//! - **Origin.** The channel talks to the origin of its credential only: the discovery
//!   document must name it, its WebSocket URL must be on it (`wss`, or `ws` on a loopback
//!   host), and the `hello` statement names it (see `origin.rs`).
//! - **Opening.** The resolved addresses are tried with a staggered fallback between the
//!   address families (RFC 8305), each attempt for at most [`CONNECT_ATTEMPT_TIMEOUT`], so
//!   that a black-holed IPv6 path costs a quarter of a second, not the system's connect
//!   timeout. Opening (DNS, TCP, TLS, the upgrade) takes at most [`OPEN_TIMEOUT`].
//! - **Handshake.** Basic authentication with the device's app password, the server's
//!   `challenge`, a `hello` signed with the device key, and the `welcome`
//!   ([`ChannelEvent::Connected`]).
//! - **Liveness.** The server pings every 30 seconds. A connection on which nothing arrives,
//!   pings included, for [`SILENCE_TIMEOUT`] is taken for dead and opened again.
//!   [`ControlChannel::last_heard`] tells when the server was last heard from (threat model
//!   C14).
//! - **Network changes** ([`ControlChannel::network_changed`]). A change ends the wait
//!   between attempts at once, unless the server named the wait, and starts the backoff over;
//!   it abandons an attempt still opening or in its handshake; and on a connection that is up,
//!   it sends a ping and leaves the connection if nothing arrives within [`PROBE_TIMEOUT`]. So
//!   the channel is back about as soon as the network is, not after the backoff. Attempts
//!   still start at least [`NETWORK_RETRY_SPACING`] apart, and a change brings one forward only
//!   while fewer than [`EARLY_ATTEMPTS_PER_MINUTE`] started in the last minute, which keeps a
//!   flapping network below the server's limit of 20 a minute (protocol 5.2).
//! - **Requests** ([`ControlChannel::request`] and its typed helpers) wait while the channel
//!   reconnects, for at most [`REQUEST_TIMEOUT`].
//! - **Events** reach the product as [`ChannelEvent::Message`]. The logged ones carry a `seq`:
//!   the product acts on them and then calls [`ControlChannel::ack`], which moves the cursor
//!   the next `hello` sends (protocol 5.6). Types this crate does not know are ignored
//!   (protocol 5.3), in `welcome.events` too.
//! - **Limits.** Messages and frames from the server are at most [`MAX_MESSAGE_BYTES`].
//! - **The end.** A revoked device (`4003`), a device signed out or replaced, credentials the
//!   server no longer knows (`401`), a `hello` the server refuses for good (`bad_signature`,
//!   `bad_request`, `not_found`, `not_permitted`; the close code that follows the `error`
//!   decides first, so `4003` there is a revocation) and a second protocol violation
//!   (`4008`) in a row end the channel for good ([`ChannelEvent::Ended`]); everything else is
//!   retried. `503`, `1011`, an `unavailable` answer to `hello` and other server problems are
//!   never taken for "signed out" (threat model C6).

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_util::{SinkExt as _, StreamExt as _, stream::FuturesUnordered};
use gono_protocol::connect::{
    ClientMessage, DeviceId, Discovery, ErrorCode, ServerMessage, Signed, Statement, close,
    features, limits,
    message::{
        AddressResult, HelloMessage, PairRequestResult, Purpose, SessionReport, SettingsChange,
        SettingsResult, Welcome,
    },
    statement::Hello,
};
use iroh::SecretKey;
use rand::RngExt as _;
use serde::de::DeserializeOwned;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{mpsc, oneshot, watch},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        self, Message,
        client::IntoClientRequest as _,
        protocol::{CloseFrame, WebSocketConfig},
    },
};
use url::{Host, Url};

use crate::{Credentials, Error, Result, origin::Origin, tls};

/// How long a request waits for its answer, reconnects included.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long opening a connection may take: name resolution, TCP, TLS and the upgrade.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// How long one TCP connection attempt may take.
pub const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an attempt runs alone before the next address is tried as well (RFC 8305's
/// connection attempt delay).
const CONNECT_STAGGER: Duration = Duration::from_millis(250);

/// How long the server may take to send `challenge` and `welcome`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a connection may stay silent, pings included, before it is taken for dead: two
/// and a half ping intervals (protocol 5.4).
pub const SILENCE_TIMEOUT: Duration = Duration::from_secs(limits::PING_INTERVAL_SECS * 5 / 2);

/// How often answers that nobody waits for any more are dropped.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// The first wait between reconnects.
const FIRST_BACKOFF: Duration = Duration::from_secs(1);

/// The longest wait between reconnects.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The least time between the starts of two attempts when a network change brings the next
/// one forward.
pub const NETWORK_RETRY_SPACING: Duration = Duration::from_secs(1);

/// A network change brings an attempt forward only while fewer attempts than this started in
/// the last minute; then the backoff applies. With the backoff that follows, a device stays
/// below the server's 20 `hello`s a minute (protocol 5.2) however often its network flaps.
pub const EARLY_ATTEMPTS_PER_MINUTE: usize = 10;

/// How long a connection that is up may stay silent after a network change, once pinged: a
/// connection on an interface that went away answers nothing, and would otherwise count as
/// connected until [`SILENCE_TIMEOUT`].
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait after `404` (remote access off) or `4004` (account disabled).
const SLOW_RETRY: Duration = Duration::from_secs(60 * 60);

/// The bounds of a `Retry-After` or `retry_after` the server names.
const RETRY_AFTER: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60 * 60));

/// The largest message or frame read from the server. The server keeps every message below
/// it: a `welcome` carries the backlog of logged events up to a budget, and the rest follows
/// as ordinary events.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// What the channel needs. `Debug` leaves the app password and the key out.
#[derive(Debug, Clone)]
pub struct ChannelOptions {
    /// The server's discovery document.
    pub discovery: Discovery,
    /// The device's credential.
    pub credentials: Credentials,
    /// The device's key.
    pub key: SecretKey,
    /// The last logged event the product has processed (protocol 5.6); 0 on first use.
    pub since: i64,
    /// Product version.
    pub version: String,
    /// Optional features; [`features::ALL`] by default.
    pub features: Vec<String>,
    /// Settings sent with every `hello`: `accept_remote`, `unattended`, `services`.
    pub settings: Option<SettingsChange>,
}

impl ChannelOptions {
    /// Options with every feature and no settings.
    pub fn new(discovery: Discovery, credentials: Credentials, key: SecretKey) -> Self {
        Self {
            discovery,
            credentials,
            key,
            since: 0,
            version: String::new(),
            features: features::ALL
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            settings: None,
        }
    }
}

/// Why the channel ended for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndReason {
    /// The device was revoked (`4003`): stop using the credential, never register the key
    /// again, and tell the user (protocol 9.3).
    Revoked,
    /// The device signed out (`leave`).
    SignedOut,
    /// A newer connection of the same device replaced this one (`4001`).
    Replaced,
    /// The server no longer knows the credential (`401`) or it is not a device's (`403`).
    Unauthorized,
    /// The handshake failed for good (`4000`, or an `error` answer to `hello` that is final for
    /// these credentials: `bad_signature`, `bad_request`, `not_found`, `not_permitted`): the
    /// hello proof did not hold, the `hello` was malformed (its settings, say), or the server
    /// no longer knows the device (signed out since the upgrade).
    HandshakeFailed(String),
    /// The server closed the connection for a protocol violation (`4008`) twice in a row: a bug
    /// of this crate or of the server, to report (protocol 5.4).
    ProtocolViolation(String),
}

/// What the channel hands the product.
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// Connected: the server's `welcome`, after every (re)connect. Its `events` may not hold
    /// the whole backlog: the remaining logged events follow as [`ChannelEvent::Message`], in
    /// order, before live ones.
    Connected(Box<Welcome>),
    /// An event of the server.
    Message(Box<ServerMessage>),
    /// The connection broke; the channel reconnects.
    Disconnected(String),
    /// The channel ended for good.
    Ended(EndReason),
}

struct Command {
    build: Box<dyn FnOnce(u64) -> ClientMessage + Send>,
    reply: oneshot::Sender<Result<ServerMessage>>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Command")
    }
}

/// See the module documentation. Cheap to clone; dropping the last clone stops the channel.
#[derive(Debug, Clone)]
pub struct ControlChannel {
    commands: mpsc::Sender<Command>,
    cursor: Arc<AtomicI64>,
    connected: watch::Receiver<bool>,
    /// When a frame last arrived, UNIX milliseconds; 0 before the first.
    heard: Arc<AtomicI64>,
    /// Marked changed on every network change; the background task watches it.
    network: watch::Sender<()>,
}

/// The timings of a channel; shorter in tests.
#[derive(Debug, Clone, Copy)]
struct Timing {
    handshake: Duration,
    silence: Duration,
    first_backoff: Duration,
    spacing: Duration,
    probe: Duration,
}

impl Timing {
    const DEFAULT: Self = Self {
        handshake: HANDSHAKE_TIMEOUT,
        silence: SILENCE_TIMEOUT,
        first_backoff: FIRST_BACKOFF,
        spacing: NETWORK_RETRY_SPACING,
        probe: PROBE_TIMEOUT,
    };
}

/// The checked options of a running channel.
struct Setup {
    options: ChannelOptions,
    /// The origin of the credential: what `hello` names.
    origin: Origin,
    /// The discovery document's WebSocket URL, on that origin.
    websocket: Url,
    timing: Timing,
}

/// What the background task shares with the handles.
struct Shared {
    cursor: Arc<AtomicI64>,
    heard: Arc<AtomicI64>,
    connected: watch::Sender<bool>,
    events: mpsc::Sender<ChannelEvent>,
}

impl Shared {
    /// Records that the server was heard from.
    fn heard(&self) {
        self.heard.store(unix_millis(), Ordering::Relaxed);
    }
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

impl ControlChannel {
    /// Starts the channel's background task.
    ///
    /// Fails when the options cannot work: the credential's `server` is not a usable origin
    /// ([`Error::Url`]), or the discovery document is of another version
    /// ([`Error::UnsupportedVersion`]), names another server ([`Error::WrongServer`]) or a
    /// WebSocket URL that is not on it ([`Error::Url`]).
    pub fn start(options: ChannelOptions) -> Result<(Self, mpsc::Receiver<ChannelEvent>)> {
        Self::start_with(options, Timing::DEFAULT)
    }

    fn start_with(
        options: ChannelOptions,
        timing: Timing,
    ) -> Result<(Self, mpsc::Receiver<ChannelEvent>)> {
        let origin = Origin::parse(&options.credentials.server)?;
        let websocket = origin.check_discovery(&options.discovery)?;
        let (commands, command_rx) = mpsc::channel(64);
        let (events, event_rx) = mpsc::channel(256);
        let (connected_tx, connected) = watch::channel(false);
        let (network, network_rx) = watch::channel(());
        let cursor = Arc::new(AtomicI64::new(options.since));
        let heard = Arc::new(AtomicI64::new(0));
        let shared = Shared {
            cursor: Arc::clone(&cursor),
            heard: Arc::clone(&heard),
            connected: connected_tx,
            events,
        };
        let setup = Setup {
            options,
            origin,
            websocket,
            timing,
        };
        tokio::spawn(run(setup, command_rx, shared, network_rx));
        Ok((
            Self {
                commands,
                cursor,
                connected,
                heard,
                network,
            },
            event_rx,
        ))
    }

    /// Tells the channel that the device's network changed: an interface came or went, the
    /// device switched networks, or it woke from sleep. Cheap and never blocks; call it on
    /// every change the platform reports ([`crate::Remote::network_change`] does).
    ///
    /// - Waiting to reconnect: the channel tries again at once and starts its backoff over,
    ///   unless the server named the wait (`Retry-After` or `retry_after`, `4029`, `4004`, or
    ///   `404` while remote access is off), which stands.
    /// - Opening a connection or in its handshake: that attempt is abandoned and a new one
    ///   starts, instead of running into its timeouts on a network that is gone.
    /// - Connected: the channel pings the server and reconnects if nothing arrives within 10
    ///   seconds, instead of after 75 seconds of silence.
    ///
    /// Attempts it brings forward start at least a second apart, and only while fewer than 10
    /// started in the last minute, which keeps a flapping network below the server's limit of
    /// 20 a minute.
    pub fn network_changed(&self) {
        self.network.send_replace(());
    }

    /// Whether the channel is connected now.
    pub fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }

    /// Whether the channel is connected, as it changes: true from every `welcome` until that
    /// connection breaks.
    pub(crate) fn connected(&self) -> watch::Receiver<bool> {
        self.connected.clone()
    }

    /// Waits until the channel is connected, for at most `limit`. Returns whether it is.
    pub async fn wait_connected(&self, limit: Duration) -> bool {
        let mut connected = self.connected.clone();
        tokio::time::timeout(limit, connected.wait_for(|connected| *connected))
            .await
            .is_ok_and(|result| result.is_ok())
    }

    /// When the server was last heard from: the last `welcome`, or the last frame of any kind
    /// after it, pings included. `None` before the first `welcome`.
    ///
    /// While the channel is connected this is at most 75 seconds ago, and every
    /// revocation the server sent has arrived. A product that refuses remote sessions when the
    /// server has not been heard from for too long (threat model C14) compares against this,
    /// and keeps it across restarts itself.
    pub fn last_heard(&self) -> Option<SystemTime> {
        let millis = u64::try_from(self.heard.load(Ordering::Relaxed)).ok()?;
        (millis > 0).then(|| UNIX_EPOCH + Duration::from_millis(millis))
    }

    /// The last logged event the product has acknowledged.
    pub fn cursor(&self) -> i64 {
        self.cursor.load(Ordering::Relaxed)
    }

    /// Sends the request that `build` makes from its id and returns the answer: a `result`,
    /// or [`Error::Refused`] for an `error`.
    pub async fn request(
        &self,
        build: impl FnOnce(u64) -> ClientMessage + Send + 'static,
    ) -> Result<ServerMessage> {
        let (reply, answer) = oneshot::channel();
        let command = Command {
            build: Box::new(build),
            reply,
        };
        let answer = tokio::time::timeout(REQUEST_TIMEOUT, async {
            self.commands
                .send(command)
                .await
                .map_err(|_| Error::Channel("the channel has ended".to_owned()))?;
            answer
                .await
                .map_err(|_| Error::Channel("the channel has ended".to_owned()))?
        })
        .await
        .map_err(|_| Error::Channel("no answer in time".to_owned()))??;
        match answer {
            ServerMessage::Error { code, message, .. } => Err(Error::Refused { code, message }),
            other => Ok(other),
        }
    }

    async fn typed<T: DeserializeOwned>(
        &self,
        build: impl FnOnce(u64) -> ClientMessage + Send + 'static,
    ) -> Result<T> {
        match self.request(build).await? {
            ServerMessage::Result { fields, .. } => {
                serde_json::from_value(serde_json::Value::Object(fields))
                    .map_err(|err| Error::Channel(format!("unexpected answer: {err}")))
            }
            other => Err(Error::Channel(format!("unexpected answer: {other:?}"))),
        }
    }

    async fn done(&self, build: impl FnOnce(u64) -> ClientMessage + Send + 'static) -> Result<()> {
        self.request(build).await.map(|_| ())
    }

    /// Records that the product acted on the logged events up to `seq`, and tells the server.
    pub async fn ack(&self, seq: i64) -> Result<()> {
        self.cursor.fetch_max(seq, Ordering::Relaxed);
        self.done(move |id| ClientMessage::Ack { id, seq }).await
    }

    /// Publishes the device's addresses (protocol 7.1).
    pub async fn publish(&self, relay_url: Option<String>, direct: Vec<SocketAddr>) -> Result<()> {
        self.done(move |id| ClientMessage::Publish {
            id,
            relay_url,
            direct,
        })
        .await
    }

    /// Asks to connect to `target` (protocol 7.2) and returns its addresses, unchecked: pass
    /// them through [`crate::ControlLookup::remember`] before dialing.
    pub async fn connect_to(
        &self,
        target: DeviceId,
        service: &str,
        purpose: Purpose,
        request_id: Option<String>,
    ) -> Result<AddressResult> {
        let service = service.to_owned();
        self.typed(move |id| ClientMessage::Connect {
            id,
            target,
            service,
            purpose,
            request_id,
        })
        .await
    }

    /// Fresh addresses of a device the device is connecting to (protocol 7.3), unchecked.
    pub async fn lookup(&self, target: DeviceId) -> Result<AddressResult> {
        self.typed(move |id| ClientMessage::Lookup { id, target })
            .await
    }

    /// Changes the device's own entry (protocol 6.3).
    pub async fn settings(&self, change: SettingsChange) -> Result<SettingsResult> {
        self.typed(move |id| ClientMessage::Settings { id, change })
            .await
    }

    /// Reports a session (protocol 12.2).
    pub async fn report_session(&self, report: SessionReport) -> Result<()> {
        self.done(move |id| ClientMessage::Session { id, report })
            .await
    }

    /// Asks the account's devices to pair (protocol 8.2, step 1).
    pub async fn pair_request(&self, request: Signed) -> Result<PairRequestResult> {
        self.typed(move |id| ClientMessage::PairRequest { id, request })
            .await
    }

    /// Approves a pending request (protocol 8.2, step 4).
    pub async fn pair_approve(&self, request_id: String, approval: Signed) -> Result<()> {
        self.done(move |id| ClientMessage::PairApprove {
            id,
            request_id,
            approval,
        })
        .await
    }

    /// Declines a pending request.
    pub async fn pair_decline(&self, request_id: String) -> Result<()> {
        self.done(move |id| ClientMessage::PairDecline { id, request_id })
            .await
    }

    /// Withdraws the device's own request.
    pub async fn pair_withdraw(&self, request_id: String) -> Result<()> {
        self.done(move |id| ClientMessage::PairWithdraw { id, request_id })
            .await
    }

    /// Reports applied revocations (protocol 9.3).
    pub async fn revocations_applied(&self, endpoint_ids: Vec<DeviceId>) -> Result<()> {
        self.done(move |id| ClientMessage::RevocationsApplied { id, endpoint_ids })
            .await
    }

    /// Signs the device out (protocol 9.4); the channel then ends.
    pub async fn leave(&self) -> Result<()> {
        self.done(|id| ClientMessage::Leave { id }).await
    }
}

/// How one connection ended.
#[derive(Debug)]
enum Outcome {
    /// Reconnect, after `after` or the backoff.
    Retry {
        reason: String,
        after: Option<Duration>,
        /// It got as far as the welcome, so the backoff starts over.
        was_connected: bool,
        /// The server closed it for a protocol violation (`4008`).
        violation: bool,
    },
    /// The network changed before the `welcome`: start again at once.
    NetworkChanged,
    /// Stop for good.
    End(EndReason),
    /// Every handle was dropped.
    Stopped,
}

impl Outcome {
    /// Reconnect after the backoff.
    fn retry(reason: impl Into<String>, was_connected: bool) -> Self {
        Self::Retry {
            reason: reason.into(),
            after: None,
            was_connected,
            violation: false,
        }
    }

    /// Reconnect after `after`.
    fn retry_after(reason: impl Into<String>, after: Option<Duration>) -> Self {
        Self::Retry {
            reason: reason.into(),
            after,
            was_connected: false,
            violation: false,
        }
    }
}

/// `Retry-After` or `retry_after`, kept within one second and one hour.
fn clamp_retry_after(secs: u64) -> Duration {
    Duration::from_secs(secs).clamp(RETRY_AFTER.0, RETRY_AFTER.1)
}

/// Protocol 5.4: after `4008` the device reconnects once; a second `4008` in a row ends the
/// channel. `violated` remembers the first until a connection gets as far as the welcome and
/// ends otherwise.
fn after_violation(outcome: Outcome, violated: &mut bool) -> Outcome {
    match outcome {
        Outcome::Retry {
            violation: true,
            reason,
            ..
        } if *violated => Outcome::End(EndReason::ProtocolViolation(reason)),
        Outcome::Retry {
            violation: true, ..
        } => {
            *violated = true;
            outcome
        }
        // A connection that did not get as far keeps the mark.
        Outcome::Retry {
            was_connected: false,
            ..
        }
        | Outcome::NetworkChanged => outcome,
        other => {
            *violated = false;
            other
        }
    }
}

/// When the last attempts started, for [`EARLY_ATTEMPTS_PER_MINUTE`].
#[derive(Debug, Default)]
struct Starts(VecDeque<tokio::time::Instant>);

impl Starts {
    fn push(&mut self, at: tokio::time::Instant) {
        self.0.push_back(at);
        if self.0.len() > EARLY_ATTEMPTS_PER_MINUTE {
            self.0.pop_front();
        }
    }

    /// Whether a network change may bring the next attempt forward at `now`.
    fn may_bring_forward(&self, now: tokio::time::Instant) -> bool {
        self.0.len() < EARLY_ATTEMPTS_PER_MINUTE
            || self
                .0
                .front()
                .is_some_and(|first| now.duration_since(*first) >= Duration::from_secs(60))
    }
}

async fn run(
    setup: Setup,
    mut commands: mpsc::Receiver<Command>,
    shared: Shared,
    mut network: watch::Receiver<()>,
) {
    let timing = setup.timing;
    let mut backoff = timing.first_backoff;
    let mut violated = false;
    let mut starts = Starts::default();
    loop {
        // Changes before the attempt starts are the network it runs on; only later ones count.
        network.borrow_and_update();
        let started = tokio::time::Instant::now();
        starts.push(started);
        let outcome = connection(&setup, &mut commands, &shared, &mut network).await;
        let _ = shared.connected.send(false);
        // When to try again, and whether a network change may bring that forward.
        let (reason, wait, mut wakeable) = match after_violation(outcome, &mut violated) {
            Outcome::Stopped => return,
            Outcome::End(reason) => {
                tracing::info!(?reason, "control channel ended");
                let _ = shared.events.send(ChannelEvent::Ended(reason)).await;
                // Answer whatever is still queued.
                commands.close();
                while let Some(command) = commands.recv().await {
                    let _ = command
                        .reply
                        .send(Err(Error::Channel("the channel has ended".to_owned())));
                }
                return;
            }
            Outcome::NetworkChanged if starts.may_bring_forward(tokio::time::Instant::now()) => {
                backoff = timing.first_backoff;
                (
                    "the network changed while connecting".to_owned(),
                    Duration::ZERO,
                    false,
                )
            }
            Outcome::NetworkChanged => {
                let wait = backoff + jitter(backoff);
                backoff = (backoff * 2).min(MAX_BACKOFF);
                (
                    "the network changed while connecting".to_owned(),
                    wait,
                    true,
                )
            }
            Outcome::Retry {
                reason,
                after,
                was_connected,
                ..
            } => {
                if was_connected {
                    backoff = timing.first_backoff;
                }
                let wait = after.unwrap_or(backoff + jitter(backoff));
                backoff = (backoff * 2).min(MAX_BACKOFF);
                // A wait the server named stands, network change or not.
                (reason, wait, after.is_none())
            }
        };
        tracing::debug!(reason, "control channel disconnected");
        if shared
            .events
            .send(ChannelEvent::Disconnected(reason))
            .await
            .is_err()
        {
            return;
        }
        let mut deadline = tokio::time::Instant::now() + wait;
        if wait.is_zero() {
            deadline = deadline.max(started + timing.spacing);
        }
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => break,
                // Every handle dropped while waiting.
                () = commands_closed(&commands) => return,
                Ok(()) = network.changed(), if wakeable => {
                    let now = tokio::time::Instant::now();
                    if starts.may_bring_forward(now) {
                        tracing::debug!("the network changed; reconnecting now");
                        backoff = timing.first_backoff;
                        deadline = deadline.min((started + timing.spacing).max(now));
                        wakeable = false;
                    } else {
                        tracing::debug!("the network changed; too many attempts this minute to reconnect early");
                    }
                }
            }
        }
    }
}

/// A random part of up to half of `backoff`, so that devices do not reconnect in step.
fn jitter(backoff: Duration) -> Duration {
    Duration::from_millis(rand::rng().random_range(0..=backoff.as_millis() as u64 / 2))
}

/// Resolves once no handle is left.
async fn commands_closed(commands: &mpsc::Receiver<Command>) {
    loop {
        if commands.is_closed() && commands.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A byte stream the WebSocket runs on: TCP, or TLS over TCP.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Socket = WebSocketStream<Box<dyn Io>>;

/// The addresses in the order RFC 8305 tries them: the families alternate, starting with the
/// family of the resolver's first answer.
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (preferred, other): (Vec<_>, Vec<_>) = addrs
        .into_iter()
        .partition(|addr| addr.is_ipv6() == first_v6);
    let mut ordered = Vec::with_capacity(preferred.len() + other.len());
    let (mut preferred, mut other) = (preferred.into_iter(), other.into_iter());
    loop {
        match (preferred.next(), other.next()) {
            (None, None) => return ordered,
            (first, second) => ordered.extend(first.into_iter().chain(second)),
        }
    }
}

/// Connects to the first of `addrs` that answers: a new attempt starts every `stagger`, or as
/// soon as one fails, while the earlier ones keep running (RFC 8305).
async fn race<T, F, Fut>(addrs: Vec<SocketAddr>, stagger: Duration, connect: F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut queue = addrs.into_iter();
    let mut attempts = FuturesUnordered::new();
    let mut last_error = None;
    loop {
        if attempts.is_empty() {
            match queue.next() {
                Some(addr) => attempts.push(connect(addr)),
                None => {
                    return Err(last_error.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "the host has no address")
                    }));
                }
            }
        }
        let more = !queue.as_slice().is_empty();
        tokio::select! {
            Some(result) = attempts.next() => match result {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    last_error = Some(err);
                    // The next address at once.
                    if let Some(addr) = queue.next() {
                        attempts.push(connect(addr));
                    }
                }
            },
            () = tokio::time::sleep(stagger), if more => {
                if let Some(addr) = queue.next() {
                    attempts.push(connect(addr));
                }
            }
        }
    }
}

/// One TCP connection attempt, for at most [`CONNECT_ATTEMPT_TIMEOUT`].
async fn attempt(addr: SocketAddr) -> io::Result<TcpStream> {
    tokio::time::timeout(CONNECT_ATTEMPT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{addr} timed out")))?
}

/// Resolves `host` and connects to one of its addresses.
async fn connect_tcp(host: &Host<&str>, port: u16) -> io::Result<TcpStream> {
    let addrs = match host {
        Host::Domain(domain) => tokio::net::lookup_host((*domain, port)).await?.collect(),
        Host::Ipv4(ip) => vec![SocketAddr::from((*ip, port))],
        Host::Ipv6(ip) => vec![SocketAddr::from((*ip, port))],
    };
    race(interleave(addrs), CONNECT_STAGGER, attempt).await
}

/// The limits of the server's messages.
fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
}

/// Opens the WebSocket with the device's credential.
async fn open(setup: &Setup) -> std::result::Result<Socket, Outcome> {
    let retry = |reason: String| Outcome::retry(reason, false);
    let url = &setup.websocket;
    let host = url
        .host()
        .ok_or_else(|| retry("the websocket URL has no host".to_owned()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| retry("the websocket URL has no port".to_owned()))?;
    let tcp = connect_tcp(&host, port)
        .await
        .map_err(|err| retry(err.to_string()))?;
    let _ = tcp.set_nodelay(true);
    // `ws` is only ever a loopback host's: the origin check refuses it anywhere else.
    let stream: Box<dyn Io> = if url.scheme() == "wss" {
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(&[b"http/1.1"])));
        let name = match host {
            Host::Domain(domain) => rustls::pki_types::ServerName::try_from(domain.to_owned())
                .map_err(|err| retry(err.to_string()))?,
            Host::Ipv4(ip) => IpAddr::V4(ip).into(),
            Host::Ipv6(ip) => IpAddr::V6(ip).into(),
        };
        Box::new(
            connector
                .connect(name, tcp)
                .await
                .map_err(|err| retry(err.to_string()))?,
        )
    } else {
        Box::new(tcp)
    };
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|err| retry(err.to_string()))?;
    let credentials = base64_encode(
        format!(
            "{}:{}",
            setup.options.credentials.username, setup.options.credentials.app_password
        )
        .as_bytes(),
    );
    request.headers_mut().insert(
        "authorization",
        format!("Basic {credentials}")
            .parse()
            .map_err(|_| retry("unusable credential".to_owned()))?,
    );
    match tokio_tungstenite::client_async_with_config(request, stream, Some(websocket_config()))
        .await
    {
        Ok((socket, _)) => Ok(socket),
        Err(tungstenite::Error::Http(response)) => {
            let status = response.status().as_u16();
            Err(match status {
                401 | 403 => Outcome::End(EndReason::Unauthorized),
                404 => Outcome::retry_after("remote access is off on the server", Some(SLOW_RETRY)),
                429 => Outcome::retry_after(
                    "rate limited",
                    response
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.trim().parse().ok())
                        .map(clamp_retry_after),
                ),
                _ => retry(format!("the server answered {status}")),
            })
        }
        Err(err) => Err(retry(err.to_string())),
    }
}

/// Standard base64 of `bytes`, for the Basic header.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The next text frame of the handshake, as a server message; frames of unknown types are
/// skipped. The handshake does not count as hearing from the server: no event can arrive
/// before the `welcome`.
async fn next_message(socket: &mut Socket) -> std::result::Result<ServerMessage, Outcome> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                match serde_json::from_str(text.as_str()) {
                    // A type of a newer server (protocol 5.3).
                    Ok(ServerMessage::Unknown) => {}
                    Ok(message) => return Ok(message),
                    Err(err) => {
                        return Err(Outcome::retry(format!("unreadable frame: {err}"), false));
                    }
                }
            }
            Some(Ok(Message::Close(frame))) => return Err(closed(frame.as_ref(), false)),
            Some(Ok(_)) => {}
            Some(Err(err)) => return Err(Outcome::retry(err.to_string(), false)),
            None => return Err(Outcome::retry("the connection closed", false)),
        }
    }
}

/// What a close frame of the server means (protocol 5.4).
fn closed(frame: Option<&CloseFrame>, was_connected: bool) -> Outcome {
    let code = frame.map(|frame| u16::from(frame.code));
    let reason = frame
        .map(|frame| frame.reason.to_string())
        .unwrap_or_default();
    let retry = |after, violation| Outcome::Retry {
        reason: format!("closed by the server ({code:?}): {reason}"),
        after,
        was_connected,
        violation,
    };
    match code {
        Some(close::REVOKED) => Outcome::End(EndReason::Revoked),
        Some(close::REPLACED) => Outcome::End(EndReason::Replaced),
        Some(close::HANDSHAKE_FAILED) => Outcome::End(EndReason::HandshakeFailed(reason)),
        Some(1000) => Outcome::End(EndReason::SignedOut),
        Some(close::ACCOUNT_DISABLED) => retry(Some(SLOW_RETRY), false),
        Some(close::RATE_LIMITED) => retry(Some(Duration::from_secs(60)), false),
        Some(close::PROTOCOL) => retry(None, true),
        _ => retry(None, false),
    }
}

/// What an `error` answer to `hello` means, with the close code that followed it, if one
/// arrived (protocol 5.2).
///
/// - The close code decides first: `4003` is a revocation, `1001` and `1011` are the server's
///   own trouble whatever the code says, `4029` and `4004` wait as they do elsewhere.
/// - Otherwise only the codes that are final for these credentials end the channel: a proof
///   the server rejects (`bad_signature`), a malformed `hello` (`bad_request`: retrying it
///   cannot help), a device it no longer knows (`not_found`), a refusal by its rules
///   (`not_permitted`).
/// - Everything else (`unavailable` while the server shuts down or its database fails,
///   `rate_limited`, codes of newer servers) is retried, after `retry_after` when it names one.
///   Server problems are never taken for "signed out" (threat model C6).
fn refused_hello(
    code: ErrorCode,
    message: String,
    retry_after: Option<u64>,
    close_code: Option<u16>,
) -> Outcome {
    let retry_after = retry_after.map(clamp_retry_after);
    let reason = format!("the server refused hello ({code:?}, {close_code:?}): {message}");
    match close_code {
        Some(close::REVOKED) => return Outcome::End(EndReason::Revoked),
        Some(1001 | 1011) => return Outcome::retry_after(reason, retry_after),
        Some(close::RATE_LIMITED) => {
            return Outcome::retry_after(reason, retry_after.or(Some(Duration::from_secs(60))));
        }
        Some(close::ACCOUNT_DISABLED) => return Outcome::retry_after(reason, Some(SLOW_RETRY)),
        _ => {}
    }
    match code {
        ErrorCode::BadSignature
        | ErrorCode::BadRequest
        | ErrorCode::NotFound
        | ErrorCode::NotPermitted => Outcome::End(EndReason::HandshakeFailed(message)),
        _ => Outcome::retry_after(reason, retry_after),
    }
}

/// How long the close frame that follows a refused `hello` may take.
const REFUSAL_CLOSE_WAIT: Duration = Duration::from_secs(2);

/// The code of the close frame that follows a refused `hello`, if it arrives in time.
async fn refusal_close_code(socket: &mut Socket) -> Option<u16> {
    tokio::time::timeout(REFUSAL_CLOSE_WAIT, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(frame))) => return frame.map(|frame| u16::from(frame.code)),
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// The requests waiting for their answers, by id, with when they were sent.
type Pending = HashMap<u64, (Instant, oneshot::Sender<Result<ServerMessage>>)>;

/// Drops the requests whose callers stopped waiting or would have by now.
fn sweep(pending: &mut Pending, now: Instant) {
    pending.retain(|_, (sent, reply)| {
        !reply.is_closed() && now.duration_since(*sent) < REQUEST_TIMEOUT
    });
}

/// Opens the connection and runs the handshake, within their timeouts.
async fn handshake(
    setup: &Setup,
    shared: &Shared,
) -> std::result::Result<(Socket, Box<Welcome>), Outcome> {
    let mut socket = match tokio::time::timeout(OPEN_TIMEOUT, open(setup)).await {
        Ok(opened) => opened?,
        Err(_) => return Err(Outcome::retry("opening the connection timed out", false)),
    };
    let options = &setup.options;
    let welcome = tokio::time::timeout(setup.timing.handshake, async {
        let ServerMessage::Challenge { nonce, .. } = next_message(&mut socket).await? else {
            return Err(Outcome::retry("the server did not send a challenge", false));
        };
        let hello = ClientMessage::Hello(HelloMessage {
            proof: Signed::sign(
                &Statement::Hello(Hello {
                    // The origin the device talks to, never one the server names (C16).
                    server: setup.origin.as_str().to_owned(),
                    account: options.credentials.username.clone(),
                    endpoint_id: options.key.public().into(),
                    nonce,
                }),
                &options.key,
            ),
            since: shared.cursor.load(Ordering::Relaxed),
            version: options.version.clone(),
            features: options.features.clone(),
            settings: options.settings.clone(),
        });
        socket
            .send(Message::text(
                serde_json::to_string(&hello).unwrap_or_default(),
            ))
            .await
            .map_err(|err| Outcome::retry(err.to_string(), false))?;
        match next_message(&mut socket).await? {
            ServerMessage::Welcome(welcome) => Ok(welcome),
            ServerMessage::Error {
                code,
                message,
                retry_after,
                ..
            } => {
                let close_code = refusal_close_code(&mut socket).await;
                Err(refused_hello(code, message, retry_after, close_code))
            }
            other => Err(Outcome::retry(
                format!("unexpected answer to hello: {other:?}"),
                false,
            )),
        }
    })
    .await;
    match welcome {
        Ok(Ok(mut welcome)) => {
            // Types of newer servers are ignored (protocol 5.3).
            welcome
                .events
                .retain(|event| !matches!(event, ServerMessage::Unknown));
            Ok((socket, welcome))
        }
        Ok(Err(outcome)) => Err(outcome),
        Err(_) => Err(Outcome::retry("the handshake timed out", false)),
    }
}

/// One connection, from opening it to its end.
async fn connection(
    setup: &Setup,
    commands: &mut mpsc::Receiver<Command>,
    shared: &Shared,
    network: &mut watch::Receiver<()>,
) -> Outcome {
    if commands.is_closed() && commands.is_empty() {
        return Outcome::Stopped;
    }
    // An attempt begun on a network that is gone would only run into its timeouts (up to
    // `OPEN_TIMEOUT` and the handshake's): start again instead.
    let handshake = tokio::select! {
        handshake = handshake(setup, shared) => handshake,
        Ok(()) = network.changed() => return Outcome::NetworkChanged,
    };
    let (mut socket, welcome) = match handshake {
        Ok(opened) => opened,
        Err(outcome) => return outcome,
    };
    shared.heard();
    let _ = shared.connected.send(true);
    if shared
        .events
        .send(ChannelEvent::Connected(welcome))
        .await
        .is_err()
    {
        return Outcome::Stopped;
    }

    let silence_limit = setup.timing.silence;
    let silence = tokio::time::sleep(silence_limit);
    tokio::pin!(silence);
    let mut sweeping = tokio::time::interval(SWEEP_INTERVAL);
    sweeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending = Pending::new();
    let mut next_id: u64 = 1;
    // Since a network change, waiting for any frame after the ping it sent.
    let mut probing = false;
    let outcome = loop {
        tokio::select! {
            frame = socket.next() => {
                if let Some(Ok(_)) = frame {
                    shared.heard();
                    probing = false;
                    silence
                        .as_mut()
                        .reset(tokio::time::Instant::now() + silence_limit);
                }
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        let message = match serde_json::from_str::<ServerMessage>(text.as_str()) {
                            // A type of a newer server (protocol 5.3).
                            Ok(ServerMessage::Unknown) => continue,
                            Ok(message) => message,
                            Err(_) => {
                                tracing::debug!("ignoring an unreadable frame of the control channel");
                                continue;
                            }
                        };
                        let answered = match &message {
                            ServerMessage::Result { id, .. } => Some(*id),
                            ServerMessage::Error { id, .. } => *id,
                            _ => None,
                        };
                        match answered {
                            Some(id) => match pending.remove(&id) {
                                Some((_, reply)) => {
                                    let _ = reply.send(Ok(message));
                                }
                                // An answer is never an event.
                                None => tracing::debug!(id, "dropping an answer nobody waits for"),
                            },
                            None => {
                                if shared
                                    .events
                                    .send(ChannelEvent::Message(Box::new(message)))
                                    .await
                                    .is_err()
                                {
                                    break Outcome::Stopped;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(frame))) => break closed(frame.as_ref(), true),
                    Some(Ok(_)) => {}
                    Some(Err(err)) => break Outcome::retry(err.to_string(), true),
                    None => break Outcome::retry("the connection closed", true),
                }
            }
            () = &mut silence => {
                if probing {
                    break Outcome::retry("no answer to a ping after the network changed", true);
                }
                break Outcome::retry(
                    format!("nothing from the server for {} seconds", silence_limit.as_secs_f32()),
                    true,
                );
            }
            // The connection may run on an interface that went away, where it would count as
            // connected until the silence timeout: a ping tells sooner. Any frame answers it.
            Ok(()) = network.changed() => {
                let probe = setup.timing.probe;
                let ping = tokio::time::timeout(probe, socket.send(Message::Ping(Default::default())))
                    .await
                    .unwrap_or_else(|_| Err(tungstenite::Error::Io(io::ErrorKind::TimedOut.into())));
                if let Err(err) = ping {
                    break Outcome::retry(format!("the network changed and the ping failed: {err}"), true);
                }
                let deadline = tokio::time::Instant::now() + probe;
                if deadline < silence.deadline() {
                    silence.as_mut().reset(deadline);
                    probing = true;
                }
            }
            _ = sweeping.tick() => sweep(&mut pending, Instant::now()),
            command = commands.recv() => match command {
                Some(command) => {
                    let id = next_id;
                    next_id += 1;
                    let text = serde_json::to_string(&(command.build)(id)).unwrap_or_default();
                    // A dead peer with full buffers must not hold the loop longer than silence
                    // would.
                    let sent = tokio::time::timeout(silence_limit, socket.send(Message::text(text)))
                        .await
                        .unwrap_or_else(|_| Err(tungstenite::Error::Io(io::ErrorKind::TimedOut.into())));
                    if let Err(err) = sent {
                        let _ = command.reply.send(Err(Error::Channel(err.to_string())));
                        break Outcome::retry(err.to_string(), true);
                    }
                    pending.insert(id, (Instant::now(), command.reply));
                }
                None => {
                    let _ = tokio::time::timeout(silence_limit, socket.close(None)).await;
                    break Outcome::Stopped;
                }
            },
        }
    };
    for (_, (_, reply)) in pending {
        let _ = reply.send(Err(Error::Channel("the connection broke".to_owned())));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use gono_protocol::connect::{
        VERSION,
        message::{AccountInfo, ConnectionLimits},
    };
    use tokio::net::TcpListener;

    use super::*;
    use crate::tests::{credentials, entry};

    fn frame(code: u16) -> CloseFrame {
        CloseFrame {
            code: code.into(),
            reason: "".into(),
        }
    }

    #[test]
    fn close_codes_decide_whether_to_reconnect() {
        let end = |code| match closed(Some(&frame(code)), true) {
            Outcome::End(reason) => Some(reason),
            _ => None,
        };
        assert_eq!(end(close::REVOKED), Some(EndReason::Revoked));
        assert_eq!(end(close::REPLACED), Some(EndReason::Replaced));
        assert_eq!(end(1000), Some(EndReason::SignedOut));
        assert!(matches!(
            end(close::HANDSHAKE_FAILED),
            Some(EndReason::HandshakeFailed(_))
        ));
        for code in [1001, 1011, close::TIMED_OUT] {
            assert!(
                matches!(
                    closed(Some(&frame(code)), true),
                    Outcome::Retry {
                        after: None,
                        violation: false,
                        ..
                    }
                ),
                "{code}"
            );
        }
        assert!(matches!(
            closed(Some(&frame(close::PROTOCOL)), true),
            Outcome::Retry {
                violation: true,
                ..
            }
        ));
        assert!(matches!(
            closed(Some(&frame(close::ACCOUNT_DISABLED)), true),
            Outcome::Retry {
                after: Some(SLOW_RETRY),
                ..
            }
        ));
        // A connection that ends without a close frame is retried.
        assert!(matches!(closed(None, false), Outcome::Retry { .. }));
    }

    #[test]
    fn a_protocol_violation_is_retried_once() {
        let violation = || closed(Some(&frame(close::PROTOCOL)), true);
        let mut violated = false;
        assert!(matches!(
            after_violation(violation(), &mut violated),
            Outcome::Retry { .. }
        ));
        // A reconnect that fails to open keeps the mark.
        assert!(matches!(
            after_violation(Outcome::retry("refused", false), &mut violated),
            Outcome::Retry { .. }
        ));
        assert!(matches!(
            after_violation(violation(), &mut violated),
            Outcome::End(EndReason::ProtocolViolation(_))
        ));
        // A connection that ended otherwise after its welcome clears it.
        let mut violated = true;
        let _ = after_violation(Outcome::retry("1011", true), &mut violated);
        assert!(!violated);
        assert!(matches!(
            after_violation(violation(), &mut violated),
            Outcome::Retry { .. }
        ));
    }

    #[test]
    fn only_final_hello_errors_end_the_channel() {
        let refused = |code, close_code| refused_hello(code, "no".to_owned(), None, close_code);
        // Final for these credentials, with 4000 or without a close frame.
        for code in [
            ErrorCode::BadSignature,
            ErrorCode::BadRequest,
            ErrorCode::NotFound,
            ErrorCode::NotPermitted,
        ] {
            for close_code in [Some(close::HANDSHAKE_FAILED), None] {
                assert!(
                    matches!(
                        refused(code, close_code),
                        Outcome::End(EndReason::HandshakeFailed(_))
                    ),
                    "{code:?} {close_code:?}"
                );
            }
        }
        // The server's own trouble, and codes of newer servers, even with 4000.
        for (code, close_code) in [
            (ErrorCode::Unavailable, Some(1011)),
            (ErrorCode::Unavailable, Some(close::HANDSHAKE_FAILED)),
            (ErrorCode::Unavailable, None),
            (ErrorCode::Unknown, Some(close::HANDSHAKE_FAILED)),
            (ErrorCode::BadSignature, Some(1011)),
            (ErrorCode::NotFound, Some(1001)),
        ] {
            assert!(
                matches!(
                    refused(code, close_code),
                    Outcome::Retry { after: None, .. }
                ),
                "{code:?} {close_code:?}"
            );
        }
        // A revocation since the upgrade.
        assert!(matches!(
            refused(ErrorCode::NotPermitted, Some(close::REVOKED)),
            Outcome::End(EndReason::Revoked)
        ));
        // Too many connections: 60 seconds, or what the server names.
        assert!(matches!(
            refused(ErrorCode::RateLimited, Some(close::RATE_LIMITED)),
            Outcome::Retry { after: Some(after), .. } if after == Duration::from_secs(60)
        ));
        assert!(matches!(
            refused_hello(ErrorCode::RateLimited, String::new(), Some(30), None),
            Outcome::Retry { after: Some(after), .. } if after == Duration::from_secs(30)
        ));
        assert!(matches!(
            refused(ErrorCode::Unknown, Some(close::ACCOUNT_DISABLED)),
            Outcome::Retry {
                after: Some(SLOW_RETRY),
                ..
            }
        ));
    }

    #[test]
    fn retry_after_is_clamped() {
        assert_eq!(clamp_retry_after(0), Duration::from_secs(1));
        assert_eq!(clamp_retry_after(90), Duration::from_secs(90));
        assert_eq!(clamp_retry_after(u64::MAX), Duration::from_secs(60 * 60));
    }

    #[test]
    fn answers_nobody_waits_for_are_swept() {
        let now = Instant::now();
        let mut pending = Pending::new();
        let (waiting, _waiting_rx) = oneshot::channel();
        let (gone, gone_rx) = oneshot::channel();
        let (old, _old_rx) = oneshot::channel();
        drop(gone_rx);
        pending.insert(1, (now, waiting));
        pending.insert(2, (now, gone));
        pending.insert(3, (now.checked_sub(REQUEST_TIMEOUT).unwrap(), old));
        sweep(&mut pending, now);
        assert_eq!(pending.keys().copied().collect::<Vec<_>>(), [1]);
    }

    #[test]
    fn address_families_alternate() {
        let v4 = |n: u8| SocketAddr::from(([192, 0, 2, n], 443));
        let v6 = |n: u16| SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, n], 443));
        assert_eq!(
            interleave(vec![v6(1), v6(2), v6(3), v4(1)]),
            [v6(1), v4(1), v6(2), v6(3)]
        );
        assert_eq!(
            interleave(vec![v4(1), v4(2), v6(1), v6(2)]),
            [v4(1), v6(1), v4(2), v6(2)]
        );
        assert!(interleave(Vec::new()).is_empty());
    }

    /// A connector for [`race`]: port 1 never answers (a black hole), port 2 answers, any
    /// other port refuses at once.
    async fn fake_connect(addr: SocketAddr) -> io::Result<u16> {
        match addr.port() {
            1 => std::future::pending().await,
            2 => Ok(2),
            _ => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
        }
    }

    fn port(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test(start_paused = true)]
    async fn a_black_hole_costs_one_stagger() {
        let start = tokio::time::Instant::now();
        let won = race(vec![port(1), port(2)], CONNECT_STAGGER, fake_connect).await;
        assert_eq!(won.unwrap(), 2);
        assert_eq!(start.elapsed(), CONNECT_STAGGER);

        // A refusal moves on at once.
        let start = tokio::time::Instant::now();
        let won = race(vec![port(3), port(2)], CONNECT_STAGGER, fake_connect).await;
        assert_eq!(won.unwrap(), 2);
        assert_eq!(start.elapsed(), Duration::ZERO);

        let lost = race(vec![port(3), port(4)], CONNECT_STAGGER, fake_connect).await;
        assert_eq!(lost.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        let none = race(Vec::new(), CONNECT_STAGGER, fake_connect).await;
        assert_eq!(none.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn debug_leaves_secrets_out() {
        let options = ChannelOptions::new(
            discovery("https://cloud.example.com"),
            credentials("https://cloud.example.com", 1),
            SecretKey::from_bytes(&[1; 32]),
        );
        let text = format!("{options:?}");
        assert!(!text.contains("secret"), "{text}");
    }

    #[test]
    fn options_must_match_the_credential_origin() {
        let key = SecretKey::from_bytes(&[1; 32]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let good = ChannelOptions::new(
            discovery("https://cloud.example.com"),
            credentials("https://cloud.example.com", 1),
            key.clone(),
        );
        assert!(ControlChannel::start(good).is_ok());
        let other = ChannelOptions::new(
            discovery("https://other.example.com"),
            credentials("https://cloud.example.com", 1),
            key.clone(),
        );
        assert!(matches!(
            ControlChannel::start(other),
            Err(Error::WrongServer { .. })
        ));
        let mut plain = discovery("https://cloud.example.com");
        plain.websocket = "ws://cloud.example.com/gono/v1/ws".to_owned();
        assert!(matches!(
            ControlChannel::start(ChannelOptions::new(
                plain,
                credentials("https://cloud.example.com", 1),
                key,
            )),
            Err(Error::Url(_))
        ));
    }

    // A scripted server on a loopback port, for the behaviour of the running channel.

    fn discovery(origin: &str) -> Discovery {
        let websocket = origin.replacen("http", "ws", 1);
        Discovery {
            version: VERSION,
            server: origin.to_owned(),
            login: format!("{origin}/gono/v1/login"),
            websocket: format!("{websocket}/gono/v1/ws"),
            relay_url: "https://relay.example.com/".to_owned(),
            two_factor_required: true,
        }
    }

    const FAST: Timing = Timing {
        handshake: Duration::from_secs(5),
        silence: Duration::from_millis(400),
        first_backoff: Duration::from_millis(20),
        spacing: Duration::from_millis(100),
        probe: Duration::from_millis(300),
    };

    const LIMIT: Duration = Duration::from_secs(10);

    type ServerSocket = WebSocketStream<TcpStream>;

    /// A listener and a channel that connects to it.
    async fn scripted() -> (TcpListener, ControlChannel, mpsc::Receiver<ChannelEvent>) {
        scripted_with(FAST).await
    }

    /// [`scripted`] with other timings.
    async fn scripted_with(
        timing: Timing,
    ) -> (TcpListener, ControlChannel, mpsc::Receiver<ChannelEvent>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let options = ChannelOptions::new(
            discovery(&origin),
            credentials(&origin, 1),
            SecretKey::from_bytes(&[1; 32]),
        );
        let (channel, events) = ControlChannel::start_with(options, timing).unwrap();
        (listener, channel, events)
    }

    /// Accepts the next connection and reads its `hello`.
    async fn accept_hello(listener: &TcpListener) -> ServerSocket {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let challenge = ServerMessage::Challenge {
            nonce: "bm9uY2U".to_owned(),
            server_time: 0,
        };
        socket
            .send(Message::text(challenge.to_text()))
            .await
            .unwrap();
        loop {
            if let Some(Ok(Message::Text(text))) = socket.next().await {
                assert!(text.as_str().contains(r#""type":"hello""#), "{text}");
                return socket;
            }
        }
    }

    /// A `welcome`, with `extra` appended to its events as they are.
    fn welcome(extra: &[serde_json::Value]) -> String {
        let welcome = Welcome {
            server_time: 0,
            account: AccountInfo {
                username: "kim".to_owned(),
                display_name: "Kim".to_owned(),
                remote_access: true,
                relay: Some(gono_protocol::connect::message::RelayAccess::Full),
            },
            device: entry(1),
            relay_url: "https://relay.example.com/".to_owned(),
            devices: vec![entry(1), entry(2)],
            pair_requests: Vec::new(),
            events: vec![ServerMessage::DeviceRemoved {
                endpoint_id: entry(2).endpoint_id,
                at: 1,
            }],
            events_truncated: false,
            cursor: 0,
            features: Vec::new(),
            limits: ConnectionLimits {
                max_frame_bytes: 65536,
                requests_per_second: 10,
                request_burst: 100,
                max_direct_addresses: 16,
                lookup_window_secs: 600,
            },
        };
        let mut value = serde_json::to_value(ServerMessage::Welcome(Box::new(welcome))).unwrap();
        let events = value["events"].as_array_mut().unwrap();
        events.extend(extra.iter().cloned());
        value.to_string()
    }

    async fn next(events: &mut mpsc::Receiver<ChannelEvent>) -> ChannelEvent {
        tokio::time::timeout(LIMIT, events.recv())
            .await
            .expect("an event in time")
            .expect("the channel runs")
    }

    async fn send_close(socket: &mut ServerSocket, code: u16) {
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: code.into(),
                reason: "".into(),
            })))
            .await;
    }

    #[tokio::test]
    async fn unknown_types_are_ignored_and_stray_answers_dropped() {
        let (listener, channel, mut events) = scripted().await;
        assert_eq!(channel.last_heard(), None);
        let server = tokio::spawn(async move {
            let mut socket = accept_hello(&listener).await;
            let future = serde_json::json!({"type": "from.the.future", "seq": 9});
            socket
                .send(Message::text(welcome(std::slice::from_ref(&future))))
                .await
                .unwrap();
            for text in [
                future.to_string(),
                ServerMessage::result(999, &()).to_text(),
                ServerMessage::Account {
                    remote_access: false,
                    relay: None,
                }
                .to_text(),
            ] {
                socket.send(Message::text(text)).await.unwrap();
            }
            // Keep the connection until the test ends.
            while socket.next().await.is_some() {}
        });
        let ChannelEvent::Connected(welcome) = next(&mut events).await else {
            panic!("expected the welcome");
        };
        assert_eq!(welcome.events.len(), 1);
        assert!(matches!(
            welcome.events[0],
            ServerMessage::DeviceRemoved { .. }
        ));
        let event = next(&mut events).await;
        assert!(
            matches!(&event, ChannelEvent::Message(message) if matches!(**message, ServerMessage::Account { remote_access: false, .. })),
            "{event:?}"
        );
        assert!(channel.last_heard().is_some());
        drop(channel);
        server.abort();
    }

    #[tokio::test]
    async fn transient_hello_errors_are_retried_and_final_ones_end() {
        let (listener, _channel, mut events) = scripted().await;
        let server = tokio::spawn(async move {
            // The server shuts down, or its database failed.
            let mut socket = accept_hello(&listener).await;
            let unavailable =
                ServerMessage::error(None, ErrorCode::Unavailable, "the server is shutting down");
            socket
                .send(Message::text(unavailable.to_text()))
                .await
                .unwrap();
            send_close(&mut socket, 1011).await;
            // A code of a newer server.
            let mut socket = accept_hello(&listener).await;
            let future = r#"{"type":"error","code":"from_the_future","message":"?"}"#;
            socket.send(Message::text(future)).await.unwrap();
            send_close(&mut socket, close::HANDSHAKE_FAILED).await;
            // Then the proof does not hold.
            let mut socket = accept_hello(&listener).await;
            let refused = ServerMessage::error(
                None,
                ErrorCode::BadSignature,
                "the hello proof does not hold",
            );
            socket.send(Message::text(refused.to_text())).await.unwrap();
            send_close(&mut socket, close::HANDSHAKE_FAILED).await;
        });
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Disconnected(reason) if reason.contains("Unavailable")
        ));
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Disconnected(reason) if reason.contains("Unknown")
        ));
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Ended(EndReason::HandshakeFailed(_))
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_revocation_at_hello_ends_as_revoked() {
        let (listener, _channel, mut events) = scripted().await;
        let server = tokio::spawn(async move {
            let mut socket = accept_hello(&listener).await;
            let revoked =
                ServerMessage::error(None, ErrorCode::NotPermitted, "the device was revoked");
            socket.send(Message::text(revoked.to_text())).await.unwrap();
            send_close(&mut socket, close::REVOKED).await;
        });
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Ended(EndReason::Revoked)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_silent_server_is_left_and_a_second_violation_ends() {
        let (listener, _channel, mut events) = scripted().await;
        let server = tokio::spawn(async move {
            // Silent after the welcome: neither frames nor pings.
            let mut silent = accept_hello(&listener).await;
            silent.send(Message::text(welcome(&[]))).await.unwrap();
            // The channel opens a new connection; it ends with 4008 twice.
            for _ in 0..2 {
                let mut socket = accept_hello(&listener).await;
                socket.send(Message::text(welcome(&[]))).await.unwrap();
                send_close(&mut socket, close::PROTOCOL).await;
            }
            drop(silent);
        });
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Disconnected(reason) if reason.contains("nothing from the server")
        ));
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Disconnected(_)
        ));
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Ended(EndReason::ProtocolViolation(_))
        ));
        server.await.unwrap();
    }

    /// The `publish` frames the server receives on `socket`, answered with `answer`, until
    /// `count` arrived: their addresses and when they arrived.
    async fn publishes(
        socket: &mut ServerSocket,
        count: usize,
        answer: impl Fn(u64, usize) -> ServerMessage,
    ) -> Vec<(Vec<SocketAddr>, tokio::time::Instant)> {
        let mut seen = Vec::new();
        while seen.len() < count {
            let frame = tokio::time::timeout(LIMIT, socket.next())
                .await
                .expect("a frame in time");
            let Some(Ok(Message::Text(text))) = frame else {
                continue;
            };
            let value: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
            if value["type"] != "publish" {
                continue;
            }
            let direct: Vec<SocketAddr> = serde_json::from_value(value["direct"].clone()).unwrap();
            let id = value["id"].as_u64().unwrap();
            socket
                .send(Message::text(answer(id, seen.len()).to_text()))
                .await
                .unwrap();
            seen.push((direct, tokio::time::Instant::now()));
        }
        seen
    }

    #[tokio::test]
    async fn addresses_are_published_spaced_coalesced_and_again_after_a_reconnect() {
        use crate::lookup::{Addresses, publish_latest};

        let (listener, channel, mut events) = scripted().await;
        let interval = Duration::from_millis(300);
        let (latest, receiver) = watch::channel(None);
        let addresses = |port: u16| {
            Some(Addresses {
                relay_url: None,
                direct: vec![SocketAddr::from(([192, 0, 2, 1], port))],
            })
        };
        latest.send_replace(addresses(1));
        tokio::spawn(publish_latest(channel.clone(), receiver, interval));

        let mut socket = accept_hello(&listener).await;
        socket.send(Message::text(welcome(&[]))).await.unwrap();
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        // The first is refused for the rate and sent again after the interval.
        let seen = publishes(&mut socket, 2, |id, n| {
            if n == 0 {
                ServerMessage::error(Some(id), ErrorCode::RateLimited, "one per second")
            } else {
                ServerMessage::result(id, &())
            }
        })
        .await;
        assert_eq!(seen[0].0, seen[1].0);
        assert!(seen[1].1 - seen[0].1 >= interval);
        // Two changes in quick succession: only the last one goes out.
        latest.send_replace(addresses(2));
        latest.send_replace(addresses(3));
        let seen = publishes(&mut socket, 1, |id, _| ServerMessage::result(id, &())).await;
        assert_eq!(seen[0].0, vec![SocketAddr::from(([192, 0, 2, 1], 3))]);
        // A new connection gets them again, without a change.
        send_close(&mut socket, 1011).await;
        drop(socket);
        let mut socket = accept_hello(&listener).await;
        socket.send(Message::text(welcome(&[]))).await.unwrap();
        let seen = publishes(&mut socket, 1, |id, _| ServerMessage::result(id, &())).await;
        assert_eq!(seen[0].0, vec![SocketAddr::from(([192, 0, 2, 1], 3))]);
        drop(latest);
    }

    /// [`FAST`] with a backoff that only a network change ends within a test.
    const SLOW_BACKOFF: Timing = Timing {
        first_backoff: Duration::from_secs(30),
        ..FAST
    };

    #[tokio::test]
    async fn a_network_change_ends_the_backoff_with_attempts_spaced_and_capped() {
        let (listener, channel, _events) = scripted_with(SLOW_BACKOFF).await;
        // Every attempt fails at once: the server drops the connection.
        let attempts = tokio::spawn(async move {
            let mut at = Vec::new();
            while let Ok(Ok((tcp, _))) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept()).await
            {
                at.push(Instant::now());
                drop(tcp);
            }
            at
        });
        // A network that keeps changing, for longer than the attempts it may bring forward.
        for _ in 0..100 {
            channel.network_changed();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let at = attempts.await.unwrap();
        // The first attempt, then one per change but spaced, until the cap; then the backoff.
        assert_eq!(at.len(), EARLY_ATTEMPTS_PER_MINUTE, "{at:?}");
        for pair in at.windows(2) {
            let gap = pair[1] - pair[0];
            assert!(
                gap >= FAST.spacing - Duration::from_millis(10) && gap < Duration::from_secs(1),
                "{gap:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_wait_the_server_named_stands() {
        let (listener, channel, mut events) = scripted().await;
        let mut socket = accept_hello(&listener).await;
        socket.send(Message::text(welcome(&[]))).await.unwrap();
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        // Over 20 connections a minute: the server says to come back in 60 seconds.
        send_close(&mut socket, close::RATE_LIMITED).await;
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Disconnected(_)
        ));
        channel.network_changed();
        assert!(
            tokio::time::timeout(Duration::from_millis(1500), listener.accept())
                .await
                .is_err(),
            "reconnected within the server's 60 seconds"
        );
    }

    #[tokio::test]
    async fn a_network_change_abandons_a_stalled_attempt() {
        let (listener, channel, mut events) = scripted_with(SLOW_BACKOFF).await;
        // The first attempt stalls: the server takes the connection and never answers the
        // upgrade, so only `OPEN_TIMEOUT` would end it.
        let (_stalled, _) = listener.accept().await.unwrap();
        let changed = Instant::now();
        channel.network_changed();
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Disconnected(reason) if reason.contains("network changed")
        ));
        let mut socket = accept_hello(&listener).await;
        socket.send(Message::text(welcome(&[]))).await.unwrap();
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        assert!(
            changed.elapsed() < Duration::from_secs(2),
            "{:?}",
            changed.elapsed()
        );
    }

    #[tokio::test]
    async fn a_network_change_pings_and_leaves_only_a_dead_connection() {
        // Only the ping can tell a dead connection from a quiet one within the test.
        let timing = Timing {
            silence: Duration::from_secs(30),
            ..FAST
        };
        let (listener, channel, mut events) = scripted_with(timing).await;

        // A connection on a network that is gone: open, but nothing answers.
        let mut dead = accept_hello(&listener).await;
        dead.send(Message::text(welcome(&[]))).await.unwrap();
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        let changed = Instant::now();
        channel.network_changed();
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Disconnected(reason) if reason.contains("ping")
        ));
        assert!(
            changed.elapsed() < Duration::from_secs(2),
            "{:?}",
            changed.elapsed()
        );

        // The channel connects again; a connection that answers the ping stays.
        let mut socket = accept_hello(&listener).await;
        socket.send(Message::text(welcome(&[]))).await.unwrap();
        assert!(matches!(
            next(&mut events).await,
            ChannelEvent::Connected(_)
        ));
        // Reading answers the ping with a pong.
        let answering = tokio::spawn(async move { while let Some(Ok(_)) = socket.next().await {} });
        channel.network_changed();
        assert!(
            tokio::time::timeout(timing.probe * 3, events.recv())
                .await
                .is_err(),
            "the answered ping keeps the connection"
        );
        assert!(channel.is_connected());
        answering.abort();
        drop(dead);
    }
}
