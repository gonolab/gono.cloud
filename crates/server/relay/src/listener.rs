//! The relay's plain-HTTP listener on `relay.bind`: the relay protocol's WebSocket on `/relay`,
//! and the probes devices use (`/ping`, `/generate_204`) next to `/healthz`.
//!
//! iroh-relay's own server cannot read each device at the rate of its [`Tier`](crate::Tier): it
//! applies one rate limit to the TCP stream before the relay handshake has said which device is
//! connecting, and its access control answers only yes or no. So this listener mounts the relay
//! protocol itself with the parts iroh-relay 1.4.1 exports for embedders, following the accept
//! path of its own server (`server/http_server.rs`): the same WebSocket upgrade and protocol
//! version negotiation, handshake, write timeout, queue depth and metrics. It differs in one
//! point: once the handshake proved the device, the allowlist gives its tier, and the connection
//! is read at that tier's rate (`limit.rs`).
//!
//! One thing iroh-relay keeps to itself: the `Status::RateLimited` notice its server sends a
//! client the first time it holds the client back (`client::Config::rate_limited` is private to
//! the crate). Devices only log that notice, so they miss nothing else here.

use std::{
    convert::Infallible,
    fmt,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use base64::Engine as _;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
    header::{
        ACCESS_CONTROL_ALLOW_ORIGIN, CONNECTION, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
        SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION,
        STRICT_TRANSPORT_SECURITY, UPGRADE,
    },
    request::Parts,
};
use http_body_util::Full;
use hyper::{
    body::Incoming,
    server::conn::http1,
    service::service_fn,
    upgrade::{OnUpgrade, Upgraded},
};
use hyper_util::rt::TokioIo;
use iroh_relay::{
    ExportKeyingMaterial, KeyCache,
    defaults::{DEFAULT_KEY_CACHE_CAPACITY, timeouts::SERVER_WRITE_TIMEOUT},
    http::{CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH, RELAY_PROBE_PATH},
    protos::{handshake, streams::StreamError},
    server::{
        Access, ClientRequest, DynAccessControl, Metrics, OnDisconnectGuard,
        client::Config,
        clients::Clients,
        streams::{InvalidBucketConfig, RelayedStream},
    },
};
use sha1::{Digest as _, Sha1};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinError, JoinHandle, JoinSet},
};
use tokio_websockets::{Message, Payload, WebSocketStream};
use tracing::Instrument as _;

use crate::{
    access::Allowlist,
    limit::{Limits, Throttled},
};

/// How long a connection may take from its first byte until it is registered with the relay:
/// its HTTP request, the WebSocket upgrade and the relay handshake. iroh-relay's own value.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// The value of the `Upgrade` header that asks for a WebSocket (iroh-relay does not export it).
const WEBSOCKET: &str = "websocket";

/// The only WebSocket version there is (RFC 6455); iroh-relay accepts only it.
const WEBSOCKET_VERSION: &str = "13";

/// Appended to a client's `Sec-WebSocket-Key` for the accept key (RFC 6455, section 1.3).
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The largest WebSocket message of the relay protocol, as iroh-relay's `MAX_FRAME_SIZE`
/// (which it does not export).
const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// The captive-portal probe's challenge and answer headers, as iroh-relay serves them.
const NO_CONTENT_CHALLENGE: HeaderName = HeaderName::from_static("x-iroh-challenge");
const NO_CONTENT_RESPONSE: HeaderName = HeaderName::from_static("x-iroh-response");

const INDEX: &str = "<html><body>\n<h1>Gono Cloud relay</h1>\n<p>\n  Gono devices reach each \
                     other through this relay when they cannot connect directly.\n</p>\n\
                     </body></html>\n";
const ROBOTS_TXT: &str = "User-agent: *\nDisallow: /\n";
const HEALTH: &str = concat!(
    "{\"status\":\"ok\",\"version\":\"",
    env!("CARGO_PKG_VERSION"),
    "\"}"
);

/// What every connection of the listener shares.
#[derive(Debug)]
pub(crate) struct State {
    access: Arc<Allowlist>,
    /// The same allowlist, as the guards of admitted connections report their end to it.
    on_disconnect: Arc<dyn DynAccessControl>,
    limits: Limits,
    clients: Clients,
    key_cache: KeyCache,
    metrics: Arc<Metrics>,
    /// Sent with every response: the headers iroh-relay's server sends. The reverse proxy
    /// serves the relay over HTTPS only.
    headers: HeaderMap,
}

impl State {
    pub(crate) fn new(access: Arc<Allowlist>, limits: Limits, metrics: Arc<Metrics>) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri \
                 'self'; block-all-mixed-content; plugin-types 'none'",
            ),
        );
        Self {
            on_disconnect: access.clone(),
            access,
            limits,
            clients: Clients::default(),
            key_cache: KeyCache::new(DEFAULT_KEY_CACHE_CAPACITY),
            metrics,
            headers,
        }
    }

    /// The registry of connected devices, through which they are disconnected.
    pub(crate) fn clients(&self) -> &Clients {
        &self.clients
    }

    /// A response with the common headers.
    fn reply(&self, status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
        let mut response = Response::new(Full::new(body.into()));
        *response.status_mut() = status;
        response.headers_mut().extend(self.headers.clone());
        response
    }
}

/// The running listener. Dropping it stops accepting connections; [`Listener::shutdown`] also
/// closes the devices' connections.
#[derive(Debug)]
pub(crate) struct Listener {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    /// Whether [`Listener::stopped`] saw the task end, after which it must not be awaited again.
    ended: bool,
}

impl Listener {
    /// Serves `listener` with `state` until stopped.
    pub(crate) fn spawn(listener: TcpListener, state: Arc<State>) -> Self {
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(listener, state, stopped));
        Self {
            stop: Some(stop),
            task,
            ended: false,
        }
    }

    /// Completes when the listener stops on its own, which only a panic in one of its
    /// connections causes.
    pub(crate) async fn stopped(&mut self) -> Result<(), JoinError> {
        let result = (&mut self.task).await;
        self.ended = true;
        result
    }

    /// Stops accepting connections, closes the devices' connections and waits until all are
    /// gone.
    pub(crate) async fn shutdown(mut self) -> Result<(), JoinError> {
        if self.ended {
            return Ok(());
        }
        if let Some(stop) = self.stop.take() {
            // The task may be gone already, which is what is asked for.
            let _ = stop.send(());
        }
        (&mut self.task).await
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The accept loop, as iroh-relay's: a task per connection, until `stop`.
async fn serve(listener: TcpListener, state: Arc<State>, mut stop: oneshot::Receiver<()>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            Some(joined) = connections.join_next() => {
                // A panic in a connection takes the relay down, as in iroh-relay.
                if let Err(err) = joined
                    && err.is_panic()
                {
                    std::panic::resume_unwind(err.into_panic());
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let span = tracing::debug_span!("relay connection", %peer);
                    connections.spawn(serve_connection(Arc::clone(&state), stream).instrument(span));
                }
                Err(err) => tracing::error!(error = %err, "relay: cannot accept a connection"),
            },
        }
    }
    // Connections still being set up go first, so that none registers after the others closed.
    connections.shutdown().await;
    state.clients.shutdown().await;
}

/// Serves one TCP connection: probes, or the relay protocol after an upgrade.
async fn serve_connection(state: Arc<State>, stream: TcpStream) {
    let metrics = Arc::clone(&state.metrics);
    metrics.http_connections.inc();
    let result = tokio::time::timeout(ESTABLISH_TIMEOUT, establish(state, stream)).await;
    metrics.http_connections_closed.inc();
    match result {
        Ok(Ok(())) => {}
        Ok(Err(Failure::Http(err))) if err.is_incomplete_message() => {
            tracing::debug!(reason = %err, "peer disconnected");
        }
        Ok(Err(err @ Failure::Http(_))) => {
            metrics.http_connections_errored.inc();
            tracing::warn!(error = %err, "relay connection failed");
        }
        Ok(Err(err)) => tracing::warn!(error = %err, "relay connection not accepted"),
        Err(_) => {
            metrics.http_connections_errored.inc();
            tracing::debug!(
                "relay connection closed: not established within {} seconds",
                ESTABLISH_TIMEOUT.as_secs()
            );
        }
    }
}

/// Why a connection was not accepted.
#[derive(Debug)]
enum Failure {
    Http(hyper::Error),
    Upgrade(hyper::Error),
    /// hyper upgraded another type of stream than the one it was given.
    Downcast,
    /// The client sent relay frames before it saw the upgrade.
    BufferNotEmpty,
    Handshake(handshake::Error),
    RateLimit(InvalidBucketConfig),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(err) => write!(f, "HTTP: {err}"),
            Self::Upgrade(err) => write!(f, "WebSocket upgrade: {err}"),
            Self::Downcast => f.write_str("cannot take over the upgraded connection"),
            Self::BufferNotEmpty => f.write_str("data arrived before the upgrade was answered"),
            Self::Handshake(err) => write!(f, "relay handshake: {err}"),
            Self::RateLimit(err) => write!(f, "rate limit misconfigured: {err}"),
        }
    }
}

/// A `/relay` request that was answered with `101 Switching Protocols`.
struct Upgrade {
    on_upgrade: OnUpgrade,
    parts: Parts,
    version: ProtocolVersion,
}

/// Serves HTTP on `stream` until the connection closes or upgrades, then runs the relay
/// protocol on the upgraded connection.
///
/// iroh-relay runs the protocol in a task of its own once the upgrade is answered; here it runs
/// in the connection's task, so that the establish timeout also covers the handshake and
/// shutting the listener down also ends connections still in it.
async fn establish(state: Arc<State>, stream: TcpStream) -> Result<(), Failure> {
    let upgrade: Arc<Mutex<Option<Upgrade>>> = Arc::new(Mutex::new(None));
    let service = {
        let state = Arc::clone(&state);
        let upgrade = Arc::clone(&upgrade);
        service_fn(move |request| {
            let response = respond(&state, request, &upgrade);
            std::future::ready(Ok::<_, Infallible>(response))
        })
    };
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .map_err(Failure::Http)?;
    let upgrade = upgrade
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    let Some(Upgrade {
        on_upgrade,
        parts,
        version,
    }) = upgrade
    else {
        return Ok(());
    };
    let upgraded = on_upgrade.await.map_err(Failure::Upgrade)?;
    accept(&state, upgraded, parts, version).await
}

/// Answers one HTTP request. A `/relay` request that may upgrade leaves its upgrade in
/// `upgrade`.
fn respond(
    state: &State,
    mut request: Request<Incoming>,
    upgrade: &Mutex<Option<Upgrade>>,
) -> Response<Full<Bytes>> {
    if request.method() != Method::GET {
        return state.reply(StatusCode::NOT_FOUND, "Not Found");
    }
    match request.uri().path() {
        RELAY_PATH => match negotiate(request.headers()) {
            Ok((key, version)) => {
                let Ok(accept_key) = HeaderValue::try_from(accept_key(&key)) else {
                    return state.reply(StatusCode::INTERNAL_SERVER_ERROR, "");
                };
                let on_upgrade = hyper::upgrade::on(&mut request);
                let (parts, _body) = request.into_parts();
                *upgrade.lock().unwrap_or_else(PoisonError::into_inner) = Some(Upgrade {
                    on_upgrade,
                    parts,
                    version,
                });
                let mut response = state.reply(
                    StatusCode::SWITCHING_PROTOCOLS,
                    "switching to websocket protocol",
                );
                let headers = response.headers_mut();
                headers.insert(UPGRADE, HeaderValue::from_static(WEBSOCKET));
                headers.insert(SEC_WEBSOCKET_ACCEPT, accept_key);
                headers.insert(SEC_WEBSOCKET_PROTOCOL, version.to_header_value());
                headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
                response
            }
            Err(refusal) => {
                let mut response = state.reply(StatusCode::BAD_REQUEST, refusal.to_string());
                // It's convention to send back the version we do support.
                if let Refusal::WebSocketVersion = refusal {
                    response.headers_mut().insert(
                        SEC_WEBSOCKET_VERSION,
                        HeaderValue::from_static(WEBSOCKET_VERSION),
                    );
                }
                response
            }
        },
        RELAY_PROBE_PATH => {
            let mut response = state.reply(StatusCode::OK, Bytes::new());
            response
                .headers_mut()
                .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
            response
        }
        "/generate_204" => no_content(state, request.headers()),
        "/" | "/index.html" => {
            let mut response = state.reply(StatusCode::OK, INDEX);
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            response
        }
        "/robots.txt" => state.reply(StatusCode::OK, ROBOTS_TXT),
        "/healthz" => {
            let mut response = state.reply(StatusCode::OK, HEALTH);
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        }
        _ => state.reply(StatusCode::NOT_FOUND, "Not Found"),
    }
}

/// Why a `/relay` request cannot upgrade. The messages are iroh-relay's.
#[derive(Debug)]
enum Refusal {
    MissingHeader(HeaderName),
    InvalidHeader(HeaderName, &'static str),
    WebSocketVersion,
    RelayVersion(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader(header) => write!(f, "missing header: {header}"),
            Self::InvalidHeader(header, details) => {
                write!(f, "invalid header value for {header}: {details}")
            }
            Self::WebSocketVersion => write!(
                f,
                "invalid header value for {SEC_WEBSOCKET_VERSION}: unsupported websocket \
                 version, only supporting {WEBSOCKET_VERSION}"
            ),
            Self::RelayVersion(offered) => write!(
                f,
                "invalid header value for {SEC_WEBSOCKET_PROTOCOL}: unsupported relay version: \
                 we support {} but you only provide {offered}",
                ProtocolVersion::all_joined()
            ),
        }
    }
}

/// Checks the WebSocket upgrade of a `/relay` request as iroh-relay does, and picks the newest
/// relay protocol version both sides support. Returns the client's WebSocket key with it.
fn negotiate(headers: &HeaderMap) -> Result<(HeaderValue, ProtocolVersion), Refusal> {
    let header = |name: HeaderName| {
        headers
            .get(&name)
            .ok_or_else(|| Refusal::MissingHeader(name))
    };
    if header(UPGRADE)? != WEBSOCKET {
        return Err(Refusal::InvalidHeader(UPGRADE, "value must be websocket"));
    }
    let key = header(SEC_WEBSOCKET_KEY)?.clone();
    if header(SEC_WEBSOCKET_VERSION)? != WEBSOCKET_VERSION {
        return Err(Refusal::WebSocketVersion);
    }
    let offered = header(SEC_WEBSOCKET_PROTOCOL)?
        .to_str()
        .map_err(|_| Refusal::InvalidHeader(SEC_WEBSOCKET_PROTOCOL, "header value is not ascii"))?;
    let version = offered
        .split(',')
        .map(str::trim)
        .filter_map(ProtocolVersion::match_from_str)
        .max()
        .ok_or_else(|| Refusal::RelayVersion(offered.to_owned()))?;
    Ok((key, version))
}

/// The `Sec-WebSocket-Accept` value for the client's `Sec-WebSocket-Key`.
fn accept_key(key: &HeaderValue) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(WEBSOCKET_GUID);
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

/// The captive-portal probe: 204, answering a well-formed challenge as iroh-relay does.
fn no_content(state: &State, headers: &HeaderMap) -> Response<Full<Bytes>> {
    let mut response = state.reply(StatusCode::NO_CONTENT, Bytes::new());
    if let Some(challenge) = headers.get(NO_CONTENT_CHALLENGE)
        && !challenge.is_empty()
        && challenge.len() < 64
        && challenge
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        let answer = [b"response ".as_slice(), challenge.as_bytes()].concat();
        if let Ok(answer) = HeaderValue::from_bytes(&answer) {
            response.headers_mut().insert(NO_CONTENT_RESPONSE, answer);
        }
    }
    response
}

/// Runs the relay handshake on an upgraded `/relay` connection, admits the device at its tier
/// and registers it with the relay.
async fn accept(
    state: &State,
    upgraded: Upgraded,
    parts: Parts,
    version: ProtocolVersion,
) -> Result<(), Failure> {
    let upgraded = upgraded
        .downcast::<TokioIo<TcpStream>>()
        .map_err(|_| Failure::Downcast)?;
    if !upgraded.read_buf.is_empty() {
        return Err(Failure::BufferNotEmpty);
    }
    let stream = upgraded.io.into_inner();
    disable_nagle(&stream);
    let websocket = tokio_websockets::ServerBuilder::new()
        .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)))
        .serve(stream);
    let mut frames = Frames(websocket);

    let client_auth = parts.headers.get(CLIENT_AUTH_HEADER).cloned();
    let authentication = handshake::serverside(&mut frames, client_auth)
        .await
        .map_err(Failure::Handshake)?;
    tracing::trace!(mechanism = ?authentication.mechanism, "relay handshake verified");
    let request = ClientRequest::new(authentication.client_key, version, parts);

    let Some(tier) = state.access.admit(&request) else {
        // No reason: the client learns that it was refused, nothing about the list. The
        // allowlist logged the refusal; what the client makes of the answer does not matter.
        let _ = authentication
            .authorize_if(Access::Deny { reason: None }, &mut frames)
            .await;
        return Ok(());
    };
    // From here on the guard reports the end of the connection to the allowlist, however it
    // ends.
    let guard = OnDisconnectGuard::for_access_control(Arc::clone(&state.on_disconnect), &request);
    let bucket = state.limits.bucket(tier).map_err(Failure::RateLimit)?;
    authentication
        .authorize_if(Access::Allow, &mut frames)
        .await
        .map_err(Failure::Handshake)?;

    let stream = RelayedStream::new(
        Throttled::new(frames, bucket, Arc::clone(&state.metrics)),
        state.key_cache.clone(),
    );
    let mut config = Config::new(guard, stream, version);
    config.write_timeout = SERVER_WRITE_TIMEOUT;
    tracing::trace!(device = %request.endpoint_id().fmt_short(), ?tier, "relay client registered");
    state.clients.register(config, Arc::clone(&state.metrics));
    Ok(())
}

/// Turns Nagle's algorithm off, as iroh-relay does for its connections: relayed packets are
/// small and latency matters. Warns once if that fails.
fn disable_nagle(stream: &TcpStream) {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if stream.set_nodelay(true).is_err() && !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "cannot turn Nagle's algorithm off for relay connections; this slows relaying down"
        );
    }
}

/// The relay protocol's frames on a WebSocket, one binary message each, as iroh-relay's own
/// `WsBytesFramed` (which it does not export) reads and writes them.
struct Frames(WebSocketStream<TcpStream>);

impl fmt::Debug for Frames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frames").finish_non_exhaustive()
    }
}

impl Stream for Frames {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            return match ready!(Pin::new(&mut self.0).poll_next(cx)) {
                None => Poll::Ready(None),
                Some(Err(err)) => Poll::Ready(Some(Err(StreamError::from_std(err)))),
                // The WebSocket ends with a close message; it need not be read to the end.
                Some(Ok(message)) if message.is_close() => Poll::Ready(None),
                // tokio-websockets answers pings itself.
                Some(Ok(message)) if message.is_ping() || message.is_pong() => continue,
                Some(Ok(message)) if message.is_binary() => {
                    Poll::Ready(Some(Ok(message.into_payload().into())))
                }
                Some(Ok(_)) => {
                    tracing::debug!("relay connection sent a text message; skipped");
                    continue;
                }
            };
        }
    }
}

impl Sink<Bytes> for Frames {
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_ready(cx)
            .map_err(StreamError::from_std)
    }

    fn start_send(mut self: Pin<&mut Self>, frame: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.0)
            .start_send(Message::binary(Payload::from(frame)))
            .map_err(StreamError::from_std)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(StreamError::from_std)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_close(cx)
            .map_err(StreamError::from_std)
    }
}

/// The listener serves plain HTTP behind the reverse proxy, so there is no TLS session to
/// export keying material from: the handshake falls back to signing a challenge, as with
/// iroh-relay's own plain-HTTP listener.
impl ExportKeyingMaterial for Frames {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        _output: T,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Option<T> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_follows_rfc_6455() {
        // The example of RFC 6455, section 1.3.
        let key = HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept_key(&key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    fn upgrade_headers(protocols: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
        headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(protocols).unwrap(),
        );
        headers
    }

    #[test]
    fn negotiation_picks_the_newest_common_version() {
        let (_, version) = negotiate(&upgrade_headers("iroh-relay-v1, iroh-relay-v2")).unwrap();
        assert_eq!(version, ProtocolVersion::V2);
        let (_, version) = negotiate(&upgrade_headers("iroh-relay-v1")).unwrap();
        assert_eq!(version, ProtocolVersion::V1);
        assert!(matches!(
            negotiate(&upgrade_headers("iroh-relay-v9")),
            Err(Refusal::RelayVersion(_))
        ));

        let mut old = upgrade_headers("iroh-relay-v2");
        old.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("8"));
        assert!(matches!(negotiate(&old), Err(Refusal::WebSocketVersion)));
        let mut bare = upgrade_headers("iroh-relay-v2");
        bare.remove(SEC_WEBSOCKET_PROTOCOL);
        assert!(matches!(negotiate(&bare), Err(Refusal::MissingHeader(_))));
    }
}
