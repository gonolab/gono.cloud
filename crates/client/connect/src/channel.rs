//! The control channel (protocol 5): one WebSocket to the server, kept open by a background
//! task that reconnects with backoff and hands the product its events.
//!
//! - **Handshake.** Basic authentication with the device's app password, the server's
//!   `challenge`, a `hello` signed with the device key, and the `welcome`
//!   ([`ChannelEvent::Connected`]).
//! - **Requests** ([`ControlChannel::request`] and its typed helpers) wait while the channel
//!   reconnects, for at most [`REQUEST_TIMEOUT`].
//! - **Events** reach the product as [`ChannelEvent::Message`]. The logged ones carry a `seq`:
//!   the product acts on them and then calls [`ControlChannel::ack`], which moves the cursor
//!   the next `hello` sends (protocol 5.6).
//! - **The end.** A revoked device (`4003`), a device signed out or replaced, credentials the
//!   server no longer knows (`401`) and a failed handshake end the channel for good
//!   ([`ChannelEvent::Ended`]); everything else is retried. `503` and other server problems
//!   are never taken for "signed out" (threat model C6).

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use futures_util::{SinkExt as _, StreamExt as _};
use gono_protocol::connect::{
    ClientMessage, DeviceId, Discovery, ServerMessage, Signed, Statement, close, features,
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
    tungstenite::{self, Message, client::IntoClientRequest as _, protocol::CloseFrame},
};
use url::Url;

use crate::{Credentials, Error, Result, tls};

/// How long a request waits for its answer, reconnects included.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the server may take to send `challenge` and `welcome`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The longest wait between reconnects.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long to wait after `404` (remote access off) or `4004` (account disabled).
const SLOW_RETRY: Duration = Duration::from_secs(60 * 60);

/// What the channel needs.
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
    /// The handshake failed (`4000`): the hello proof did not hold.
    HandshakeFailed(String),
}

/// What the channel hands the product.
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// Connected: the server's `welcome`, after every (re)connect.
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

/// See the module documentation. Cheap to clone; dropping the last clone stops the channel.
#[derive(Debug, Clone)]
pub struct ControlChannel {
    commands: mpsc::Sender<Command>,
    cursor: Arc<AtomicI64>,
    connected: watch::Receiver<bool>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Command")
    }
}

impl ControlChannel {
    /// Starts the channel's background task.
    pub fn start(options: ChannelOptions) -> (Self, mpsc::Receiver<ChannelEvent>) {
        let (commands, command_rx) = mpsc::channel(64);
        let (events, event_rx) = mpsc::channel(256);
        let (connected_tx, connected) = watch::channel(false);
        let cursor = Arc::new(AtomicI64::new(options.since));
        tokio::spawn(run(
            options,
            Arc::clone(&cursor),
            command_rx,
            events,
            connected_tx,
        ));
        (
            Self {
                commands,
                cursor,
                connected,
            },
            event_rx,
        )
    }

    /// Whether the channel is connected now.
    pub fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }

    /// Waits until the channel is connected, for at most `limit`. Returns whether it is.
    pub async fn wait_connected(&self, limit: Duration) -> bool {
        let mut connected = self.connected.clone();
        tokio::time::timeout(limit, connected.wait_for(|connected| *connected))
            .await
            .is_ok_and(|result| result.is_ok())
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
    pub async fn publish(
        &self,
        relay_url: Option<String>,
        direct: Vec<std::net::SocketAddr>,
    ) -> Result<()> {
        self.done(move |id| ClientMessage::Publish {
            id,
            relay_url,
            direct,
        })
        .await
    }

    /// Asks to connect to `target` (protocol 7.2) and returns its addresses.
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

    /// Fresh addresses of a device the device is connecting to (protocol 7.3).
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
enum Outcome {
    /// Reconnect, after `after` or the backoff.
    Retry {
        reason: String,
        after: Option<Duration>,
        /// It got as far as the welcome, so the backoff starts over.
        was_connected: bool,
    },
    /// Stop for good.
    End(EndReason),
    /// Every handle was dropped.
    Stopped,
}

async fn run(
    options: ChannelOptions,
    cursor: Arc<AtomicI64>,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<ChannelEvent>,
    connected: watch::Sender<bool>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let outcome = connection(&options, &cursor, &mut commands, &events, &connected).await;
        let _ = connected.send(false);
        match outcome {
            Outcome::Stopped => return,
            Outcome::End(reason) => {
                tracing::info!(?reason, "control channel ended");
                let _ = events.send(ChannelEvent::Ended(reason)).await;
                // Answer whatever is still queued.
                commands.close();
                while let Some(command) = commands.recv().await {
                    let _ = command
                        .reply
                        .send(Err(Error::Channel("the channel has ended".to_owned())));
                }
                return;
            }
            Outcome::Retry {
                reason,
                after,
                was_connected,
            } => {
                tracing::debug!(reason, "control channel disconnected");
                if events
                    .send(ChannelEvent::Disconnected(reason))
                    .await
                    .is_err()
                {
                    return;
                }
                if was_connected {
                    backoff = Duration::from_secs(1);
                }
                let jitter = rand::rng().random_range(0..=backoff.as_millis() as u64 / 2);
                let wait = after.unwrap_or(backoff + Duration::from_millis(jitter));
                backoff = (backoff * 2).min(MAX_BACKOFF);
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    // Every handle dropped while waiting.
                    () = commands_closed(&commands) => return,
                }
            }
        }
    }
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

/// Opens the WebSocket with the device's credential.
async fn open(options: &ChannelOptions) -> std::result::Result<Socket, Outcome> {
    let retry = |reason: String| Outcome::Retry {
        reason,
        after: None,
        was_connected: false,
    };
    let url = Url::parse(&options.discovery.websocket).map_err(|err| retry(err.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| retry("the websocket URL has no host".to_owned()))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| retry("the websocket URL has no port".to_owned()))?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|err| retry(err.to_string()))?;
    let _ = tcp.set_nodelay(true);
    let stream: Box<dyn Io> = if url.scheme() == "wss" {
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(&[b"http/1.1"])));
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|err| retry(err.to_string()))?;
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
            options.credentials.username, options.credentials.app_password
        )
        .as_bytes(),
    );
    request.headers_mut().insert(
        "authorization",
        format!("Basic {credentials}")
            .parse()
            .map_err(|_| retry("unusable credential".to_owned()))?,
    );
    match tokio_tungstenite::client_async(request, stream).await {
        Ok((socket, _)) => Ok(socket),
        Err(tungstenite::Error::Http(response)) => {
            let status = response.status().as_u16();
            Err(match status {
                401 | 403 => Outcome::End(EndReason::Unauthorized),
                404 => Outcome::Retry {
                    reason: "remote access is off on the server".to_owned(),
                    after: Some(SLOW_RETRY),
                    was_connected: false,
                },
                429 => Outcome::Retry {
                    reason: "rate limited".to_owned(),
                    after: response
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse().ok())
                        .map(Duration::from_secs),
                    was_connected: false,
                },
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

/// The next text frame, as a server message.
async fn next_message(socket: &mut Socket) -> std::result::Result<ServerMessage, Outcome> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(text.as_str()).map_err(|err| Outcome::Retry {
                    reason: format!("unreadable frame: {err}"),
                    after: None,
                    was_connected: false,
                });
            }
            Some(Ok(Message::Close(frame))) => return Err(closed(frame.as_ref(), false)),
            Some(Ok(_)) => {}
            Some(Err(err)) => {
                return Err(Outcome::Retry {
                    reason: err.to_string(),
                    after: None,
                    was_connected: false,
                });
            }
            None => {
                return Err(Outcome::Retry {
                    reason: "the connection closed".to_owned(),
                    after: None,
                    was_connected: false,
                });
            }
        }
    }
}

/// What a close frame of the server means (protocol 5.4).
fn closed(frame: Option<&CloseFrame>, was_connected: bool) -> Outcome {
    let code = frame.map(|frame| u16::from(frame.code));
    let reason = frame
        .map(|frame| frame.reason.to_string())
        .unwrap_or_default();
    let retry = |after| Outcome::Retry {
        reason: format!("closed by the server ({code:?}): {reason}"),
        after,
        was_connected,
    };
    match code {
        Some(close::REVOKED) => Outcome::End(EndReason::Revoked),
        Some(close::REPLACED) => Outcome::End(EndReason::Replaced),
        Some(close::HANDSHAKE_FAILED) => Outcome::End(EndReason::HandshakeFailed(reason)),
        Some(1000) => Outcome::End(EndReason::SignedOut),
        Some(close::ACCOUNT_DISABLED) => retry(Some(SLOW_RETRY)),
        Some(close::RATE_LIMITED) => retry(Some(Duration::from_secs(60))),
        _ => retry(None),
    }
}

/// One connection, from opening it to its end.
async fn connection(
    options: &ChannelOptions,
    cursor: &AtomicI64,
    commands: &mut mpsc::Receiver<Command>,
    events: &mpsc::Sender<ChannelEvent>,
    connected: &watch::Sender<bool>,
) -> Outcome {
    if commands.is_closed() && commands.is_empty() {
        return Outcome::Stopped;
    }
    let mut socket = match open(options).await {
        Ok(socket) => socket,
        Err(outcome) => return outcome,
    };
    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let ServerMessage::Challenge { nonce, .. } = next_message(&mut socket).await? else {
            return Err(Outcome::Retry {
                reason: "the server did not send a challenge".to_owned(),
                after: None,
                was_connected: false,
            });
        };
        let hello = ClientMessage::Hello(HelloMessage {
            proof: Signed::sign(
                &Statement::Hello(Hello {
                    server: options.credentials.server.clone(),
                    account: options.credentials.username.clone(),
                    endpoint_id: options.key.public().into(),
                    nonce,
                }),
                &options.key,
            ),
            since: cursor.load(Ordering::Relaxed),
            version: options.version.clone(),
            features: options.features.clone(),
            settings: options.settings.clone(),
        });
        socket
            .send(Message::text(
                serde_json::to_string(&hello).unwrap_or_default(),
            ))
            .await
            .map_err(|err| Outcome::Retry {
                reason: err.to_string(),
                after: None,
                was_connected: false,
            })?;
        match next_message(&mut socket).await? {
            ServerMessage::Welcome(welcome) => Ok(welcome),
            ServerMessage::Error { message, .. } => {
                Err(Outcome::End(EndReason::HandshakeFailed(message)))
            }
            other => Err(Outcome::Retry {
                reason: format!("unexpected answer to hello: {other:?}"),
                after: None,
                was_connected: false,
            }),
        }
    })
    .await;
    let welcome = match handshake {
        Ok(Ok(welcome)) => welcome,
        Ok(Err(outcome)) => return outcome,
        Err(_) => {
            return Outcome::Retry {
                reason: "the handshake timed out".to_owned(),
                after: None,
                was_connected: false,
            };
        }
    };
    let _ = connected.send(true);
    if events.send(ChannelEvent::Connected(welcome)).await.is_err() {
        return Outcome::Stopped;
    }

    let mut pending: HashMap<u64, oneshot::Sender<Result<ServerMessage>>> = HashMap::new();
    let mut next_id: u64 = 1;
    let outcome = loop {
        tokio::select! {
            frame = socket.next() => match frame {
                Some(Ok(Message::Text(text))) => {
                    let Ok(message) = serde_json::from_str::<ServerMessage>(text.as_str()) else {
                        tracing::debug!("ignoring an unreadable frame of the control channel");
                        continue;
                    };
                    let answered = match &message {
                        ServerMessage::Result { id, .. } => Some(*id),
                        ServerMessage::Error { id, .. } => *id,
                        _ => None,
                    };
                    match answered.and_then(|id| pending.remove(&id)) {
                        Some(reply) => {
                            let _ = reply.send(Ok(message));
                        }
                        None => {
                            if events
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
                Some(Err(err)) => break Outcome::Retry {
                    reason: err.to_string(),
                    after: None,
                    was_connected: true,
                },
                None => break Outcome::Retry {
                    reason: "the connection closed".to_owned(),
                    after: None,
                    was_connected: true,
                },
            },
            command = commands.recv() => match command {
                Some(command) => {
                    let id = next_id;
                    next_id += 1;
                    let text = serde_json::to_string(&(command.build)(id)).unwrap_or_default();
                    if let Err(err) = socket.send(Message::text(text)).await {
                        let _ = command.reply.send(Err(Error::Channel(err.to_string())));
                        break Outcome::Retry {
                            reason: err.to_string(),
                            after: None,
                            was_connected: true,
                        };
                    }
                    pending.insert(id, command.reply);
                }
                None => {
                    let _ = socket.close(None).await;
                    break Outcome::Stopped;
                }
            },
        }
    };
    for (_, reply) in pending {
        let _ = reply.send(Err(Error::Channel("the connection broke".to_owned())));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for code in [1001, 1011, close::TIMED_OUT, close::PROTOCOL] {
            assert!(
                matches!(
                    closed(Some(&frame(code)), true),
                    Outcome::Retry { after: None, .. }
                ),
                "{code}"
            );
        }
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
}
