//! One device's control connection (`docs/connect-protocol.md`, section 5): the handshake,
//! the answers to its requests, and its events.
//!
//! The HTTP server owns the WebSocket: it authenticates the upgrade, sends the `challenge`
//! frame of [`Connect::challenge`], passes the first frame to [`Connect::hello`], and then
//! moves frames between the socket and the [`Session`] while it keeps the connection alive.

// Request handlers answer `Ok(result)` or `Err(error)`, both a `ServerMessage` that is sent at
// once; boxing the error frame would buy nothing.
#![allow(clippy::result_large_err)]

use std::{collections::VecDeque, net::IpAddr, sync::Arc};

use gono_protocol::connect::{
    ClientMessage, DeviceId, ErrorCode, ServerMessage, Statement, close, features, is_dialable,
    limits,
    message::{
        AccountInfo, AddressResult, ConnectionLimits, Envelope, HelloMessage, PairRequestResult,
        PairRequested, Purpose, SessionEvent, SessionReport, SettingsChange, SettingsResult,
        Welcome,
    },
    name, statement,
};
use gono_server_core::{
    app_passwords,
    audit::{self, Actor, Record},
    db,
    devices::{self, Device, EndpointId, Settings},
    error::Error,
};
use rand::RngExt as _;
use serde_json::json;
use tokio::sync::mpsc;
use url::Url;

use crate::{
    Connect, device_id, entry,
    hub::{Dropped, Frame, Grant, LookupBasis, Outgoing, PendingPair, Published, RequestRefusal},
    limit::Limit,
    logged_message,
};

/// How often `last_seen_at` is written while a device stays connected.
const SEEN_SECS: i64 = 5 * 60;

/// How far an approval's `issued_at` may be from the server's clock, in seconds. Devices learn
/// the server's time from `challenge` and `welcome`.
const APPROVAL_SKEW_SECS: u64 = 10 * 60;

/// The logged events a `welcome` carries, in bytes; the rest of the backlog follows as
/// ordinary event messages, in order, before live ones. Keeps every message well below the
/// 4 MiB devices accept.
const WELCOME_EVENT_BYTES: usize = 512 * 1024;

/// The values of a session report's `role` and `path` (protocol 12.2).
const ROLES: &[&str] = &["controller", "controlled", "initiator", "acceptor"];
const PATHS: &[&str] = &["direct", "relayed", "mixed"];

/// A `challenge` waiting for its `hello`.
#[derive(Debug)]
pub struct Handshake {
    nonce: [u8; 32],
}

/// The device a control connection was authenticated as.
#[derive(Debug, Clone)]
pub struct DeviceLogin {
    /// The account.
    pub user_id: i64,
    /// Its username.
    pub username: String,
    /// Its display name.
    pub display_name: String,
    /// The device, found by its app password ([`Connect::device_for`]).
    pub device: Device,
    /// Where the connection comes from.
    pub client_ip: IpAddr,
}

/// What to do after a frame of the device.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reply {
    /// A frame to send.
    pub text: Option<String>,
    /// Close the connection afterwards.
    pub close: Option<(u16, &'static str)>,
}

impl Reply {
    fn message(message: ServerMessage) -> Self {
        Self {
            text: Some(message.to_text()),
            close: None,
        }
    }
}

/// An open control connection. Dropping it ends the device's presence.
#[derive(Debug)]
pub struct Session {
    connect: Arc<Connect>,
    user_id: i64,
    username: String,
    device: Device,
    key: EndpointId,
    id: DeviceId,
    conn_id: u64,
    rx: mpsc::Receiver<Frame>,
    /// Set when the hub dropped this connection for not reading its frames.
    dropped: Arc<Dropped>,
    /// Logged events the `welcome` had no room for, sent before anything else.
    backlog: VecDeque<String>,
    /// The last logged event the `welcome` carried or covered; later copies are dropped.
    cursor: i64,
    features: Vec<String>,
    seen_at: i64,
}

/// Why a `hello` was refused: the `error` frame to send, and the close code and reason that
/// follow it (protocol 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The `error` frame.
    pub frame: String,
    /// The close code.
    pub code: u16,
    /// The close reason.
    pub reason: &'static str,
}

impl Refusal {
    fn new(code: ErrorCode, message: &str) -> Self {
        let (close, reason) = match code {
            // The server's own trouble: the device reconnects.
            ErrorCode::Unavailable => (1011, "try again later"),
            ErrorCode::RateLimited => (close::RATE_LIMITED, "reconnecting too often"),
            _ => (close::HANDSHAKE_FAILED, "handshake failed"),
        };
        Self {
            frame: error(None, code, message).to_text(),
            code: close,
            reason,
        }
    }

    fn revoked() -> Self {
        Self {
            frame: error(None, ErrorCode::NotPermitted, "the device was revoked").to_text(),
            code: close::REVOKED,
            reason: "revoked",
        }
    }
}

fn error(id: Option<u64>, code: ErrorCode, message: &str) -> ServerMessage {
    ServerMessage::error(id, code, message)
}

fn refused<T>(id: u64, code: ErrorCode, message: &str) -> Result<T, ServerMessage> {
    Err(error(Some(id), code, message))
}

impl Connect {
    /// Starts a handshake: the nonce and the `challenge` frame to send right after the
    /// upgrade.
    pub fn challenge(&self) -> (Handshake, String) {
        let nonce: [u8; 32] = rand::rng().random();
        let frame = ServerMessage::Challenge {
            nonce: statement::encode_bytes(&nonce),
            server_time: db::unix_now(),
        };
        (Handshake { nonce }, frame.to_text())
    }

    /// Checks the device's `hello` and opens its session. Returns the session and the
    /// `welcome` frame, or the [`Refusal`] to send before closing.
    pub async fn hello(
        self: &Arc<Self>,
        handshake: Handshake,
        login: DeviceLogin,
        text: &str,
    ) -> Result<(Session, String), Refusal> {
        let fail = Refusal::new;
        if self.is_stopping() {
            return Err(fail(ErrorCode::Unavailable, "the server is shutting down"));
        }
        let hello: HelloMessage = match serde_json::from_str(text) {
            Ok(ClientMessage::Hello(hello)) => hello,
            _ => {
                return Err(fail(
                    ErrorCode::BadRequest,
                    "the first message must be hello",
                ));
            }
        };
        let Some(id) = device_id(login.device.endpoint_id) else {
            return Err(fail(ErrorCode::Unavailable, "damaged directory entry"));
        };
        let proven = hello.proof.open().ok().is_some_and(|statement| {
            matches!(statement, Statement::Hello(proof)
                if proof.server == self.origin
                    && proof.account == login.username
                    && proof.endpoint_id == id
                    && proof.nonce == statement::encode_bytes(&handshake.nonce))
        });
        if !proven {
            return Err(fail(
                ErrorCode::BadSignature,
                "the hello proof does not hold",
            ));
        }

        let now = db::unix_now();
        if !self
            .hub
            .allow(login.user_id, login.device.endpoint_id, Limit::Hello, now)
        {
            return Err(fail(ErrorCode::RateLimited, "reconnecting too often"));
        }
        let mut device = login.device.clone();
        if let Some(change) = &hello.settings {
            match devices::update_settings(
                &self.pool,
                device.id,
                &settings(change),
                Actor::Device,
                now,
            )
            .await
            {
                Ok(Some(updated)) => device = updated,
                // No longer registered: revoked or signed out since the upgrade.
                Ok(None) => {
                    let revoked = devices::get(&self.pool, device.id)
                        .await
                        .ok()
                        .flatten()
                        .is_some_and(|current| current.is_revoked());
                    return Err(if revoked {
                        Refusal::revoked()
                    } else {
                        fail(ErrorCode::NotFound, "the device signed out")
                    });
                }
                Err(Error::InvalidDevice { .. }) => {
                    return Err(fail(ErrorCode::BadRequest, "invalid settings"));
                }
                Err(err) => {
                    tracing::error!(error = %err, "cannot apply device settings");
                    return Err(fail(ErrorCode::Unavailable, "try again later"));
                }
            }
        }
        let features: Vec<String> = hello
            .features
            .iter()
            .filter(|feature| features::ALL.contains(&feature.as_str()))
            .cloned()
            .collect();

        let key = device.endpoint_id;
        let registered = self.hub.register(
            login.user_id,
            key,
            login.client_ip,
            now,
            features.iter().any(|feature| feature == features::PAIRING),
            Outgoing::Close(close::REPLACED, "replaced by a newer connection"),
        );
        // The device was read at the upgrade. A revocation or sign-out since then must not
        // leave it a session: read it again now that the connection is registered, so that
        // whatever happens after this read reaches the connection through the hub.
        let refusal = match devices::get(&self.pool, device.id).await {
            Ok(Some(current))
                if current.is_active() && current.app_password_id == device.app_password_id =>
            {
                None
            }
            Ok(Some(current)) if current.is_revoked() => Some(Refusal::revoked()),
            Ok(_) => Some(fail(ErrorCode::NotFound, "the device signed out")),
            Err(err) => {
                tracing::error!(error = %err, "cannot read the device directory");
                Some(fail(ErrorCode::Unavailable, "try again later"))
            }
        };
        if let Some(refusal) = refusal {
            self.hub.unregister(login.user_id, key, registered.conn_id);
            return Err(refusal);
        }
        if registered.new_address {
            self.record(
                Record::new(login.user_id, "device.connected", Actor::Device)
                    .device(key)
                    .client_ip(Some(login.client_ip)),
                now,
            )
            .await;
        }
        if let Some(addresses) = &registered.flapping {
            tracing::warn!(device = %key.short(), "a device's connections keep replacing each other");
            let addresses: Vec<String> = addresses.iter().map(ToString::to_string).collect();
            self.record(
                Record::new(login.user_id, "device.flapping", Actor::Server)
                    .device(key)
                    .details(json!({ "client_ips": addresses })),
                now,
            )
            .await;
        }
        if let Err(err) = devices::record_seen(&self.pool, device.id, now).await {
            tracing::warn!(error = %err, "cannot record that a device was seen");
        }
        device.last_seen_at = Some(now);

        let mut session = Session {
            connect: Arc::clone(self),
            user_id: login.user_id,
            username: login.username.clone(),
            device,
            key,
            id,
            conn_id: registered.conn_id,
            rx: registered.rx,
            dropped: registered.dropped,
            backlog: VecDeque::new(),
            cursor: 0,
            features,
            seen_at: now,
        };
        let welcome = match session.welcome(&login, hello.since, now).await {
            Ok(welcome) => welcome,
            Err(err) => {
                tracing::error!(error = %err, "cannot build the welcome of a device");
                return Err(fail(ErrorCode::Unavailable, "try again later"));
            }
        };
        tracing::info!(
            user = %login.username,
            device = %key.short(),
            client = %login.client_ip,
            "device connected to the control channel"
        );
        session.announce(true);
        Ok((session, welcome))
    }
}

fn settings(change: &SettingsChange) -> Settings {
    Settings {
        name: change.name.clone(),
        accept_remote: change.accept_remote,
        unattended: change.unattended,
        services: change.services.clone(),
    }
}

/// Whether two relay URLs name the same relay.
fn same_relay(a: &str, b: &str) -> bool {
    match (Url::parse(a), Url::parse(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

impl Session {
    /// The device of this session.
    pub fn device(&self) -> &Device {
        &self.device
    }

    async fn welcome(
        &mut self,
        login: &DeviceLogin,
        since: i64,
        now: i64,
    ) -> gono_server_core::Result<String> {
        let pool = &self.connect.pool;
        let remote_access = devices::remote_access(pool, self.user_id).await?;
        if self
            .connect
            .hub
            .set_remote_access(self.user_id, remote_access)
        {
            // Noticed here before the background task: the other devices hear of it now.
            let message = ServerMessage::Account { remote_access };
            self.connect
                .hub
                .broadcast(self.user_id, &message.to_text(), Some(self.key));
        }
        let online = self.connect.hub.online(self.user_id);
        // Signed-out devices are not in the directory that devices see (protocol 9.4).
        let devices: Vec<_> = devices::list(pool, self.user_id)
            .await?
            .iter()
            .filter(|device| !device.is_signed_out())
            .filter_map(|device| entry(device, online.contains(&device.endpoint_id)))
            .collect();
        let pair_requests = if self.has(features::PAIRING) {
            self.connect
                .hub
                .requests(self.user_id)
                .into_iter()
                .filter(|pending| pending.requester != self.key)
                .map(|pending| pair_requested(&pending))
                .collect()
        } else {
            Vec::new()
        };
        // The cursor first: an event appended after it reaches the device live as well, which
        // is a harmless duplicate; read the other way round, it could be missed.
        let cursor = devices::last_seq(pool).await?;
        let (events, truncated) =
            devices::events_since(pool, self.user_id, since.max(0), limits::MAX_WELCOME_EVENTS)
                .await?;
        self.cursor = events.iter().map(|event| event.seq).fold(cursor, i64::max);
        let mut carried = Vec::new();
        let mut bytes = 0;
        for message in events.iter().filter_map(logged_message) {
            let text = message.to_text();
            bytes += text.len();
            if bytes <= WELCOME_EVENT_BYTES && self.backlog.is_empty() {
                carried.push(message);
            } else {
                self.backlog.push_back(text);
            }
        }
        let events = carried;
        let welcome = Welcome {
            server_time: now,
            account: AccountInfo {
                username: login.username.clone(),
                display_name: login.display_name.clone(),
                remote_access,
            },
            device: entry(&self.device, true).ok_or(Error::InvalidDevice {
                field: "endpoint_id",
                reason: "damaged directory entry",
            })?,
            relay_url: self.connect.relay_url().to_owned(),
            devices,
            pair_requests,
            events,
            events_truncated: truncated,
            cursor,
            features: self.features.clone(),
            limits: ConnectionLimits {
                max_frame_bytes: limits::MAX_FRAME_BYTES,
                requests_per_second: limits::REQUESTS_PER_SECOND,
                request_burst: limits::REQUEST_BURST,
                max_direct_addresses: limits::MAX_DIRECT_ADDRESSES,
                lookup_window_secs: limits::LOOKUP_WINDOW_SECS,
            },
        };
        Ok(ServerMessage::Welcome(Box::new(welcome)).to_text())
    }

    fn has(&self, feature: &str) -> bool {
        self.features.iter().any(|known| known == feature)
    }

    /// Tells the account's other devices that this one came or went.
    fn announce(&self, online: bool) {
        if let Some(entry) = entry(&self.device, online) {
            let updated = ServerMessage::DeviceUpdated { device: entry };
            self.connect
                .hub
                .broadcast(self.user_id, &updated.to_text(), Some(self.key));
        }
    }

    async fn record(&self, record: Record, now: i64) {
        self.connect.record(record, now).await;
    }

    /// The next frame to send to the device. When the hub dropped this connection (its queue
    /// was full), the answer is to close it.
    pub async fn next_outgoing(&mut self) -> Outgoing {
        if let Some(text) = self.backlog.pop_front() {
            return Outgoing::Text(text);
        }
        loop {
            tokio::select! {
                biased;
                () = self.dropped.wait() => return Outgoing::Close(close::TIMED_OUT, "too slow"),
                frame = self.rx.recv() => match frame {
                    Some(Frame::Out(frame)) => return frame,
                    Some(Frame::Logged(seq, text)) if seq > self.cursor => {
                        return Outgoing::Text(text);
                    }
                    // The welcome carried it already.
                    Some(Frame::Logged(..)) => {}
                    None => return Outgoing::Close(close::TIMED_OUT, "too slow"),
                },
            }
        }
    }

    /// The check of every ping (protocol 5.4): whether the device may stay connected. Also
    /// records that it was seen.
    pub async fn check(&mut self) -> Option<(u16, &'static str)> {
        let now = db::unix_now();
        let pool = &self.connect.pool;
        match devices::get(pool, self.device.id).await {
            Ok(Some(device)) if device.is_revoked() => return Some((close::REVOKED, "revoked")),
            Ok(Some(device)) if device.app_password_id == self.device.app_password_id => {}
            Ok(_) => return Some((1000, "signed out")),
            // A database problem never ends the connection; the next check tries again.
            Err(err) => {
                tracing::warn!(error = %err, "cannot check a device");
                return None;
            }
        }
        if let Some(app_password_id) = self.device.app_password_id {
            match app_passwords::is_active(pool, app_password_id, now).await {
                Ok(false) => return Some((close::ACCOUNT_DISABLED, "account disabled")),
                Ok(true) => {}
                Err(err) => tracing::warn!(error = %err, "cannot check a device"),
            }
        }
        if now - self.seen_at >= SEEN_SECS {
            self.seen_at = now;
            if let Err(err) = devices::record_seen(pool, self.device.id, now).await {
                tracing::warn!(error = %err, "cannot record that a device was seen");
            }
        }
        None
    }

    /// Answers one text frame of the device.
    pub async fn handle(&mut self, text: &str) -> Reply {
        if self.dropped.is_set() {
            return Reply {
                text: None,
                close: Some((close::TIMED_OUT, "too slow")),
            };
        }
        if !self
            .connect
            .hub
            .is_current(self.user_id, self.key, self.conn_id)
        {
            // Replaced: its `4001` is on the way; the newer connection is the device's session.
            return Reply {
                text: None,
                close: Some((close::REPLACED, "replaced by a newer connection")),
            };
        }
        let envelope: Envelope = match serde_json::from_str(text) {
            Ok(envelope) => envelope,
            Err(_) => {
                return Reply::message(error(None, ErrorCode::BadRequest, "malformed message"));
            }
        };
        let now = db::unix_now();
        if !self
            .connect
            .hub
            .allow(self.user_id, self.key, Limit::Request, now)
        {
            let mut limited = error(envelope.id, ErrorCode::RateLimited, "too many requests");
            if let ServerMessage::Error { retry_after, .. } = &mut limited {
                *retry_after = Some(1);
            }
            return Reply::message(limited);
        }
        if envelope.kind == "hello" {
            return Reply {
                text: Some(error(None, ErrorCode::BadRequest, "hello was sent already").to_text()),
                close: Some((close::PROTOCOL, "second hello")),
            };
        }
        if !ClientMessage::TYPES.contains(&envelope.kind.as_str()) {
            return Reply::message(error(envelope.id, ErrorCode::UnknownType, "unknown type"));
        }
        let message: ClientMessage = match serde_json::from_str(text) {
            Ok(message) => message,
            Err(_) => {
                return Reply::message(error(
                    envelope.id,
                    ErrorCode::BadRequest,
                    "malformed message",
                ));
            }
        };
        let leaving = matches!(message, ClientMessage::Leave { .. });
        let answer = match message {
            ClientMessage::Hello(_) => unreachable!("handled above"),
            ClientMessage::Settings { id, change } => self.settings(id, &change, now).await,
            ClientMessage::Publish {
                id,
                relay_url,
                direct,
            } => self.publish(id, relay_url, direct, now),
            ClientMessage::Connect {
                id,
                target,
                service,
                purpose,
                request_id,
            } => {
                self.connect_to(id, target, &service, purpose, request_id, now)
                    .await
            }
            ClientMessage::Lookup { id, target } => self.lookup(id, target, now).await,
            ClientMessage::Session { id, report } => self.session(id, &report, now).await,
            ClientMessage::PairRequest { id, request } => {
                self.pair_request(id, &request, now).await
            }
            ClientMessage::PairApprove {
                id,
                request_id,
                approval,
            } => self.pair_approve(id, &request_id, &approval, now).await,
            ClientMessage::PairDecline { id, request_id } => {
                self.pair_decline(id, &request_id, now).await
            }
            ClientMessage::PairWithdraw { id, request_id } => {
                self.pair_withdraw(id, &request_id, now).await
            }
            ClientMessage::RevocationsApplied { id, endpoint_ids } => {
                self.revocations_applied(id, &endpoint_ids, now).await
            }
            ClientMessage::Ack { id, .. } => Ok(ServerMessage::result(id, &())),
            ClientMessage::Leave { id } => self.leave(id).await,
        };
        let message = answer.unwrap_or_else(|refusal| refusal);
        let ok = matches!(message, ServerMessage::Result { .. });
        Reply {
            text: Some(message.to_text()),
            close: (leaving && ok).then_some((1000, "signed out")),
        }
    }

    /// `not_found` for keys that are not registered devices of this account; the device
    /// itself.
    async fn account_device(&self, target: DeviceId) -> Result<Device, ErrorCode> {
        match devices::find(&self.connect.pool, EndpointId(*target.as_bytes())).await {
            Ok(Some(device)) if device.user_id == self.user_id && device.is_active() => Ok(device),
            Ok(_) => Err(ErrorCode::NotFound),
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the device directory");
                Err(ErrorCode::Unavailable)
            }
        }
    }

    /// What every request that reaches another device checks again: this device is still
    /// registered with the credential it connected with, so that a revocation or sign-out that
    /// the connection has not heard of yet takes effect here (protocol 9.2), and remote access
    /// is available on the account.
    async fn authorized(&self, id: u64) -> Result<(), ServerMessage> {
        match devices::get(&self.connect.pool, self.device.id).await {
            Ok(Some(device))
                if device.is_active() && device.app_password_id == self.device.app_password_id => {}
            Ok(found) => {
                let (code, reason) = if found.is_some_and(|device| device.is_revoked()) {
                    (close::REVOKED, "revoked")
                } else {
                    (1000, "signed out")
                };
                self.connect
                    .hub
                    .send(self.user_id, self.key, Outgoing::Close(code, reason));
                return refused(
                    id,
                    ErrorCode::NotPermitted,
                    "this device is no longer registered",
                );
            }
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the device directory");
                return refused(id, ErrorCode::Unavailable, "try again later");
            }
        }
        match devices::remote_access(&self.connect.pool, self.user_id).await {
            Ok(true) => Ok(()),
            Ok(false) => refused(
                id,
                ErrorCode::TwoFactorRequired,
                "remote access is not available",
            ),
            Err(err) => {
                tracing::warn!(error = %err, "cannot read remote access of an account");
                refused(id, ErrorCode::Unavailable, "try again later")
            }
        }
    }

    async fn settings(
        &mut self,
        id: u64,
        change: &SettingsChange,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        let updated = devices::update_settings(
            &self.connect.pool,
            self.device.id,
            &settings(change),
            Actor::Device,
            now,
        )
        .await;
        match updated {
            Ok(Some(device)) => {
                self.device = device;
                self.announce(true);
                let entry = entry(&self.device, true).ok_or_else(|| {
                    error(Some(id), ErrorCode::Unavailable, "damaged directory entry")
                })?;
                Ok(ServerMessage::result(id, &SettingsResult { device: entry }))
            }
            Ok(None) => refused(id, ErrorCode::NotFound, "the device is gone"),
            Err(Error::InvalidDevice { field, reason }) => {
                refused(id, ErrorCode::BadRequest, &format!("{field} {reason}"))
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot change device settings");
                refused(id, ErrorCode::Unavailable, "try again later")
            }
        }
    }

    fn publish(
        &mut self,
        id: u64,
        relay_url: Option<String>,
        direct: Vec<std::net::SocketAddr>,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        if let Some(url) = &relay_url
            && !same_relay(url, self.connect.relay_url())
        {
            return refused(
                id,
                ErrorCode::BadRequest,
                "relay_url is not this server's relay",
            );
        }
        if direct.len() > limits::MAX_DIRECT_ADDRESSES {
            return refused(id, ErrorCode::BadRequest, "too many direct addresses");
        }
        // Loopback, multicast, port 0 and the like: iroh would probe whatever it is given.
        if !direct.iter().all(is_dialable) {
            return refused(
                id,
                ErrorCode::BadRequest,
                "direct addresses must be reachable by peers",
            );
        }
        if !self
            .connect
            .hub
            .allow(self.user_id, self.key, Limit::Publish, now)
        {
            let mut limited = error(Some(id), ErrorCode::RateLimited, "one publish per second");
            if let ServerMessage::Error { retry_after, .. } = &mut limited {
                *retry_after = Some(1);
            }
            return Err(limited);
        }
        self.connect.hub.publish(
            self.user_id,
            self.key,
            self.conn_id,
            Published {
                relay_url,
                direct,
                at: now,
            },
        );
        Ok(ServerMessage::result(id, &()))
    }

    /// The addresses of `target` as `connect` and `lookup` answer them.
    fn addresses(
        &self,
        id: u64,
        target: DeviceId,
        device: &Device,
    ) -> Result<ServerMessage, ServerMessage> {
        match self.connect.hub.published(self.user_id, device.endpoint_id) {
            None => {
                let mut offline = error(Some(id), ErrorCode::NotOnline, "the device is offline");
                if let ServerMessage::Error { last_seen_at, .. } = &mut offline {
                    *last_seen_at = device.last_seen_at;
                }
                Err(offline)
            }
            Some(published) => {
                let (relay_url, direct, published_at) = match published {
                    Some(published) => (
                        published
                            .relay_url
                            .unwrap_or_else(|| self.connect.relay_url().to_owned()),
                        published.direct,
                        Some(published.at),
                    ),
                    None => (self.connect.relay_url().to_owned(), Vec::new(), None),
                };
                Ok(ServerMessage::result(
                    id,
                    &AddressResult {
                        target,
                        relay_url: Some(relay_url),
                        direct,
                        published_at,
                    },
                ))
            }
        }
    }

    async fn connect_to(
        &mut self,
        id: u64,
        target: DeviceId,
        service: &str,
        purpose: Purpose,
        request_id: Option<String>,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        if !self
            .connect
            .hub
            .allow(self.user_id, self.key, Limit::Connect, now)
        {
            return refused(id, ErrorCode::RateLimited, "too many connect requests");
        }
        // Checked before anything is recorded: the audit log takes only well-formed values.
        if devices::check_services(&[service.to_owned()]).is_err() {
            return refused(id, ErrorCode::BadRequest, "invalid service");
        }
        if target == self.id {
            return refused(
                id,
                ErrorCode::BadRequest,
                "a device cannot connect to itself",
            );
        }
        let answer = self
            .authorize_connect(id, target, service, purpose, request_id.as_deref(), now)
            .await;
        let outcome = match &answer {
            Ok(_) => "allowed".to_owned(),
            Err(ServerMessage::Error { code, .. }) => serde_json::to_value(code)
                .ok()
                .and_then(|code| code.as_str().map(str::to_owned))
                .unwrap_or_default(),
            Err(_) => String::new(),
        };
        let peer = EndpointId(*target.as_bytes());
        self.record(
            Record::new(self.user_id, "connect.requested", Actor::Device)
                .device(self.key)
                .peer(peer)
                .details(json!({
                    "service": service,
                    "purpose": purpose,
                    "outcome": outcome,
                })),
            now,
        )
        .await;
        answer
    }

    async fn authorize_connect(
        &mut self,
        id: u64,
        target: DeviceId,
        service: &str,
        purpose: Purpose,
        request_id: Option<&str>,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        self.authorized(id).await?;
        let device = self
            .account_device(target)
            .await
            .map_err(|code| error(Some(id), code, "no such device"))?;
        self.permitted(id, &device, purpose, service, request_id)?;
        let answer = self.addresses(id, target, &device)?;
        self.connect.hub.grant(
            self.user_id,
            self.key,
            device.endpoint_id,
            Grant {
                at: now,
                purpose,
                service: service.to_owned(),
                request_id: request_id.map(str::to_owned),
            },
        );
        let incoming = ServerMessage::Incoming {
            from: self.id,
            service: service.to_owned(),
            purpose,
            request_id: request_id
                .filter(|_| purpose == Purpose::Pair)
                .map(str::to_owned),
        };
        self.connect.hub.send(
            self.user_id,
            device.endpoint_id,
            Outgoing::Text(incoming.to_text()),
        );
        Ok(answer)
    }

    /// Whether `connect` to `device` with `purpose` and `service` is permitted now (protocol
    /// 10); `lookup` checks it again for the `connect` it relies on.
    fn permitted(
        &self,
        id: u64,
        device: &Device,
        purpose: Purpose,
        service: &str,
        request_id: Option<&str>,
    ) -> Result<(), ServerMessage> {
        match purpose {
            Purpose::Session => {
                if !device.accept_remote || !device.services.iter().any(|known| known == service) {
                    return refused(
                        id,
                        ErrorCode::NotPermitted,
                        "the device does not accept this",
                    );
                }
            }
            Purpose::Pair => {
                let pending = request_id
                    .filter(|_| self.has(features::PAIRING))
                    .and_then(|request_id| self.connect.hub.request(self.user_id, request_id));
                if !pending.is_some_and(|pending| pending.requester == device.endpoint_id) {
                    return refused(
                        id,
                        ErrorCode::NotPermitted,
                        "no pending request of that device",
                    );
                }
            }
        }
        Ok(())
    }

    async fn lookup(
        &mut self,
        id: u64,
        target: DeviceId,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        if !self
            .connect
            .hub
            .allow(self.user_id, self.key, Limit::Lookup, now)
        {
            return refused(id, ErrorCode::RateLimited, "too many lookups");
        }
        self.authorized(id).await?;
        let device = self
            .account_device(target)
            .await
            .map_err(|code| error(Some(id), code, "no such device"))?;
        let window = i64::try_from(limits::LOOKUP_WINDOW_SECS).unwrap_or(i64::MAX);
        match self
            .connect
            .hub
            .lookup_basis(self.user_id, self.key, device.endpoint_id, now, window)
        {
            None => return refused(id, ErrorCode::NotPermitted, "send connect first"),
            // As `connect` would check it now: the target may have stopped accepting it.
            Some(LookupBasis::Connect(grant)) => self.permitted(
                id,
                &device,
                grant.purpose,
                &grant.service,
                grant.request_id.as_deref(),
            )?,
            Some(LookupBasis::Session) => {}
        }
        self.addresses(id, target, &device)
    }

    async fn session(
        &mut self,
        id: u64,
        report: &SessionReport,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        if !self.has(features::SESSION_REPORTS) {
            return refused(
                id,
                ErrorCode::NotPermitted,
                "session-reports was not negotiated",
            );
        }
        if !self
            .connect
            .hub
            .allow(self.user_id, self.key, Limit::Report, now)
        {
            return refused(id, ErrorCode::RateLimited, "too many session reports");
        }
        // The audit log takes only the formats of protocol 12.2.
        let well_formed = statement::decode_bytes(&report.session_id)
            .is_some_and(|session_id| session_id.len() == 16)
            && ROLES.contains(&report.role.as_str())
            && PATHS.contains(&report.path.as_str())
            && devices::check_services(std::slice::from_ref(&report.service)).is_ok()
            && report.peer != self.id;
        if !well_formed {
            return refused(id, ErrorCode::BadRequest, "malformed session report");
        }
        let open = report.event == SessionEvent::Started;
        let peer = EndpointId(*report.peer.as_bytes());
        match devices::find(&self.connect.pool, peer).await {
            Ok(Some(device)) if device.user_id == self.user_id && (device.is_active() || !open) => {
            }
            Ok(_) => return refused(id, ErrorCode::NotFound, "no such device"),
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the device directory");
                return refused(id, ErrorCode::Unavailable, "try again later");
            }
        }
        let window = i64::try_from(limits::LOOKUP_WINDOW_SECS).unwrap_or(i64::MAX);
        if !self
            .connect
            .hub
            .session(self.user_id, self.key, peer, open, now, window)
        {
            return refused(
                id,
                ErrorCode::NotPermitted,
                "no connect between the two devices",
            );
        }
        let kind = if open {
            "session.started"
        } else {
            "session.ended"
        };
        self.record(
            Record::new(self.user_id, kind, Actor::Device)
                .device(self.key)
                .peer(peer)
                .details(json!({
                    "session_id": report.session_id,
                    "role": report.role,
                    "service": report.service,
                    "path": report.path,
                    "started_at": report.started_at,
                    "ended_at": report.ended_at,
                    "bytes_direct": report.bytes_direct,
                    "bytes_relayed": report.bytes_relayed,
                })),
            now,
        )
        .await;
        Ok(ServerMessage::result(id, &()))
    }

    async fn pair_request(
        &mut self,
        id: u64,
        request: &gono_protocol::connect::Signed,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        if !self.has(features::PAIRING) {
            return refused(id, ErrorCode::NotPermitted, "pairing was not negotiated");
        }
        self.authorized(id).await?;
        let statement = request.open().map_err(|_| {
            error(
                Some(id),
                ErrorCode::BadSignature,
                "the request does not verify",
            )
        })?;
        let Statement::PairRequest(statement) = statement else {
            return refused(id, ErrorCode::BadRequest, "not a pair-request statement");
        };
        if statement.requester.endpoint_id != self.id
            || statement.server != self.connect.origin
            || statement.account != self.username
            || statement::decode_bytes(&statement.nonce).is_none_or(|nonce| nonce.len() != 32)
            // Approvers show the name in their prompt (protocol 2.1).
            || name::check_name(&statement.requester.name).is_err()
        {
            return refused(
                id,
                ErrorCode::BadRequest,
                "the request names another device or server",
            );
        }
        let fresh = match devices::get(&self.connect.pool, self.device.id).await {
            Ok(Some(device)) => device,
            Ok(None) => return refused(id, ErrorCode::NotFound, "the device is gone"),
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the device directory");
                return refused(id, ErrorCode::Unavailable, "try again later");
            }
        };
        if !fresh.pairing_open(now) {
            return refused(id, ErrorCode::NotPermitted, "the pairing window is closed");
        }
        let requester_entry = entry(&fresh, true)
            .ok_or_else(|| error(Some(id), ErrorCode::Unavailable, "damaged directory entry"))?;
        let request_id = statement::encode_bytes(&rand::rng().random::<[u8; 16]>());
        let pending = PendingPair {
            request_id: request_id.clone(),
            requester: self.key,
            requester_device_id: self.device.id,
            nonce: statement.nonce.clone(),
            request: request.clone(),
            requester_entry,
            expires_at: now + limits::PAIR_REQUEST_TTL_SECS,
        };
        let requested = pair_requested(&pending);
        match self.connect.hub.add_request(
            self.user_id,
            pending,
            now,
            limits::PAIR_REQUESTS_PER_HOUR,
        ) {
            Ok(()) => {}
            Err(RequestRefusal::Pending) => {
                return refused(
                    id,
                    ErrorCode::Conflict,
                    "a request of this device is pending",
                );
            }
            Err(RequestRefusal::TooMany) => {
                return refused(
                    id,
                    ErrorCode::RateLimited,
                    "too many pairing requests this hour",
                );
            }
        }
        self.connect.hub.broadcast_pairing(
            self.user_id,
            &ServerMessage::PairRequested(requested).to_text(),
            Some(self.key),
        );
        self.record(
            Record::new(self.user_id, "pair.requested", Actor::Device)
                .device(self.key)
                .details(json!({ "request_id": request_id })),
            now,
        )
        .await;
        Ok(ServerMessage::result(
            id,
            &PairRequestResult {
                request_id,
                expires_at: now + limits::PAIR_REQUEST_TTL_SECS,
            },
        ))
    }

    async fn pair_approve(
        &mut self,
        id: u64,
        request_id: &str,
        approval: &gono_protocol::connect::Signed,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        if !self.has(features::PAIRING) {
            return refused(id, ErrorCode::NotPermitted, "pairing was not negotiated");
        }
        self.authorized(id).await?;
        let Some(pending) = self.connect.hub.request(self.user_id, request_id) else {
            return refused(id, ErrorCode::NotFound, "no such pending request");
        };
        if pending.requester == self.key {
            return refused(
                id,
                ErrorCode::NotPermitted,
                "a device cannot approve itself",
            );
        }
        let statement = approval.open().map_err(|_| {
            error(
                Some(id),
                ErrorCode::BadSignature,
                "the approval does not verify",
            )
        })?;
        let Statement::PairApproval(statement) = statement else {
            return refused(id, ErrorCode::BadRequest, "not a pair-approval statement");
        };
        let valid = statement.approver == self.id
            && statement.subject.endpoint_id.as_bytes() == &pending.requester.0
            && statement.request_nonce == pending.nonce
            && statement.server == self.connect.origin
            && statement.account == self.username
            && statement.method == "remote-sas"
            && statement.issued_at.abs_diff(now) <= APPROVAL_SKEW_SECS
            && statement.expires_at > now
            // Both come from the device: no overflow, and a positive, bounded lifetime.
            && statement
                .expires_at
                .checked_sub(statement.issued_at)
                .is_some_and(|lifetime| 0 < lifetime && lifetime <= limits::MAX_APPROVAL_SECS)
            && statement.introduced.len() <= limits::MAX_INTRODUCED
            // Every device shows these names in its notice (protocol 2.1).
            && name::check_name(&statement.subject.name).is_ok()
            && statement
                .introduced
                .iter()
                .all(|device| name::check_name(&device.name).is_ok());
        if !valid {
            return refused(
                id,
                ErrorCode::BadRequest,
                "the approval does not match the request",
            );
        }
        if self
            .connect
            .hub
            .take_request(self.user_id, request_id)
            .is_none()
        {
            return refused(id, ErrorCode::Conflict, "the request was decided already");
        }
        let body = json!({ "request_id": request_id, "approval": approval, "at": now });
        if let Err(err) = devices::record_approval(
            &self.connect.pool,
            self.user_id,
            self.device.id,
            pending.requester_device_id,
            &body,
            now,
        )
        .await
        {
            tracing::error!(error = %err, "cannot record an approval");
            return refused(id, ErrorCode::Unavailable, "try again later");
        }
        self.connect.poke();
        let closed = ServerMessage::PairClosed {
            request_id: request_id.to_owned(),
            outcome: "approved".to_owned(),
        };
        self.connect
            .hub
            .broadcast_pairing(self.user_id, &closed.to_text(), None);
        let introduced: Vec<String> = statement
            .introduced
            .iter()
            .map(|device| device.endpoint_id.to_hex())
            .collect();
        tracing::info!(
            approver = %self.key.short(),
            subject = %pending.requester.short(),
            introduced = introduced.len(),
            "pairing approved"
        );
        self.record(
            Record::new(self.user_id, "pair.approved", Actor::Device)
                .device(self.key)
                .peer(pending.requester)
                .details(json!({ "request_id": request_id, "introduced": introduced })),
            now,
        )
        .await;
        Ok(ServerMessage::result(id, &()))
    }

    async fn pair_decline(
        &mut self,
        id: u64,
        request_id: &str,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        let Some(pending) = self.connect.hub.request(self.user_id, request_id) else {
            return refused(id, ErrorCode::NotFound, "no such pending request");
        };
        if pending.requester == self.key {
            return refused(
                id,
                ErrorCode::NotPermitted,
                "withdraw your own request instead",
            );
        }
        self.close_request(request_id, "declined", "pair.declined", now)
            .await;
        Ok(ServerMessage::result(id, &()))
    }

    async fn pair_withdraw(
        &mut self,
        id: u64,
        request_id: &str,
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        let mine = self
            .connect
            .hub
            .request(self.user_id, request_id)
            .is_some_and(|pending| pending.requester == self.key);
        if !mine {
            return refused(id, ErrorCode::NotFound, "no such pending request");
        }
        self.close_request(request_id, "withdrawn", "pair.withdrawn", now)
            .await;
        Ok(ServerMessage::result(id, &()))
    }

    async fn close_request(&self, request_id: &str, outcome: &str, kind: &'static str, now: i64) {
        if let Some(pending) = self.connect.hub.take_request(self.user_id, request_id) {
            let closed = ServerMessage::PairClosed {
                request_id: request_id.to_owned(),
                outcome: outcome.to_owned(),
            };
            self.connect
                .hub
                .broadcast_pairing(self.user_id, &closed.to_text(), None);
            self.record(
                Record::new(self.user_id, kind, Actor::Device)
                    .device(self.key)
                    .peer(pending.requester)
                    .details(json!({ "request_id": request_id })),
                now,
            )
            .await;
        }
    }

    async fn revocations_applied(
        &mut self,
        id: u64,
        endpoint_ids: &[DeviceId],
        now: i64,
    ) -> Result<ServerMessage, ServerMessage> {
        let keys: Vec<EndpointId> = endpoint_ids
            .iter()
            .map(|id| EndpointId(*id.as_bytes()))
            .collect();
        match devices::record_applied(&self.connect.pool, self.device.id, &keys, now).await {
            Ok(recorded) if !recorded.is_empty() => {
                let recorded: Vec<String> = recorded.iter().map(EndpointId::to_hex).collect();
                self.record(
                    Record::new(self.user_id, "revocation.applied", Actor::Device)
                        .device(self.key)
                        .details(json!({ "revoked": recorded })),
                    now,
                )
                .await;
                Ok(ServerMessage::result(id, &()))
            }
            Ok(_) => Ok(ServerMessage::result(id, &())),
            Err(err) => {
                tracing::error!(error = %err, "cannot record applied revocations");
                refused(id, ErrorCode::Unavailable, "try again later")
            }
        }
    }

    async fn leave(&mut self, id: u64) -> Result<ServerMessage, ServerMessage> {
        match self.connect.sign_out(&self.device).await {
            Ok(_) => Ok(ServerMessage::result(id, &())),
            Err(err) => {
                tracing::error!(error = %err, "cannot sign a device out");
                refused(id, ErrorCode::Unavailable, "try again later")
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let was_current = self
            .connect
            .hub
            .unregister(self.user_id, self.key, self.conn_id);
        // Dropped for not reading, the hub forgot the connection already; unless the device
        // reconnected since, this was its presence.
        let dropped_last =
            self.dropped.is_set() && !self.connect.hub.online(self.user_id).contains(&self.key);
        if !was_current && !dropped_last {
            // Replaced by a newer connection, which is the device's presence now.
            return;
        }
        let now = db::unix_now();
        self.device.last_seen_at = Some(now);
        self.announce(false);
        tracing::info!(device = %self.key.short(), "device left the control channel");
        let pool = self.connect.pool.clone();
        let device_id = self.device.id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(err) = devices::record_seen(&pool, device_id, now).await {
                    tracing::warn!(error = %err, "cannot record that a device was seen");
                }
            });
        }
    }
}

fn pair_requested(pending: &PendingPair) -> PairRequested {
    PairRequested {
        request_id: pending.request_id.clone(),
        expires_at: pending.expires_at,
        requester: pending.requester_entry.clone(),
        request: pending.request.clone(),
    }
}

impl Connect {
    /// Writes an audit record; a failure is logged and otherwise ignored, so that the audit
    /// log never takes the control channel down.
    pub(crate) async fn record(&self, record: Record, now: i64) {
        if let Err(err) = audit::record(&self.pool, &record, now).await {
            tracing::warn!(error = %err, kind = record.kind, "cannot write the audit log");
        }
    }
}
