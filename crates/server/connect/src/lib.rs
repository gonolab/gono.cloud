//! The device directory and the control channel through which Gono devices find and reach
//! each other: the server side of `docs/connect-protocol.md` (version 1).
//!
//! - [`Connect`] holds what the protocol needs at run time: the database, the live state of
//!   the control channel (the hub), and the [`Directory`] that admits devices to the relay.
//! - **Registration** (protocol 4): [`Connect::start_login`] and [`Connect::poll_login`]
//!   answer `POST /gono/v1/login` and `POST /gono/v1/login/poll`. The browser pages that grant
//!   a registration are the Login Flow v2 pages of the server.
//! - **The control channel** (protocol 5): [`Connect::challenge`] and [`Connect::hello`] open
//!   a [`Session`], which answers the device's requests and hands it its events. The HTTP
//!   server owns the WebSocket and its keep-alive.
//! - **The background task** ([`Connect::run`]) sends the logged events of the database to
//!   the connected devices (whatever process wrote them, the CLI included), ends the access of
//!   revoked devices at the relay and on the control channel, keeps the [`Directory`] current,
//!   expires pairing requests, and purges old events and audit records.
//!
//! Trust between devices is never decided here: the server carries requests and signed
//! statements, and refuses only what the authorization rules of protocol 10 refuse.

mod hub;
mod limit;
mod session;

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, OnceLock, PoisonError, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use gono_protocol::connect::{
    DeviceEntry, DeviceId, Discovery, LoginStart, LoginStarted, PollEndpoint, PollRequest,
    Registered, ServerMessage, Statement, VERSION, paths, statement,
};
use gono_server_core::{
    audit::{self, Actor, Record},
    db::{self, Pool},
    devices::{self, Device, EndpointId, NewDevice, Registration},
    login_flows::{self, DeviceCompletion, DevicePoll},
};
use gono_server_relay::{Admission, RelayStatus, Tier};
use serde_json::{Value, json};
use tokio::sync::Notify;
use url::Url;

pub use hub::Outgoing;
pub use session::{DeviceLogin, Handshake, Refusal, Reply, Session};

/// How often the background task runs when nothing pokes it.
const TICK: Duration = Duration::from_secs(2);

/// How often the [`Directory`] is read again from the database without a poke, which picks up
/// changes made by another process (the CLI) and by account changes.
const REFRESH_SECS: i64 = 30;

/// How often old events and audit records are purged.
const PURGE_SECS: i64 = 60 * 60;

/// How often a refused tombstone is recorded in the audit log, per key.
const REFUSAL_RECORD_SECS: i64 = 10 * 60;

/// The settings of remote connectivity.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// `server.base_url`.
    pub base_url: Url,
    /// `relay.public_url`: the relay devices must use.
    pub relay_url: Url,
    /// How long audit records are kept, in seconds.
    pub audit_retention_secs: i64,
    /// `connect.require_two_factor`: whether remote access needs two-step verification on the
    /// account (protocol 13). False only while remote control is in development.
    pub require_two_factor: bool,
}

impl ConnectConfig {
    /// Whether remote connectivity may be served with `base_url`: HTTPS, or a loopback host
    /// for tests (protocol 3).
    pub fn allowed_origin(base_url: &Url) -> bool {
        base_url.scheme() == "https"
            || match base_url.host() {
                Some(url::Host::Domain(domain)) => domain == "localhost",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            }
    }
}

/// The server origin of `url`, the form statements name (protocol 2.1).
pub fn origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// See the crate documentation.
#[derive(Debug)]
pub struct Connect {
    pool: Pool,
    config: ConnectConfig,
    origin: String,
    hub: hub::Hub,
    directory: Arc<Directory>,
    relay: OnceLock<RelayStatus>,
    poke: Notify,
    /// Set by [`Connect::shut_down`]: no new sessions.
    stopping: AtomicBool,
}

impl Connect {
    /// Creates the state of remote connectivity and reads the directory.
    pub async fn new(pool: Pool, config: ConnectConfig) -> gono_server_core::Result<Arc<Self>> {
        let directory = Arc::new(Directory::new(pool.clone(), config.require_two_factor));
        directory.refresh().await?;
        Ok(Arc::new(Self {
            origin: origin(&config.base_url),
            pool,
            config,
            hub: hub::Hub::default(),
            directory,
            relay: OnceLock::new(),
            poke: Notify::new(),
            stopping: AtomicBool::new(false),
        }))
    }

    /// The admission of the relay: the devices the directory admits.
    pub fn directory(&self) -> Arc<Directory> {
        Arc::clone(&self.directory)
    }

    /// Hands over the running relay, through which revoked devices are disconnected.
    pub fn set_relay(&self, relay: RelayStatus) {
        let _ = self.relay.set(relay);
    }

    /// The relay this process runs, once [`Connect::set_relay`] handed it over: what the
    /// account page shows of an account's devices on it.
    pub fn relay(&self) -> Option<&RelayStatus> {
        self.relay.get()
    }

    /// The database.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// The server origin statements must name.
    pub fn server_origin(&self) -> &str {
        &self.origin
    }

    /// The relay URL devices must use.
    pub fn relay_url(&self) -> &str {
        self.config.relay_url.as_str()
    }

    /// Whether remote access needs two-step verification on the account
    /// (`connect.require_two_factor`).
    pub fn requires_two_factor(&self) -> bool {
        self.config.require_two_factor
    }

    /// Ends every control connection with `1001 Going Away` and refuses new ones, when the
    /// server stops.
    pub fn shut_down(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        self.hub
            .close_all(&Outgoing::Close(1001, "the server is shutting down"));
    }

    /// Whether [`Connect::shut_down`] was called.
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    /// Wakes the background task, after a change it must act on at once (a revocation, a new
    /// registration, an approval).
    pub fn poke(&self) {
        self.poke.notify_one();
    }

    /// The discovery document (protocol 3).
    pub fn discovery(&self) -> Discovery {
        let mut websocket = self.config.base_url.clone();
        let scheme = if websocket.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        let _ = websocket.set_scheme(scheme);
        websocket.set_path(paths::WEBSOCKET);
        let mut login = self.config.base_url.clone();
        login.set_path(paths::LOGIN);
        Discovery {
            version: VERSION,
            server: self.origin.clone(),
            login: login.to_string(),
            websocket: websocket.to_string(),
            relay_url: self.relay_url().to_owned(),
            two_factor_required: self.config.require_two_factor,
        }
    }

    /// Answers `POST /gono/v1/login` (protocol 4.1) with a status and a JSON body.
    pub async fn start_login(&self, start: LoginStart, now: i64) -> (u16, Value) {
        let checked = (|| -> gono_server_core::Result<NewDevice> {
            Ok(NewDevice {
                endpoint_id: EndpointId(*start.endpoint_id.as_bytes()),
                product: devices::check_slug("product", &start.product)?,
                platform: devices::check_slug("platform", &start.platform)?,
                name: devices::check_name(&start.name)?,
                version: devices::check_version(&start.version)?,
            })
        })();
        let device = match checked {
            Ok(device) => device,
            Err(err) => {
                return (
                    400,
                    json!({ "error": "bad_request", "message": err.to_string() }),
                );
            }
        };
        match login_flows::create_device(&self.pool, &device, now).await {
            Ok(Some((flow, challenge))) => {
                use secrecy::ExposeSecret as _;
                let mut login_url = self.config.base_url.clone();
                login_url.set_path(&format!(
                    "/login/v2/flow/{}",
                    flow.login_token.expose_secret()
                ));
                let mut poll = self.config.base_url.clone();
                poll.set_path(paths::LOGIN_POLL);
                tracing::info!(
                    device = %device.endpoint_id.short(),
                    product = device.product,
                    platform = device.platform,
                    "device registration started"
                );
                let started = LoginStarted {
                    login_url: login_url.to_string(),
                    poll: PollEndpoint {
                        endpoint: poll.to_string(),
                        token: flow.poll_token.expose_secret().to_owned(),
                    },
                    challenge: statement::encode_bytes(&challenge),
                    expires_at: flow.expires_at,
                };
                (200, serde_json::to_value(started).unwrap_or_default())
            }
            Ok(None) => (503, json!({ "error": "unavailable" })),
            Err(err) => {
                tracing::error!(error = %err, "cannot start a device registration");
                (500, json!({ "error": "unavailable" }))
            }
        }
    }

    /// Answers `POST /gono/v1/login/poll` (protocol 4.3) with a status and a JSON body.
    pub async fn poll_login(&self, poll: PollRequest, now: i64) -> (u16, Value) {
        let state = match login_flows::device_poll(&self.pool, &poll.token, now).await {
            Ok(state) => state,
            Err(err) => {
                tracing::error!(error = %err, "device registration poll failed");
                return (503, json!({ "error": "unavailable" }));
            }
        };
        let (endpoint_id, challenge) = match state {
            DevicePoll::Pending => return (202, json!({ "status": "pending" })),
            DevicePoll::Gone => return (404, json!({ "error": "not_found" })),
            // The consent page refused it because of the account (`service_not_enabled`).
            DevicePoll::Refused(reason) => return (404, json!({ "error": reason })),
            DevicePoll::Granted {
                endpoint_id,
                challenge,
            } => (endpoint_id, challenge),
        };
        let proven = poll
            .proof
            .as_ref()
            .and_then(|proof| proof.open().ok())
            .is_some_and(|statement| {
                matches!(statement, Statement::Login(login)
                    if login.server == self.origin
                        && login.endpoint_id.as_bytes() == &endpoint_id.0
                        && login.challenge == statement::encode_bytes(&challenge))
            });
        if !proven {
            return (400, json!({ "error": "bad_proof" }));
        }
        let completed = match login_flows::complete_device(&self.pool, &poll.token, now).await {
            Ok(completed) => completed,
            Err(err) => {
                tracing::error!(error = %err, "cannot complete a device registration");
                return (503, json!({ "error": "unavailable" }));
            }
        };
        match completed {
            DeviceCompletion::Gone => (404, json!({ "error": "not_found" })),
            DeviceCompletion::ServiceNotEnabled => (404, json!({ "error": "service_not_enabled" })),
            DeviceCompletion::Done(username, registration) => match registration {
                Registration::Registered {
                    device,
                    app_password,
                    new,
                } => {
                    use secrecy::ExposeSecret as _;
                    tracing::info!(
                        user = %username,
                        device = %device.endpoint_id.short(),
                        new,
                        "device registered for remote access"
                    );
                    // The device may be admissible now; its `device.added` must go out.
                    self.poke();
                    let Some(entry) = entry(&device, false) else {
                        return (500, json!({ "error": "unavailable" }));
                    };
                    let registered = Registered {
                        status: "registered".to_owned(),
                        server: self.origin.clone(),
                        username: username.as_str().to_owned(),
                        app_password: app_password.expose_secret().to_owned(),
                        device: entry,
                        pairing_open_until: device.pairing_open_until,
                    };
                    (200, serde_json::to_value(registered).unwrap_or_default())
                }
                Registration::Taken => (409, json!({ "error": "endpoint_taken" })),
                Registration::Revoked => (409, json!({ "error": "endpoint_revoked" })),
                Registration::TooMany => (409, json!({ "error": "too_many_devices" })),
            },
        }
    }

    /// The device whose credential is app password `app_password_id`, if it is unrevoked.
    pub async fn device_for(
        &self,
        app_password_id: i64,
    ) -> gono_server_core::Result<Option<Device>> {
        devices::find_by_app_password(&self.pool, app_password_id).await
    }

    /// Whether `device` of `user_id` has a control connection.
    pub fn is_online(&self, user_id: i64, device: EndpointId) -> bool {
        self.hub.online(user_id).contains(&device)
    }

    /// The account's devices with their presence, for the account page.
    pub async fn devices_with_presence(
        &self,
        user_id: i64,
    ) -> gono_server_core::Result<Vec<(Device, bool)>> {
        let online = self.hub.online(user_id);
        Ok(devices::list(&self.pool, user_id)
            .await?
            .into_iter()
            .map(|device| {
                let is_online = online.contains(&device.endpoint_id);
                (device, is_online)
            })
            .collect())
    }

    /// Signs device `device` out (protocol 9.4): deletes its credential, tells the account's
    /// other devices, and ends its access. The entry stays, bound to the account. `actor` is
    /// the device itself, or its user on the account page.
    pub async fn sign_out(&self, device: &Device, actor: Actor) -> gono_server_core::Result<bool> {
        let now = db::unix_now();
        let Some(left) = devices::leave(&self.pool, device.id, actor, now).await? else {
            return Ok(false);
        };
        tracing::info!(device = %left.endpoint_id.short(), "device signed out");
        let Some(id) = device_id(left.endpoint_id) else {
            return Ok(true);
        };
        let removed = ServerMessage::DeviceRemoved {
            endpoint_id: id,
            at: now,
        };
        self.hub
            .broadcast(left.user_id, &removed.to_text(), Some(left.endpoint_id));
        self.close_requests_of(left.user_id, left.endpoint_id, "withdrawn");
        self.hub.send(
            left.user_id,
            left.endpoint_id,
            Outgoing::Close(1000, "signed out"),
        );
        self.hub.forget_device(left.user_id, left.endpoint_id);
        self.end_relay_access().await;
        Ok(true)
    }

    /// Reads the directory again and ends the relay connections of every device it no longer
    /// admits.
    async fn end_relay_access(&self) {
        if let Err(err) = self.directory.refresh().await {
            tracing::warn!(error = %err, "cannot read the device directory");
        }
        self.sweep_relay();
    }

    /// Ends the relay connections of devices the directory no longer admits. Cheap: it reads
    /// only memory.
    fn sweep_relay(&self) {
        if let Some(relay) = self.relay.get() {
            let swept = relay.sweep();
            if swept > 0 {
                tracing::info!(
                    devices = swept,
                    "ended the relay access of devices no longer admitted"
                );
            }
        }
    }

    /// Ends the pending pairing requests of `device` with `outcome`.
    fn close_requests_of(&self, user_id: i64, device: EndpointId, outcome: &str) {
        for pending in self.hub.drop_requests_of(user_id, device) {
            let closed = ServerMessage::PairClosed {
                request_id: pending.request_id,
                outcome: outcome.to_owned(),
            };
            self.hub.broadcast_pairing(user_id, &closed.to_text(), None);
        }
    }

    /// Runs the background task until the process ends.
    pub async fn run(self: Arc<Self>) {
        let mut last_seq = match devices::last_seq(&self.pool).await {
            Ok(seq) => seq,
            Err(err) => {
                tracing::error!(error = %err, "cannot read the device event log");
                0
            }
        };
        let mut refreshed_at = db::unix_now();
        let mut purged_at = 0;
        loop {
            let poked = tokio::select! {
                () = self.poke.notified() => true,
                () = tokio::time::sleep(TICK) => false,
            };
            let now = db::unix_now();
            last_seq = self.dispatch_events(last_seq).await;
            if poked || now - refreshed_at >= REFRESH_SECS {
                refreshed_at = now;
                self.refresh_access().await;
            }
            // Also catches connections admitted just before a change, which a disconnect at
            // the time could not reach yet.
            self.sweep_relay();
            self.expire_requests(now).await;
            if now - purged_at >= PURGE_SECS {
                purged_at = now;
                self.purge(now).await;
            }
        }
    }

    /// Sends the logged events after `last_seq` and returns the last one sent.
    async fn dispatch_events(&self, mut last_seq: i64) -> i64 {
        loop {
            let events = match devices::events_after(&self.pool, last_seq, 500).await {
                Ok(events) => events,
                Err(err) => {
                    tracing::warn!(error = %err, "cannot read the device event log");
                    return last_seq;
                }
            };
            if events.is_empty() {
                return last_seq;
            }
            let mut revoked = Vec::new();
            for event in &events {
                last_seq = event.seq;
                let Some(message) = logged_message(event) else {
                    tracing::warn!(
                        seq = event.seq,
                        kind = event.kind,
                        "unreadable device event"
                    );
                    continue;
                };
                if let ServerMessage::DeviceRevoked { endpoint_id, .. } = &message {
                    revoked.push((event.user_id, EndpointId(*endpoint_id.as_bytes())));
                }
                self.hub
                    .broadcast_logged(event.user_id, event.seq, &message.to_text());
            }
            for (user_id, key) in &revoked {
                self.hub.send(
                    *user_id,
                    *key,
                    Outgoing::Close(gono_protocol::connect::close::REVOKED, "revoked"),
                );
                self.close_requests_of(*user_id, *key, "withdrawn");
                self.hub.forget_device(*user_id, *key);
            }
            if !revoked.is_empty() {
                self.end_relay_access().await;
            }
        }
    }

    /// Reads the directory again, disconnects the devices it no longer admits from the relay,
    /// closes the control connections of accounts that were disabled or deleted, and tells
    /// connected devices when remote access on their account changed.
    async fn refresh_access(&self) {
        if let Err(err) = self.directory.refresh().await {
            tracing::warn!(error = %err, "cannot read the device directory");
            return;
        }
        self.sweep_relay();
        let enabled: HashSet<i64> = match devices::enabled_accounts(&self.pool).await {
            Ok(accounts) => accounts.into_iter().collect(),
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the enabled accounts");
                return;
            }
        };
        for user_id in self.hub.known_accounts() {
            if !enabled.contains(&user_id) {
                let closed = Outgoing::Close(
                    gono_protocol::connect::close::ACCOUNT_DISABLED,
                    "account disabled",
                );
                let requests = self.hub.remove_account(user_id, &closed);
                tracing::info!(
                    user_id,
                    requests = requests.len(),
                    "closed the control connections of a disabled or deleted account"
                );
            }
        }
        let access: HashMap<i64, devices::AccountAccess> =
            match devices::enabled_account_access(&self.pool, self.config.require_two_factor).await
            {
                Ok(accounts) => accounts.into_iter().collect(),
                Err(err) => {
                    tracing::warn!(error = %err, "cannot read remote access of accounts");
                    return;
                }
            };
        for user_id in self.hub.accounts() {
            // Accounts that are no longer enabled were closed above.
            let Some(access) = access.get(&user_id) else {
                continue;
            };
            let state = session::announced(access);
            if self.hub.set_remote_access(user_id, state) {
                self.hub
                    .broadcast(user_id, &session::account_message(state).to_text(), None);
            }
        }
    }

    /// Ends the pairing requests that expired.
    async fn expire_requests(&self, now: i64) {
        for (user_id, pending) in self.hub.expire_requests(now) {
            let closed = ServerMessage::PairClosed {
                request_id: pending.request_id.clone(),
                outcome: "expired".to_owned(),
            };
            self.hub.broadcast_pairing(user_id, &closed.to_text(), None);
            let record = Record::new(user_id, "pair.expired", Actor::Server)
                .device(pending.requester)
                .details(json!({ "request_id": pending.request_id }));
            if let Err(err) = audit::record(&self.pool, &record, now).await {
                tracing::warn!(error = %err, "cannot write the audit log");
            }
        }
    }

    async fn purge(&self, now: i64) {
        let events = devices::purge_events(&self.pool, now - devices::EVENT_RETENTION_SECS).await;
        let records = audit::purge(&self.pool, now - self.config.audit_retention_secs).await;
        match (events, records) {
            (Ok(events), Ok(records)) if events + records > 0 => {
                tracing::debug!(
                    events,
                    records,
                    "purged old device events and audit records"
                );
            }
            (Err(err), _) | (_, Err(err)) => {
                tracing::warn!(error = %err, "cannot purge old device events and audit records");
            }
            _ => {}
        }
    }
}

/// A logged event as the control channel sends it: its body with `type` and `seq`.
fn logged_message(event: &devices::Event) -> Option<ServerMessage> {
    let mut body: serde_json::Map<String, Value> = serde_json::from_str(&event.body).ok()?;
    body.insert("type".to_owned(), Value::from(event.kind.clone()));
    body.insert("seq".to_owned(), Value::from(event.seq));
    serde_json::from_value(Value::Object(body)).ok()
}

/// The wire form of a stored key. Keys reach the database only through [`DeviceId`] parsing,
/// so this fails only for a damaged row.
pub fn device_id(key: EndpointId) -> Option<DeviceId> {
    DeviceId::from_bytes(&key.0).ok()
}

/// The directory entry of protocol 6.1.
pub fn entry(device: &Device, online: bool) -> Option<DeviceEntry> {
    Some(DeviceEntry {
        endpoint_id: device_id(device.endpoint_id)?,
        name: device.name.clone(),
        product: device.product.clone(),
        platform: device.platform.clone(),
        version: device.version.clone(),
        registered_at: device.registered_at,
        online,
        last_seen_at: device.last_seen_at,
        accept_remote: device.accept_remote,
        unattended: device.unattended,
        services: device.services.clone(),
        revoked_at: device.revoked_at,
    })
}

/// The devices the relay admits from the directory (protocol 11.1), held in memory so that the
/// relay decides without a database query.
#[derive(Debug)]
pub struct Directory {
    pool: Pool,
    /// `connect.require_two_factor`.
    require_two_factor: bool,
    /// Held while the directory is read, so that an older read never replaces a newer one.
    refreshing: tokio::sync::Mutex<()>,
    /// The admitted devices with their tier: full with the relay service, limited with direct
    /// connections alone.
    admitted: RwLock<HashMap<EndpointId, Tier>>,
    /// Tombstones, with their accounts, so that a revoked key that tries the relay is recorded.
    revoked: RwLock<HashMap<EndpointId, i64>>,
    /// When a refused tombstone was last recorded.
    recorded: Mutex<HashMap<EndpointId, i64>>,
}

impl Directory {
    fn new(pool: Pool, require_two_factor: bool) -> Self {
        Self {
            pool,
            require_two_factor,
            refreshing: tokio::sync::Mutex::new(()),
            admitted: RwLock::new(HashMap::new()),
            revoked: RwLock::new(HashMap::new()),
            recorded: Mutex::new(HashMap::new()),
        }
    }

    /// Reads the admitted keys and the tombstones from the database.
    pub async fn refresh(&self) -> gono_server_core::Result<()> {
        let _serialized = self.refreshing.lock().await;
        let admitted: HashMap<EndpointId, Tier> =
            devices::admissible(&self.pool, self.require_two_factor)
                .await?
                .into_iter()
                .map(|(key, relay)| (key, if relay { Tier::Full } else { Tier::Limited }))
                .collect();
        let revoked: HashMap<EndpointId, i64> = devices::revoked_keys(&self.pool)
            .await?
            .into_iter()
            .collect();
        *self
            .admitted
            .write()
            .unwrap_or_else(PoisonError::into_inner) = admitted;
        *self.revoked.write().unwrap_or_else(PoisonError::into_inner) = revoked;
        Ok(())
    }

    fn tier_of(&self, key: &EndpointId) -> Option<Tier> {
        self.admitted
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .copied()
    }
}

impl Admission for Directory {
    /// Devices of accounts with the relay service relay at the full rate; those with direct
    /// connections alone at the limited rate, enough to set up a direct connection.
    fn tier(&self, device: &iroh_base::EndpointId) -> Option<Tier> {
        self.tier_of(&EndpointId(*device.as_bytes()))
    }

    fn count(&self) -> usize {
        self.admitted
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn refused(&self, device: &iroh_base::EndpointId) {
        let key = EndpointId(*device.as_bytes());
        let Some(user_id) = self
            .revoked
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .copied()
        else {
            return;
        };
        let now = db::unix_now();
        {
            let mut recorded = self.recorded.lock().unwrap_or_else(PoisonError::into_inner);
            if recorded
                .get(&key)
                .is_some_and(|at| now - at < REFUSAL_RECORD_SECS)
            {
                return;
            }
            recorded.insert(key, now);
        }
        tracing::warn!(device = %key.short(), "a revoked device tried to use the relay");
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let record = Record::new(user_id, "relay.refused_revoked", Actor::Server).device(key);
            if let Err(err) = audit::record(&pool, &record, now).await {
                tracing::warn!(error = %err, "cannot write the audit log");
            }
        });
    }
}
