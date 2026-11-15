//! The live state of the control channel, kept in memory only: which device of which account
//! is connected, what it published, whom it is connecting to, and the pending pairing
//! requests (`docs/connect-protocol.md`, sections 5, 7 and 8).
//!
//! Addresses never leave this module except in `connect` and `lookup` answers (S3 of the
//! threat model). Each connection has a bounded queue of frames; a device that does not read
//! its frames loses its place, which ends its connection at once.
//!
//! What a device is allowed and how much it has used are kept per device, not per connection,
//! so that reconnecting resets neither: the `connect` grants that open `lookup` (protocol
//! 7.3), the sessions it reported (12.2), and its rate limits (15).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use gono_protocol::connect::{DeviceEntry, Signed, message::Purpose};
use gono_server_core::devices::EndpointId;
use tokio::sync::{Notify, mpsc};

use crate::limit::{DeviceLimits, Limit};

/// Frames a connection may have queued before it counts as too slow.
const QUEUE: usize = 256;

/// How many replacements within [`FLAPPING_WINDOW_SECS`] from different addresses count as
/// flapping (protocol 5.1).
const FLAPPING_REPLACEMENTS: usize = 3;

/// The window of [`FLAPPING_REPLACEMENTS`], in seconds.
const FLAPPING_WINDOW_SECS: i64 = 10 * 60;

/// How long a reported session keeps `lookup` open without an `ended` report, in seconds.
const SESSION_MAX_SECS: i64 = 24 * 60 * 60;

/// How long a `connect` grant is kept, in seconds; longer than any window that uses it.
const GRANT_KEEP_SECS: i64 = 60 * 60;

/// What a connection's task sends next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outgoing {
    /// A text frame.
    Text(String),
    /// Close the connection with this code and reason.
    Close(u16, &'static str),
}

/// What the hub queues for a connection: a frame, or a logged event with its sequence
/// number, which the session drops if its `welcome` carried it already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    Out(Outgoing),
    Logged(i64, String),
}

/// What a device published (protocol 7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Published {
    pub relay_url: Option<String>,
    pub direct: Vec<SocketAddr>,
    pub at: i64,
}

/// A pending pairing request (protocol 8.2).
#[derive(Debug, Clone)]
pub(crate) struct PendingPair {
    pub request_id: String,
    pub requester: EndpointId,
    pub requester_device_id: i64,
    pub nonce: String,
    pub request: Signed,
    pub requester_entry: DeviceEntry,
    pub expires_at: i64,
}

/// A `connect` the server allowed (protocol 7.2), which later `lookup`s of the same target
/// rely on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub at: i64,
    pub purpose: Purpose,
    pub service: String,
    pub request_id: Option<String>,
}

/// Why a `lookup` may be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LookupBasis {
    /// A `connect` within the window, to be checked again as `connect` checks it.
    Connect(Grant),
    /// A reported session that has not ended.
    Session,
}

/// Set by the hub when it drops a connection whose queue was full; the session then closes at
/// once instead of draining the queue.
#[derive(Debug, Default)]
pub(crate) struct Dropped {
    set: AtomicBool,
    notify: Notify,
}

impl Dropped {
    fn set(&self) {
        self.set.store(true, Ordering::Relaxed);
        // A stored permit: a session that is not waiting right now still sees it.
        self.notify.notify_one();
    }

    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::Relaxed)
    }

    /// Completes once the connection was dropped.
    pub async fn wait(&self) {
        if !self.is_set() {
            self.notify.notified().await;
        }
    }
}

#[derive(Debug)]
struct Conn {
    id: u64,
    tx: mpsc::Sender<Frame>,
    published: Option<Published>,
    /// The device negotiated `pairing`, so it gets the pairing events.
    pairing: bool,
    dropped: Arc<Dropped>,
}

#[derive(Debug, Default)]
struct Account {
    conns: HashMap<EndpointId, Conn>,
    /// Allowed `connect`s by (caller, target).
    grants: HashMap<(EndpointId, EndpointId), Grant>,
    /// Sessions reported as started and not yet ended by (reporter, peer), with when.
    sessions: HashMap<(EndpointId, EndpointId), i64>,
    /// Each device's rate limits.
    limits: HashMap<EndpointId, DeviceLimits>,
    requests: HashMap<String, PendingPair>,
    /// When the account's pairing requests were made, for the hourly limit.
    request_times: VecDeque<i64>,
    /// Remote access as last announced, to send `account` only on changes.
    remote_access: Option<bool>,
    /// Recent replacements per device, with the address of the new connection.
    replacements: HashMap<EndpointId, VecDeque<(i64, IpAddr)>>,
    /// The address of each device's last connection.
    last_ip: HashMap<EndpointId, IpAddr>,
    /// When flapping was last recorded per device.
    flapping_at: HashMap<EndpointId, i64>,
}

/// What [`Hub::register`] observed about the new connection.
#[derive(Debug)]
pub(crate) struct Registered {
    pub conn_id: u64,
    pub rx: mpsc::Receiver<Frame>,
    pub dropped: Arc<Dropped>,
    /// The device connected from an address it did not use last time.
    pub new_address: bool,
    /// Its connections keep replacing each other from different addresses: the addresses.
    pub flapping: Option<Vec<IpAddr>>,
}

/// See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct Hub {
    accounts: Mutex<HashMap<i64, Account>>,
    next_id: AtomicU64,
}

impl Hub {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i64, Account>> {
        self.accounts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts one `limit` of `device`; `false` when it is over.
    pub fn allow(&self, user_id: i64, device: EndpointId, limit: Limit, now: i64) -> bool {
        self.lock()
            .entry(user_id)
            .or_default()
            .limits
            .entry(device)
            .or_default()
            .allow(limit, now)
    }

    /// Registers a connection of `device`, closing an older one of the same device with
    /// `replaced` (protocol 5.1). `pairing` is whether it negotiated the feature.
    pub fn register(
        &self,
        user_id: i64,
        device: EndpointId,
        ip: IpAddr,
        now: i64,
        pairing: bool,
        replaced: Outgoing,
    ) -> Registered {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(QUEUE);
        let mut accounts = self.lock();
        let account = accounts.entry(user_id).or_default();
        let mut flapping = None;
        if let Some(old) = account.conns.remove(&device) {
            let _ = old.tx.try_send(Frame::Out(replaced));
            let history = account.replacements.entry(device).or_default();
            history.push_back((now, ip));
            while history
                .front()
                .is_some_and(|(at, _)| now - at > FLAPPING_WINDOW_SECS)
            {
                history.pop_front();
            }
            let addresses: HashSet<IpAddr> = history.iter().map(|(_, ip)| *ip).collect();
            let reported = account
                .flapping_at
                .get(&device)
                .is_some_and(|at| now - at < FLAPPING_WINDOW_SECS);
            if history.len() >= FLAPPING_REPLACEMENTS && addresses.len() > 1 && !reported {
                account.flapping_at.insert(device, now);
                let mut addresses: Vec<IpAddr> = addresses.into_iter().collect();
                addresses.sort();
                flapping = Some(addresses);
            }
        }
        let new_address = account.last_ip.insert(device, ip) != Some(ip);
        let dropped = Arc::new(Dropped::default());
        account.conns.insert(
            device,
            Conn {
                id,
                tx,
                published: None,
                pairing,
                dropped: Arc::clone(&dropped),
            },
        );
        Registered {
            conn_id: id,
            rx,
            dropped,
            new_address,
            flapping,
        }
    }

    /// Whether connection `conn_id` is the one `device` is registered with.
    pub fn is_current(&self, user_id: i64, device: EndpointId, conn_id: u64) -> bool {
        self.lock()
            .get(&user_id)
            .and_then(|account| account.conns.get(&device))
            .is_some_and(|conn| conn.id == conn_id)
    }

    /// Removes connection `conn_id` of `device`. Returns `false` if a newer connection had
    /// replaced it already.
    pub fn unregister(&self, user_id: i64, device: EndpointId, conn_id: u64) -> bool {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return false;
        };
        if account
            .conns
            .get(&device)
            .is_some_and(|conn| conn.id == conn_id)
        {
            account.conns.remove(&device);
            true
        } else {
            false
        }
    }

    /// Queues `frame` for `device`. A connection whose queue is full is dropped, which ends it.
    pub fn send(&self, user_id: i64, device: EndpointId, frame: Outgoing) -> bool {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return false;
        };
        Self::queue(account, device, Frame::Out(frame))
    }

    fn queue(account: &mut Account, device: EndpointId, frame: Frame) -> bool {
        let Some(conn) = account.conns.get(&device) else {
            return false;
        };
        match conn.tx.try_send(frame) {
            Ok(()) => true,
            Err(_) => {
                // Full or closed: the connection ends at once.
                if let Some(conn) = account.conns.remove(&device) {
                    conn.dropped.set();
                }
                false
            }
        }
    }

    /// Queues `text` for every connected device of `user_id` except `except`.
    pub fn broadcast(&self, user_id: i64, text: &str, except: Option<EndpointId>) {
        self.broadcast_to(user_id, text, except, false);
    }

    /// Queues `text` for every connected device of `user_id` that negotiated `pairing`,
    /// except `except` (protocol 2.4: the pairing events go only to those).
    pub fn broadcast_pairing(&self, user_id: i64, text: &str, except: Option<EndpointId>) {
        self.broadcast_to(user_id, text, except, true);
    }

    fn broadcast_to(&self, user_id: i64, text: &str, except: Option<EndpointId>, pairing: bool) {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return;
        };
        let devices: Vec<EndpointId> = account
            .conns
            .iter()
            .filter(|(device, conn)| Some(**device) != except && (conn.pairing || !pairing))
            .map(|(device, _)| *device)
            .collect();
        for device in devices {
            Self::queue(account, device, Frame::Out(Outgoing::Text(text.to_owned())));
        }
    }

    /// Queues the logged event `seq` for every connected device of `user_id`.
    pub fn broadcast_logged(&self, user_id: i64, seq: i64, text: &str) {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return;
        };
        let devices: Vec<EndpointId> = account.conns.keys().copied().collect();
        for device in devices {
            Self::queue(account, device, Frame::Logged(seq, text.to_owned()));
        }
    }

    /// Closes every connection of `user_id` with `frame` and forgets everything about the
    /// account (disabled or deleted). Returns its pending pairing requests.
    pub fn remove_account(&self, user_id: i64, frame: &Outgoing) -> Vec<PendingPair> {
        let Some(account) = self.lock().remove(&user_id) else {
            return Vec::new();
        };
        for conn in account.conns.values() {
            let _ = conn.tx.try_send(Frame::Out(frame.clone()));
        }
        account.requests.into_values().collect()
    }

    /// Forgets the grants, sessions and limits of `device` (revoked or signed out).
    pub fn forget_device(&self, user_id: i64, device: EndpointId) {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return;
        };
        account
            .grants
            .retain(|(from, to), _| *from != device && *to != device);
        account
            .sessions
            .retain(|(from, to), _| *from != device && *to != device);
        account.limits.remove(&device);
    }

    /// Queues `frame` for every connection and forgets them all (shutdown).
    pub fn close_all(&self, frame: &Outgoing) {
        for account in self.lock().values_mut() {
            for conn in account.conns.values() {
                let _ = conn.tx.try_send(Frame::Out(frame.clone()));
            }
            account.conns.clear();
        }
    }

    /// Whether `device` of `user_id` has a control connection.
    #[cfg(test)]
    pub fn is_online(&self, user_id: i64, device: EndpointId) -> bool {
        self.lock()
            .get(&user_id)
            .is_some_and(|account| account.conns.contains_key(&device))
    }

    /// The connected devices of `user_id`.
    pub fn online(&self, user_id: i64) -> HashSet<EndpointId> {
        self.lock()
            .get(&user_id)
            .map(|account| account.conns.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The accounts with connected devices.
    pub fn accounts(&self) -> Vec<i64> {
        self.lock()
            .iter()
            .filter(|(_, account)| !account.conns.is_empty())
            .map(|(user_id, _)| *user_id)
            .collect()
    }

    /// Every account the hub holds state for: connections, pending requests, grants or limits.
    pub fn known_accounts(&self) -> Vec<i64> {
        self.lock().keys().copied().collect()
    }

    /// Records what connection `conn_id` of `device` published.
    pub fn publish(&self, user_id: i64, device: EndpointId, conn_id: u64, published: Published) {
        if let Some(conn) = self.conn(user_id, device, conn_id).as_mut() {
            conn.published = Some(published);
        }
    }

    /// What `device` published, if it is connected.
    pub fn published(&self, user_id: i64, device: EndpointId) -> Option<Option<Published>> {
        self.lock()
            .get(&user_id)?
            .conns
            .get(&device)
            .map(|conn| conn.published.clone())
    }

    /// Remembers that `device` was allowed `connect` to `target`.
    pub fn grant(&self, user_id: i64, device: EndpointId, target: EndpointId, grant: Grant) {
        let mut accounts = self.lock();
        let account = accounts.entry(user_id).or_default();
        let now = grant.at;
        account
            .grants
            .retain(|_, kept| now - kept.at < GRANT_KEEP_SECS);
        account.grants.insert((device, target), grant);
    }

    /// Why `device` may `lookup` `target` (protocol 7.3): it was allowed `connect` for it
    /// within `window` seconds, or reported a session with it that has not ended. `None` if
    /// neither.
    pub fn lookup_basis(
        &self,
        user_id: i64,
        device: EndpointId,
        target: EndpointId,
        now: i64,
        window: i64,
    ) -> Option<LookupBasis> {
        let accounts = self.lock();
        let account = accounts.get(&user_id)?;
        if let Some(grant) = account
            .grants
            .get(&(device, target))
            .filter(|grant| now - grant.at <= window)
        {
            return Some(LookupBasis::Connect(grant.clone()));
        }
        account
            .sessions
            .get(&(device, target))
            .filter(|started| now - **started < SESSION_MAX_SECS)
            .map(|_| LookupBasis::Session)
    }

    /// Records a session of `device` with `peer` as started or ended (protocol 12.2). A session
    /// may start only between devices one of which was allowed `connect` to the other within
    /// `window` seconds; a session already open may be reported again (after a reconnect).
    /// Returns `false` when a start is refused.
    pub fn session(
        &self,
        user_id: i64,
        device: EndpointId,
        peer: EndpointId,
        open: bool,
        now: i64,
        window: i64,
    ) -> bool {
        let mut accounts = self.lock();
        let account = accounts.entry(user_id).or_default();
        if !open {
            account.sessions.remove(&(device, peer));
            return true;
        }
        account
            .sessions
            .retain(|_, started| now - *started < SESSION_MAX_SECS);
        let granted = |from, to| {
            account
                .grants
                .get(&(from, to))
                .is_some_and(|grant| now - grant.at <= window)
        };
        if account.sessions.contains_key(&(device, peer))
            || granted(device, peer)
            || granted(peer, device)
        {
            account.sessions.entry((device, peer)).or_insert(now);
            true
        } else {
            false
        }
    }

    fn conn(&self, user_id: i64, device: EndpointId, conn_id: u64) -> ConnGuard<'_> {
        ConnGuard {
            accounts: self.lock(),
            user_id,
            device,
            conn_id,
        }
    }

    /// Adds a pending pairing request, unless the requester has one or the account reached
    /// `per_hour` requests in the last hour.
    pub fn add_request(
        &self,
        user_id: i64,
        request: PendingPair,
        now: i64,
        per_hour: usize,
    ) -> Result<(), RequestRefusal> {
        let mut accounts = self.lock();
        let account = accounts.entry(user_id).or_default();
        if account
            .requests
            .values()
            .any(|pending| pending.requester == request.requester)
        {
            return Err(RequestRefusal::Pending);
        }
        while account
            .request_times
            .front()
            .is_some_and(|at| now - at >= 3600)
        {
            account.request_times.pop_front();
        }
        if account.request_times.len() >= per_hour {
            return Err(RequestRefusal::TooMany);
        }
        account.request_times.push_back(now);
        account.requests.insert(request.request_id.clone(), request);
        Ok(())
    }

    /// The pending request `request_id` of `user_id`.
    pub fn request(&self, user_id: i64, request_id: &str) -> Option<PendingPair> {
        self.lock().get(&user_id)?.requests.get(request_id).cloned()
    }

    /// The pending requests of `user_id`.
    pub fn requests(&self, user_id: i64) -> Vec<PendingPair> {
        let mut requests: Vec<PendingPair> = self
            .lock()
            .get(&user_id)
            .map(|account| account.requests.values().cloned().collect())
            .unwrap_or_default();
        requests.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        requests
    }

    /// Removes the pending request `request_id`. Returns it if it was there.
    pub fn take_request(&self, user_id: i64, request_id: &str) -> Option<PendingPair> {
        self.lock().get_mut(&user_id)?.requests.remove(request_id)
    }

    /// Removes the pending requests that expired at `now` and returns them with their accounts.
    pub fn expire_requests(&self, now: i64) -> Vec<(i64, PendingPair)> {
        let mut expired = Vec::new();
        for (user_id, account) in self.lock().iter_mut() {
            let ids: Vec<String> = account
                .requests
                .values()
                .filter(|pending| pending.expires_at <= now)
                .map(|pending| pending.request_id.clone())
                .collect();
            for id in ids {
                if let Some(pending) = account.requests.remove(&id) {
                    expired.push((*user_id, pending));
                }
            }
        }
        expired
    }

    /// Removes the pending requests of `device` (revoked or signed out, or the pairing window
    /// closed) and returns them.
    pub fn drop_requests_of(&self, user_id: i64, device: EndpointId) -> Vec<PendingPair> {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return Vec::new();
        };
        let ids: Vec<String> = account
            .requests
            .values()
            .filter(|pending| pending.requester == device)
            .map(|pending| pending.request_id.clone())
            .collect();
        ids.iter()
            .filter_map(|id| account.requests.remove(id))
            .collect()
    }

    /// Records `available` as the account's remote access. Returns `true` if it changed from
    /// what was recorded before (and something was recorded before).
    pub fn set_remote_access(&self, user_id: i64, available: bool) -> bool {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return false;
        };
        let before = account.remote_access.replace(available);
        before.is_some_and(|before| before != available)
    }
}

/// Why a pairing request was not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestRefusal {
    /// The requester has a pending request.
    Pending,
    /// The account reached its hourly limit.
    TooMany,
}

/// Mutable access to one connection while the hub is locked.
struct ConnGuard<'a> {
    accounts: std::sync::MutexGuard<'a, HashMap<i64, Account>>,
    user_id: i64,
    device: EndpointId,
    conn_id: u64,
}

impl ConnGuard<'_> {
    fn as_mut(&mut self) -> Option<&mut Conn> {
        self.accounts
            .get_mut(&self.user_id)
            .and_then(|account| account.conns.get_mut(&self.device))
            .filter(|conn| conn.id == self.conn_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> EndpointId {
        EndpointId([seed; 32])
    }

    fn register(hub: &Hub, device: EndpointId, ip: IpAddr, now: i64) -> Registered {
        hub.register(1, device, ip, now, true, Outgoing::Close(4001, "replaced"))
    }

    fn grant(at: i64) -> Grant {
        Grant {
            at,
            purpose: Purpose::Session,
            service: "test/1".to_owned(),
            request_id: None,
        }
    }

    #[tokio::test]
    async fn a_new_connection_replaces_the_old_one_and_flapping_is_noticed() {
        let hub = Hub::default();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let replaced = || Outgoing::Close(4001, "replaced");
        let mut first = register(&hub, key(1), a, 0);
        assert!(first.new_address);
        let second = register(&hub, key(1), a, 10);
        assert!(!second.new_address);
        assert_eq!(first.rx.recv().await, Some(Frame::Out(replaced())));
        assert!(
            !hub.unregister(1, key(1), first.conn_id),
            "replaced already"
        );
        assert!(!first.dropped.is_set(), "replaced is not dropped");
        let third = register(&hub, key(1), b, 20);
        assert!(third.flapping.is_none());
        let fourth = register(&hub, key(1), a, 30);
        assert_eq!(fourth.flapping, Some(vec![a, b]));
        let fifth = register(&hub, key(1), b, 40);
        assert!(fifth.flapping.is_none(), "recorded once per window");
        assert!(hub.is_online(1, key(1)));
        assert!(hub.is_current(1, key(1), fifth.conn_id));
        assert!(hub.unregister(1, key(1), fifth.conn_id));
        assert!(!hub.is_online(1, key(1)));
    }

    #[tokio::test]
    async fn lookups_follow_a_recent_connect_or_an_open_session_across_reconnects() {
        let hub = Hub::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let _conn = register(&hub, key(1), ip, 0);
        assert_eq!(hub.lookup_basis(1, key(1), key(2), 0, 600), None);
        hub.grant(1, key(1), key(2), grant(100));
        // A reconnect keeps the grant.
        let _again = register(&hub, key(1), ip, 200);
        assert_eq!(
            hub.lookup_basis(1, key(1), key(2), 700, 600),
            Some(LookupBasis::Connect(grant(100)))
        );
        assert_eq!(hub.lookup_basis(1, key(1), key(2), 701, 600), None);
        assert_eq!(
            hub.lookup_basis(1, key(2), key(1), 200, 600),
            None,
            "the grant is one way"
        );
    }

    #[tokio::test]
    async fn a_session_can_start_only_after_a_connect_between_the_two() {
        let hub = Hub::default();
        assert!(
            !hub.session(1, key(1), key(2), true, 0, 600),
            "no connect at all"
        );
        assert_eq!(hub.lookup_basis(1, key(1), key(2), 0, 600), None);
        // Device 2 connected to device 1; either side may then report the session.
        hub.grant(1, key(2), key(1), grant(100));
        assert!(hub.session(1, key(1), key(2), true, 110, 600));
        assert!(hub.session(1, key(2), key(1), true, 110, 600));
        assert_eq!(
            hub.lookup_basis(1, key(1), key(2), 5000, 600),
            Some(LookupBasis::Session)
        );
        // Long after the connect, an open session may be reported again, a new one not.
        assert!(hub.session(1, key(1), key(2), true, 5000, 600));
        assert!(!hub.session(1, key(1), key(3), true, 5000, 600));
        assert!(hub.session(1, key(1), key(2), false, 5000, 600));
        assert_eq!(hub.lookup_basis(1, key(1), key(2), 5000, 600), None);
        hub.forget_device(1, key(2));
        assert_eq!(hub.lookup_basis(1, key(2), key(1), 110, 600), None);
    }

    #[tokio::test]
    async fn limits_are_kept_per_device() {
        let hub = Hub::default();
        for _ in 0..crate::limit::HELLOS_PER_MINUTE {
            assert!(hub.allow(1, key(1), Limit::Hello, 0));
        }
        assert!(!hub.allow(1, key(1), Limit::Hello, 0));
        assert!(hub.allow(1, key(2), Limit::Hello, 0), "another device");
        hub.forget_device(1, key(1));
        assert!(hub.allow(1, key(1), Limit::Hello, 0));
    }

    #[tokio::test]
    async fn a_connection_that_does_not_read_is_dropped_at_once() {
        let hub = Hub::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let conn = register(&hub, key(1), ip, 0);
        for _ in 0..QUEUE {
            assert!(hub.send(1, key(1), Outgoing::Text("x".to_owned())));
        }
        assert!(!conn.dropped.is_set());
        assert!(!hub.send(1, key(1), Outgoing::Text("x".to_owned())));
        assert!(!hub.is_online(1, key(1)));
        assert!(conn.dropped.is_set());
        tokio::time::timeout(std::time::Duration::from_secs(1), conn.dropped.wait())
            .await
            .expect("the session hears of it");
    }

    #[tokio::test]
    async fn pairing_events_go_only_to_devices_that_negotiated_pairing() {
        let hub = Hub::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut with = register(&hub, key(1), ip, 0);
        let mut without = hub.register(1, key(2), ip, 0, false, Outgoing::Close(4001, ""));
        hub.broadcast_pairing(1, "p", None);
        hub.broadcast(1, "b", None);
        assert_eq!(
            with.rx.recv().await,
            Some(Frame::Out(Outgoing::Text("p".to_owned())))
        );
        assert_eq!(
            without.rx.recv().await,
            Some(Frame::Out(Outgoing::Text("b".to_owned())))
        );
    }

    #[tokio::test]
    async fn removing_an_account_closes_its_connections_and_forgets_it() {
        let hub = Hub::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut conn = register(&hub, key(1), ip, 0);
        hub.grant(1, key(1), key(2), grant(0));
        let closed = Outgoing::Close(4004, "account disabled");
        assert!(hub.remove_account(1, &closed).is_empty());
        assert_eq!(conn.rx.recv().await, Some(Frame::Out(closed)));
        assert!(hub.known_accounts().is_empty());
        assert_eq!(hub.lookup_basis(1, key(1), key(2), 0, 600), None);
    }
}
