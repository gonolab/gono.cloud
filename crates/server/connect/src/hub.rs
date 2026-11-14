//! The live state of the control channel, kept in memory only: which device of which account
//! is connected, what it published, whom it is connecting to, and the pending pairing
//! requests (`docs/connect-protocol.md`, sections 5, 7 and 8).
//!
//! Addresses never leave this module except in `connect` and `lookup` answers (S3 of the
//! threat model). Each connection has a bounded queue of frames; a device that does not read
//! its frames loses its place, which ends its connection.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use gono_protocol::connect::{DeviceEntry, Signed};
use gono_server_core::devices::EndpointId;
use tokio::sync::mpsc;

/// Frames a connection may have queued before it counts as too slow.
const QUEUE: usize = 256;

/// How many replacements within [`FLAPPING_WINDOW_SECS`] from different addresses count as
/// flapping (protocol 5.1).
const FLAPPING_REPLACEMENTS: usize = 3;

/// The window of [`FLAPPING_REPLACEMENTS`], in seconds.
const FLAPPING_WINDOW_SECS: i64 = 10 * 60;

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

#[derive(Debug)]
struct Conn {
    id: u64,
    tx: mpsc::Sender<Frame>,
    published: Option<Published>,
    /// Targets of `connect`, with when.
    connects: HashMap<EndpointId, i64>,
    /// Peers of sessions reported as started and not yet ended.
    sessions: HashSet<EndpointId>,
}

#[derive(Debug, Default)]
struct Account {
    conns: HashMap<EndpointId, Conn>,
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

    /// Registers a connection of `device`, closing an older one of the same device with
    /// `replaced` (protocol 5.1).
    pub fn register(
        &self,
        user_id: i64,
        device: EndpointId,
        ip: IpAddr,
        now: i64,
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
        account.conns.insert(
            device,
            Conn {
                id,
                tx,
                published: None,
                connects: HashMap::new(),
                sessions: HashSet::new(),
            },
        );
        Registered {
            conn_id: id,
            rx,
            new_address,
            flapping,
        }
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
                // Full or closed: the connection's task ends when its queue runs dry.
                account.conns.remove(&device);
                false
            }
        }
    }

    /// Queues `text` for every connected device of `user_id` except `except`.
    pub fn broadcast(&self, user_id: i64, text: &str, except: Option<EndpointId>) {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(&user_id) else {
            return;
        };
        let devices: Vec<EndpointId> = account
            .conns
            .keys()
            .copied()
            .filter(|device| Some(*device) != except)
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

    /// Remembers that connection `conn_id` of `device` sent `connect` for `target` at `now`.
    pub fn connecting(
        &self,
        user_id: i64,
        device: EndpointId,
        conn_id: u64,
        target: EndpointId,
        now: i64,
    ) {
        let mut accounts = self.lock();
        if let Some(conn) = accounts
            .get_mut(&user_id)
            .and_then(|account| account.conns.get_mut(&device))
            .filter(|conn| conn.id == conn_id)
        {
            conn.connects.retain(|_, at| now - *at < 3600);
            conn.connects.insert(target, now);
        }
    }

    /// Whether `lookup` of `target` is allowed for connection `conn_id` of `device`: it sent
    /// `connect` for it within `window` seconds, or has a session with it (protocol 7.3).
    pub fn may_look_up(
        &self,
        user_id: i64,
        device: EndpointId,
        conn_id: u64,
        target: EndpointId,
        now: i64,
        window: i64,
    ) -> bool {
        let accounts = self.lock();
        accounts
            .get(&user_id)
            .and_then(|account| account.conns.get(&device))
            .filter(|conn| conn.id == conn_id)
            .is_some_and(|conn| {
                conn.sessions.contains(&target)
                    || conn
                        .connects
                        .get(&target)
                        .is_some_and(|at| now - at <= window)
            })
    }

    /// Records a session of connection `conn_id` of `device` with `peer` as open or ended.
    pub fn session(
        &self,
        user_id: i64,
        device: EndpointId,
        conn_id: u64,
        peer: EndpointId,
        open: bool,
    ) {
        if let Some(conn) = self.conn(user_id, device, conn_id).as_mut() {
            if open {
                conn.sessions.insert(peer);
            } else {
                conn.sessions.remove(&peer);
            }
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

    /// Removes the pending requests of `device` (revoked or signed out) and returns them.
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

    #[tokio::test]
    async fn a_new_connection_replaces_the_old_one_and_flapping_is_noticed() {
        let hub = Hub::default();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let replaced = || Outgoing::Close(4001, "replaced");
        let mut first = hub.register(1, key(1), a, 0, replaced());
        assert!(first.new_address);
        let second = hub.register(1, key(1), a, 10, replaced());
        assert!(!second.new_address);
        assert_eq!(first.rx.recv().await, Some(Frame::Out(replaced())));
        assert!(
            !hub.unregister(1, key(1), first.conn_id),
            "replaced already"
        );
        let third = hub.register(1, key(1), b, 20, replaced());
        assert!(third.flapping.is_none());
        let fourth = hub.register(1, key(1), a, 30, replaced());
        assert_eq!(fourth.flapping, Some(vec![a, b]));
        let fifth = hub.register(1, key(1), b, 40, replaced());
        assert!(fifth.flapping.is_none(), "recorded once per window");
        assert!(hub.is_online(1, key(1)));
        assert!(hub.unregister(1, key(1), fifth.conn_id));
        assert!(!hub.is_online(1, key(1)));
    }

    #[tokio::test]
    async fn lookups_follow_a_recent_connect_or_an_open_session() {
        let hub = Hub::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let conn = hub.register(1, key(1), ip, 0, Outgoing::Close(4001, ""));
        assert!(!hub.may_look_up(1, key(1), conn.conn_id, key(2), 0, 600));
        hub.connecting(1, key(1), conn.conn_id, key(2), 100);
        assert!(hub.may_look_up(1, key(1), conn.conn_id, key(2), 700, 600));
        assert!(!hub.may_look_up(1, key(1), conn.conn_id, key(2), 701, 600));
        hub.session(1, key(1), conn.conn_id, key(2), true);
        assert!(hub.may_look_up(1, key(1), conn.conn_id, key(2), 5000, 600));
        hub.session(1, key(1), conn.conn_id, key(2), false);
        assert!(!hub.may_look_up(1, key(1), conn.conn_id, key(2), 5000, 600));
    }

    #[tokio::test]
    async fn a_connection_that_does_not_read_loses_its_place() {
        let hub = Hub::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let _conn = hub.register(1, key(1), ip, 0, Outgoing::Close(4001, ""));
        for _ in 0..QUEUE {
            assert!(hub.send(1, key(1), Outgoing::Text("x".to_owned())));
        }
        assert!(!hub.send(1, key(1), Outgoing::Text("x".to_owned())));
        assert!(!hub.is_online(1, key(1)));
    }
}
