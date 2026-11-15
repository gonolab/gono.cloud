//! iroh's address lookup backed by the control channel (protocol 7).
//!
//! - **Publishing.** iroh calls [`AddressLookup::publish`] whenever the endpoint's own
//!   addresses change. A task sends the latest of them to the server with `publish`: at most
//!   once a second, which the server enforces (protocol 15), so changes in quick succession
//!   (the local addresses, then the public one QUIC address discovery found) are coalesced
//!   and a refusal for the rate is sent again; and again after every reconnect, because the
//!   server keeps what a device published per connection (protocol 7.1).
//! - **Resolving.** A connection starts with `connect` ([`crate::Remote::connect`]), whose
//!   answer is remembered here. iroh's later resolves are answered from that for up to
//!   [`CACHE_TTL`], then with `lookup`, which the server allows only after a recent `connect`
//!   or during a reported session.
//! - **Relay first.** While the endpoint holds its relay connection
//!   ([`ControlLookup::watch_relay`]), resolves name the relay alone, and the direct path is
//!   left to iroh's NAT traversal inside the connection: a direct address handed to iroh
//!   before the handshake makes it send the Initial there too, and a direct path that works one
//!   way only then holds the handshake (see [`crate::endpoint::dial`]). Without the relay
//!   (an outage of gono-cloud stops the embedded relay too), resolves name the cached direct
//!   addresses, so that new connections can still use them (protocol 7.4).
//! - **Checks.** An answer for another key than the one asked for is refused. A relay URL
//!   other than the discovery document's is dropped, because iroh dials whatever relay it is
//!   given and the endpoint must contact no relay but ours (plan 3.5, threat model C15).
//!   Direct addresses no peer can reach ([`is_dialable`]: loopback, multicast, port 0, …) are
//!   dropped, because iroh would probe them, and at most [`limits::MAX_DIRECT_ADDRESSES`] are
//!   kept. The same filter applies to what the device publishes, which the server would refuse
//!   otherwise (protocol 7.1).
//!
//! Addresses are hints (protocol 1.1, rule 3): iroh dials by key, so a wrong address only fails.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use gono_protocol::connect::{DeviceId, ErrorCode, is_dialable, limits, message::AddressResult};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl, Watcher as _,
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Error as LookupError, Item},
};
use n0_future::boxed::BoxStream;
use tokio::sync::watch;

use crate::{ControlChannel, Error, Result};

/// How long a `connect` or `lookup` answer is used (protocol 15).
pub const CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// The most peers whose answers are cached. An account has at most 50 devices (protocol 15).
const MAX_CACHED: usize = 256;

/// The provenance iroh records for these results.
const PROVENANCE: &str = "gono-connect";

/// The least time between two `publish` (protocol 15).
const PUBLISH_INTERVAL: Duration = Duration::from_secs(1);

/// What a device publishes (protocol 7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Addresses {
    pub(crate) relay_url: Option<String>,
    pub(crate) direct: Vec<SocketAddr>,
}

/// Says whether the endpoint holds its relay connection right now.
struct RelayCheck(Mutex<Box<dyn FnMut() -> bool + Send>>);

impl std::fmt::Debug for RelayCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayCheck")
    }
}

/// See the module documentation.
#[derive(Debug, Clone)]
pub struct ControlLookup {
    channel: ControlChannel,
    relay_url: RelayUrl,
    cache: Arc<Mutex<Cache>>,
    /// The latest addresses, for the task that publishes them; started by the first
    /// [`AddressLookup::publish`], and ended when the last clone of the lookup is dropped.
    published: Arc<OnceLock<watch::Sender<Option<Addresses>>>>,
    /// The endpoint's relay status, once [`ControlLookup::watch_relay`] was called.
    relay: Arc<OnceLock<RelayCheck>>,
}

impl ControlLookup {
    /// A lookup that asks `channel`. `relay_url` is the discovery document's: the only relay
    /// an answer may name.
    pub fn new(channel: ControlChannel, relay_url: RelayUrl) -> Self {
        Self {
            channel,
            relay_url,
            cache: Arc::new(Mutex::new(Cache::default())),
            published: Arc::new(OnceLock::new()),
            relay: Arc::new(OnceLock::new()),
        }
    }

    /// Lets resolves follow the relay status of `endpoint`, the endpoint this lookup serves:
    /// the relay alone while it is connected, the cached direct addresses besides while it is
    /// not. Until this is called, resolves name both. [`crate::Remote::start`] calls it.
    pub fn watch_relay(&self, endpoint: &Endpoint) {
        // A watcher of the status only: holding the endpoint here would keep it alive.
        let mut status = endpoint.home_relay_status();
        let check: Box<dyn FnMut() -> bool + Send> =
            Box::new(move || status.get().iter().any(|relay| relay.is_connected()));
        let _ = self.relay.set(RelayCheck(Mutex::new(check)));
    }

    /// Whether resolves leave the direct addresses to NAT traversal.
    fn relay_first(&self) -> bool {
        self.relay
            .get()
            .is_some_and(|check| (check.0.lock().unwrap_or_else(PoisonError::into_inner))())
    }

    /// Checks the answer of a `connect` or `lookup` for `target` (see the module
    /// documentation), remembers it, and returns the address to dial.
    pub fn remember(&self, target: DeviceId, result: &AddressResult) -> Result<EndpointAddr> {
        let info = self.check_and_remember(target, result)?;
        Ok(EndpointAddr::from_parts(
            target.0,
            info.data.addrs().cloned(),
        ))
    }

    fn check_and_remember(&self, target: DeviceId, result: &AddressResult) -> Result<EndpointInfo> {
        let result = checked(&self.relay_url, target.0, result)?;
        let info = info(&result, true);
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(target.0, result, Instant::now());
        Ok(info)
    }

    fn cached(&self, id: &EndpointId) -> Option<AddressResult> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id, Instant::now())
    }
}

/// The answers of `connect` and `lookup`, per peer, for [`CACHE_TTL`].
#[derive(Debug, Default)]
struct Cache {
    entries: HashMap<EndpointId, (AddressResult, Instant)>,
}

impl Cache {
    fn get(&self, id: &EndpointId, now: Instant) -> Option<AddressResult> {
        self.entries
            .get(id)
            .filter(|(_, at)| now.duration_since(*at) < CACHE_TTL)
            .map(|(result, _)| result.clone())
    }

    /// Inserts an answer; drops expired ones, and the oldest while [`MAX_CACHED`] are kept.
    fn insert(&mut self, id: EndpointId, result: AddressResult, now: Instant) {
        self.entries
            .retain(|_, (_, at)| now.duration_since(*at) < CACHE_TTL);
        while self.entries.len() >= MAX_CACHED && !self.entries.contains_key(&id) {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(id, _)| *id)
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.entries.insert(id, (result, now));
    }
}

/// The answer for `target`, with the relay URL dropped unless it is `relay`, and at most
/// [`limits::MAX_DIRECT_ADDRESSES`] dialable direct addresses. An answer for another key is
/// refused.
fn checked(relay: &RelayUrl, target: EndpointId, result: &AddressResult) -> Result<AddressResult> {
    if result.target.0 != target {
        return Err(Error::Channel(format!(
            "the server answered with the addresses of {} instead of {}",
            result.target.short(),
            DeviceId::from(target).short()
        )));
    }
    let relay_url = result.relay_url.as_deref().and_then(|url| {
        let ours = url.parse::<RelayUrl>().is_ok_and(|url| url == *relay);
        if !ours {
            tracing::warn!(url, "ignoring a relay that is not the server's");
        }
        ours.then(|| relay.to_string())
    });
    let mut direct = result.direct.clone();
    direct.retain(is_dialable);
    direct.truncate(limits::MAX_DIRECT_ADDRESSES);
    Ok(AddressResult {
        target: result.target,
        relay_url,
        direct,
        published_at: result.published_at,
    })
}

/// The endpoint information of a checked answer, with or without its direct addresses.
fn info(result: &AddressResult, direct: bool) -> EndpointInfo {
    let mut info = EndpointInfo::new(result.target.0);
    if direct || result.relay_url.is_none() {
        info = info.with_ip_addrs(result.direct.clone());
    }
    if let Some(relay) = result
        .relay_url
        .as_deref()
        .and_then(|url| url.parse::<RelayUrl>().ok())
    {
        info = info.with_relay_url(relay);
    }
    info
}

impl AddressLookup for ControlLookup {
    fn publish(&self, data: &EndpointData) {
        let relay_url = data.relay_urls().next().map(ToString::to_string);
        // The server refuses a `publish` with more, or with an address no peer can reach
        // (protocol 7.1).
        let direct: Vec<_> = data
            .ip_addrs()
            .copied()
            .filter(is_dialable)
            .take(limits::MAX_DIRECT_ADDRESSES)
            .collect();
        let latest = self.published.get_or_init(|| {
            let (latest, receiver) = watch::channel(None);
            tokio::spawn(publish_latest(
                self.channel.clone(),
                receiver,
                PUBLISH_INTERVAL,
            ));
            latest
        });
        latest.send_replace(Some(Addresses { relay_url, direct }));
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, LookupError>>> {
        let direct = !self.relay_first();
        if let Some(result) = self.cached(&endpoint_id) {
            let item = Item::new(info(&result, direct), PROVENANCE, None);
            return Some(Box::pin(n0_future::stream::once(Ok(item))));
        }
        let lookup = self.clone();
        Some(Box::pin(n0_future::stream::once_future(async move {
            let target = DeviceId::from(endpoint_id);
            let result = lookup
                .channel
                .lookup(target)
                .await
                .map_err(|err| LookupError::from_err(PROVENANCE, err))?;
            lookup
                .check_and_remember(target, &result)
                .map_err(|err| LookupError::from_err(PROVENANCE, err))?;
            let checked = checked(&lookup.relay_url, target.0, &result)
                .map_err(|err| LookupError::from_err(PROVENANCE, err))?;
            Ok(Item::new(info(&checked, direct), PROVENANCE, None))
        })))
    }
}

/// Sends the latest addresses of `latest` with `publish` while `channel` is connected: at
/// most one `publish` per `interval`, again after a refusal for the rate, and again after
/// every reconnect. Ends when the sender of `latest` is dropped.
pub(crate) async fn publish_latest(
    channel: ControlChannel,
    mut latest: watch::Receiver<Option<Addresses>>,
    interval: Duration,
) {
    let mut connected = channel.connected();
    // What the current connection has.
    let mut sent: Option<Addresses> = None;
    let mut last_sent: Option<tokio::time::Instant> = None;
    loop {
        let is_connected = *connected.borrow_and_update();
        let pending = latest
            .borrow_and_update()
            .clone()
            .filter(|addresses| sent.as_ref() != Some(addresses));
        if let Some(addresses) = pending.filter(|_| is_connected) {
            if let Some(at) = last_sent {
                tokio::time::sleep_until(at + interval).await;
            }
            last_sent = Some(tokio::time::Instant::now());
            let result = channel
                .publish(addresses.relay_url.clone(), addresses.direct.clone())
                .await;
            match result {
                Ok(()) => sent = Some(addresses),
                // Sent again once the interval has passed.
                Err(Error::Refused {
                    code: ErrorCode::RateLimited,
                    ..
                }) => {}
                // Not again: the same addresses would be refused the same way.
                Err(Error::Refused { code, message }) => {
                    tracing::debug!(?code, message, "the server refused the device's addresses");
                    sent = Some(addresses);
                }
                // Not connected: sent again after the reconnect.
                Err(err) => tracing::debug!(error = %err, "cannot publish the device's addresses"),
            }
            continue;
        }
        tokio::select! {
            changed = latest.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            changed = connected.changed() => {
                if changed.is_err() {
                    return;
                }
                // A new connection knows nothing of what an earlier one published.
                sent = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::tests::device_id;

    fn relay() -> RelayUrl {
        "https://relay.example.com/".parse().unwrap()
    }

    fn answer(target: DeviceId, relay_url: &str, direct: usize) -> AddressResult {
        AddressResult {
            target,
            relay_url: Some(relay_url.to_owned()),
            direct: (0..direct)
                .map(|port| SocketAddr::from(([192, 0, 2, 1], 1000 + port as u16)))
                .collect(),
            published_at: Some(1),
        }
    }

    #[test]
    fn addresses_no_peer_can_reach_are_dropped_before_the_cap() {
        let target = device_id(1);
        let mut result = answer(target, "https://relay.example.com/", 0);
        result.direct = [
            "127.0.0.1:24850",
            "[::ffff:127.0.0.1]:24850",
            "224.0.0.251:5353",
            "0.0.0.0:24850",
            "192.0.2.10:0",
            "[::1]:24850",
        ]
        .iter()
        .map(|addr| addr.parse().unwrap())
        .chain(answer(target, "https://relay.example.com/", 20).direct)
        .collect();
        let checked = checked(&relay(), target.0, &result).unwrap();
        assert_eq!(checked.direct.len(), limits::MAX_DIRECT_ADDRESSES);
        assert!(
            checked.direct.iter().all(is_dialable),
            "{:?}",
            checked.direct
        );
    }

    #[test]
    fn answers_for_another_key_are_refused() {
        let asked = device_id(1);
        let other = answer(device_id(2), "https://relay.example.com/", 1);
        assert!(checked(&relay(), asked.0, &other).is_err());
        assert!(
            checked(
                &relay(),
                asked.0,
                &answer(asked, "https://relay.example.com/", 1)
            )
            .is_ok()
        );
    }

    #[test]
    fn only_our_relay_is_kept_and_direct_addresses_are_capped() {
        let target = device_id(1);
        let ours = checked(
            &relay(),
            target.0,
            &answer(target, "https://relay.example.com", 40),
        )
        .unwrap();
        assert_eq!(
            ours.relay_url.as_deref(),
            Some("https://relay.example.com/")
        );
        assert_eq!(ours.direct.len(), limits::MAX_DIRECT_ADDRESSES);
        for foreign in [
            "https://evil.example.com/",
            "https://relay.example.com:8443/",
            "http://relay.example.com/",
            "not a url",
        ] {
            let result = checked(&relay(), target.0, &answer(target, foreign, 1)).unwrap();
            assert_eq!(result.relay_url, None, "{foreign}");
            assert_eq!(result.direct.len(), 1);
        }
        let info = info(&ours, true);
        assert_eq!(info.data.relay_urls().count(), 1);
    }

    #[test]
    fn resolves_leave_direct_addresses_out_while_the_relay_works() {
        let target = device_id(1);
        let relayed = checked(
            &relay(),
            target.0,
            &answer(target, "https://relay.example.com/", 3),
        )
        .unwrap();
        // Relay first: the relay alone, so that iroh does not send the Initial directly.
        let first = info(&relayed, false);
        assert_eq!(first.data.relay_urls().count(), 1);
        assert_eq!(first.data.ip_addrs().count(), 0);
        // Without the relay (an outage): the cached direct addresses (protocol 7.4).
        let fallback = info(&relayed, true);
        assert_eq!(fallback.data.ip_addrs().count(), 3);
        // An answer without our relay keeps its direct addresses in any case.
        let direct_only = checked(
            &relay(),
            target.0,
            &answer(target, "https://evil.example.com/", 2),
        )
        .unwrap();
        assert_eq!(info(&direct_only, false).data.ip_addrs().count(), 2);
    }

    #[test]
    fn the_cache_expires_and_stays_bounded() {
        let start = Instant::now();
        let mut cache = Cache::default();
        let first = device_id(1);
        cache.insert(
            first.0,
            answer(first, "https://relay.example.com/", 1),
            start,
        );
        assert!(cache.get(&first.0, start + CACHE_TTL / 2).is_some());
        assert!(cache.get(&first.0, start + CACHE_TTL).is_none());

        // Expired entries go on the next insert.
        let second = device_id(2);
        cache.insert(
            second.0,
            answer(second, "https://relay.example.com/", 1),
            start + CACHE_TTL,
        );
        assert_eq!(cache.entries.len(), 1);

        // At most MAX_CACHED; the oldest goes first.
        let mut cache = Cache::default();
        let keys: Vec<EndpointId> = (0..=MAX_CACHED)
            .map(|_| iroh::SecretKey::generate().public())
            .collect();
        for (n, key) in keys.iter().enumerate() {
            let at = start + Duration::from_millis(n as u64);
            cache.insert(
                *key,
                answer(DeviceId::from(*key), "https://relay.example.com/", 0),
                at,
            );
        }
        assert_eq!(cache.entries.len(), MAX_CACHED);
        assert!(!cache.entries.contains_key(&keys[0]));
        assert!(cache.entries.contains_key(&keys[MAX_CACHED]));
    }
}
