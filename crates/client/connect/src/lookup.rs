//! iroh's address lookup backed by the control channel (protocol 7).
//!
//! - **Publishing.** iroh calls [`AddressLookup::publish`] whenever the endpoint's own
//!   addresses change; they go to the server with `publish`.
//! - **Resolving.** A connection starts with `connect` ([`crate::Remote::connect`]), whose
//!   answer is remembered here. iroh's later resolves are answered from that for up to
//!   [`CACHE_TTL`], then with `lookup`, which the server allows only after a recent `connect`
//!   or during a reported session.
//! - **Checks.** An answer for another key than the one asked for is refused. A relay URL
//!   other than the discovery document's is dropped, because iroh dials whatever relay it is
//!   given and the endpoint must contact no relay but ours (plan 3.5, threat model C15).
//!   At most [`limits::MAX_DIRECT_ADDRESSES`] direct addresses are kept.
//!
//! Addresses are hints (protocol 1.1, rule 3): iroh dials by key, so a wrong address only fails.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use gono_protocol::connect::{DeviceId, limits, message::AddressResult};
use iroh::{
    EndpointAddr, EndpointId, RelayUrl,
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Error as LookupError, Item},
};
use n0_future::boxed::BoxStream;

use crate::{ControlChannel, Error, Result};

/// How long a `connect` or `lookup` answer is used (protocol 15).
pub const CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// The most peers whose answers are cached. An account has at most 50 devices (protocol 15).
const MAX_CACHED: usize = 256;

/// The provenance iroh records for these results.
const PROVENANCE: &str = "gono-connect";

/// See the module documentation.
#[derive(Debug, Clone)]
pub struct ControlLookup {
    channel: ControlChannel,
    relay_url: RelayUrl,
    cache: Arc<Mutex<Cache>>,
}

impl ControlLookup {
    /// A lookup that asks `channel`. `relay_url` is the discovery document's: the only relay
    /// an answer may name.
    pub fn new(channel: ControlChannel, relay_url: RelayUrl) -> Self {
        Self {
            channel,
            relay_url,
            cache: Arc::new(Mutex::new(Cache::default())),
        }
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
        let info = info(&result);
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
/// [`limits::MAX_DIRECT_ADDRESSES`] direct addresses. An answer for another key is refused.
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
    direct.truncate(limits::MAX_DIRECT_ADDRESSES);
    Ok(AddressResult {
        target: result.target,
        relay_url,
        direct,
        published_at: result.published_at,
    })
}

/// The endpoint information of a checked answer.
fn info(result: &AddressResult) -> EndpointInfo {
    let mut info = EndpointInfo::new(result.target.0).with_ip_addrs(result.direct.clone());
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
        // The server refuses a `publish` with more (protocol 7.1).
        let direct: Vec<_> = data
            .ip_addrs()
            .copied()
            .take(limits::MAX_DIRECT_ADDRESSES)
            .collect();
        let channel = self.channel.clone();
        tokio::spawn(async move {
            if let Err(err) = channel.publish(relay_url, direct).await {
                tracing::debug!(error = %err, "cannot publish the device's addresses");
            }
        });
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, LookupError>>> {
        if let Some(result) = self.cached(&endpoint_id) {
            let item = Item::new(info(&result), PROVENANCE, None);
            return Some(Box::pin(n0_future::stream::once(Ok(item))));
        }
        let lookup = self.clone();
        Some(Box::pin(n0_future::stream::once_future(async move {
            let target = DeviceId::from(endpoint_id);
            lookup
                .channel
                .lookup(target)
                .await
                .and_then(|result| lookup.check_and_remember(target, &result))
                .map(|info| Item::new(info, PROVENANCE, None))
                .map_err(|err| LookupError::from_err(PROVENANCE, err))
        })))
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
        let info = info(&ours);
        assert_eq!(info.data.relay_urls().count(), 1);
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
