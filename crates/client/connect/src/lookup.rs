//! iroh's address lookup backed by the control channel (protocol 7).
//!
//! - **Publishing.** iroh calls [`AddressLookup::publish`] whenever the endpoint's own
//!   addresses change; they go to the server with `publish`.
//! - **Resolving.** A connection starts with `connect` ([`crate::Remote::connect`]), whose
//!   answer is remembered here. iroh's later resolves are answered from that for up to
//!   [`CACHE_TTL`], then with `lookup`, which the server allows only after a recent `connect`
//!   or during a reported session.
//!
//! Addresses are hints (protocol 1.1, rule 3): iroh dials by key, so a wrong address only fails.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use gono_protocol::connect::{DeviceId, message::AddressResult};
use iroh::{
    EndpointId, RelayUrl,
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Error as LookupError, Item},
};
use n0_future::boxed::BoxStream;

use crate::ControlChannel;

/// How long a `connect` or `lookup` answer is used (protocol 15).
pub const CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// The provenance iroh records for these results.
const PROVENANCE: &str = "gono-connect";

/// See the module documentation.
#[derive(Debug, Clone)]
pub struct ControlLookup {
    channel: ControlChannel,
    cache: Arc<Mutex<HashMap<EndpointId, (AddressResult, Instant)>>>,
}

impl ControlLookup {
    /// A lookup that asks `channel`.
    pub fn new(channel: ControlChannel) -> Self {
        Self {
            channel,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Remembers the answer of a `connect` or `lookup`.
    pub fn remember(&self, result: &AddressResult) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(result.target.0, (result.clone(), Instant::now()));
    }

    fn cached(&self, id: &EndpointId) -> Option<AddressResult> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .filter(|(_, at)| at.elapsed() < CACHE_TTL)
            .map(|(result, _)| result.clone())
    }
}

/// The endpoint information of an answer.
pub(crate) fn info(result: &AddressResult) -> EndpointInfo {
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
        let direct: Vec<_> = data.ip_addrs().copied().collect();
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
            match lookup.channel.lookup(DeviceId::from(endpoint_id)).await {
                Ok(result) => {
                    lookup.remember(&result);
                    Ok(Item::new(info(&result), PROVENANCE, None))
                }
                Err(err) => Err(LookupError::from_err(PROVENANCE, err)),
            }
        })))
    }
}
