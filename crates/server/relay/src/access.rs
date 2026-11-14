//! Which devices may use the relay.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::anyhow;
use iroh_base::EndpointId;
use iroh_relay::server::{Access, AccessControl, ClientRequest, ConnectionId};

/// Admits the devices of `relay.allowed_endpoints` and refuses every other one.
///
/// The relay handshake proves that a connecting device holds the secret key of the id it
/// claims before [`AccessControl::on_connect`] runs, so the id alone decides. The allowlist
/// also counts what it admitted and refused, for the admin UI.
#[derive(Debug)]
pub(crate) struct Allowlist {
    allowed: HashSet<EndpointId>,
    /// Open connections that were admitted, with the device each belongs to. A device may hold
    /// several, for example while it reconnects.
    connected: Mutex<HashMap<ConnectionId, EndpointId>>,
    /// Connection attempts refused since the start.
    denied: AtomicU64,
}

impl Allowlist {
    /// Parses the device ids of `relay.allowed_endpoints` (64 hex digits each, any case).
    pub(crate) fn parse(ids: &[String]) -> anyhow::Result<Self> {
        let allowed = ids
            .iter()
            .map(|id| {
                id.to_ascii_lowercase()
                    .parse::<EndpointId>()
                    .map_err(|err| {
                        anyhow!("relay.allowed_endpoints: {id:?} is not a device id: {err}")
                    })
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            allowed,
            connected: Mutex::new(HashMap::new()),
            denied: AtomicU64::new(0),
        })
    }

    /// Number of distinct allowed devices.
    pub(crate) fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Open connections and the number of distinct devices holding them.
    pub(crate) fn connected(&self) -> (usize, usize) {
        let connected = self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let devices = connected.values().collect::<HashSet<_>>().len();
        (connected.len(), devices)
    }

    /// Connection attempts refused since the start.
    pub(crate) fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }
}

impl AccessControl for Allowlist {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let device = request.endpoint_id();
        if self.allowed.contains(&device) {
            self.connected
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(request.connection_id(), device);
            tracing::debug!(device = %device.fmt_short(), "relay connection admitted");
            Access::Allow
        } else {
            self.denied.fetch_add(1, Ordering::Relaxed);
            // The full id, so that an operator setting up a device can allow it.
            tracing::info!(
                %device,
                "relay connection refused: the device is not in relay.allowed_endpoints"
            );
            // No reason: the client learns that it was refused, nothing about the list.
            Access::Deny { reason: None }
        }
    }

    fn on_disconnect(&self, _device: EndpointId, connection_id: ConnectionId) {
        self.connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&connection_id);
    }
}
