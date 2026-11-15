//! Which devices may use the relay.

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::anyhow;
use iroh_base::EndpointId;
use iroh_relay::server::{Access, AccessControl, ClientRequest, ConnectionId};

/// Devices admitted besides `relay.allowed_endpoints`: the device directory of Gono Cloud
/// (`docs/connect-protocol.md`, section 11.1).
pub trait Admission: Debug + Send + Sync + 'static {
    /// Whether `device` may use the relay now. Called for every connection, so it must answer
    /// from memory.
    fn admits(&self, device: &EndpointId) -> bool;

    /// How many devices it admits, for the admin UI.
    fn count(&self) -> usize;

    /// Called when `device` was refused, by this and by the static list.
    fn refused(&self, device: &EndpointId) {
        let _ = device;
    }
}

/// Admits the devices of `relay.allowed_endpoints` and those an [`Admission`] admits, and
/// refuses every other one.
///
/// The relay handshake proves that a connecting device holds the secret key of the id it
/// claims before [`AccessControl::on_connect`] runs, so the id alone decides. The allowlist
/// also counts what it admitted and refused, for the admin UI.
#[derive(Debug)]
pub(crate) struct Allowlist {
    allowed: HashSet<EndpointId>,
    admission: Option<Arc<dyn Admission>>,
    /// Open connections that were admitted, with the device each belongs to. A device may hold
    /// several, for example while it reconnects.
    connected: Mutex<HashMap<ConnectionId, EndpointId>>,
    /// Connection attempts refused since the start.
    denied: AtomicU64,
}

impl Allowlist {
    /// Parses the device ids of `relay.allowed_endpoints` (64 hex digits each, any case), and
    /// admits the devices of `admission` as well.
    pub(crate) fn parse(
        ids: &[String],
        admission: Option<Arc<dyn Admission>>,
    ) -> anyhow::Result<Self> {
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
            admission,
            connected: Mutex::new(HashMap::new()),
            denied: AtomicU64::new(0),
        })
    }

    /// Number of allowed devices: the static list and the admission.
    pub(crate) fn len(&self) -> usize {
        self.allowed.len()
            + self
                .admission
                .as_ref()
                .map_or(0, |admission| admission.count())
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

    /// Whether `device` is admitted now: by the static list or by the admission.
    fn admits(&self, device: &EndpointId) -> bool {
        self.allowed.contains(device)
            || self
                .admission
                .as_ref()
                .is_some_and(|admission| admission.admits(device))
    }

    /// The devices with open connections that are no longer admitted.
    pub(crate) fn no_longer_admitted(&self) -> Vec<EndpointId> {
        let devices: HashSet<EndpointId> = self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .copied()
            .collect();
        devices
            .into_iter()
            .filter(|device| !self.admits(device))
            .collect()
    }
}

impl AccessControl for Allowlist {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let device = request.endpoint_id();
        if self.admits(&device) {
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
                "relay connection refused: the device is neither registered for remote access \
                 nor in relay.allowed_endpoints"
            );
            if let Some(admission) = &self.admission {
                admission.refused(&device);
            }
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
