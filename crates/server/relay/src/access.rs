//! Which devices may use the relay, and how much of it.

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

/// How much of the relay an admitted device may use. It decides the rate at which the relay
/// reads from each of the device's connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Direct connections only: enough relaying for the handshakes and the hole-punching
    /// coordination that set up a direct connection, at `relay.limited_bytes_per_sec`.
    Limited,
    /// Full-rate relaying, at `relay.max_client_bytes_per_sec`. The devices of
    /// `relay.allowed_endpoints` have it.
    Full,
}

/// Devices admitted besides `relay.allowed_endpoints`: the device directory of Gono Cloud
/// (`docs/connect-protocol.md`, section 11.1).
pub trait Admission: Debug + Send + Sync + 'static {
    /// The tier at which `device` may use the relay now, or `None` if it may not. Called for
    /// every connection, so it must answer from memory.
    fn tier(&self, device: &EndpointId) -> Option<Tier>;

    /// How many devices it admits, for the admin UI.
    fn count(&self) -> usize;

    /// Called when `device` was refused, by this and by the static list.
    fn refused(&self, device: &EndpointId) {
        let _ = device;
    }
}

/// Admits the devices of `relay.allowed_endpoints` at [`Tier::Full`] and those an [`Admission`]
/// admits at the tier it gives, and refuses every other one.
///
/// The relay handshake proves that a connecting device holds the secret key of the id it
/// claims before [`Allowlist::admit`] runs, so the id alone decides. The allowlist also keeps
/// the open connections it admitted with their tiers, so that a sweep finds those whose device
/// lost its admission or changed its tier, and counts what it admitted and refused, for the
/// admin UI.
#[derive(Debug)]
pub(crate) struct Allowlist {
    allowed: HashSet<EndpointId>,
    admission: Option<Arc<dyn Admission>>,
    /// Open connections that were admitted, with the device each belongs to and the tier it was
    /// admitted at. A device may hold several, for example while it reconnects.
    connected: Mutex<HashMap<ConnectionId, Admitted>>,
    /// Connection attempts refused since the start.
    denied: AtomicU64,
}

/// An open connection that the allowlist admitted.
#[derive(Debug, Clone, Copy)]
struct Admitted {
    device: EndpointId,
    tier: Tier,
}

/// An open connection that its device may no longer hold as it is: the device is no longer
/// admitted, or at another tier than the connection was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stale {
    pub(crate) device: EndpointId,
    pub(crate) connection: ConnectionId,
    /// The tier the connection was admitted at.
    pub(crate) was: Tier,
    /// The device's tier now, if it is still admitted.
    pub(crate) now: Option<Tier>,
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

    /// Number of devices in `relay.allowed_endpoints`.
    pub(crate) fn listed(&self) -> usize {
        self.allowed.len()
    }

    /// Whether `device` is in `relay.allowed_endpoints`.
    pub(crate) fn is_listed(&self, device: &EndpointId) -> bool {
        self.allowed.contains(device)
    }

    /// The devices holding open connections, with how many each, ordered by device.
    pub(crate) fn connected_devices(&self) -> Vec<(EndpointId, usize)> {
        let mut counts: HashMap<EndpointId, usize> = HashMap::new();
        for admitted in self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            *counts.entry(admitted.device).or_default() += 1;
        }
        let mut devices: Vec<(EndpointId, usize)> = counts.into_iter().collect();
        devices.sort_unstable_by_key(|(device, _)| *device.as_bytes());
        devices
    }

    /// Open connections and the number of distinct devices holding them.
    pub(crate) fn connected(&self) -> (usize, usize) {
        let connected = self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let devices = connected
            .values()
            .map(|admitted| admitted.device)
            .collect::<HashSet<_>>()
            .len();
        (connected.len(), devices)
    }

    /// Connection attempts refused since the start.
    pub(crate) fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    /// The tier `device` has now: [`Tier::Full`] for the static list, else what the admission
    /// says.
    fn tier(&self, device: &EndpointId) -> Option<Tier> {
        if self.allowed.contains(device) {
            return Some(Tier::Full);
        }
        self.admission
            .as_ref()
            .and_then(|admission| admission.tier(device))
    }

    /// Decides whether the connection of `request` is admitted, and at which tier.
    ///
    /// An admitted connection is kept until [`AccessControl::on_disconnect`] reports its end,
    /// so the caller must hand it an [`iroh_relay::server::OnDisconnectGuard`] made from this
    /// allowlist and `request`. A refused one is counted, logged and reported to the admission.
    pub(crate) fn admit(&self, request: &ClientRequest) -> Option<Tier> {
        let device = request.endpoint_id();
        match self.tier(&device) {
            Some(tier) => {
                self.connected
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(request.connection_id(), Admitted { device, tier });
                tracing::debug!(device = %device.fmt_short(), ?tier, "relay connection admitted");
                Some(tier)
            }
            None => {
                self.denied.fetch_add(1, Ordering::Relaxed);
                // The full id, so that an operator setting up a device can allow it.
                tracing::info!(
                    %device,
                    "relay connection refused: the device is neither registered for remote \
                     access nor in relay.allowed_endpoints"
                );
                if let Some(admission) = &self.admission {
                    admission.refused(&device);
                }
                None
            }
        }
    }

    /// The open connections whose device is no longer admitted, or admitted at another tier
    /// than the connection was.
    pub(crate) fn stale(&self) -> Vec<Stale> {
        let connected: Vec<(ConnectionId, Admitted)> = self
            .connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(connection, admitted)| (*connection, *admitted))
            .collect();
        // Ask the admission outside the lock, once per device.
        let mut tiers: HashMap<EndpointId, Option<Tier>> = HashMap::new();
        connected
            .into_iter()
            .filter_map(|(connection, admitted)| {
                let now = *tiers
                    .entry(admitted.device)
                    .or_insert_with(|| self.tier(&admitted.device));
                (now != Some(admitted.tier)).then_some(Stale {
                    device: admitted.device,
                    connection,
                    was: admitted.tier,
                    now,
                })
            })
            .collect()
    }
}

/// The relay asks [`Allowlist::admit`] itself, since it needs the tier; `on_connect` gives the
/// same decision for anything that only needs a yes or no. `on_disconnect` is how an admitted
/// connection leaves the allowlist: its [`iroh_relay::server::OnDisconnectGuard`] calls it when
/// the connection ends.
impl AccessControl for Allowlist {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        match self.admit(request) {
            Some(_) => Access::Allow,
            // No reason: the client learns that it was refused, nothing about the list.
            None => Access::Deny { reason: None },
        }
    }

    fn on_disconnect(&self, _device: EndpointId, connection_id: ConnectionId) {
        self.connected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&connection_id);
    }
}
