//! The relay through which devices reach each other across the internet.
//!
//! Devices (Input Show today) connect to each other with iroh. When two devices cannot reach
//! each other directly, iroh sends their QUIC packets through a relay; the packets are
//! encrypted end to end between the devices, so the relay never sees their content. The relay
//! also tells devices the public address it sees them at (QUIC address discovery, QAD), which
//! they need to punch holes through NAT and connect directly. This crate runs that relay, the
//! protocol of [`iroh_relay::server`], as part of Gono Cloud, configured by the `[relay]` table:
//!
//! - **Plain HTTP behind the reverse proxy** on `relay.bind`, a loopback address. The proxy
//!   terminates TLS for the relay's own host name (`relay.public_url`) and forwards the relay's
//!   WebSocket (`/relay`) and its probes (`/ping`, `/generate_204`) to it. The listener is this
//!   crate's own (`listener.rs`), so that each device is read at the rate of its tier.
//! - **QAD on a public UDP socket**, `relay.qad_bind`, served by iroh-relay's server. QUIC
//!   needs a certificate of its own: the relay reads the certificate of its host name from
//!   `relay.tls_cert` and `relay.tls_key` and reads them again every
//!   `relay.tls_reload_interval_secs`, so that a renewal takes effect without a restart
//!   (`tls.rs`: a new pair is served only once the key belongs to the certificate).
//! - **Access control**: only the devices of `relay.allowed_endpoints` and those an
//!   [`Admission`] admits may connect (the allowlist in `access.rs`), each at a [`Tier`].
//!   `serve` passes the device directory, and disconnects a device through
//!   [`RelayStatus::disconnect`] once it may no longer use the relay.
//! - **A rate limit** per connection, by tier (`limit.rs`): `relay.limited_bytes_per_sec` for
//!   [`Tier::Limited`], `relay.max_client_bytes_per_sec` for [`Tier::Full`].
//!
//! The relay serves no metrics endpoint of its own; [`RelayStatus`] hands its counters to the
//! admin UI.

mod access;
mod limit;
mod listener;
mod tls;

pub use access::{Admission, Tier};

use std::{
    collections::HashSet,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use gono_server_core::config::RelayConfig;
use iroh_base::EndpointId;
use iroh_relay::server::{QuicConfig, RelayMetrics, Server, ServerConfig, clients::Clients};
use tokio::net::TcpListener;
use url::Url;

use self::{
    access::{Allowlist, Stale},
    limit::Limits,
    listener::{Listener, State},
    tls::{CertificateFiles, ReloadTask},
};

/// The running relay.
#[derive(Debug)]
pub struct Relay {
    listener: Listener,
    /// iroh-relay's server, running QAD only, when QAD is on.
    qad: Option<Server>,
    status: RelayStatus,
    /// Reads the certificate of QAD again; stops when the relay is dropped.
    _certificate_reloads: Option<ReloadTask>,
}

impl Relay {
    /// Starts the relay described by `config`, which must be valid
    /// ([`gono_server_core::Config::validate`]) and enabled. `admission` admits devices besides
    /// `relay.allowed_endpoints`.
    pub async fn spawn(
        config: &RelayConfig,
        admission: Option<Arc<dyn Admission>>,
    ) -> anyhow::Result<Self> {
        let public_url = config
            .public_url
            .clone()
            .context("relay.public_url is not set")?;
        let access = Arc::new(Allowlist::parse(&config.allowed_endpoints, admission)?);
        let limits = Limits::from_config(config)?;

        let start = || format!("start the relay on {}", config.bind);
        let http = TcpListener::bind(config.bind).await.with_context(start)?;
        let http_addr = http.local_addr().with_context(start)?;

        let (qad, certificate_reloads) = match config.qad_bind {
            Some(bind) => {
                let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) else {
                    bail!("relay.qad_bind needs relay.tls_cert and relay.tls_key");
                };
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let files = CertificateFiles::load(cert, key, provider.clone())
                    .map(Arc::new)
                    .with_context(|| {
                        format!(
                            "read the relay certificate {} and its key {}",
                            cert.display(),
                            key.display()
                        )
                    })?;
                let reloads =
                    files.spawn_reloads(Duration::from_secs(config.tls_reload_interval_secs));
                let mut quic = QuicConfig::new(bind);
                quic.server_config = Some(qad_tls_config(provider, files)?);
                let mut server_config = ServerConfig::default();
                server_config.quic = Some(quic);
                let server = Server::spawn(server_config)
                    .await
                    .with_context(|| format!("start QUIC address discovery on {bind}"))?;
                (Some(server), Some(reloads))
            }
            None => (None, None),
        };
        // One set of counters: the relay's connections count in QAD's metrics.
        let metrics = qad
            .as_ref()
            .map_or_else(RelayMetrics::default, |server| server.metrics().clone());

        let state = Arc::new(State::new(
            Arc::clone(&access),
            limits,
            Arc::clone(&metrics.server),
        ));
        let status = RelayStatus(Arc::new(Shared {
            metrics,
            clients: state.clients().clone(),
            access,
            public_url,
            http_addr,
            qad_addr: qad.as_ref().and_then(Server::quic_addr),
            tls_cert: config.qad_bind.and(config.tls_cert.clone()),
            tls_reload_interval_secs: config.tls_reload_interval_secs,
            client_rate_limit: config.max_client_bytes_per_sec,
            running: AtomicBool::new(true),
        }));
        let listener = Listener::spawn(http, state);
        tracing::info!(
            public_url = %status.0.public_url,
            address = %status.0.http_addr,
            qad = ?status.0.qad_addr,
            devices = status.0.access.len(),
            "relay listening"
        );
        Ok(Self {
            listener,
            qad,
            status,
            _certificate_reloads: certificate_reloads,
        })
    }

    /// A handle on the relay's settings and counters.
    pub fn status(&self) -> RelayStatus {
        self.status.clone()
    }

    /// Serves until `stop` resolves, then shuts the relay down. Returns an error when the
    /// relay stops on its own first, which only happens when it fails.
    pub async fn run_until(self, stop: impl Future<Output = ()>) -> anyhow::Result<()> {
        let status = self.status.clone();
        let result = self.serve_until(stop).await;
        status.0.running.store(false, Ordering::Relaxed);
        result
    }

    async fn serve_until(mut self, stop: impl Future<Output = ()>) -> anyhow::Result<()> {
        let failed = {
            let (listener, qad) = (&mut self.listener, &mut self.qad);
            let listener = listener.stopped();
            let qad = async move {
                match qad {
                    Some(server) => server.join().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                result = listener => Some(match result {
                    Ok(()) => Err(anyhow!("the relay stopped unexpectedly")),
                    Err(err) => Err(err).context("the relay task failed"),
                }),
                result = qad => Some(match result {
                    Ok(Ok(())) => Err(anyhow!("QUIC address discovery stopped unexpectedly")),
                    Ok(Err(err)) => {
                        Err(anyhow!("{err}")).context("QUIC address discovery failed")
                    }
                    Err(err) => Err(err).context("the QUIC address discovery task failed"),
                }),
                () = stop => None,
            }
        };
        // Whatever stopped, the rest goes too, and the devices are disconnected, as iroh-relay's
        // server does when one of its parts fails.
        let closed = self.listener.shutdown().await;
        let qad_stopped = match self.qad {
            // After a failure the server is dropped instead, which aborts it: one that failed
            // has ended, and must not be awaited again.
            Some(server) if failed.is_none() => server
                .shutdown()
                .await
                .map_err(|err| anyhow!("{err}"))
                .context("stop QUIC address discovery"),
            _ => Ok(()),
        };
        if let Some(failure) = failed {
            return failure;
        }
        closed.context("stop the relay")?;
        qad_stopped?;
        tracing::info!("relay stopped");
        Ok(())
    }
}

/// The relay's settings and live counters, for the admin UI. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RelayStatus(Arc<Shared>);

#[derive(Debug)]
struct Shared {
    metrics: RelayMetrics,
    /// The registry of connected devices, through which they are disconnected.
    clients: Clients,
    access: Arc<Allowlist>,
    public_url: Url,
    http_addr: SocketAddr,
    qad_addr: Option<SocketAddr>,
    /// The certificate QAD serves, when QAD is on.
    tls_cert: Option<PathBuf>,
    tls_reload_interval_secs: u64,
    client_rate_limit: Option<u32>,
    /// Cleared when [`Relay::run_until`] returns, whether the relay was stopped or failed.
    running: AtomicBool,
}

impl RelayStatus {
    /// Whether the relay is serving. It stops at shutdown, or on its own when it fails.
    pub fn is_running(&self) -> bool {
        self.0.running.load(Ordering::Relaxed)
    }

    /// `relay.public_url`.
    pub fn public_url(&self) -> &Url {
        &self.0.public_url
    }

    /// Address of the plain-HTTP listener.
    pub fn http_addr(&self) -> SocketAddr {
        self.0.http_addr
    }

    /// Address of the QAD socket, when QAD is on.
    pub fn qad_addr(&self) -> Option<SocketAddr> {
        self.0.qad_addr
    }

    /// Number of allowed devices: `relay.allowed_endpoints` and the admission.
    pub fn allowed_devices(&self) -> usize {
        self.0.access.len()
    }

    /// Number of devices in `relay.allowed_endpoints`.
    pub fn listed_devices(&self) -> usize {
        self.0.access.listed()
    }

    /// Whether `device` is in `relay.allowed_endpoints`.
    pub fn is_listed(&self, device: &EndpointId) -> bool {
        self.0.access.is_listed(device)
    }

    /// The devices with open connections right now, each with its number of connections,
    /// ordered by device.
    pub fn connected_devices(&self) -> Vec<(EndpointId, usize)> {
        self.0.access.connected_devices()
    }

    /// The certificate file QAD serves, when QAD is on (`relay.tls_cert`).
    pub fn tls_cert(&self) -> Option<&Path> {
        self.0.tls_cert.as_deref()
    }

    /// How often QAD reads its certificate again, in seconds.
    pub fn tls_reload_interval_secs(&self) -> u64 {
        self.0.tls_reload_interval_secs
    }

    /// Disconnects every connection of `device` at once. Returns `false` if it had none. A
    /// device that the allowlist no longer admits cannot connect again.
    pub fn disconnect(&self, device: &EndpointId) -> bool {
        let disconnected = self.0.clients.disconnect(*device, None);
        if disconnected {
            tracing::info!(device = %device.fmt_short(), "relay connections closed");
        }
        disconnected
    }

    /// Disconnects every connection whose device the allowlist no longer admits, or admits at
    /// another tier than the connection was admitted at, so that the device comes back at its
    /// new rate. Returns how many devices lost connections.
    ///
    /// [`RelayStatus::disconnect`] cannot reach a connection that was admitted but is not yet
    /// registered with the relay, and a caller may miss a change of the admission; sweeping
    /// regularly ends such connections too.
    pub fn sweep(&self) -> usize {
        let mut devices = HashSet::new();
        for Stale {
            device,
            connection,
            was,
            now,
        } in self.0.access.stale()
        {
            if self.0.clients.disconnect(device, Some(connection)) {
                match now {
                    None => tracing::info!(
                        device = %device.fmt_short(),
                        "relay connection closed: the device is no longer admitted"
                    ),
                    Some(now) => tracing::info!(
                        device = %device.fmt_short(),
                        ?was,
                        ?now,
                        "relay connection closed, to come back at the device's new tier"
                    ),
                }
            }
            devices.insert(device);
        }
        devices.len()
    }

    /// `relay.max_client_bytes_per_sec`, the rate limit of [`Tier::Full`].
    pub fn client_rate_limit(&self) -> Option<u32> {
        self.0.client_rate_limit
    }

    /// The counters right now.
    pub fn snapshot(&self) -> RelaySnapshot {
        let metrics = &self.0.metrics.server;
        let (connections, devices) = self.0.access.connected();
        RelaySnapshot {
            connections,
            devices,
            denied: self.0.access.denied(),
            bytes_received: metrics.bytes_recv.get(),
            bytes_sent: metrics.bytes_sent.get(),
            packets_dropped: metrics.send_packets_dropped.get(),
            bytes_rate_limited: metrics.bytes_rx_ratelimited_total.get(),
            qad_connections: metrics.qad_connections.get(),
        }
    }
}

/// The relay's counters at one moment. Totals count since the start of the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaySnapshot {
    /// Open device connections.
    pub connections: usize,
    /// Distinct devices holding them.
    pub devices: usize,
    /// Connection attempts refused because the device is not allowed.
    pub denied: u64,
    /// Bytes of packets received from devices.
    pub bytes_received: u64,
    /// Bytes of packets delivered to devices.
    pub bytes_sent: u64,
    /// Packets that could not be delivered, mostly because the receiver was not connected.
    pub packets_dropped: u64,
    /// Bytes of frames that a device sent faster than its tier's rate limit allows
    /// (`relay.limited_bytes_per_sec` or `relay.max_client_bytes_per_sec`); the relay read on
    /// only once the device was back within it.
    pub bytes_rate_limited: u64,
    /// QAD connections accepted.
    pub qad_connections: u64,
}

/// The TLS configuration of the QAD socket: TLS 1.3 (QUIC needs it) with the certificate that
/// `files` serves.
fn qad_tls_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    files: Arc<CertificateFiles>,
) -> anyhow::Result<rustls::ServerConfig> {
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configure TLS 1.3 for QUIC address discovery")?
        .with_no_client_auth()
        .with_cert_resolver(files);
    Ok(config)
}
