//! The relay through which devices reach each other across the internet.
//!
//! Devices (Input Show today) connect to each other with iroh. When two devices cannot reach
//! each other directly, iroh sends their QUIC packets through a relay; the packets are
//! encrypted end to end between the devices, so the relay never sees their content. The relay
//! also tells devices the public address it sees them at (QUIC address discovery, QAD), which
//! they need to punch holes through NAT and connect directly. This crate runs that relay,
//! [`iroh_relay::server`], as part of Gono Cloud, configured by the `[relay]` table:
//!
//! - **Plain HTTP behind the reverse proxy** on `relay.bind`, a loopback address. The proxy
//!   terminates TLS for the relay's own host name (`relay.public_url`) and forwards the relay's
//!   WebSocket (`/relay`) and its probes (`/ping`, `/generate_204`) to it.
//! - **QAD on a public UDP socket**, `relay.qad_bind`. QUIC needs a certificate of its own: the
//!   relay reads the certificate of its host name from `relay.tls_cert` and `relay.tls_key`
//!   and reads them again every `relay.tls_reload_interval_secs`, so that a renewal takes
//!   effect without a restart.
//! - **Access control**: only the devices of `relay.allowed_endpoints` may connect (the
//!   allowlist in `access.rs`).
//! - **A rate limit** per connection, `relay.max_client_bytes_per_sec`.
//!
//! The relay serves no metrics endpoint of its own; [`RelayStatus`] hands its counters to the
//! admin UI.

mod access;

use std::{
    future::Future,
    net::SocketAddr,
    num::NonZeroU32,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use gono_server_core::config::RelayConfig;
use iroh_relay::server::{
    ClientRateLimit, QuicConfig, RelayMetrics, Server, ServerConfig, reloading_resolver,
};
use url::Url;

use self::access::Allowlist;

/// The running relay.
#[derive(Debug)]
pub struct Relay {
    server: Server,
    status: RelayStatus,
}

impl Relay {
    /// Starts the relay described by `config`, which must be valid
    /// ([`gono_server_core::Config::validate`]) and enabled.
    pub async fn spawn(config: &RelayConfig) -> anyhow::Result<Self> {
        let public_url = config
            .public_url
            .clone()
            .context("relay.public_url is not set")?;
        let access = Arc::new(Allowlist::parse(&config.allowed_endpoints)?);

        let mut relay = iroh_relay::server::RelayConfig::new(config.bind);
        relay.access = access.clone();
        relay.limits.client_rx = client_rate_limit(config);

        let quic = match config.qad_bind {
            Some(bind) => {
                let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) else {
                    bail!("relay.qad_bind needs relay.tls_cert and relay.tls_key");
                };
                let interval = Duration::from_secs(config.tls_reload_interval_secs);
                let mut quic = QuicConfig::new(bind);
                quic.server_config = Some(qad_tls_config(cert, key, interval).await?);
                Some(quic)
            }
            None => None,
        };

        let mut server_config = ServerConfig::default();
        server_config.relay = Some(relay);
        server_config.quic = quic;
        let server = Server::spawn(server_config)
            .await
            .with_context(|| format!("start the relay on {}", config.bind))?;

        let status = RelayStatus(Arc::new(Shared {
            metrics: server.metrics().clone(),
            access,
            public_url,
            http_addr: server.http_addr().unwrap_or(config.bind),
            qad_addr: server.quic_addr(),
            client_rate_limit: config.max_client_bytes_per_sec,
            running: AtomicBool::new(true),
        }));
        tracing::info!(
            public_url = %status.0.public_url,
            address = %status.0.http_addr,
            qad = ?status.0.qad_addr,
            devices = status.0.access.len(),
            "relay listening"
        );
        Ok(Self { server, status })
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
            let joined = self.server.join();
            tokio::pin!(joined);
            tokio::select! {
                result = &mut joined => Some(result),
                () = stop => None,
            }
        };
        match failed {
            None => {
                self.server
                    .shutdown()
                    .await
                    .map_err(|err| anyhow!("{err}"))
                    .context("stop the relay")?;
                tracing::info!("relay stopped");
                Ok(())
            }
            Some(Ok(Ok(()))) => bail!("the relay stopped unexpectedly"),
            Some(Ok(Err(err))) => Err(anyhow!("{err}")).context("the relay failed"),
            Some(Err(err)) => Err(err).context("the relay task failed"),
        }
    }
}

/// The relay's settings and live counters, for the admin UI. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RelayStatus(Arc<Shared>);

#[derive(Debug)]
struct Shared {
    metrics: RelayMetrics,
    access: Arc<Allowlist>,
    public_url: Url,
    http_addr: SocketAddr,
    qad_addr: Option<SocketAddr>,
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

    /// Number of allowed devices.
    pub fn allowed_devices(&self) -> usize {
        self.0.access.len()
    }

    /// `relay.max_client_bytes_per_sec`.
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
    /// Bytes held back by `relay.max_client_bytes_per_sec`.
    pub bytes_rate_limited: u64,
    /// QAD connections accepted.
    pub qad_connections: u64,
}

/// The per-connection rate limit of `relay.max_client_bytes_per_sec`.
fn client_rate_limit(config: &RelayConfig) -> Option<ClientRateLimit> {
    let bytes_per_second = NonZeroU32::new(config.max_client_bytes_per_sec?)?;
    let mut limit = ClientRateLimit::new(bytes_per_second);
    limit.max_burst_bytes = config.max_client_burst_bytes.and_then(NonZeroU32::new);
    Some(limit)
}

/// The TLS configuration of the QAD socket: TLS 1.3 (QUIC needs it) with the certificate in
/// `cert` and `key`, read again every `interval`.
async fn qad_tls_config(
    cert: &Path,
    key: &Path,
    interval: Duration,
) -> anyhow::Result<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let resolver = reloading_resolver(&provider, cert.to_path_buf(), key.to_path_buf(), interval)
        .await
        .map_err(|err| anyhow!("{err}"))
        .with_context(|| {
            format!(
                "read the relay certificate {} and its key {}",
                cert.display(),
                key.display()
            )
        })?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configure TLS 1.3 for QUIC address discovery")?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(config)
}
