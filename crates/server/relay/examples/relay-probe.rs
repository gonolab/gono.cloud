//! Probes a running relay the way devices use it, for the install test and the load numbers of
//! the iroh plan (V6).
//!
//! ```text
//! relay-probe qad ADDR SERVER_NAME CA_PEM   QUIC address discovery on ADDR (UDP), trusting only
//!                                           the certificates of CA_PEM; prints the address the
//!                                           relay saw and the SHA-256 of the certificate it
//!                                           served
//! relay-probe ids N                         device ids 0..N, as items of relay.allowed_endpoints
//! relay-probe pair URL                      device 0 sends a datagram to device 1 through URL
//! relay-probe idle URL N SECS               connects devices 0..N and holds them for SECS
//!                                           seconds, answering the relay's pings
//! relay-probe blast URL SECS [MBIT]         device 0 sends batches of ten 1200-byte datagrams
//!                                           to device 1 for SECS seconds, as fast as it can or
//!                                           at MBIT Mbit/s
//! ```
//!
//! URL is the relay's URL, `http://` for its listener and `https://` through the reverse proxy.
//! `PROBE_CA` names a PEM file of extra roots to trust for `https://` URLs. Host names are
//! resolved by the system (`getaddrinfo`), so `/etc/hosts` entries apply. The devices' keys are
//! derived from their numbers, so `ids` lists the devices the other modes connect.

use std::{
    env,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    pin::Pin,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
use iroh_relay::{
    client::{Client, ClientBuilder},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    quic::QuicClient,
    tls::{CaTlsConfig, default_provider},
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use sha2::{Digest as _, Sha256};

/// How long one connection or handshake may take.
const TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str = "usage: relay-probe qad ADDR SERVER_NAME CA_PEM | ids N | pair URL | \
                     idle URL N SECS | blast URL SECS [MBIT]";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["qad", addr, server_name, ca] => qad(addr, server_name, ca).await,
        ["ids", n] => ids(n),
        ["pair", url] => pair(url).await,
        ["idle", url, n, secs] => idle(url, n, secs).await,
        ["blast", url, secs] => blast(url, secs, None).await,
        ["blast", url, secs, mbit] => blast(url, secs, Some(mbit)).await,
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("relay-probe: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The key of device `i`.
fn key(i: u32) -> SecretKey {
    let mut bytes = [7u8; 32];
    bytes[..4].copy_from_slice(&i.to_le_bytes());
    SecretKey::from_bytes(&bytes)
}

fn parse<T: std::str::FromStr>(what: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {what}: {value}"))
}

/// The certificates of the PEM file at `path`.
fn read_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = std::fs::read(path).map_err(|err| format!("read {path}: {err}"))?;
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse {path}: {err}"))?;
    if certificates.is_empty() {
        return Err(format!("{path} holds no certificate"));
    }
    Ok(certificates)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------
// QUIC address discovery
// ---------------------------------------------------------------------------------------------

async fn qad(addr: &str, server_name: &str, ca: &str) -> Result<(), String> {
    let addr: SocketAddr = parse("address", addr)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in read_certificates(ca)? {
        roots
            .add(certificate)
            .map_err(|err| format!("trust {ca}: {err}"))?;
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|err| err.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let local: IpAddr = match addr {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let endpoint = noq::Endpoint::client(SocketAddr::new(local, 0))
        .map_err(|err| format!("bind a UDP socket: {err}"))?;

    let connection = tokio::time::timeout(
        TIMEOUT,
        QuicClient::new(endpoint.clone(), tls).create_conn(addr, server_name),
    )
    .await
    .map_err(|_| format!("no QAD handshake with {addr} within {TIMEOUT:?}"))?
    .map_err(|err| format!("QAD handshake with {addr}: {err}"))?;
    let observed = tokio::time::timeout(TIMEOUT, connection.observed_external_addr().next())
        .await
        .map_err(|_| format!("{addr} reported no address within {TIMEOUT:?}"))?
        .ok_or_else(|| format!("{addr} closed the connection before reporting an address"))?;
    let served = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|chain| chain.first().cloned())
        .ok_or_else(|| format!("{addr} served no certificate"))?;
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    println!(
        "observed {}",
        SocketAddr::new(observed.ip().to_canonical(), observed.port())
    );
    println!("certificate {}", hex(&Sha256::digest(&served)));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Relay clients
// ---------------------------------------------------------------------------------------------

/// Resolves host names with the system's resolver, so that `/etc/hosts` applies.
#[derive(Debug, Clone, Copy)]
struct SystemResolver;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl SystemResolver {
    /// The addresses of `host`, none when it does not resolve: the connection then fails.
    async fn lookup(host: String) -> Vec<IpAddr> {
        match tokio::net::lookup_host((host.as_str(), 0)).await {
            Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl Resolver for SystemResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(async move {
            let addrs = Self::lookup(host)
                .await
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                });
            Ok(Box::new(addrs) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async move {
            let addrs = Self::lookup(host)
                .await
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(ip) => Some(ip),
                    IpAddr::V4(_) => None,
                });
            Ok(Box::new(addrs) as BoxIter<Ipv6Addr>)
        })
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<TxtRecordData>) })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(Self)
    }
}

/// Connects device `i` to the relay at `url`.
async fn connect(url: &RelayUrl, i: u32) -> Result<Client, String> {
    let mut ca = CaTlsConfig::default();
    if let Ok(path) = env::var("PROBE_CA") {
        ca = ca.with_extra_roots(read_certificates(&path)?);
    }
    let tls = ca
        .client_config(default_provider())
        .map_err(|err| err.to_string())?;
    let builder = ClientBuilder::new(url.clone(), key(i), DnsResolver::custom(SystemResolver))
        .tls_client_config(tls);
    tokio::time::timeout(TIMEOUT, builder.connect())
        .await
        .map_err(|_| format!("device {i}: no connection to {url} within {TIMEOUT:?}"))?
        .map_err(|err| format!("device {i}: connect to {url}: {err}"))
}

/// Keeps `client` connected in the background: answers the relay's pings and adds the bytes
/// of the datagrams it receives to `received`.
fn serve(client: Client, received: Arc<AtomicU64>) {
    let (mut stream, mut sink) = client.split();
    tokio::spawn(async move {
        while let Some(Ok(message)) = stream.next().await {
            match message {
                RelayToClientMsg::Ping(payload) => {
                    if sink.send(ClientToRelayMsg::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                RelayToClientMsg::Datagrams { datagrams, .. } => {
                    received.fetch_add(datagrams.contents.len() as u64, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    });
}

fn ids(n: &str) -> Result<(), String> {
    let n: u32 = parse("count", n)?;
    for i in 0..n {
        println!("  \"{}\",", key(i).public());
    }
    Ok(())
}

async fn pair(url: &str) -> Result<(), String> {
    const MESSAGE: &[u8] = b"through the relay";
    let url: RelayUrl = parse("relay URL", url)?;
    let mut sender = connect(&url, 0).await?;
    let receiver = connect(&url, 1).await?;
    let received = Arc::new(AtomicU64::new(0));
    serve(receiver, received.clone());
    sender
        .send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: key(1).public(),
            datagrams: Datagrams::from(MESSAGE),
        })
        .await
        .map_err(|err| format!("send: {err}"))?;
    let deadline = Instant::now() + TIMEOUT;
    while received.load(Ordering::Relaxed) < MESSAGE.len() as u64 {
        if Instant::now() > deadline {
            return Err(format!("nothing arrived through {url}"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("relayed {} bytes through {url}", MESSAGE.len());
    Ok(())
}

async fn idle(url: &str, n: &str, secs: &str) -> Result<(), String> {
    let url: RelayUrl = parse("relay URL", url)?;
    let n: u32 = parse("count", n)?;
    let secs: u64 = parse("seconds", secs)?;
    let start = Instant::now();
    let received = Arc::new(AtomicU64::new(0));
    let devices: Vec<u32> = (0..n).collect();
    for batch in devices.chunks(50) {
        let clients = futures_util::future::join_all(batch.iter().map(|&i| connect(&url, i))).await;
        for client in clients {
            serve(client?, received.clone());
        }
    }
    println!("connected {n} devices in {:?}", start.elapsed());
    tokio::time::sleep(Duration::from_secs(secs)).await;
    println!("done");
    Ok(())
}

async fn blast(url: &str, secs: &str, mbit: Option<&str>) -> Result<(), String> {
    let url: RelayUrl = parse("relay URL", url)?;
    let secs: u64 = parse("seconds", secs)?;
    let bytes_per_sec = mbit
        .map(|mbit| parse::<f64>("rate", mbit).map(|mbit| mbit * 1e6 / 8.0))
        .transpose()?;
    let sender = connect(&url, 0).await?;
    let receiver = connect(&url, 1).await?;
    let received = Arc::new(AtomicU64::new(0));
    serve(receiver, received.clone());
    let (mut stream, mut sink) = sender.split();
    tokio::spawn(async move { while let Some(Ok(_)) = stream.next().await {} });

    let batch = Bytes::from(vec![0xa5u8; 1200 * 10]);
    let destination = key(1).public();
    let start = Instant::now();
    let mut sent = 0u64;
    while start.elapsed() < Duration::from_secs(secs) {
        if let Some(rate) = bytes_per_sec {
            // Paced: wait until the rate allows the next batch.
            let due = Duration::from_secs_f64(sent as f64 / rate);
            if let Some(wait) = due.checked_sub(start.elapsed()) {
                tokio::time::sleep(wait).await;
            }
        }
        sink.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: destination,
            datagrams: Datagrams {
                ecn: None,
                segment_size: NonZeroU16::new(1200),
                contents: batch.clone(),
            },
        })
        .await
        .map_err(|err| format!("send: {err}"))?;
        sent += batch.len() as u64;
    }
    let elapsed = start.elapsed();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let got = received.load(Ordering::Relaxed);
    let mbps = |bytes: u64| bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1e6;
    println!(
        "sent {sent} B ({:.0} Mbit/s), received {got} B ({:.0} Mbit/s) in {elapsed:?}",
        mbps(sent),
        mbps(got)
    );
    Ok(())
}
