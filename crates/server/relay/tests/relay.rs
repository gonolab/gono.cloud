//! The relay as devices see it: iroh relay clients and a QUIC address discovery client talk to
//! a relay started from a `[relay]` table.

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use futures_util::{SinkExt as _, StreamExt as _};
use gono_server_core::config::RelayConfig;
use gono_server_relay::{Relay, RelaySnapshot};
use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    quic::QuicClient,
    tls::{CaTlsConfig, default_provider},
};

const TIMEOUT: Duration = Duration::from_secs(10);

/// A device key derived from `seed`.
fn device(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A `[relay]` table on a free loopback port that allows `allowed`.
fn relay_config(allowed: &[&SecretKey]) -> RelayConfig {
    RelayConfig {
        enabled: true,
        public_url: Some("https://relay.example.com".parse().unwrap()),
        bind: "127.0.0.1:0".parse().unwrap(),
        allowed_endpoints: allowed.iter().map(|key| key.public().to_string()).collect(),
        ..RelayConfig::default()
    }
}

/// Connects `key`'s device to the relay at `addr` over plain HTTP, as the reverse proxy does.
async fn connect(addr: SocketAddr, key: &SecretKey) -> Result<Client, ConnectError> {
    let url: RelayUrl = format!("http://{addr}").parse().unwrap();
    let tls = CaTlsConfig::default()
        .client_config(default_provider())
        .unwrap();
    ClientBuilder::new(url, key.clone(), DnsResolver::new())
        .tls_client_config(tls)
        .connect()
        .await
}

/// Waits for the next datagrams on `client`, answering the relay's pings meanwhile.
async fn receive(client: &mut Client) -> (EndpointId, Vec<u8>) {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match client.next().await.expect("connection open").unwrap() {
                RelayToClientMsg::Datagrams {
                    remote_endpoint_id,
                    datagrams,
                } => return (remote_endpoint_id, datagrams.contents.to_vec()),
                RelayToClientMsg::Ping(payload) => {
                    client.send(ClientToRelayMsg::Pong(payload)).await.unwrap();
                }
                _ => {}
            }
        }
    })
    .await
    .expect("datagrams within the timeout")
}

/// Polls `relay`'s counters until `done` holds.
async fn wait_for(relay: &gono_server_relay::RelayStatus, done: impl Fn(&RelaySnapshot) -> bool) {
    tokio::time::timeout(TIMEOUT, async {
        while !done(&relay.snapshot()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("counters stuck at {:?}", relay.snapshot()));
}

#[tokio::test]
async fn allowed_devices_reach_each_other_and_others_are_refused() {
    let (alice, bob, mallory) = (device(1), device(2), device(3));
    let relay = Relay::spawn(&relay_config(&[&alice, &bob])).await.unwrap();
    let status = relay.status();
    assert_eq!(status.allowed_devices(), 2);
    assert_eq!(status.qad_addr(), None);
    let addr = status.http_addr();

    let mut from = connect(addr, &alice).await.unwrap();
    let mut to = connect(addr, &bob).await.unwrap();
    from.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: bob.public(),
        datagrams: Datagrams::from(b"through the relay"),
    })
    .await
    .unwrap();
    assert_eq!(
        receive(&mut to).await,
        (alice.public(), b"through the relay".to_vec())
    );

    let refused = connect(addr, &mallory).await;
    assert!(
        refused.is_err(),
        "a device outside the list must be refused"
    );

    let snapshot = status.snapshot();
    assert_eq!((snapshot.connections, snapshot.devices), (2, 2));
    assert_eq!(snapshot.denied, 1);
    assert!(snapshot.bytes_received >= 17, "{snapshot:?}");
    assert!(snapshot.bytes_sent >= 17, "{snapshot:?}");

    // A closed connection leaves the count.
    drop(from);
    wait_for(&status, |snapshot| snapshot.connections == 1).await;
}

#[tokio::test]
async fn device_ids_are_accepted_in_either_case() {
    let alice = device(4);
    let mut config = relay_config(&[]);
    config.allowed_endpoints = vec![alice.public().to_string().to_ascii_uppercase()];
    let relay = Relay::spawn(&config).await.unwrap();
    connect(relay.status().http_addr(), &alice).await.unwrap();
}

#[tokio::test]
async fn invalid_device_ids_stop_the_start() {
    let mut config = relay_config(&[]);
    // 64 hex digits that are not an Ed25519 public key: no point on the curve has them.
    config.allowed_endpoints = vec!["02".repeat(32)];
    let err = Relay::spawn(&config).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("relay.allowed_endpoints"),
        "{err:#}"
    );
}

#[tokio::test]
async fn run_until_shuts_the_relay_down() {
    let alice = device(5);
    let relay = Relay::spawn(&relay_config(&[&alice])).await.unwrap();
    let status = relay.status();
    connect(status.http_addr(), &alice).await.unwrap();
    assert!(status.is_running());

    tokio::time::timeout(TIMEOUT, relay.run_until(async {}))
        .await
        .expect("shutdown within the timeout")
        .unwrap();
    assert!(!status.is_running());
    assert!(connect(status.http_addr(), &alice).await.is_err());
}

/// Writes a self-signed certificate for `localhost` into `dir`.
fn write_certificate(dir: &Path) -> (rustls::pki_types::CertificateDer<'static>, RelayConfig) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = dir.join("fullchain.pem");
    let key = dir.join("privkey.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    let config = RelayConfig {
        qad_bind: Some("127.0.0.1:0".parse().unwrap()),
        tls_cert: Some(cert),
        tls_key: Some(key),
        ..relay_config(&[])
    };
    (certified.cert.der().clone(), config)
}

/// Opens a QAD connection to `qad` that trusts only `certificate`, and returns it with the
/// client's own address.
async fn qad_handshake(
    qad: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
) -> Result<(noq::Connection, SocketAddr), String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let endpoint = noq::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let local = endpoint.local_addr().unwrap();
    let connection = tokio::time::timeout(
        TIMEOUT,
        QuicClient::new(endpoint, tls).create_conn(qad, "localhost"),
    )
    .await
    .map_err(|_| "no handshake within the timeout".to_owned())?
    .map_err(|err| err.to_string())?;
    Ok((connection, local))
}

#[tokio::test]
async fn quic_address_discovery_reports_the_address_it_sees() {
    let dir = tempfile::tempdir().unwrap();
    let (certificate, config) = write_certificate(dir.path());
    let relay = Relay::spawn(&config).await.unwrap();
    let status = relay.status();
    let qad = status.qad_addr().expect("QAD is on");

    let (connection, local) = qad_handshake(qad, certificate).await.unwrap();
    let observed = tokio::time::timeout(TIMEOUT, connection.observed_external_addr().next())
        .await
        .expect("an address within the timeout")
        .expect("an observed address");
    assert_eq!(
        SocketAddr::new(observed.ip().to_canonical(), observed.port()),
        local
    );
    wait_for(&status, |snapshot| snapshot.qad_connections == 1).await;
}

#[tokio::test]
async fn quic_address_discovery_picks_up_a_renewed_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let (old, mut config) = write_certificate(dir.path());
    config.tls_reload_interval_secs = 1;
    let relay = Relay::spawn(&config).await.unwrap();
    let qad = relay.status().qad_addr().expect("QAD is on");
    qad_handshake(qad, old.clone()).await.unwrap();

    // The renewal hook replaces both files; no restart follows.
    let (new, _) = write_certificate(dir.path());
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while let Err(err) = qad_handshake(qad, new.clone()).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the renewed certificate was not picked up: {err}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        qad_handshake(qad, old).await.is_err(),
        "the replaced certificate is no longer served"
    );
}

#[tokio::test]
async fn a_missing_certificate_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let (_, mut config) = write_certificate(dir.path());
    config.tls_cert = Some(dir.path().join("missing.pem"));
    let err = Relay::spawn(&config).await.unwrap_err();
    assert!(format!("{err:#}").contains("missing.pem"), "{err:#}");
}
