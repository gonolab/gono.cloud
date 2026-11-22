//! The relay as devices see it: iroh relay clients and a QUIC address discovery client talk to
//! a relay started from a `[relay]` table.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures_util::{SinkExt as _, StreamExt as _};
use gono_server_core::config::RelayConfig;
use gono_server_relay::{Admission, Relay, RelaySnapshot, Tier};
use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    quic::QuicClient,
    tls::{CaTlsConfig, default_provider},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
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

/// Waits until the relay closes `client`'s connection, answering its pings meanwhile.
async fn closed(client: &mut Client) {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match client.next().await {
                None | Some(Err(_)) => break,
                Some(Ok(RelayToClientMsg::Ping(payload))) => {
                    let _ = client.send(ClientToRelayMsg::Pong(payload)).await;
                }
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("the connection ends");
}

/// Sends `count` datagrams of `size` bytes from `from` to `to` through the relay, and returns
/// how long it took until `to` had them all.
async fn relay_datagrams(
    from: &mut Client,
    to: &mut Client,
    to_id: EndpointId,
    count: usize,
    size: usize,
) -> Duration {
    let payload = vec![7; size];
    let start = Instant::now();
    let send = async {
        for _ in 0..count {
            from.send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: to_id,
                datagrams: Datagrams::from(&payload),
            })
            .await
            .unwrap();
        }
    };
    let arrive = async {
        let mut received = 0;
        while received < count * size {
            received += receive(to).await.1.len();
        }
    };
    tokio::join!(send, arrive);
    start.elapsed()
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
    let relay = Relay::spawn(&relay_config(&[&alice, &bob]), None)
        .await
        .unwrap();
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
    let relay = Relay::spawn(&config, None).await.unwrap();
    connect(relay.status().http_addr(), &alice).await.unwrap();
}

#[tokio::test]
async fn invalid_device_ids_stop_the_start() {
    let mut config = relay_config(&[]);
    // 64 hex digits that are not an Ed25519 public key: no point on the curve has them.
    config.allowed_endpoints = vec!["02".repeat(32)];
    let err = Relay::spawn(&config, None).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("relay.allowed_endpoints"),
        "{err:#}"
    );
}

#[tokio::test]
async fn run_until_shuts_the_relay_down() {
    let alice = device(5);
    let relay = Relay::spawn(&relay_config(&[&alice]), None).await.unwrap();
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

/// An admission whose devices and tiers the test changes, as the device directory does.
#[derive(Debug, Default)]
struct Directory {
    admitted: Mutex<HashMap<EndpointId, Tier>>,
    refused: Mutex<Vec<EndpointId>>,
}

impl Directory {
    /// Admits `device` at `tier`, or no longer with `None`.
    fn set(&self, device: &SecretKey, tier: Option<Tier>) {
        let mut admitted = self.admitted.lock().unwrap();
        match tier {
            Some(tier) => admitted.insert(device.public(), tier),
            None => admitted.remove(&device.public()),
        };
    }
}

impl Admission for Directory {
    fn tier(&self, device: &EndpointId) -> Option<Tier> {
        self.admitted.lock().unwrap().get(device).copied()
    }

    fn count(&self) -> usize {
        self.admitted.lock().unwrap().len()
    }

    fn refused(&self, device: &EndpointId) {
        self.refused.lock().unwrap().push(*device);
    }
}

#[tokio::test]
async fn an_admission_admits_devices_and_disconnect_ends_their_connections() {
    let (alice, bob) = (device(6), device(7));
    let directory = Arc::new(Directory::default());
    directory.set(&alice, Some(Tier::Full));
    let relay = Relay::spawn(&relay_config(&[]), Some(directory.clone()))
        .await
        .unwrap();
    let status = relay.status();
    assert_eq!(status.allowed_devices(), 1);
    let addr = status.http_addr();

    let mut client = connect(addr, &alice).await.unwrap();
    assert!(connect(addr, &bob).await.is_err());
    assert_eq!(*directory.refused.lock().unwrap(), [bob.public()]);
    wait_for(&status, |snapshot| snapshot.connections == 1).await;

    // The directory no longer admits Alice: disconnect her, and she cannot come back.
    directory.set(&alice, None);
    assert!(status.disconnect(&alice.public()));
    closed(&mut client).await;
    wait_for(&status, |snapshot| snapshot.connections == 0).await;
    assert!(connect(addr, &alice).await.is_err());
    assert!(!status.disconnect(&alice.public()), "nothing left to close");
}

#[tokio::test]
async fn a_sweep_ends_the_connections_of_devices_no_longer_admitted() {
    let (alice, bob) = (device(8), device(9));
    let directory = Arc::new(Directory::default());
    directory.set(&alice, Some(Tier::Full));
    directory.set(&bob, Some(Tier::Limited));
    let relay = Relay::spawn(&relay_config(&[]), Some(directory.clone()))
        .await
        .unwrap();
    let status = relay.status();
    let addr = status.http_addr();
    let mut alices = connect(addr, &alice).await.unwrap();
    let _bobs = connect(addr, &bob).await.unwrap();
    wait_for(&status, |snapshot| snapshot.connections == 2).await;
    assert_eq!(status.sweep(), 0, "both are admitted");
    let mut connected = vec![(alice.public(), 1), (bob.public(), 1)];
    connected.sort_unstable_by_key(|(device, _)| *device.as_bytes());
    assert_eq!(status.connected_devices(), connected);
    assert!(
        !status.is_listed(&alice.public()),
        "admitted by the directory"
    );

    // The directory drops Alice without anyone calling `disconnect` for her.
    directory.set(&alice, None);
    assert_eq!(status.sweep(), 1);
    closed(&mut alices).await;
    wait_for(&status, |snapshot| snapshot.connections == 1).await;
    assert_eq!(status.sweep(), 0, "Bob stays");
}

#[tokio::test]
async fn a_limited_device_is_read_at_the_limited_rate_and_a_full_one_is_not() {
    let (limited, full, receiver, stranger) = (device(10), device(11), device(12), device(13));
    let directory = Arc::new(Directory::default());
    directory.set(&limited, Some(Tier::Limited));
    directory.set(&full, Some(Tier::Full));
    // 20 000 bytes per second after a burst of 4 000, unlike the defaults; full relay access
    // stays unlimited (relay.max_client_bytes_per_sec unset).
    let config = RelayConfig {
        limited_bytes_per_sec: 20_000,
        limited_burst_bytes: 4_000,
        ..relay_config(&[&receiver])
    };
    let relay = Relay::spawn(&config, Some(directory.clone()))
        .await
        .unwrap();
    let status = relay.status();
    let addr = status.http_addr();
    let mut limiteds = connect(addr, &limited).await.unwrap();
    let mut fulls = connect(addr, &full).await.unwrap();
    let mut receivers = connect(addr, &receiver).await.unwrap();
    wait_for(&status, |snapshot| snapshot.connections == 3).await;

    // 40 datagrams of 1 000 bytes: the frames hold a little more, the burst takes 4 000 bytes
    // of them, and the remaining 36 000 at least take 1.8 s at the limited rate.
    let (count, size) = (40, 1_000);
    let at_limited_rate = Duration::from_millis(1_800);

    let full_took =
        relay_datagrams(&mut fulls, &mut receivers, receiver.public(), count, size).await;
    assert!(full_took < at_limited_rate / 4, "full: {full_took:?}");
    assert_eq!(status.snapshot().bytes_rate_limited, 0);

    let limited_took = relay_datagrams(
        &mut limiteds,
        &mut receivers,
        receiver.public(),
        count,
        size,
    )
    .await;
    // The bucket refills every 100 ms, so the limit may let a refill through early.
    assert!(
        limited_took >= at_limited_rate - Duration::from_millis(100),
        "limited: {limited_took:?}"
    );
    // Near the limited rate, not held back further: the frame headers add 4% at most.
    assert!(
        limited_took < at_limited_rate + Duration::from_millis(1_500),
        "limited: {limited_took:?}"
    );
    assert!(status.snapshot().bytes_rate_limited > 0);

    // A key that neither the list nor the directory admits is still refused.
    assert!(connect(addr, &stranger).await.is_err());
    assert_eq!(*directory.refused.lock().unwrap(), [stranger.public()]);
}

#[tokio::test]
async fn a_sweep_moves_a_device_whose_tier_changed_to_its_new_rate() {
    let (alice, bob) = (device(14), device(15));
    let directory = Arc::new(Directory::default());
    directory.set(&alice, Some(Tier::Limited));
    directory.set(&bob, Some(Tier::Full));
    let relay = Relay::spawn(&relay_config(&[]), Some(directory.clone()))
        .await
        .unwrap();
    let status = relay.status();
    let addr = status.http_addr();
    let mut old = connect(addr, &alice).await.unwrap();
    let mut bobs = connect(addr, &bob).await.unwrap();
    wait_for(&status, |snapshot| snapshot.connections == 2).await;
    assert_eq!(status.sweep(), 0, "both are at the tiers they connected at");

    // Alice's account gains relaying, and she connects again before the next sweep: the sweep
    // ends only the connection admitted at the limited tier.
    directory.set(&alice, Some(Tier::Full));
    let mut new = connect(addr, &alice).await.unwrap();
    wait_for(&status, |snapshot| snapshot.connections == 3).await;
    assert_eq!(status.sweep(), 1);
    closed(&mut old).await;
    wait_for(&status, |snapshot| snapshot.connections == 2).await;
    assert_eq!(status.sweep(), 0, "the new connection is at the new tier");
    assert_eq!(
        status
            .connected_devices()
            .iter()
            .map(|(_, n)| n)
            .sum::<usize>(),
        2
    );

    // The new connection carries Alice's traffic.
    bobs.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: alice.public(),
        datagrams: Datagrams::from(b"at full rate"),
    })
    .await
    .unwrap();
    assert_eq!(
        receive(&mut new).await,
        (bob.public(), b"at full rate".to_vec())
    );

    // Back to the limited tier: the sweep ends the full connection too.
    directory.set(&alice, Some(Tier::Limited));
    assert_eq!(status.sweep(), 1);
    closed(&mut new).await;
    wait_for(&status, |snapshot| snapshot.connections == 1).await;
    assert_eq!(status.sweep(), 0, "Bob stays");
}

/// Sends a GET for `path` with `headers` (lines ending in CRLF) to the relay at `addr`, and
/// returns the response with its header names in lower case, as HTTP/1.1 sends them here.
async fn get(addr: SocketAddr, path: &str, headers: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: relay.example.com\r\n{headers}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_string(&mut response))
        .await
        .expect("a response within the timeout")
        .unwrap();
    response
}

#[tokio::test]
async fn the_probes_answer_as_iroh_relay_does() {
    let relay = Relay::spawn(&relay_config(&[]), None).await.unwrap();
    let addr = relay.status().http_addr();

    let ping = get(addr, "/ping", "").await;
    assert!(ping.starts_with("HTTP/1.1 200"), "{ping}");
    assert!(ping.contains("access-control-allow-origin: *"), "{ping}");
    assert!(ping.contains("strict-transport-security: "), "{ping}");

    let captive = get(addr, "/generate_204", "X-Iroh-Challenge: gono-ci-204\r\n").await;
    assert!(captive.starts_with("HTTP/1.1 204"), "{captive}");
    assert!(
        captive.contains("x-iroh-response: response gono-ci-204"),
        "{captive}"
    );
    let unanswered = get(addr, "/generate_204", "X-Iroh-Challenge: not/this\r\n").await;
    assert!(unanswered.starts_with("HTTP/1.1 204"), "{unanswered}");
    assert!(!unanswered.contains("x-iroh-response"), "{unanswered}");

    let health = get(addr, "/healthz", "").await;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.contains("\"status\":\"ok\""), "{health}");
    assert!(get(addr, "/robots.txt", "").await.contains("Disallow: /"));
    assert!(get(addr, "/nothing", "").await.starts_with("HTTP/1.1 404"));

    // What docs/reverse-proxy.md checks through the proxy: an upgrade without the relay
    // protocol is refused with 400.
    let upgrade = get(
        addr,
        "/relay",
        "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
    )
    .await;
    assert!(upgrade.starts_with("HTTP/1.1 400"), "{upgrade}");
    assert!(
        upgrade.contains("missing header: sec-websocket-protocol"),
        "{upgrade}"
    );
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
    let relay = Relay::spawn(&config, None).await.unwrap();
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
    let relay = Relay::spawn(&config, None).await.unwrap();
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
    let err = Relay::spawn(&config, None).await.unwrap_err();
    assert!(format!("{err:#}").contains("missing.pem"), "{err:#}");
}
