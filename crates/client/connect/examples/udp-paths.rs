//! One dial between two endpoints in this process, through a relay on loopback, for
//! `scripts/test-udp-paths.sh`, which runs it under UDP filters in a network namespace (plan V8's
//! firewall matrix). The dialer A binds UDP 41001 and the acceptor B UDP 41002, so that a
//! filter can single out one side.
//!
//! ```text
//! udp-paths <gono|plain> <relay-only|with-direct> [--expect-direct] [--relay-down]
//! ```
//!
//! - `gono` dials with `gono_connect::endpoint::dial` (relay first), `plain` with iroh's
//!   `Endpoint::connect` (every known path at once), for comparison.
//! - `with-direct` gives A the direct address of B besides its relay, as the control plane
//!   would; `relay-only` the relay alone.
//! - `--expect-direct` also waits for a direct path after the connection is up.
//! - `--relay-down` stops the relay before the dial, as an outage of gono-cloud would.
//!
//! Prints one line and exits with 0 when A connected and the echo came back, 1 otherwise.

use std::{
    net::SocketAddr,
    process::ExitCode,
    time::{Duration, Instant},
};

use gono_connect::endpoint::{self, BindAddresses, Dns, EndpointOptions, TransportOptions};
use iroh::{
    Endpoint, EndpointAddr, RelayUrl, SecretKey, address_lookup::MemoryLookup, endpoint::Connection,
};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};

const ALPN: &[u8] = b"udp-paths/1";

/// Longer than iroh's idle timeout, so that a stuck handshake fails rather than hangs.
const DIAL_TIMEOUT: Duration = Duration::from_secs(35);

async fn bind(seed: u8, relay: &RelayUrl) -> Endpoint {
    endpoint::bind(
        EndpointOptions {
            secret_key: SecretKey::from_bytes(&[seed; 32]),
            relay_url: Some(relay.clone()),
            alpns: vec![ALPN.to_vec()],
            port: 41000 + u16::from(seed),
            bind: BindAddresses {
                ipv4: "0.0.0.0".parse().unwrap(),
                ipv6: None,
            },
            dns: Dns::System,
            transport: TransportOptions::default(),
        },
        MemoryLookup::new(),
    )
    .await
    .expect("bind")
}

fn paths(connection: &Connection) -> Vec<String> {
    connection
        .paths()
        .iter()
        .map(|path| format!("{:?}", path.remote_addr()))
        .collect()
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(stack), Some(addrs)) = (args.first(), args.get(1)) else {
        eprintln!(
            "usage: udp-paths <gono|plain> <relay-only|with-direct> [--expect-direct] [--relay-down]"
        );
        return ExitCode::from(2);
    };
    let expect_direct = args.iter().any(|arg| arg == "--expect-direct");
    let relay_down = args.iter().any(|arg| arg == "--relay-down");
    let case = args.join(" ");

    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
    ));
    let server = Server::spawn(config).await.expect("relay");
    let relay: RelayUrl = format!("http://{}", server.http_addr().unwrap())
        .parse()
        .unwrap();
    let (a, b) = (bind(1, &relay).await, bind(2, &relay).await);
    for endpoint in [&a, &b] {
        let _ = tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await;
    }
    let mut target = EndpointAddr::new(b.id()).with_relay_url(relay);
    if addrs == "with-direct" {
        for addr in b.addr().ip_addrs() {
            target = target.with_ip_addr(*addr);
        }
    }
    tokio::spawn({
        let b = b.clone();
        async move {
            while let Some(incoming) = b.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    if let Ok((mut send, mut recv)) = connection.accept_bi().await
                        && let Ok(ping) = recv.read_to_end(64).await
                    {
                        let _ = send.write_all(&ping).await;
                        let _ = send.finish();
                    }
                    connection.closed().await;
                });
            }
        }
    });
    if relay_down {
        let _ = server.shutdown().await;
        let deadline = Instant::now() + Duration::from_secs(10);
        while endpoint::relay_connected(&a) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let start = Instant::now();
    let dialed = tokio::time::timeout(DIAL_TIMEOUT, async {
        match stack.as_str() {
            "gono" => endpoint::dial(&a, target, ALPN)
                .await
                .map_err(|err| err.to_string()),
            _ => a.connect(target, ALPN).await.map_err(|err| err.to_string()),
        }
    })
    .await;
    let connection = match dialed {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => {
            println!("{case}: FAILED after {:?}: {err}", start.elapsed());
            return ExitCode::FAILURE;
        }
        Err(_) => {
            println!("{case}: TIMED OUT after {:?}", start.elapsed());
            return ExitCode::FAILURE;
        }
    };
    let connected = start.elapsed();
    let first = paths(&connection);
    let echoed = async {
        let (mut send, mut recv) = connection.open_bi().await.ok()?;
        send.write_all(b"ping").await.ok()?;
        send.finish().ok()?;
        recv.read_to_end(64).await.ok()
    };
    if tokio::time::timeout(Duration::from_secs(10), echoed).await != Ok(Some(b"ping".to_vec())) {
        println!("{case}: connected in {connected:?} but no echo, paths {first:?}");
        return ExitCode::FAILURE;
    }
    let mut direct_after = None;
    if expect_direct {
        while start.elapsed() < Duration::from_secs(15) {
            if paths(&connection).iter().any(|path| path.starts_with("Ip")) {
                direct_after = Some(start.elapsed());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    println!(
        "{case}: OK in {connected:?}, first paths {first:?}, now {:?}{}",
        paths(&connection),
        direct_after.map_or(String::new(), |at| format!(", direct after {at:?}"))
    );
    connection.close(0u32.into(), b"done");
    if expect_direct && direct_after.is_none() {
        println!("{case}: no direct path");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
