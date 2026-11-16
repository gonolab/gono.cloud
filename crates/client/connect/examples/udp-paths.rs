//! One dial between two endpoints in this process, through a relay on loopback, for
//! `scripts/test-udp-paths.sh`, which runs it under UDP filters in a network namespace (plan V8's
//! firewall matrix). The dialer A binds UDP 41001 and the acceptor B UDP 41002, so that a
//! filter can single out one side.
//!
//! ```text
//! udp-paths <gono|plain> <relay-only|with-direct> [--expect-direct] [--relay-down]
//!           [--silent-break [--outage-below MS] [--outage-above MS]]
//!           [--path-timers IDLE_MS/KEEP_ALIVE_MS] [--idle SECS]
//! ```
//!
//! - `gono` dials with `gono_connect::endpoint::dial` (relay first), `plain` with iroh's
//!   `Endpoint::connect` (every known path at once), for comparison.
//! - `with-direct` gives A the direct address of B besides its relay, as the control plane
//!   would; `relay-only` the relay alone.
//! - `--expect-direct` also waits for a direct path after the connection is up.
//! - `--relay-down` stops the relay before the dial, as an outage of gono-cloud would.
//! - `--silent-break` waits for the direct path to be selected, echoes a probe every 10 ms on
//!   one stream (as a product's key events on its control stream), then drops all UDP to both
//!   ports with nftables (the process must be allowed to run `nft`: root, or a namespace of its
//!   own), as a network that starts dropping UDP does. It reports how long after the drop the
//!   first probe sent after it is echoed (over the relay), then lets UDP through again and
//!   reports how long the direct path takes to come back (up to iroh's 60 s upgrade check,
//!   since no address changes here). `--outage-below` and `--outage-above` bound the outage.
//! - `--path-timers` sets both endpoints' path idle timeout and keep-alive interval, for
//!   example `15000/5000` for iroh's own (the remote endpoint's defaults are gono-connect's).
//! - `--idle` waits for the direct path, then counts the QUIC datagrams and bytes on the
//!   direct and the relay path (both directions, without the relay's TCP framing) while the
//!   connection carries nothing for SECS: the cost of the keep-alives.
//!
//! Prints one line and exits with 0 when A connected, the echo came back and every check
//! held, 1 otherwise. `RUST_LOG` logs to stderr.

use std::{
    net::SocketAddr,
    process::{Command, ExitCode},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
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

/// The ports of A and B.
const PORTS: [u16; 2] = [41001, 41002];

/// The nftables table of `--silent-break`.
const BREAK_TABLE: &str = "udp_paths_break";

/// How often `--silent-break` sends a probe.
const PROBE_INTERVAL: Duration = Duration::from_millis(10);

/// How long `--silent-break` waits for the probes to come back over the relay.
const BREAK_WAIT: Duration = Duration::from_secs(30);

/// How long `--silent-break` waits for the direct path after UDP is let through again. Once
/// iroh abandoned a direct path, it punches again only when either side's address candidates
/// change or at its upgrade check, every 60 s per peer; on loopback nothing changes.
const DIRECT_WAIT: Duration = Duration::from_secs(70);

struct Args {
    stack: String,
    addrs: String,
    expect_direct: bool,
    relay_down: bool,
    silent_break: bool,
    outage_below: Option<Duration>,
    outage_above: Option<Duration>,
    path_timers: Option<(Duration, Duration)>,
    idle: Option<Duration>,
}

fn millis(value: &str) -> Option<Duration> {
    value.parse().ok().map(Duration::from_millis)
}

fn parse_args() -> Option<Args> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| {
        args.iter()
            .position(|arg| arg == flag)
            .map(|at| args.get(at + 1))
    };
    let flag = |flag: &str| args.iter().any(|arg| arg == flag);
    let path_timers = match value("--path-timers") {
        None => None,
        Some(timers) => {
            let (idle, keep_alive) = timers?.split_once('/')?;
            Some((millis(idle)?, millis(keep_alive)?))
        }
    };
    let bound = |name: &str| match value(name) {
        None => Some(None),
        Some(ms) => millis(ms?).map(Some),
    };
    Some(Args {
        stack: args.first()?.clone(),
        addrs: args.get(1)?.clone(),
        expect_direct: flag("--expect-direct"),
        relay_down: flag("--relay-down"),
        silent_break: flag("--silent-break"),
        outage_below: bound("--outage-below")?,
        outage_above: bound("--outage-above")?,
        path_timers,
        idle: match value("--idle") {
            None => None,
            Some(secs) => Some(Duration::from_secs(secs?.parse().ok()?)),
        },
    })
}

async fn bind(seed: u8, relay: &RelayUrl, transport: TransportOptions) -> Endpoint {
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
            transport,
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

/// QUIC datagrams and bytes on `connection`'s paths in both directions: direct, then relay.
fn traffic(connection: &Connection) -> [(u64, u64); 2] {
    let mut kinds = [(0, 0); 2];
    for path in connection.paths().iter() {
        let stats = path.stats();
        let kind = &mut kinds[usize::from(path.is_relay())];
        kind.0 += stats.udp_tx.datagrams + stats.udp_rx.datagrams;
        kind.1 += stats.udp_tx.bytes + stats.udp_rx.bytes;
    }
    kinds
}

/// Whether the selected path is a direct one; `None` while none is selected.
fn selected_is_direct(connection: &Connection) -> Option<bool> {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map(|path| path.is_ip())
}

/// Waits up to `within` for a selected path that is direct (or relayed); returns when.
async fn wait_for_selected(
    connection: &Connection,
    direct: bool,
    within: Duration,
) -> Option<Instant> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if selected_is_direct(connection) == Some(direct) {
            return Some(Instant::now());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    None
}

/// Echoes every bidirectional stream of `connection` back as it arrives.
async fn echo(connection: Connection) {
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(Some(read)) = recv.read(&mut buf).await {
                if send.write_all(&buf[..read]).await.is_err() {
                    return;
                }
            }
            let _ = send.finish();
        });
    }
}

/// Runs one nftables command (nft joins its arguments into one command line).
fn nft(command: &str) -> Result<(), String> {
    let output = Command::new("nft")
        .arg(command)
        .output()
        .map_err(|err| format!("nft: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft {command}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Drops every UDP datagram to A's and B's ports on arrival: both directions of the direct
/// path die silently (sending still succeeds), while the relay, on TCP, keeps working.
fn break_udp() -> Result<(), String> {
    nft(&format!("add table inet {BREAK_TABLE}"))?;
    nft(&format!(
        "add chain inet {BREAK_TABLE} in {{ type filter hook input priority -10; policy accept; }}"
    ))?;
    nft(&format!(
        "add rule inet {BREAK_TABLE} in udp dport {{ {}, {} }} drop",
        PORTS[0], PORTS[1]
    ))
}

fn restore_udp() -> Result<(), String> {
    nft(&format!("delete table inet {BREAK_TABLE}"))
}

/// What `--silent-break` measured.
struct Break {
    /// From the drop to the echo of the first probe sent after it.
    outage: Duration,
    /// From the drop until A selected the relay path.
    relay_selected: Duration,
    /// The longest time without any echo around the drop.
    longest_gap: Duration,
    /// From letting UDP through again until A selected a direct path again.
    direct_again: Option<Duration>,
    /// Probes echoed after the direct path came back.
    echoed_after: usize,
}

/// See `--silent-break` in the module documentation.
async fn silent_break(connection: &Connection) -> Result<Break, String> {
    wait_for_selected(connection, true, Duration::from_secs(15))
        .await
        .ok_or("no direct path before the break")?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| format!("open_bi: {err}"))?;
    let sent: Arc<Mutex<Vec<Instant>>> = Arc::default();
    let echoed: Arc<Mutex<Vec<(usize, Instant)>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let (sent, stop) = (sent.clone(), stop.clone());
        async move {
            let mut ticks = tokio::time::interval(PROBE_INTERVAL);
            while !stop.load(Ordering::Relaxed) {
                ticks.tick().await;
                let seq = {
                    let mut sent = sent.lock().unwrap();
                    sent.push(Instant::now());
                    sent.len() - 1
                };
                if send.write_all(&(seq as u64).to_be_bytes()).await.is_err() {
                    return;
                }
            }
            let _ = send.finish();
        }
    });
    tokio::spawn({
        let echoed = echoed.clone();
        async move {
            let mut seq = [0u8; 8];
            while recv.read_exact(&mut seq).await.is_ok() {
                let seq = u64::from_be_bytes(seq) as usize;
                echoed.lock().unwrap().push((seq, Instant::now()));
            }
        }
    });
    let finish = |result| {
        stop.store(true, Ordering::Relaxed);
        result
    };

    // A second of steady traffic on the direct path, then the drop.
    tokio::time::sleep(Duration::from_secs(1)).await;
    if echoed.lock().unwrap().len() < 50 {
        return finish(Err("probes are not echoed before the break".to_owned()));
    }
    if let Err(err) = break_udp() {
        return finish(Err(err));
    }
    let broken = Instant::now();
    let first_after = sent.lock().unwrap().len();

    let mut relay_selected = None;
    let mut back = None;
    while relay_selected.is_none() || back.is_none() {
        if broken.elapsed() > BREAK_WAIT {
            return finish(Err(format!(
                "after the drop: relay selected {relay_selected:?}, probes echoed {back:?}"
            )));
        }
        if relay_selected.is_none() && selected_is_direct(connection) == Some(false) {
            relay_selected = Some(broken.elapsed());
        }
        if back.is_none() {
            back = echoed
                .lock()
                .unwrap()
                .iter()
                .find(|(seq, _)| *seq >= first_after)
                .map(|(_, at)| *at - broken);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let outage = back.unwrap();
    let longest_gap = {
        let echoed = echoed.lock().unwrap();
        let mut arrivals: Vec<Instant> = echoed
            .iter()
            .map(|(_, at)| *at)
            .filter(|at| *at + Duration::from_secs(1) >= broken && *at <= broken + outage)
            .collect();
        arrivals.sort();
        arrivals
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .max()
            .unwrap_or_default()
    };

    // Stay on the relay for a while, then let UDP through again.
    tokio::time::sleep(Duration::from_secs(2)).await;
    if let Err(err) = restore_udp() {
        return finish(Err(err));
    }
    let restored = Instant::now();
    let direct_again = wait_for_selected(connection, true, DIRECT_WAIT)
        .await
        .map(|at| at - restored);
    let echoed_before = echoed.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let echoed_after = echoed.lock().unwrap().len() - echoed_before;
    finish(Ok(Break {
        outage,
        relay_selected: relay_selected.unwrap(),
        longest_gap,
        direct_again,
        echoed_after,
    }))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let Some(args) = parse_args() else {
        eprintln!(
            "usage: udp-paths <gono|plain> <relay-only|with-direct> [--expect-direct] \
             [--relay-down] [--silent-break [--outage-below MS] [--outage-above MS]] \
             [--path-timers IDLE_MS/KEEP_ALIVE_MS] [--idle SECS]"
        );
        return ExitCode::from(2);
    };
    let case = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let transport = TransportOptions {
        path_idle_timeout: args.path_timers.map(|(idle, _)| idle),
        path_keep_alive_interval: args.path_timers.map(|(_, keep_alive)| keep_alive),
        ..TransportOptions::default()
    };

    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
    ));
    let server = Server::spawn(config).await.expect("relay");
    let relay: RelayUrl = format!("http://{}", server.http_addr().unwrap())
        .parse()
        .unwrap();
    let (a, b) = (
        bind(1, &relay, transport.clone()).await,
        bind(2, &relay, transport).await,
    );
    for endpoint in [&a, &b] {
        let _ = tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await;
    }
    let mut target = EndpointAddr::new(b.id()).with_relay_url(relay);
    if args.addrs == "with-direct" {
        for addr in b.addr().ip_addrs() {
            target = target.with_ip_addr(*addr);
        }
    }
    tokio::spawn({
        let b = b.clone();
        async move {
            while let Some(incoming) = b.accept().await {
                tokio::spawn(async move {
                    if let Ok(connection) = incoming.await {
                        echo(connection).await;
                    }
                });
            }
        }
    });
    if args.relay_down {
        let _ = server.shutdown().await;
        let deadline = Instant::now() + Duration::from_secs(10);
        while endpoint::relay_connected(&a) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let start = Instant::now();
    let dialed = tokio::time::timeout(DIAL_TIMEOUT, async {
        match args.stack.as_str() {
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
    if args.expect_direct {
        while start.elapsed() < Duration::from_secs(15) {
            if paths(&connection).iter().any(|path| path.starts_with("Ip")) {
                direct_after = Some(start.elapsed());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let mut failed = Vec::new();
    let mut idle = String::new();
    if let Some(secs) = args.idle {
        if wait_for_selected(&connection, true, Duration::from_secs(15))
            .await
            .is_none()
        {
            failed.push("no direct path to idle on".to_owned());
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let before = traffic(&connection);
            tokio::time::sleep(secs).await;
            let after = traffic(&connection);
            let [direct, relay] = [0, 1].map(|kind| {
                (
                    after[kind].0 - before[kind].0,
                    after[kind].1 - before[kind].1,
                )
            });
            idle = format!(
                ", idle {secs:?}: direct {} datagrams / {} bytes, relay {} datagrams / {} bytes",
                direct.0, direct.1, relay.0, relay.1
            );
        }
    }
    let mut silent = String::new();
    if args.silent_break {
        match silent_break(&connection).await {
            Ok(measured) => {
                let direct_again = match measured.direct_again {
                    Some(after) => format!("{after:?} after UDP returned"),
                    None => "never".to_owned(),
                };
                silent = format!(
                    ", silent break: echoed again after {:?} (relay selected after {:?}, \
                     longest gap {:?}), direct again {direct_again}",
                    measured.outage, measured.relay_selected, measured.longest_gap,
                );
                if let Some(bound) = args.outage_below
                    && measured.outage >= bound
                {
                    failed.push(format!("outage not below {bound:?}"));
                }
                if let Some(bound) = args.outage_above
                    && measured.outage <= bound
                {
                    failed.push(format!("outage not above {bound:?}"));
                }
                if measured.direct_again.is_none() {
                    failed.push("no direct path after UDP returned".to_owned());
                }
                if measured.echoed_after == 0 {
                    failed.push("no echo after the direct path returned".to_owned());
                }
            }
            Err(err) => failed.push(format!("silent break: {err}")),
        }
    }
    println!(
        "{case}: OK in {connected:?}, first paths {first:?}, now {:?}{}{idle}{silent}",
        paths(&connection),
        direct_after.map_or(String::new(), |at| format!(", direct after {at:?}"))
    );
    connection.close(0u32.into(), b"done");
    if args.expect_direct && direct_after.is_none() {
        failed.push("no direct path".to_owned());
    }
    if !failed.is_empty() {
        println!("{case}: {}", failed.join("; "));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
