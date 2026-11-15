//! Measures remote connectivity against a running Gono Cloud: the latency of the control
//! channel's `connect` and `lookup`, how two devices reach each other, whether QUIC address
//! discovery works, how long a revocation takes to reach the relay, the revoked device and
//! its peers, and what an outage of the server does (plan V7, and the Phase 2 criterion "a
//! revocation takes effect at the relay, with the delay measured").
//!
//! Each round registers two fresh devices, A and B, with the server. The registration is
//! granted by `--grant-cmd` instead of a browser, so the probe runs unattended on a test
//! server. A accepts connections from B and echoes what it gets; B asks the server for A's
//! addresses, dials A, and pings it. Then `--revoke-cmd` revokes A, and the probe times:
//! - the command's exit (the revocation is in the database);
//! - A's relay connection dropping;
//! - A's control channel ending with `4003`;
//! - B hearing `device.revoked`.
//!
//! With `--outage-stop` and `--outage-start`, a last round keeps A and B connected, stops the
//! server for `--outage-secs`, pings across the outage, and times how long both control
//! channels take to come back.
//!
//! ```text
//! probe --server https://cloud.example.com \
//!   --grant-cmd 'grant-device {hex}' --revoke-cmd 'revoke-device {hex}' \
//!   [--rounds 3] [--lookups 50] \
//!   [--outage-stop 'systemctl stop gono-cloud' --outage-start 'systemctl start gono-cloud' \
//!    --outage-secs 30]
//! ```
//!
//! Commands run with `sh -c`, with `{hex}` replaced by the device's endpoint ID. Timestamps
//! are printed in UTC (RFC 3339, milliseconds) so that they can be matched with the server's
//! log on the same host (`journalctl -o short-iso-precise`).

use std::{
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use gono_connect::{
    ChannelEvent, ChannelOptions, Credentials, DeviceInfo, EndReason, Remote, RemoteOptions,
    Server,
    endpoint::Dns,
    iroh::{SecretKey, Watcher as _, endpoint::Connection},
    protocol::{
        DeviceId, Discovery, ServerMessage,
        message::{Purpose, SettingsChange},
    },
};
use tokio::sync::watch;

/// The ALPN the two devices speak: an echo.
const ALPN: &[u8] = b"gono-probe/1";

/// How long any single step may take.
const STEP: Duration = Duration::from_secs(30);

/// How long the registration of a device may take, its grant included.
const REGISTRATION: Duration = Duration::from_secs(60);

/// Pings over the device connection, per round.
const PINGS: usize = 20;

#[derive(Debug, Clone)]
struct Args {
    server: String,
    grant_cmd: String,
    revoke_cmd: String,
    rounds: usize,
    lookups: usize,
    outage_stop: Option<String>,
    outage_start: Option<String>,
    outage_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        server: String::new(),
        grant_cmd: String::new(),
        revoke_cmd: String::new(),
        rounds: 3,
        lookups: 50,
        outage_stop: None,
        outage_start: None,
        outage_secs: 30,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--server" => args.server = value()?,
            "--grant-cmd" => args.grant_cmd = value()?,
            "--revoke-cmd" => args.revoke_cmd = value()?,
            "--rounds" => args.rounds = value()?.parse().map_err(|_| "bad --rounds")?,
            "--lookups" => args.lookups = value()?.parse().map_err(|_| "bad --lookups")?,
            "--outage-stop" => args.outage_stop = Some(value()?),
            "--outage-start" => args.outage_start = Some(value()?),
            "--outage-secs" => {
                args.outage_secs = value()?.parse().map_err(|_| "bad --outage-secs")?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.server.is_empty() || args.grant_cmd.is_empty() || args.revoke_cmd.is_empty() {
        return Err("--server, --grant-cmd and --revoke-cmd are required".to_owned());
    }
    if args.outage_stop.is_some() != args.outage_start.is_some() {
        return Err("--outage-stop and --outage-start go together".to_owned());
    }
    Ok(args)
}

/// A moment, both for measuring (monotonic) and for printing (wall clock).
#[derive(Debug, Clone, Copy)]
struct Stamp {
    at: Instant,
    wall: SystemTime,
}

impl Stamp {
    fn now() -> Self {
        Self {
            at: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    fn since(&self, start: &Stamp) -> Duration {
        self.at.saturating_duration_since(start.at)
    }
}

/// `t` as RFC 3339 in UTC with milliseconds.
fn rfc3339(t: SystemTime) -> String {
    let since = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        since.subsec_millis()
    )
}

fn ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}

/// p50, p95 and the maximum of `samples`, or `None` without samples.
fn summary(samples: &[Duration]) -> Option<(Duration, Duration, Duration)> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort();
    let at = |p: usize| sorted[(sorted.len() * p).div_ceil(100).saturating_sub(1)];
    Some((at(50), at(95), sorted[sorted.len() - 1]))
}

fn print_summary(what: &str, samples: &[Duration]) {
    match summary(samples) {
        Some((p50, p95, max)) => println!(
            "  {what}: n={} p50={} p95={} max={}",
            samples.len(),
            ms(p50),
            ms(p95),
            ms(max)
        ),
        None => println!("  {what}: no samples"),
    }
}

/// Runs `template` with `{hex}` replaced, through `sh -c`, and fails unless it succeeds.
async fn run(template: &str, hex: &str) -> Result<(), String> {
    let command = template.replace("{hex}", hex);
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .output()
    })
    .await
    .map_err(|err| err.to_string())?
    .map_err(|err| err.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{template} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// A running device and what its control channel reported.
struct Device {
    name: String,
    key: SecretKey,
    remote: Remote,
    /// How many `welcome`s it got.
    welcomes: watch::Receiver<u32>,
    /// When the channel ended for good, and why.
    ended: watch::Receiver<Option<(Stamp, EndReason)>>,
    /// When it heard that another device was revoked, and which.
    peer_revoked: watch::Receiver<Option<(Stamp, DeviceId)>>,
}

impl Device {
    fn id(&self) -> DeviceId {
        self.key.public().into()
    }

    fn hex(&self) -> String {
        self.id().to_hex()
    }

    fn relay_connected(&self) -> bool {
        self.remote
            .endpoint()
            .home_relay_status()
            .get()
            .iter()
            .any(|status| status.is_connected())
    }

    /// Waits until `check` holds, polling every 5 ms, for at most `limit`.
    async fn until(&self, limit: Duration, check: impl Fn(&Self) -> bool) -> Option<Stamp> {
        let deadline = Instant::now() + limit;
        loop {
            if check(self) {
                return Some(Stamp::now());
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Waits until the channel has had `count` welcomes.
    async fn welcomed(&self, count: u32, limit: Duration) -> Option<Stamp> {
        let mut welcomes = self.welcomes.clone();
        let reached = tokio::time::timeout(limit, welcomes.wait_for(|seen| *seen >= count)).await;
        matches!(reached, Ok(Ok(_))).then(Stamp::now)
    }
}

/// Registers a fresh device named `name` and returns its key and credential.
async fn register(
    args: &Args,
    server: &Server,
    discovery: &Discovery,
    name: &str,
) -> Result<(SecretKey, Credentials), String> {
    let key = SecretKey::generate();
    let hex = DeviceId::from(key.public()).to_hex();
    let pending = server
        .start_registration(
            discovery,
            &key,
            &DeviceInfo {
                product: "gono-probe".to_owned(),
                platform: std::env::consts::OS.to_owned(),
                name: name.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
        )
        .await
        .map_err(|err| format!("start the registration of {name}: {err}"))?;
    run(&args.grant_cmd, &hex).await?;
    let credentials = tokio::time::timeout(REGISTRATION, pending.wait())
        .await
        .map_err(|_| format!("{name} was not registered in time"))?
        .map_err(|err| format!("register {name}: {err}"))?;
    Ok((key, credentials))
}

/// Starts device `name` with `key` and `credentials`, and waits for its first `welcome`.
async fn start(
    discovery: &Discovery,
    name: &str,
    key: SecretKey,
    credentials: Credentials,
) -> Result<(Device, Duration), String> {
    let mut channel = ChannelOptions::new(discovery.clone(), credentials.clone(), key.clone());
    channel.version = env!("CARGO_PKG_VERSION").to_owned();
    channel.settings = Some(SettingsChange {
        accept_remote: Some(true),
        ..SettingsChange::default()
    });
    let started = Instant::now();
    let (remote, mut events) = Remote::start(RemoteOptions {
        discovery: discovery.clone(),
        credentials,
        key: key.clone(),
        alpns: vec![ALPN.to_vec()],
        port: 0,
        dns: Dns::System,
        channel: Some(channel),
    })
    .await
    .map_err(|err| format!("start {name}: {err}"))?;
    let (welcomes_tx, welcomes) = watch::channel(0u32);
    let (ended_tx, ended) = watch::channel(None);
    let (revoked_tx, peer_revoked) = watch::channel(None);
    let label = name.to_owned();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                ChannelEvent::Connected(_) => welcomes_tx.send_modify(|count| *count += 1),
                ChannelEvent::Message(message) => {
                    if let ServerMessage::DeviceRevoked { endpoint_id, .. } = *message {
                        revoked_tx.send_replace(Some((Stamp::now(), endpoint_id)));
                    }
                }
                ChannelEvent::Disconnected(reason) => {
                    println!(
                        "  [{}] {label}: channel disconnected: {reason}",
                        rfc3339(SystemTime::now())
                    );
                }
                ChannelEvent::Ended(reason) => {
                    ended_tx.send_replace(Some((Stamp::now(), reason)));
                }
            }
        }
    });
    let device = Device {
        name: name.to_owned(),
        key,
        remote,
        welcomes,
        ended,
        peer_revoked,
    };
    device
        .welcomed(1, STEP)
        .await
        .ok_or_else(|| format!("{name} got no welcome"))?;
    Ok((device, started.elapsed()))
}

/// Lets `device` accept connections from `peer` and echo every stream.
fn serve_echo(device: &Device, peer: DeviceId) {
    let peer = *peer.as_bytes();
    let mut incoming = device
        .remote
        .accept_trusted(move |id| id.as_bytes() == &peer);
    tokio::spawn(async move {
        while let Some(connection) = incoming.recv().await {
            tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        if let Ok(data) = recv.read_to_end(1024).await {
                            let _ = send.write_all(&data).await;
                            let _ = send.finish();
                        }
                    });
                }
            });
        }
    });
}

/// One echo over a new stream of `connection`: its round trip, or `None` on failure.
async fn ping(connection: &Connection) -> Option<Duration> {
    let started = Instant::now();
    let exchange = async {
        let (mut send, mut recv) = connection.open_bi().await.ok()?;
        send.write_all(b"ping").await.ok()?;
        send.finish().ok()?;
        let echo = recv.read_to_end(64).await.ok()?;
        (echo == b"ping").then_some(())
    };
    tokio::time::timeout(Duration::from_secs(2), exchange)
        .await
        .ok()
        .flatten()
        .map(|()| started.elapsed())
}

/// The paths of `connection`: which one is selected, its kind and round trip.
fn describe_paths(connection: &Connection) -> String {
    let paths = connection.paths();
    let described: Vec<String> = paths
        .iter()
        .map(|path| {
            format!(
                "{}{} {:?} rtt={}",
                if path.is_selected() { "*" } else { "" },
                if path.is_relay() { "relay" } else { "direct" },
                path.remote_addr(),
                ms(path.rtt())
            )
        })
        .collect();
    described.join(", ")
}

/// Waits for the endpoint of `device` to know a public IPv4 address of its own, which on a
/// host behind NAT only QUIC address discovery can tell it.
async fn public_address(device: &Device, limit: Duration) -> Option<std::net::SocketAddr> {
    let deadline = Instant::now() + limit;
    loop {
        let found = device
            .remote
            .endpoint()
            .addr()
            .ip_addrs()
            .copied()
            .find(|addr| match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    !(ip.is_private() || ip.is_loopback() || ip.is_link_local())
                }
                std::net::IpAddr::V6(ip) => ip.segments()[0] & 0xe000 == 0x2000,
            });
        if found.is_some() || Instant::now() >= deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// What one round measured.
#[derive(Debug, Default)]
struct Round {
    channel_open: Vec<Duration>,
    connect: Option<Duration>,
    lookups: Vec<Duration>,
    dial: Option<Duration>,
    pings: Vec<Duration>,
    cli: Option<Duration>,
    relay_dropped: Option<Duration>,
    channel_closed: Option<Duration>,
    peer_notified: Option<Duration>,
}

/// Registers and starts A and B, has A serve the echo, and waits until both hold their relay
/// connection.
async fn pair(
    args: &Args,
    server: &Server,
    discovery: &Discovery,
    label: &str,
    round: &mut Round,
) -> Result<(Device, Device), String> {
    let (a_key, a_credentials) = register(args, server, discovery, &format!("{label}-a")).await?;
    let (b_key, b_credentials) = register(args, server, discovery, &format!("{label}-b")).await?;
    let (a, a_open) = start(discovery, &format!("{label}-a"), a_key, a_credentials).await?;
    let (b, b_open) = start(discovery, &format!("{label}-b"), b_key, b_credentials).await?;
    round.channel_open.extend([a_open, b_open]);
    println!(
        "  devices: A {} ({}), B {} ({})",
        a.id().short(),
        a.name,
        b.id().short(),
        b.name
    );
    serve_echo(&a, b.id());
    for device in [&a, &b] {
        if device.until(STEP, Device::relay_connected).await.is_none() {
            return Err(format!("{} did not connect to the relay", device.name));
        }
    }
    Ok((a, b))
}

/// B asks for A's addresses with one `connect` and `lookups` lookups, dials A and pings it.
async fn measure_paths(
    args: &Args,
    a: &Device,
    b: &Device,
    round: &mut Round,
) -> Result<Connection, String> {
    match public_address(a, Duration::from_secs(10)).await {
        Some(addr) => println!("  QAD: A learned its public address {addr}"),
        None => println!("  QAD: A learned no public address within 10 s"),
    }
    // Give A a moment to publish what it learned.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let started = Instant::now();
    let answer = b
        .remote
        .channel()
        .connect_to(a.id(), "gono-probe/1", Purpose::Session, None)
        .await
        .map_err(|err| format!("connect: {err}"))?;
    round.connect = Some(started.elapsed());
    println!(
        "  connect: {} (relay {:?}, {} direct addresses: {:?})",
        ms(started.elapsed()),
        answer.relay_url,
        answer.direct.len(),
        answer.direct
    );
    for _ in 0..args.lookups {
        let started = Instant::now();
        b.remote
            .channel()
            .lookup(a.id())
            .await
            .map_err(|err| format!("lookup: {err}"))?;
        round.lookups.push(started.elapsed());
        // Stay below the 120 lookups a minute of protocol 15.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let started = Instant::now();
    let connection = tokio::time::timeout(STEP, b.remote.connect(a.id(), ALPN))
        .await
        .map_err(|_| "the dial timed out".to_owned())?
        .map_err(|err| format!("dial: {err}"))?;
    round.dial = Some(started.elapsed());
    println!(
        "  dial: {}; paths right after: {}",
        ms(started.elapsed()),
        describe_paths(&connection)
    );
    let first = ping(&connection).await;
    println!("  first ping: {}", first.map_or("failed".to_owned(), ms));
    tokio::time::sleep(Duration::from_secs(3)).await;
    for _ in 0..PINGS {
        if let Some(rtt) = ping(&connection).await {
            round.pings.push(rtt);
        }
    }
    println!("  paths after 3 s: {}", describe_paths(&connection));
    Ok(connection)
}

/// Revokes A with `--revoke-cmd` and times what follows.
async fn measure_revocation(
    args: &Args,
    a: &Device,
    b: &Device,
    round: &mut Round,
) -> Result<(), String> {
    let t0 = Stamp::now();
    println!("  t0 revoke command starts       {}", rfc3339(t0.wall));
    // Watch A's relay connection, A's channel and B's channel while the command runs.
    let relay = async { a.until(STEP, |device| !device.relay_connected()).await };
    let closed = async {
        let mut ended = a.ended.clone();
        let reached = tokio::time::timeout(STEP, ended.wait_for(Option::is_some)).await;
        reached
            .ok()
            .and_then(|seen| seen.ok().and_then(|seen| seen.clone()))
    };
    let a_id = a.id();
    let notified = async {
        let mut revoked = b.peer_revoked.clone();
        let reached = tokio::time::timeout(
            STEP,
            revoked.wait_for(|seen| seen.is_some_and(|(_, id)| id == a_id)),
        )
        .await;
        reached
            .ok()
            .and_then(|seen| seen.ok().and_then(|seen| *seen))
    };
    let command = async {
        let result = run(&args.revoke_cmd, &a.hex()).await;
        (Stamp::now(), result)
    };
    let ((cli, result), relay, closed, notified) = tokio::join!(command, relay, closed, notified);
    result?;
    round.cli = Some(cli.since(&t0));
    println!(
        "  +{:>9} revoke command exits     {}",
        ms(cli.since(&t0)),
        rfc3339(cli.wall)
    );
    match relay {
        Some(at) => {
            round.relay_dropped = Some(at.since(&t0));
            println!(
                "  +{:>9} A's relay connection drops {}",
                ms(at.since(&t0)),
                rfc3339(at.wall)
            );
        }
        None => println!("  A's relay connection did not drop within {STEP:?}"),
    }
    match closed {
        Some((at, reason)) => {
            round.channel_closed = Some(at.since(&t0));
            println!(
                "  +{:>9} A's channel ends: {reason:?} {}",
                ms(at.since(&t0)),
                rfc3339(at.wall)
            );
        }
        None => println!("  A's channel did not end within {STEP:?}"),
    }
    match notified {
        Some((at, _)) => {
            round.peer_notified = Some(at.since(&t0));
            println!(
                "  +{:>9} B hears device.revoked  {}",
                ms(at.since(&t0)),
                rfc3339(at.wall)
            );
        }
        None => println!("  B did not hear of the revocation within {STEP:?}"),
    }
    // The relay refuses A from now on.
    let refused = a
        .until(Duration::from_secs(5), Device::relay_connected)
        .await
        .is_none();
    println!("  A's relay connection stays down for 5 s: {refused}");
    Ok(())
}

/// Stops the server for `--outage-secs` while A and B are connected, and times the recovery.
async fn measure_outage(args: &Args, server: &Server, discovery: &Discovery) -> Result<(), String> {
    let (Some(stop), Some(start_cmd)) = (&args.outage_stop, &args.outage_start) else {
        return Ok(());
    };
    println!("outage round");
    let mut round = Round::default();
    let (a, b) = pair(args, server, discovery, "outage", &mut round).await?;
    let connection = measure_paths(
        &Args {
            lookups: 1,
            ..args.clone()
        },
        &a,
        &b,
        &mut round,
    )
    .await?;
    let t0 = Stamp::now();
    run(stop, "").await?;
    println!("  t0 server stopped               {}", rfc3339(t0.wall));
    let pinging = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let pinger = {
        let connection = connection.clone();
        let pinging = Arc::clone(&pinging);
        tokio::spawn(async move {
            let (mut ok, mut failed) = (0u32, 0u32);
            while pinging.load(std::sync::atomic::Ordering::Relaxed) {
                match ping(&connection).await {
                    Some(_) => ok += 1,
                    None => failed += 1,
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            (ok, failed)
        })
    };
    tokio::time::sleep(Duration::from_secs(args.outage_secs)).await;
    pinging.store(false, std::sync::atomic::Ordering::Relaxed);
    let (ok, failed) = pinger.await.unwrap_or_default();
    println!(
        "  during the outage: {ok} pings answered, {failed} failed; paths: {}",
        describe_paths(&connection)
    );
    let welcomes = (*a.welcomes.borrow(), *b.welcomes.borrow());
    let t1 = Stamp::now();
    run(start_cmd, "").await?;
    println!("  t1 server started               {}", rfc3339(t1.wall));
    let limit = Duration::from_secs(120);
    let (a_back, b_back) = tokio::join!(
        a.welcomed(welcomes.0 + 1, limit),
        b.welcomed(welcomes.1 + 1, limit)
    );
    for (name, back) in [("A", a_back), ("B", b_back)] {
        match back {
            Some(at) => println!(
                "  +{:>9} {name}'s channel is back    {}",
                ms(at.since(&t1)),
                rfc3339(at.wall)
            ),
            None => println!("  {name}'s channel was not back within {limit:?}"),
        }
    }
    let (a_relay, b_relay) = tokio::join!(
        a.until(limit, Device::relay_connected),
        b.until(limit, Device::relay_connected)
    );
    for (name, back) in [("A", a_relay), ("B", b_relay)] {
        match back {
            Some(at) => println!("  +{:>9} {name}'s relay is back", ms(at.since(&t1))),
            None => println!("  {name}'s relay was not back within {limit:?}"),
        }
    }
    println!(
        "  after the outage: ping {}",
        ping(&connection).await.map_or("failed".to_owned(), ms)
    );
    connection.close(0u32.into(), b"done");
    a.remote.close().await;
    b.remote.close().await;
    Ok(())
}

async fn probe(args: Args) -> Result<(), String> {
    let server = Server::new(&args.server).map_err(|err| err.to_string())?;
    let discovery = server.discover().await.map_err(|err| err.to_string())?;
    println!(
        "server {} relay {} ({})",
        discovery.server,
        discovery.relay_url,
        rfc3339(SystemTime::now())
    );
    let mut rounds = Vec::new();
    for number in 1..=args.rounds {
        println!("round {number}");
        let mut round = Round::default();
        let (a, b) = pair(
            &args,
            &server,
            &discovery,
            &format!("r{number}"),
            &mut round,
        )
        .await?;
        let connection = measure_paths(&args, &a, &b, &mut round).await?;
        measure_revocation(&args, &a, &b, &mut round).await?;
        connection.close(0u32.into(), b"done");
        a.remote.close().await;
        b.remote.close().await;
        rounds.push(round);
    }
    measure_outage(&args, &server, &discovery).await?;

    println!("summary over {} rounds", rounds.len());
    let all = |pick: fn(&Round) -> Vec<Duration>| -> Vec<Duration> {
        rounds.iter().flat_map(pick).collect()
    };
    print_summary(
        "channel open (to welcome)",
        &all(|r| r.channel_open.clone()),
    );
    print_summary("connect", &all(|r| r.connect.into_iter().collect()));
    print_summary("lookup", &all(|r| r.lookups.clone()));
    print_summary("dial", &all(|r| r.dial.into_iter().collect()));
    print_summary("ping over the connection", &all(|r| r.pings.clone()));
    print_summary("revoke command", &all(|r| r.cli.into_iter().collect()));
    print_summary(
        "revocation to relay drop",
        &all(|r| r.relay_dropped.into_iter().collect()),
    );
    print_summary(
        "revocation to channel close",
        &all(|r| r.channel_closed.into_iter().collect()),
    );
    print_summary(
        "revocation to peer notice",
        &all(|r| r.peer_notified.into_iter().collect()),
    );
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    match probe(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
