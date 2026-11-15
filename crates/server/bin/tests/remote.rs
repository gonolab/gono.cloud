//! Remote access end to end: `gono-cloud serve` with the relay and remote connectivity, and two
//! devices built with `gono-connect` that register, open their control channels, reach each
//! other over iroh, and see a revocation made with the CLI.

#![cfg(unix)]

use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use gono_connect::{
    ChannelEvent, ChannelOptions, Credentials, DeviceInfo, EndReason, Remote, RemoteOptions,
    Server,
    endpoint::Dns,
    iroh::SecretKey,
    protocol::{DeviceId, ServerMessage, message::SettingsChange},
};
use tokio::sync::mpsc;

const PASSWORD: &str = "correct horse battery staple";
const ALPN: &[u8] = b"test/1";
const TIMEOUT: Duration = Duration::from_secs(20);

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Instance {
    dir: tempfile::TempDir,
    addr: SocketAddr,
}

impl Instance {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let addr = free_port();
        let relay = free_port();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                r#"
                [server]
                bind = "{addr}"
                base_url = "http://{addr}"

                [storage]
                data_dir = "data"

                [db]
                path = "db/gono-cloud.db"

                [relay]
                enabled = true
                public_url = "http://{relay}"
                bind = "{relay}"
                "#
            ),
        )
        .unwrap();
        Self { dir, addr }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gono-cloud"));
        command
            .env_remove("GONO_CLOUD_CONFIG")
            .env_remove("GONO_CLOUD_LOG")
            .arg("--config")
            .arg(self.dir.path().join("config.toml"))
            .args(args);
        command
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("db/gono-cloud.db")
    }

    async fn sql(&self, query: &'static str, bind: Option<Vec<u8>>) {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", self.db().display()))
            .await
            .unwrap();
        let mut statement = sqlx::query(query);
        if let Some(bytes) = bind {
            statement = statement.bind(bytes);
        }
        statement.execute(&pool).await.unwrap();
        pool.close().await;
    }
}

fn wait_for_port(addr: SocketAddr) {
    let deadline = Instant::now() + TIMEOUT;
    while TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "the server did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn terminate(mut child: Child) {
    let _ = rustix_kill(&child);
    let _ = child.wait();
}

fn rustix_kill(child: &Child) -> std::io::Result<()> {
    Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .map(|_| ())
}

/// Registers the device of `key`, granting the registration in the database as the browser
/// would on the consent page.
async fn register(
    instance: &Instance,
    server: &Server,
    key: &SecretKey,
    name: &str,
) -> Credentials {
    let discovery = server.discover().await.unwrap();
    let pending = server
        .start_registration(
            &discovery,
            key,
            &DeviceInfo {
                product: "input-show".to_owned(),
                platform: "linux".to_owned(),
                name: name.to_owned(),
                version: "1.0.0".to_owned(),
            },
        )
        .await
        .unwrap();
    assert_eq!(pending.short_id().len(), 19);
    assert!(
        pending.poll().await.unwrap().is_none(),
        "pending until granted"
    );
    instance
        .sql(
            "UPDATE login_flows SET granted_user_id = 1 WHERE device_endpoint_id = ?1",
            Some(key.public().as_bytes().to_vec()),
        )
        .await;
    tokio::time::timeout(TIMEOUT, pending.wait())
        .await
        .expect("registered in time")
        .unwrap()
}

async fn start(
    server: &Server,
    credentials: Credentials,
    key: SecretKey,
) -> (Remote, mpsc::Receiver<ChannelEvent>) {
    let discovery = server.discover().await.unwrap();
    let mut channel = ChannelOptions::new(discovery.clone(), credentials.clone(), key.clone());
    channel.settings = Some(SettingsChange {
        accept_remote: Some(true),
        services: Some(vec![String::from_utf8(ALPN.to_vec()).unwrap()]),
        ..SettingsChange::default()
    });
    let (remote, mut events) = Remote::start(RemoteOptions {
        discovery,
        credentials,
        key,
        alpns: vec![ALPN.to_vec()],
        port: 0,
        bind: Default::default(),
        dns: Dns::System,
        transport: Default::default(),
        channel: Some(channel),
    })
    .await
    .unwrap();
    match tokio::time::timeout(TIMEOUT, events.recv()).await {
        Ok(Some(ChannelEvent::Connected(welcome))) => assert!(welcome.account.remote_access),
        other => panic!("expected the welcome, got {other:?}"),
    }
    (remote, events)
}

/// Waits for an event matching `wanted`.
async fn expect(
    events: &mut mpsc::Receiver<ChannelEvent>,
    wanted: impl Fn(&ChannelEvent) -> bool,
) -> ChannelEvent {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let event = events.recv().await.expect("the channel is open");
            if wanted(&event) {
                return event;
            }
        }
    })
    .await
    .expect("the event in time")
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_register_reach_each_other_and_hear_of_a_revocation() {
    let instance = Instance::new();
    let mut init = instance
        .command(&["init", "--password-stdin"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    init.stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    assert!(init.wait().unwrap().success());
    // Two-step verification as part 2c will store it.
    instance
        .sql(
            "INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (1, x'00', 0)",
            None,
        )
        .await;
    let child = instance
        .command(&["serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_port(instance.addr);

    let server = Server::new(&format!("http://{}", instance.addr)).unwrap();
    let (home_key, phone_key) = (
        SecretKey::from_bytes(&[11; 32]),
        SecretKey::from_bytes(&[12; 32]),
    );
    let home_credentials = register(&instance, &server, &home_key, "Home PC").await;
    let phone_credentials = register(&instance, &server, &phone_key, "Phone").await;
    let (home, mut home_events) = start(&server, home_credentials, home_key.clone()).await;
    let (phone, mut phone_events) = start(&server, phone_credentials, phone_key).await;

    // The home PC answers one stream.
    let accepting = home.clone();
    let answering = tokio::spawn(async move {
        let incoming = accepting.accept().await.expect("an incoming connection");
        let connection = incoming.await.expect("the handshake");
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let ping = recv.read_to_end(64).await.unwrap();
        assert_eq!(ping, b"ping");
        send.write_all(b"pong").await.unwrap();
        send.finish().unwrap();
        connection.closed().await;
    });

    // The phone dials it by its device ID alone; the addresses come from the control channel.
    let connection = tokio::time::timeout(
        TIMEOUT,
        phone.connect(DeviceId::from(home_key.public()), ALPN),
    )
    .await
    .expect("connected in time")
    .unwrap();
    assert_eq!(connection.remote_id(), home_key.public());
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let pong = tokio::time::timeout(TIMEOUT, recv.read_to_end(64))
        .await
        .expect("an answer in time")
        .unwrap();
    assert_eq!(pong, b"pong");
    expect(&mut home_events, |event| {
        matches!(event, ChannelEvent::Message(message) if matches!(**message, ServerMessage::Incoming { .. }))
    })
    .await;
    connection.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(TIMEOUT, answering).await;

    // Revoked with the CLI: the running server ends the home PC's channel and tells the phone.
    let hex = DeviceId::from(home_key.public()).to_hex();
    let revoke = instance
        .command(&["device", "revoke", "admin", &hex, "--confirm", &hex])
        .output()
        .unwrap();
    assert!(
        revoke.status.success(),
        "{}",
        String::from_utf8_lossy(&revoke.stderr)
    );
    let ended = expect(&mut home_events, |event| {
        matches!(event, ChannelEvent::Ended(_))
    })
    .await;
    assert!(
        matches!(ended, ChannelEvent::Ended(EndReason::Revoked)),
        "{ended:?}"
    );
    let revoked = expect(&mut phone_events, |event| {
        matches!(event, ChannelEvent::Message(message) if matches!(**message, ServerMessage::DeviceRevoked { .. }))
    })
    .await;
    let ChannelEvent::Message(message) = revoked else {
        unreachable!()
    };
    assert!(matches!(
        *message,
        ServerMessage::DeviceRevoked { endpoint_id, .. } if endpoint_id == DeviceId::from(home_key.public())
    ));

    phone.close().await;
    home.close().await;
    terminate(child);
}
