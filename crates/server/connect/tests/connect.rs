//! The control protocol as devices see it: registration, the control channel, address
//! lookup, account-vouched pairing and revocation, against a real database. Devices are
//! simulated with their Ed25519 keys; the WebSocket itself belongs to the HTTP server and is
//! tested there.

use std::{sync::Arc, time::Duration};

use gono_protocol::connect::{
    ClientMessage, DeviceId, ErrorCode, LoginStart, LoginStarted, PollRequest, Registered,
    ServerMessage, Signed, Statement,
    message::{HelloMessage, Purpose, SessionEvent, SessionReport, SettingsChange},
    statement::{self, DeviceSummary, Hello, Introduced, Login, PairApproval, PairRequest},
};
use gono_server_connect::{Connect, ConnectConfig, DeviceLogin, Outgoing, Refusal, Session};
use gono_server_core::{
    Username, app_passwords,
    db::{self, Pool},
    devices::{self, EndpointId, RevokedBy},
    login_flows,
    users::{self, NewUser},
};
use gono_server_relay::Admission as _;
use iroh_base::SecretKey;
use secrecy::SecretString;

const SERVER: &str = "https://cloud.example.com";
const TIMEOUT: Duration = Duration::from_secs(5);

struct Fixture {
    _dir: tempfile::TempDir,
    pool: Pool,
    connect: Arc<Connect>,
}

async fn fixture() -> Fixture {
    fixture_with(true).await
}

/// A fixture with `connect.require_two_factor` set to `require_two_factor`.
async fn fixture_with(require_two_factor: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let connect = Connect::new(
        pool.clone(),
        ConnectConfig {
            base_url: SERVER.parse().unwrap(),
            relay_url: "https://relay.example.com".parse().unwrap(),
            audit_retention_secs: 3600,
            require_two_factor,
        },
    )
    .await
    .unwrap();
    tokio::spawn(Arc::clone(&connect).run());
    Fixture {
        _dir: dir,
        pool,
        connect,
    }
}

impl Fixture {
    async fn user(&self, name: &str, two_factor: bool) -> i64 {
        let username = Username::new(name).unwrap();
        let id = users::create(
            &self.pool,
            &NewUser {
                username: &username,
                display_name: name,
                password_hash: "x",
                is_admin: false,
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        if two_factor {
            sqlx::query(
                "INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (?, x'00', 0)",
            )
            .bind(id)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        id
    }

    /// Registers `key` as `name` in account `user`, granting the flow as the browser would.
    async fn register(
        &self,
        user_id: i64,
        key: &SecretKey,
        name: &str,
    ) -> (u16, serde_json::Value) {
        let now = db::unix_now();
        let (status, body) = self
            .connect
            .start_login(
                LoginStart {
                    endpoint_id: key.public().into(),
                    product: "input-show".to_owned(),
                    platform: "windows".to_owned(),
                    name: name.to_owned(),
                    version: "1.0.0".to_owned(),
                },
                now,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let started: LoginStarted = serde_json::from_value(body).unwrap();
        let login_token = started.login_url.rsplit('/').next().unwrap().to_owned();
        let flow = login_flows::find(&self.pool, &login_token, now)
            .await
            .unwrap()
            .unwrap();
        let poll = |proof| PollRequest {
            token: started.poll.token.clone(),
            proof,
        };
        assert_eq!(self.connect.poll_login(poll(None), now).await.0, 202);
        assert!(
            login_flows::grant(&self.pool, flow.id, user_id, None, now)
                .await
                .unwrap()
        );
        assert_eq!(
            self.connect.poll_login(poll(None), now).await.0,
            400,
            "no proof"
        );
        let wrong = Signed::sign(
            &Statement::Login(Login {
                server: "https://elsewhere.example.com".to_owned(),
                endpoint_id: key.public().into(),
                challenge: started.challenge.clone(),
            }),
            key,
        );
        assert_eq!(
            self.connect.poll_login(poll(Some(wrong)), now).await.0,
            400,
            "the proof names another server"
        );
        let proof = Signed::sign(
            &Statement::Login(Login {
                server: SERVER.to_owned(),
                endpoint_id: key.public().into(),
                challenge: started.challenge.clone(),
            }),
            key,
        );
        let answer = self
            .connect
            .poll_login(poll(Some(proof.clone())), now)
            .await;
        assert_eq!(
            self.connect.poll_login(poll(Some(proof)), now).await.0,
            404,
            "used once"
        );
        answer
    }

    /// Registers `key` and opens its control channel.
    async fn device(&self, user_id: i64, username: &str, key: &SecretKey, name: &str) -> Device {
        let (status, body) = self.register(user_id, key, name).await;
        assert_eq!(status, 200, "{body}");
        let registered: Registered = serde_json::from_value(body).unwrap();
        let mut device = Device {
            key: key.clone(),
            username: username.to_owned(),
            user_id,
            app_password: registered.app_password,
            session: None,
            next_id: 1,
        };
        let welcome = device.open(&self.connect, None).await;
        assert!(matches!(welcome, ServerMessage::Welcome(_)), "{welcome:?}");
        device
    }
}

struct Device {
    key: SecretKey,
    username: String,
    user_id: i64,
    app_password: String,
    session: Option<Session>,
    next_id: u64,
}

impl Device {
    fn id(&self) -> DeviceId {
        self.key.public().into()
    }

    /// Opens the control channel; returns the welcome or the error frame.
    async fn open(
        &mut self,
        connect: &Arc<Connect>,
        settings: Option<SettingsChange>,
    ) -> ServerMessage {
        let login = self.login(connect).await;
        let settings = settings.unwrap_or(SettingsChange {
            accept_remote: Some(true),
            services: Some(vec!["inputshow/1".to_owned()]),
            ..SettingsChange::default()
        });
        match self.hello(connect, login, Some(settings)).await {
            Ok(welcome) => welcome,
            Err(refusal) => serde_json::from_str(&refusal.frame).unwrap(),
        }
    }

    /// Authenticates the upgrade, as the HTTP server does.
    async fn login(&self, connect: &Arc<Connect>) -> DeviceLogin {
        let now = db::unix_now();
        let authenticated = app_passwords::authenticate(
            connect.pool(),
            &self.username,
            &SecretString::from(self.app_password.clone()),
            now,
        )
        .await
        .unwrap()
        .expect("the app password works");
        let device = connect
            .device_for(authenticated.app_password_id)
            .await
            .unwrap()
            .expect("a device's app password");
        DeviceLogin {
            user_id: self.user_id,
            username: self.username.clone(),
            display_name: self.username.clone(),
            device,
            client_ip: "192.0.2.10".parse().unwrap(),
        }
    }

    /// Sends the hello on an authenticated upgrade; returns the welcome or the refusal.
    async fn hello(
        &mut self,
        connect: &Arc<Connect>,
        login: DeviceLogin,
        settings: Option<SettingsChange>,
    ) -> Result<ServerMessage, Refusal> {
        let (handshake, challenge) = connect.challenge();
        let ServerMessage::Challenge { nonce, .. } = serde_json::from_str(&challenge).unwrap()
        else {
            panic!("expected a challenge");
        };
        let hello = ClientMessage::Hello(HelloMessage {
            proof: Signed::sign(
                &Statement::Hello(Hello {
                    server: SERVER.to_owned(),
                    account: self.username.clone(),
                    endpoint_id: self.id(),
                    nonce,
                }),
                &self.key,
            ),
            since: 0,
            version: "1.0.0".to_owned(),
            features: vec!["pairing".to_owned(), "session-reports".to_owned()],
            settings,
        });
        let (session, welcome) = connect
            .hello(handshake, login, &serde_json::to_string(&hello).unwrap())
            .await?;
        self.session = Some(session);
        Ok(serde_json::from_str(&welcome).unwrap())
    }

    /// Sends a request built by `build` with the next id and returns the answer.
    async fn request(&mut self, build: impl FnOnce(u64) -> ClientMessage) -> ServerMessage {
        let id = self.next_id;
        self.next_id += 1;
        let text = serde_json::to_string(&build(id)).unwrap();
        let reply = self.session.as_mut().unwrap().handle(&text).await;
        serde_json::from_str(&reply.text.unwrap()).unwrap()
    }

    /// The next frame queued for the device.
    async fn next(&mut self) -> Outgoing {
        tokio::time::timeout(TIMEOUT, self.session.as_mut().unwrap().next_outgoing())
            .await
            .expect("a frame within the timeout")
    }

    /// Skips frames until one matches `wanted`.
    async fn expect(&mut self, wanted: impl Fn(&ServerMessage) -> bool) -> ServerMessage {
        loop {
            match self.next().await {
                Outgoing::Text(text) => {
                    let message: ServerMessage = serde_json::from_str(&text).unwrap();
                    if wanted(&message) {
                        return message;
                    }
                }
                Outgoing::Close(code, reason) => panic!("closed with {code} {reason}"),
            }
        }
    }

    async fn expect_close(&mut self) -> u16 {
        loop {
            if let Outgoing::Close(code, _) = self.next().await {
                return code;
            }
        }
    }
}

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn error_code(message: &ServerMessage) -> Option<ErrorCode> {
    match message {
        ServerMessage::Error { code, .. } => Some(*code),
        _ => None,
    }
}

#[tokio::test]
async fn registration_ties_a_key_to_one_account() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let bob = f.user("bob", true).await;
    let discovery = f.connect.discovery();
    assert_eq!(discovery.server, SERVER);
    assert_eq!(discovery.websocket, "wss://cloud.example.com/gono/v1/ws");
    assert_eq!(discovery.relay_url, "https://relay.example.com/");

    let (status, body) = f.register(alice, &key(1), "Home PC").await;
    assert_eq!(status, 200, "{body}");
    let registered: Registered = serde_json::from_value(body).unwrap();
    assert_eq!(registered.username, "alice");
    assert_eq!(registered.device.endpoint_id, key(1).public().into());

    let (status, body) = f.register(bob, &key(1), "Bob's PC").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (409, Some("endpoint_taken"))
    );

    let (status, _) = f
        .connect
        .start_login(
            LoginStart {
                endpoint_id: key(2).public().into(),
                product: "Input Show".to_owned(),
                platform: "windows".to_owned(),
                name: "x".to_owned(),
                version: String::new(),
            },
            0,
        )
        .await;
    assert_eq!(status, 400, "product names are slugs");
}

#[tokio::test]
async fn the_hello_must_prove_the_key_for_this_connection() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;

    // A proof for another nonce than this connection's.
    let (status, body) = f.register(alice, &key(2), "Laptop").await;
    assert_eq!(status, 200, "{body}");
    let registered: Registered = serde_json::from_value(body).unwrap();
    let authenticated = app_passwords::authenticate(
        &f.pool,
        "alice",
        &SecretString::from(registered.app_password),
        db::unix_now(),
    )
    .await
    .unwrap()
    .unwrap();
    let device = f
        .connect
        .device_for(authenticated.app_password_id)
        .await
        .unwrap()
        .unwrap();
    let (handshake, _) = f.connect.challenge();
    let hello = ClientMessage::Hello(HelloMessage {
        proof: Signed::sign(
            &Statement::Hello(Hello {
                server: SERVER.to_owned(),
                account: "alice".to_owned(),
                endpoint_id: key(2).public().into(),
                nonce: statement::encode_bytes(&[0; 32]),
            }),
            &key(2),
        ),
        since: 0,
        version: String::new(),
        features: Vec::new(),
        settings: None,
    });
    let login = DeviceLogin {
        user_id: alice,
        username: "alice".to_owned(),
        display_name: "Alice".to_owned(),
        device,
        client_ip: "192.0.2.1".parse().unwrap(),
    };
    let refused = f
        .connect
        .hello(handshake, login, &serde_json::to_string(&hello).unwrap())
        .await
        .unwrap_err();
    assert!(refused.frame.contains("bad_signature"), "{refused:?}");
    assert_eq!(refused.code, 4000);

    // The working device is still alone and online.
    let answer = home.request(|id| ClientMessage::Ack { id, seq: 0 }).await;
    assert!(matches!(answer, ServerMessage::Result { .. }));
}

#[tokio::test]
async fn devices_see_each_other_and_get_addresses_only_through_connect() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let bob = f.user("bob", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    let mut phone = f.device(alice, "alice", &key(2), "Phone").await;
    let mut stranger = f.device(bob, "bob", &key(3), "Bob's PC").await;

    // Home PC hears that the phone came online.
    let updated = home
        .expect(|m| matches!(m, ServerMessage::DeviceUpdated { .. }))
        .await;
    let ServerMessage::DeviceUpdated { device } = updated else {
        unreachable!()
    };
    assert_eq!(device.endpoint_id, phone.id());
    assert!(device.online);

    let published = home
        .request(|id| ClientMessage::Publish {
            id,
            relay_url: Some("https://relay.example.com/".to_owned()),
            direct: vec!["192.0.2.10:51820".parse().unwrap()],
        })
        .await;
    assert!(
        matches!(published, ServerMessage::Result { .. }),
        "{published:?}"
    );
    let foreign = home
        .request(|id| ClientMessage::Publish {
            id,
            relay_url: Some("https://other-relay.example.com/".to_owned()),
            direct: Vec::new(),
        })
        .await;
    assert_eq!(error_code(&foreign), Some(ErrorCode::BadRequest));
    // Addresses no peer can reach are refused (protocol 7.1); the refusal checks before the
    // rate limit, so this does not use up the one publish per second either.
    for unreachable in [
        "127.0.0.1:24850",
        "[::ffff:127.0.0.1]:24850",
        "224.0.0.251:5353",
    ] {
        let refused = home
            .request(|id| ClientMessage::Publish {
                id,
                relay_url: Some("https://relay.example.com/".to_owned()),
                direct: vec![
                    "192.0.2.10:51820".parse().unwrap(),
                    unreachable.parse().unwrap(),
                ],
            })
            .await;
        assert_eq!(
            error_code(&refused),
            Some(ErrorCode::BadRequest),
            "{unreachable}"
        );
    }

    // No lookup before connect.
    let home_id = home.id();
    let early = phone
        .request(|id| ClientMessage::Lookup {
            id,
            target: home_id,
        })
        .await;
    assert_eq!(error_code(&early), Some(ErrorCode::NotPermitted));

    let answer = phone
        .request(|id| ClientMessage::Connect {
            id,
            target: home_id,
            service: "inputshow/1".to_owned(),
            purpose: Purpose::Session,
            request_id: None,
        })
        .await;
    let ServerMessage::Result { fields, .. } = &answer else {
        panic!("{answer:?}");
    };
    assert_eq!(fields["direct"], serde_json::json!(["192.0.2.10:51820"]));
    let incoming = home
        .expect(|m| matches!(m, ServerMessage::Incoming { .. }))
        .await;
    assert!(matches!(incoming, ServerMessage::Incoming { from, .. } if from == phone.id()));
    let lookup = phone
        .request(|id| ClientMessage::Lookup {
            id,
            target: home_id,
        })
        .await;
    assert!(matches!(lookup, ServerMessage::Result { .. }), "{lookup:?}");

    // A service the target does not accept, and devices of other accounts.
    let wrong_service = phone
        .request(|id| ClientMessage::Connect {
            id,
            target: home_id,
            service: "other/1".to_owned(),
            purpose: Purpose::Session,
            request_id: None,
        })
        .await;
    assert_eq!(error_code(&wrong_service), Some(ErrorCode::NotPermitted));
    let other_account = stranger
        .request(|id| ClientMessage::Connect {
            id,
            target: home_id,
            service: "inputshow/1".to_owned(),
            purpose: Purpose::Session,
            request_id: None,
        })
        .await;
    assert_eq!(error_code(&other_account), Some(ErrorCode::NotFound));

    let kinds: Vec<String> = gono_server_core::audit::list(&f.pool, Some(alice), None, 50)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.kind)
        .collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| *kind == "connect.requested")
            .count(),
        2,
        "every connect is recorded, refused ones too: {kinds:?}"
    );
}

fn report(peer: DeviceId, event: SessionEvent) -> SessionReport {
    SessionReport {
        event,
        session_id: statement::encode_bytes(&[7; 16]),
        peer,
        role: "controller".to_owned(),
        service: "inputshow/1".to_owned(),
        started_at: db::unix_now(),
        ended_at: None,
        path: "direct".to_owned(),
        bytes_direct: None,
        bytes_relayed: None,
    }
}

#[tokio::test]
async fn neither_session_reports_nor_reconnects_get_around_connect() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    let mut phone = f.device(alice, "alice", &key(2), "Phone").await;
    let home_id = home.id();

    // A session report does not stand in for a connect.
    let reported = phone
        .request(|id| ClientMessage::Session {
            id,
            report: report(home_id, SessionEvent::Started),
        })
        .await;
    assert_eq!(error_code(&reported), Some(ErrorCode::NotPermitted));
    let lookup = phone
        .request(|id| ClientMessage::Lookup {
            id,
            target: home_id,
        })
        .await;
    assert_eq!(error_code(&lookup), Some(ErrorCode::NotPermitted));
    // Malformed fields never reach the audit log.
    let mut malformed = report(home_id, SessionEvent::Started);
    malformed.session_id = "x".repeat(2000);
    let answer = phone
        .request(|id| ClientMessage::Session {
            id,
            report: malformed,
        })
        .await;
    assert_eq!(error_code(&answer), Some(ErrorCode::BadRequest));

    let connect = |id| ClientMessage::Connect {
        id,
        target: home_id,
        service: "inputshow/1".to_owned(),
        purpose: Purpose::Session,
        request_id: None,
    };
    let answer = phone.request(connect).await;
    assert!(matches!(answer, ServerMessage::Result { .. }), "{answer:?}");
    // The target stops accepting remote sessions: lookups that relied on the connect stop.
    let changed = home
        .request(|id| ClientMessage::Settings {
            id,
            change: SettingsChange {
                accept_remote: Some(false),
                ..SettingsChange::default()
            },
        })
        .await;
    assert!(
        matches!(changed, ServerMessage::Result { .. }),
        "{changed:?}"
    );
    let lookup = phone
        .request(|id| ClientMessage::Lookup {
            id,
            target: home_id,
        })
        .await;
    assert_eq!(error_code(&lookup), Some(ErrorCode::NotPermitted));
    // A session after an allowed connect is fine, and opens lookups.
    let reported = phone
        .request(|id| ClientMessage::Session {
            id,
            report: report(home_id, SessionEvent::Started),
        })
        .await;
    assert!(
        matches!(reported, ServerMessage::Result { .. }),
        "{reported:?}"
    );

    // The per-minute limit of connect survives a reconnect.
    for _ in 1..gono_protocol::connect::limits::CONNECTS_PER_MINUTE {
        phone.request(connect).await;
    }
    let welcome = phone.open(&f.connect, None).await;
    assert!(matches!(welcome, ServerMessage::Welcome(_)), "{welcome:?}");
    let limited = phone.request(connect).await;
    assert_eq!(error_code(&limited), Some(ErrorCode::RateLimited));
}

#[tokio::test]
async fn remote_access_needs_two_step_verification() {
    let f = fixture().await;
    let carol = f.user("carol", false).await;
    let mut first = f.device(carol, "carol", &key(1), "a").await;
    let second = f.device(carol, "carol", &key(2), "b").await;
    let target = second.id();
    let answer = first
        .request(|id| ClientMessage::Connect {
            id,
            target,
            service: "inputshow/1".to_owned(),
            purpose: Purpose::Session,
            request_id: None,
        })
        .await;
    assert_eq!(error_code(&answer), Some(ErrorCode::TwoFactorRequired));
    assert!(devices::admissible(&f.pool, true).await.unwrap().is_empty());
    assert!(f.connect.discovery().two_factor_required);
}

#[tokio::test]
async fn remote_access_needs_no_two_step_verification_unless_required() {
    // `connect.require_two_factor = false`, the development default (plan R10).
    let f = fixture_with(false).await;
    assert!(!f.connect.discovery().two_factor_required);
    let carol = f.user("carol", false).await;
    let mut phone = f.device(carol, "carol", &key(1), "a").await;
    let home = f.device(carol, "carol", &key(2), "b").await;
    let target = home.id();
    let answer = phone
        .request(|id| ClientMessage::Connect {
            id,
            target,
            service: "inputshow/1".to_owned(),
            purpose: Purpose::Session,
            request_id: None,
        })
        .await;
    assert!(matches!(answer, ServerMessage::Result { .. }), "{answer:?}");
    let lookup = phone
        .request(|id| ClientMessage::Lookup { id, target })
        .await;
    assert!(matches!(lookup, ServerMessage::Result { .. }), "{lookup:?}");

    let directory = f.connect.directory();
    directory.refresh().await.unwrap();
    for seed in [1, 2] {
        assert!(directory.admits(&key(seed).public()), "device {seed}");
    }
}

#[tokio::test]
async fn a_newer_connection_replaces_the_older_one() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    let mut again = Device {
        key: home.key.clone(),
        username: home.username.clone(),
        user_id: alice,
        app_password: home.app_password.clone(),
        session: None,
        next_id: 1,
    };
    let welcome = again.open(&f.connect, None).await;
    assert!(matches!(welcome, ServerMessage::Welcome(_)), "{welcome:?}");
    assert_eq!(home.expect_close().await, 4001);
}

#[tokio::test]
async fn an_approval_reaches_the_introduced_devices_and_the_newcomer() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    let mut phone = f.device(alice, "alice", &key(2), "Phone").await;
    let mut work = f.device(alice, "alice", &key(3), "Work PC").await;

    let nonce = statement::encode_bytes(&[9; 32]);
    let request_from = |name: &str, platform: &str| {
        Signed::sign(
            &Statement::PairRequest(PairRequest {
                server: SERVER.to_owned(),
                account: "alice".to_owned(),
                requester: DeviceSummary {
                    endpoint_id: work.id(),
                    name: name.to_owned(),
                    platform: platform.to_owned(),
                    product: "input-show".to_owned(),
                },
                nonce: nonce.clone(),
                issued_at: db::unix_now(),
            }),
            &work.key,
        )
    };
    let request = request_from("Work PC", "windows");
    // Statements are relayed unchanged, so their names must be trimmed already, and approvers
    // show the platform next to the name (protocol 2.1).
    let malformed = [
        request_from("Work PC\n\n\n", "windows"),
        request_from("\u{3000}Work PC", "windows"),
        request_from("Work PC", "ios\u{202E}"),
        request_from("Work PC", "Windows"),
    ];
    for bad in malformed {
        let refused = work
            .request(|id| ClientMessage::PairRequest { id, request: bad })
            .await;
        assert_eq!(error_code(&refused), Some(ErrorCode::BadRequest));
    }
    let answer = work
        .request(|id| ClientMessage::PairRequest {
            id,
            request: request.clone(),
        })
        .await;
    let ServerMessage::Result { fields, .. } = &answer else {
        panic!("{answer:?}");
    };
    let request_id = fields["request_id"].as_str().unwrap().to_owned();
    let again = work
        .request(|id| ClientMessage::PairRequest {
            id,
            request: request.clone(),
        })
        .await;
    assert_eq!(
        error_code(&again),
        Some(ErrorCode::Conflict),
        "one pending per device"
    );

    let requested = phone
        .expect(|m| matches!(m, ServerMessage::PairRequested(_)))
        .await;
    assert!(matches!(requested, ServerMessage::PairRequested(r) if r.request_id == request_id));

    // The approver dials the newcomer for the comparison code, although it does not accept
    // remote connections.
    work.request(|id| ClientMessage::Settings {
        id,
        change: SettingsChange {
            accept_remote: Some(false),
            ..SettingsChange::default()
        },
    })
    .await;
    let work_id = work.id();
    let dial = phone
        .request(|id| ClientMessage::Connect {
            id,
            target: work_id,
            service: "inputshow/1".to_owned(),
            purpose: Purpose::Pair,
            request_id: Some(request_id.clone()),
        })
        .await;
    assert!(matches!(dial, ServerMessage::Result { .. }), "{dial:?}");
    let incoming = work
        .expect(|m| matches!(m, ServerMessage::Incoming { .. }))
        .await;
    assert!(matches!(
        incoming,
        ServerMessage::Incoming { purpose: Purpose::Pair, request_id: Some(ref id), .. } if *id == request_id
    ));

    let now = db::unix_now();
    let (phone_id, phone_key, home_id) = (phone.id(), phone.key.clone(), home.id());
    let approval_from = |nonce: &str, issued_at: i64, expires_at: i64, platform: &str| {
        Signed::sign(
            &Statement::PairApproval(PairApproval {
                server: SERVER.to_owned(),
                account: "alice".to_owned(),
                approver: phone_id,
                subject: DeviceSummary {
                    endpoint_id: work_id,
                    name: "Work PC".to_owned(),
                    platform: platform.to_owned(),
                    product: "input-show".to_owned(),
                },
                request_nonce: nonce.to_owned(),
                method: "remote-sas".to_owned(),
                introduced: vec![Introduced {
                    endpoint_id: home_id,
                    name: "Home PC".to_owned(),
                    allow_incoming: true,
                    allow_outgoing: false,
                }],
                issued_at,
                expires_at,
            }),
            &phone_key,
        )
    };
    let approval_at = |nonce: &str, issued_at: i64, expires_at: i64| {
        approval_from(nonce, issued_at, expires_at, "windows")
    };
    let approval = |nonce: &str| approval_at(nonce, now, now + 3600);
    let bad_platform = phone
        .request(|id| ClientMessage::PairApprove {
            id,
            request_id: request_id.clone(),
            approval: approval_from(&nonce, now, now + 3600, "ios\u{202E}"),
        })
        .await;
    assert_eq!(error_code(&bad_platform), Some(ErrorCode::BadRequest));
    let wrong_nonce = phone
        .request(|id| ClientMessage::PairApprove {
            id,
            request_id: request_id.clone(),
            approval: approval("AAAA"),
        })
        .await;
    assert_eq!(error_code(&wrong_nonce), Some(ErrorCode::BadRequest));
    // Lifetimes from the device must neither overflow nor dodge the 30-day cap.
    for (issued_at, expires_at) in [
        (-1, i64::MAX),
        (i64::MIN, now + 60),
        (now - 86_400, now + 60),
    ] {
        let unbounded = phone
            .request(|id| ClientMessage::PairApprove {
                id,
                request_id: request_id.clone(),
                approval: approval_at(&nonce, issued_at, expires_at),
            })
            .await;
        assert_eq!(
            error_code(&unbounded),
            Some(ErrorCode::BadRequest),
            "{issued_at} {expires_at}"
        );
    }
    let approved = phone
        .request(|id| ClientMessage::PairApprove {
            id,
            request_id: request_id.clone(),
            approval: approval(&nonce),
        })
        .await;
    assert!(
        matches!(approved, ServerMessage::Result { .. }),
        "{approved:?}"
    );

    for device in [&mut home, &mut work] {
        let event = device
            .expect(|m| matches!(m, ServerMessage::PairApproved { .. }))
            .await;
        let ServerMessage::PairApproved { approval, .. } = event else {
            unreachable!()
        };
        let Statement::PairApproval(opened) = approval.open().unwrap() else {
            panic!("an approval");
        };
        assert_eq!(opened.subject.endpoint_id, work_id);
    }
    let introduced = devices::introduced_by(
        &f.pool,
        devices::find(&f.pool, EndpointId(*phone.id().as_bytes()))
            .await
            .unwrap()
            .unwrap()
            .id,
    )
    .await
    .unwrap();
    assert_eq!(introduced.len(), 1);
}

#[tokio::test]
async fn a_revoked_device_is_closed_and_the_others_hear_of_it() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    let mut laptop = f.device(alice, "alice", &key(2), "Laptop").await;
    assert_eq!(devices::admissible(&f.pool, true).await.unwrap().len(), 2);

    let laptop_key = EndpointId(*laptop.id().as_bytes());
    let revoked = devices::revoke(
        &f.pool,
        alice,
        &[laptop_key],
        RevokedBy::AccountPage,
        None,
        db::unix_now(),
    )
    .await
    .unwrap();
    assert_eq!(revoked.len(), 1);
    f.connect.poke();

    assert_eq!(laptop.expect_close().await, 4003);
    let event = home
        .expect(|m| matches!(m, ServerMessage::DeviceRevoked { .. }))
        .await;
    assert!(
        matches!(event, ServerMessage::DeviceRevoked { endpoint_id, .. } if endpoint_id == laptop.id())
    );

    // Home PC applies it, which the server records.
    let laptop_id = laptop.id();
    let applied = home
        .request(|id| ClientMessage::RevocationsApplied {
            id,
            endpoint_ids: vec![laptop_id],
        })
        .await;
    assert!(matches!(applied, ServerMessage::Result { .. }));
    assert_eq!(devices::applied(&f.pool, alice).await.unwrap().len(), 1);

    // The revoked credential no longer opens the channel.
    assert!(
        app_passwords::authenticate(
            &f.pool,
            "alice",
            &SecretString::from(laptop.app_password.clone()),
            db::unix_now(),
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[tokio::test]
async fn signing_out_keeps_the_key_bound_to_the_account() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let bob = f.user("bob", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    let mut phone = f.device(alice, "alice", &key(2), "Phone").await;
    let left = phone.request(|id| ClientMessage::Leave { id }).await;
    assert!(matches!(left, ServerMessage::Result { .. }));
    let removed = home
        .expect(|m| matches!(m, ServerMessage::DeviceRemoved { .. }))
        .await;
    assert!(
        matches!(removed, ServerMessage::DeviceRemoved { endpoint_id, .. } if endpoint_id == phone.id())
    );
    // The entry stays, signed out, and is not in the devices' directory.
    let listed = devices::list(&f.pool, alice).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[1].is_signed_out());
    let ServerMessage::Welcome(welcome) = home.open(&f.connect, None).await else {
        panic!("expected a welcome");
    };
    assert_eq!(welcome.devices.len(), 1);
    // Another account cannot take the key over.
    let (status, body) = f.register(bob, &key(2), "Not Bob's").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (409, Some("endpoint_taken"))
    );
    // The same account can register it again, and the other devices hear of it.
    let (status, body) = f.register(alice, &key(2), "Phone").await;
    assert_eq!(status, 200, "{body}");
    let added = home
        .expect(|m| matches!(m, ServerMessage::DeviceAdded { .. }))
        .await;
    assert!(matches!(added, ServerMessage::DeviceAdded { .. }));
    assert!(
        devices::list(&f.pool, alice).await.unwrap()[1].is_active(),
        "registered again"
    );
}

#[tokio::test]
async fn a_signed_out_device_can_still_be_revoked() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    let mut phone = f.device(alice, "alice", &key(2), "Phone").await;
    let left = phone.request(|id| ClientMessage::Leave { id }).await;
    assert!(matches!(left, ServerMessage::Result { .. }));
    let revoked = devices::revoke(
        &f.pool,
        alice,
        &[EndpointId(*key(2).public().as_bytes())],
        RevokedBy::AccountPage,
        None,
        db::unix_now(),
    )
    .await
    .unwrap();
    assert_eq!(revoked.len(), 1);
    home.expect(|m| matches!(m, ServerMessage::DeviceRevoked { .. }))
        .await;
    let (status, body) = f.register(alice, &key(2), "Phone").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (409, Some("endpoint_revoked"))
    );
}

#[tokio::test]
async fn a_revocation_during_the_handshake_refuses_the_hello() {
    let f = fixture().await;
    let alice = f.user("alice", true).await;
    let mut home = f.device(alice, "alice", &key(1), "Home PC").await;
    // The upgrade is authenticated, then the device is revoked before its hello.
    let login = home.login(&f.connect).await;
    devices::revoke(
        &f.pool,
        alice,
        &[EndpointId(*key(1).public().as_bytes())],
        RevokedBy::Cli,
        None,
        db::unix_now(),
    )
    .await
    .unwrap();
    // Without settings, nothing reads the device again before the connection is registered.
    let mut second = Device {
        session: None,
        app_password: home.app_password.clone(),
        key: home.key.clone(),
        username: home.username.clone(),
        user_id: home.user_id,
        next_id: 1,
    };
    let refusal = second.hello(&f.connect, login, None).await.unwrap_err();
    assert_eq!(refusal.code, 4003, "{refusal:?}");
    assert!(
        !f.connect
            .is_online(alice, EndpointId(*key(1).public().as_bytes()))
    );
    // The first connection was replaced by the refused one; it ends either way.
    let code = home.expect_close().await;
    assert!(code == 4001 || code == 4003, "{code}");
}
