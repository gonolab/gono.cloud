//! Remote connectivity endpoints (see [`gono_server_connect`] and `docs/connect-protocol.md`).
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /gono/v1/connect` | The discovery document. Anonymous. |
//! | `POST /gono/v1/login` | Starts a device registration. Anonymous; limited per client address like Login Flow v2. |
//! | `POST /gono/v1/login/poll` | `202` while pending, the device's credential once its proof holds. |
//! | `GET /gono/v1/ws` (WebSocket upgrade) | The control channel, authenticated with the device's app password. |
//! | `DELETE /gono/v1/device` | Signs the device out (no tombstone). |
//!
//! The routes exist only while remote connectivity is on: the relay is enabled and
//! `server.base_url` is HTTPS (or a loopback host). The browser pages that grant a
//! registration are the Login Flow v2 pages ([`crate::login_flow`]).
//!
//! A control connection: the upgrade is authenticated like WebDAV (Basic with the app password,
//! the shared limiter of failures); the `challenge` frame follows at once; `hello` must arrive
//! within [`limits::HELLO_TIMEOUT_SECS`]; then frames go between the socket and the
//! [`Session`]. Every [`limits::PING_INTERVAL_SECS`] the server checks the device
//! ([`Session::check`]) and pings; a device that has sent nothing since the previous ping is
//! disconnected.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use gono_protocol::connect::{LoginStart, PollRequest, close, limits};
use gono_server_connect::{Connect, DeviceLogin, Outgoing, Session};
use gono_server_core::{audit::Actor, db};

use crate::{
    app::{AppState, authenticate},
    client_ip::client_ip,
};

/// How long a close frame may take to send.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

fn json(status: u16, value: &serde_json::Value) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, serde_json::to_vec(value).unwrap_or_default()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn bad_request(message: &str) -> Response {
    json(
        400,
        &serde_json::json!({ "error": "bad_request", "message": message }),
    )
}

fn connect_of(state: &AppState) -> Result<Arc<Connect>, Box<Response>> {
    state
        .connect
        .clone()
        .ok_or_else(|| Box::new(StatusCode::NOT_FOUND.into_response()))
}

/// `GET /gono/v1/connect`.
pub async fn discovery(State(state): State<AppState>) -> Response {
    match connect_of(&state) {
        Ok(connect) => json(
            200,
            &serde_json::to_value(connect.discovery()).unwrap_or_default(),
        ),
        Err(response) => *response,
    }
}

/// `POST /gono/v1/login`.
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let connect = match connect_of(&state) {
        Ok(connect) => connect,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Some(wait) = state.flow_starts.check(client) {
        let mut response = json(429, &serde_json::json!({ "error": "rate_limited" }));
        if let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    // Every start costs one token of this client's bucket, as for Login Flow v2.
    state.flow_starts.record_failure(client);
    if body.len() > limits::MAX_FRAME_BYTES {
        return bad_request("the body is too large");
    }
    let start: LoginStart = match serde_json::from_slice(&body) {
        Ok(start) => start,
        Err(_) => return bad_request("expected a registration request"),
    };
    let (status, body) = connect.start_login(start, db::unix_now()).await;
    json(status, &body)
}

/// `POST /gono/v1/login/poll`.
pub async fn poll(State(state): State<AppState>, body: Bytes) -> Response {
    let connect = match connect_of(&state) {
        Ok(connect) => connect,
        Err(response) => return *response,
    };
    if body.len() > limits::MAX_FRAME_BYTES {
        return bad_request("the body is too large");
    }
    let poll: PollRequest = match serde_json::from_slice(&body) {
        Ok(poll) => poll,
        Err(_) => return bad_request("expected a poll request"),
    };
    let (status, body) = connect.poll_login(poll, db::unix_now()).await;
    json(status, &body)
}

/// The device an authenticated request comes from, or the answer that refuses it.
async fn device_login(
    state: &AppState,
    connect: &Connect,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<DeviceLogin, Box<Response>> {
    let identity = authenticate(state, peer, headers)
        .await
        .map_err(|rejection| Box::new(rejection.into_response()))?;
    let Some(app_password_id) = identity.app_password_id else {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    };
    let device = match connect.device_for(app_password_id).await {
        Ok(Some(device)) => device,
        Ok(None) => return Err(Box::new(StatusCode::FORBIDDEN.into_response())),
        Err(err) => {
            tracing::error!(error = %err, "cannot read the device directory");
            return Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()));
        }
    };
    Ok(DeviceLogin {
        user_id: identity.user_id,
        username: identity.username.as_str().to_owned(),
        display_name: identity.display_name.clone(),
        device,
        client_ip: client_ip(peer.ip(), headers, &state.trusted_proxies),
    })
}

/// `DELETE /gono/v1/device`.
pub async fn sign_out(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let connect = match connect_of(&state) {
        Ok(connect) => connect,
        Err(response) => return *response,
    };
    let login = match device_login(&state, &connect, peer, &headers).await {
        Ok(login) => login,
        Err(response) => return *response,
    };
    match connect.sign_out(&login.device, Actor::Device).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::error!(error = %err, "cannot sign a device out");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// `GET /gono/v1/ws`.
pub async fn websocket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let connect = match connect_of(&state) {
        Ok(connect) => connect,
        Err(response) => return *response,
    };
    let login = match device_login(&state, &connect, peer, &headers).await {
        Ok(login) => login,
        Err(response) => return *response,
    };
    upgrade
        .max_message_size(limits::MAX_FRAME_BYTES)
        .max_frame_size(limits::MAX_FRAME_BYTES)
        .on_upgrade(move |socket| serve(socket, connect, login))
}

/// One control connection, from the challenge to the close.
async fn serve(mut socket: WebSocket, connect: Arc<Connect>, login: DeviceLogin) {
    let client = login.client_ip;
    let (handshake, challenge) = connect.challenge();
    if !send_within(&mut socket, Message::text(challenge), CLOSE_TIMEOUT).await {
        return;
    }
    let hello = tokio::time::timeout(
        Duration::from_secs(limits::HELLO_TIMEOUT_SECS),
        read_text(&mut socket),
    )
    .await;
    let hello = match hello {
        Ok(Some(text)) => text,
        Ok(None) => return,
        Err(_) => {
            close_with(&mut socket, close::TIMED_OUT, "no hello").await;
            return;
        }
    };
    let (session, welcome) = match connect.hello(handshake, login, &hello).await {
        Ok(opened) => opened,
        Err(refusal) => {
            tracing::info!(
                %client,
                code = refusal.code,
                reason = refusal.reason,
                "device control connection refused at the handshake"
            );
            if send_within(&mut socket, Message::text(refusal.frame), CLOSE_TIMEOUT).await {
                close_with(&mut socket, refusal.code, refusal.reason).await;
            }
            return;
        }
    };
    if !send_within(&mut socket, Message::text(welcome), CLOSE_TIMEOUT).await {
        return;
    }
    let ended = stream(&mut socket, session, client).await;
    tracing::debug!(%client, reason = ended, "device control connection ended");
}

/// The next text frame, skipping pings and pongs; `None` when the connection ended or the
/// device sent something else.
async fn read_text(socket: &mut WebSocket) -> Option<String> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => return Some(text.as_str().to_owned()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(Message::Binary(_))) => {
                close_with(socket, close::PROTOCOL, "text frames only").await;
                return None;
            }
            Some(Ok(Message::Close(_)) | Err(_)) | None => return None,
        }
    }
}

/// Moves frames until the connection ends; returns why it ended.
async fn stream(socket: &mut WebSocket, mut session: Session, client: IpAddr) -> &'static str {
    let interval = Duration::from_secs(limits::PING_INTERVAL_SECS);
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut awaiting = false;
    loop {
        tokio::select! {
            frame = socket.recv() => {
                awaiting = false;
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        let reply = session.handle(text.as_str()).await;
                        if let Some(text) = reply.text
                            && !send_within(socket, Message::text(text), interval).await
                        {
                            return "send failed or timed out";
                        }
                        if let Some((code, reason)) = reply.close {
                            close_with(socket, code, reason).await;
                            return reason;
                        }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Binary(_))) => {
                        close_with(socket, close::PROTOCOL, "text frames only").await;
                        return "binary frame";
                    }
                    Some(Ok(Message::Close(_))) | None => return "closed by the device",
                    Some(Err(err)) if too_large(&err) => {
                        close_with(socket, 1009, "frame too large").await;
                        return "frame too large";
                    }
                    Some(Err(_)) => return "connection broke",
                }
            }
            outgoing = session.next_outgoing() => match outgoing {
                Outgoing::Text(text) => {
                    if !send_within(socket, Message::text(text), interval).await {
                        return "send failed or timed out";
                    }
                }
                Outgoing::Close(code, reason) => {
                    tracing::info!(%client, code, reason, "closing a device control connection");
                    close_with(socket, code, reason).await;
                    return reason;
                }
            },
            _ = ping.tick() => {
                if awaiting {
                    close_with(socket, close::TIMED_OUT, "ping timeout").await;
                    return "no answer to ping";
                }
                if let Some((code, reason)) = session.check().await {
                    close_with(socket, code, reason).await;
                    return reason;
                }
                if !send_within(socket, Message::Ping(Bytes::new()), interval).await {
                    return "send failed or timed out";
                }
                awaiting = true;
            }
        }
    }
}

/// Whether a read failed because the device sent a frame or message over the limit.
fn too_large(err: &axum::Error) -> bool {
    std::error::Error::source(err)
        .and_then(|source| source.downcast_ref::<tungstenite::Error>())
        .is_some_and(|err| matches!(err, tungstenite::Error::Capacity(_)))
}

/// Sends a close frame (best effort).
async fn close_with(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    send_within(socket, Message::Close(Some(frame)), CLOSE_TIMEOUT).await;
}

/// Sends a frame, giving up after `limit`: a device that stopped reading must not hold the
/// connection task up.
async fn send_within(socket: &mut WebSocket, message: Message, limit: Duration) -> bool {
    matches!(
        tokio::time::timeout(limit, socket.send(message)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use futures_util::{SinkExt as _, StreamExt as _};
    use gono_protocol::connect::{
        ClientMessage, LoginStarted, Registered, ServerMessage, Signed, Statement,
        message::{HelloMessage, Purpose, SettingsChange},
        paths,
        statement::{Hello, Login},
    };
    use gono_server_connect::ConnectConfig;
    use gono_server_core::{
        Username,
        config::DbConfig,
        db::{self, OpenMode},
        devices::{self, EndpointId, RevokedBy},
        login_flows,
        storage::DataLayout,
        users::{self, NewUser},
        web_sessions,
    };
    use gono_server_nextcloud::chunking::ChunkedUploads;
    use http_body_util::BodyExt as _;
    use iroh_base::SecretKey;
    use secrecy::ExposeSecret as _;
    use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest as _};
    use tower::ServiceExt as _;
    use url::Url;

    use super::*;
    use crate::{auth::Authenticator, ratelimit::RateLimiter, web::Web};

    type Client = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    struct Fixture {
        _dir: tempfile::TempDir,
        state: AppState,
        address: SocketAddr,
        alice: i64,
    }

    async fn fixture(two_factor: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path().join("data"));
        layout.create().unwrap();
        let config = DbConfig {
            path: dir.path().join("db.sqlite"),
            max_connections: 4,
            busy_timeout_secs: 5,
        };
        let pool = db::connect(&config, OpenMode::CreateIfMissing)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let username = Username::new("alice").unwrap();
        let alice = users::create(
            &pool,
            &NewUser {
                username: &username,
                display_name: "Alice",
                password_hash: "x",
                is_admin: false,
            },
            |id| layout.create_user(id),
        )
        .await
        .unwrap();
        if two_factor {
            sqlx::query(
                "INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (?1, x'00', 0)",
            )
            .bind(alice)
            .execute(&pool)
            .await
            .unwrap();
        }
        let meta = gono_server_core::meta::MetaStore::new(pool.clone());
        let dav = crate::commands::serve::dav_service(Duration::from_secs(600), layout, meta)
            .await
            .unwrap();
        let uploads = ChunkedUploads::new(
            dav.fs().clone(),
            gono_server_core::locks::LockStore::new(pool.clone()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = Url::parse(&format!("http://{address}")).unwrap();
        let connect = Connect::new(
            pool.clone(),
            ConnectConfig {
                base_url: base_url.clone(),
                relay_url: "https://relay.example.com".parse().unwrap(),
                audit_retention_secs: 3600,
            },
        )
        .await
        .unwrap();
        tokio::spawn(Arc::clone(&connect).run());
        let limiter = Arc::new(RateLimiter::new());
        let state = AppState {
            db: pool.clone(),
            auth: Arc::new(Authenticator::new(pool.clone(), limiter.clone())),
            dav,
            uploads,
            web: Arc::new(Web::new(pool, limiter, &base_url)),
            base_url: Arc::new(base_url),
            flow_starts: Arc::new(RateLimiter::new()),
            trusted_proxies: Arc::new(Vec::new()),
            push: None,
            admin: None,
            files: None,
            connect: Some(connect),
        };
        let app = crate::app::router(state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Fixture {
            _dir: dir,
            state,
            address,
            alice,
        }
    }

    impl Fixture {
        fn origin(&self) -> String {
            format!("http://{}", self.address)
        }

        async fn send(
            &self,
            method: &str,
            uri: &str,
            headers: &[(&str, &str)],
            body: String,
        ) -> (StatusCode, String) {
            let mut request = Request::builder().method(method).uri(uri);
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let mut request = request.body(Body::from(body)).unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 4000))));
            let response = crate::app::router(self.state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&body).into_owned())
        }

        /// Starts a registration of `key`; returns the answer and the login token.
        async fn start(&self, key: &SecretKey, name: &str) -> (LoginStarted, String) {
            let body = serde_json::json!({
                "endpoint_id": DeviceIdOf(key).hex(),
                "product": "input-show",
                "platform": "windows",
                "name": name,
            });
            let (status, body) = self.send("POST", paths::LOGIN, &[], body.to_string()).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let started: LoginStarted = serde_json::from_str(&body).unwrap();
            let token = started.login_url.rsplit('/').next().unwrap().to_owned();
            (started, token)
        }

        async fn poll(&self, key: &SecretKey, started: &LoginStarted) -> (StatusCode, String) {
            let proof = Signed::sign(
                &Statement::Login(Login {
                    server: self.origin(),
                    endpoint_id: key.public().into(),
                    challenge: started.challenge.clone(),
                }),
                key,
            );
            let body = serde_json::json!({ "token": started.poll.token, "proof": proof });
            self.send("POST", paths::LOGIN_POLL, &[], body.to_string())
                .await
        }

        /// Registers `key`, granting the flow directly, and returns its app password.
        async fn register(&self, key: &SecretKey, name: &str) -> String {
            let (started, token) = self.start(key, name).await;
            let flow = login_flows::find(&self.state.db, &token, db::unix_now())
                .await
                .unwrap()
                .unwrap();
            login_flows::grant(&self.state.db, flow.id, self.alice, None, db::unix_now())
                .await
                .unwrap();
            let (status, body) = self.poll(key, &started).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let registered: Registered = serde_json::from_str(&body).unwrap();
            registered.app_password
        }

        /// Opens the control channel of `key`; returns the socket after the welcome.
        async fn open(&self, key: &SecretKey, app_password: &str) -> (Client, ServerMessage) {
            let mut request = format!("ws://{}{}", self.address, paths::WEBSOCKET)
                .into_client_request()
                .unwrap();
            let credentials = STANDARD.encode(format!("alice:{app_password}"));
            request.headers_mut().insert(
                "authorization",
                format!("Basic {credentials}").parse().unwrap(),
            );
            let (mut client, _) = tokio_tungstenite::connect_async(request).await.unwrap();
            let ServerMessage::Challenge { nonce, .. } = next(&mut client).await else {
                panic!("expected a challenge");
            };
            let hello = ClientMessage::Hello(HelloMessage {
                proof: Signed::sign(
                    &Statement::Hello(Hello {
                        server: self.origin(),
                        account: "alice".to_owned(),
                        endpoint_id: key.public().into(),
                        nonce,
                    }),
                    key,
                ),
                since: 0,
                version: "1.0.0".to_owned(),
                features: Vec::new(),
                settings: Some(SettingsChange {
                    accept_remote: Some(true),
                    services: Some(vec!["inputshow/1".to_owned()]),
                    ..SettingsChange::default()
                }),
            });
            client
                .send(tungstenite::Message::text(
                    serde_json::to_string(&hello).unwrap(),
                ))
                .await
                .unwrap();
            let welcome = next(&mut client).await;
            (client, welcome)
        }
    }

    struct DeviceIdOf<'a>(&'a SecretKey);

    impl DeviceIdOf<'_> {
        fn hex(&self) -> String {
            gono_protocol::connect::DeviceId::from(self.0.public()).to_hex()
        }
    }

    async fn next(client: &mut Client) -> ServerMessage {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), client.next())
                .await
                .expect("a frame within the timeout")
                .expect("the connection is open")
                .unwrap();
            if let tungstenite::Message::Text(text) = frame {
                return serde_json::from_str(text.as_str()).unwrap();
            }
        }
    }

    /// Skips frames until one matches `wanted`.
    async fn expect(client: &mut Client, wanted: impl Fn(&ServerMessage) -> bool) -> ServerMessage {
        loop {
            let message = next(client).await;
            if wanted(&message) {
                return message;
            }
        }
    }

    /// The close code of the connection's end.
    async fn closed(client: &mut Client) -> Option<u16> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), client.next())
                .await
                .expect("the close within the timeout")
            {
                Some(Ok(tungstenite::Message::Close(frame))) => {
                    return frame.map(|frame| u16::from(frame.code));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return None,
            }
        }
    }

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    #[tokio::test]
    async fn devices_register_and_reach_each_other_over_the_control_channel() {
        let f = fixture(true).await;
        let (status, body) = f.send("GET", paths::DISCOVERY, &[], String::new()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"two_factor_required\":true"), "{body}");

        let home_password = f.register(&key(1), "Home PC").await;
        let phone_password = f.register(&key(2), "Phone").await;
        let (mut home, welcome) = f.open(&key(1), &home_password).await;
        assert!(
            matches!(welcome, ServerMessage::Welcome(ref w) if w.account.remote_access),
            "{welcome:?}"
        );
        let (mut phone, _) = f.open(&key(2), &phone_password).await;
        assert!(matches!(
            next(&mut home).await,
            ServerMessage::DeviceUpdated { .. }
        ));

        let target = gono_protocol::connect::DeviceId::from(key(1).public());
        let connect = ClientMessage::Connect {
            id: 1,
            target,
            service: "inputshow/1".to_owned(),
            purpose: Purpose::Session,
            request_id: None,
        };
        phone
            .send(tungstenite::Message::text(
                serde_json::to_string(&connect).unwrap(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            next(&mut phone).await,
            ServerMessage::Result { id: 1, .. }
        ));
        assert!(matches!(
            next(&mut home).await,
            ServerMessage::Incoming { .. }
        ));

        // Revoking the phone closes its channel and tells the home PC.
        devices::revoke(
            &f.state.db,
            f.alice,
            &[EndpointId(*key(2).public().as_bytes())],
            RevokedBy::AccountPage,
            None,
            db::unix_now(),
        )
        .await
        .unwrap();
        f.state.connect.as_ref().unwrap().poke();
        assert_eq!(closed(&mut phone).await, Some(close::REVOKED));
        expect(&mut home, |m| {
            matches!(m, ServerMessage::DeviceRevoked { .. })
        })
        .await;

        // The revoked credential no longer upgrades.
        let mut request = format!("ws://{}{}", f.address, paths::WEBSOCKET)
            .into_client_request()
            .unwrap();
        let credentials = STANDARD.encode(format!("alice:{phone_password}"));
        request.headers_mut().insert(
            "authorization",
            format!("Basic {credentials}").parse().unwrap(),
        );
        assert!(tokio_tungstenite::connect_async(request).await.is_err());
    }

    #[tokio::test]
    async fn an_app_password_without_a_device_is_refused_and_signing_out_works() {
        let f = fixture(true).await;
        let (_, other) = gono_server_core::app_passwords::create(
            &f.state.db,
            f.alice,
            "desktop",
            Vec::new(),
            None,
        )
        .await
        .unwrap();
        let basic =
            |password: &str| format!("Basic {}", STANDARD.encode(format!("alice:{password}")));
        let (status, _) = f
            .send(
                "DELETE",
                paths::DEVICE,
                &[("Authorization", &basic(other.expose_secret()))],
                String::new(),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let password = f.register(&key(3), "Laptop").await;
        let (status, _) = f
            .send(
                "DELETE",
                paths::DEVICE,
                &[("Authorization", &basic(&password))],
                String::new(),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // The entry stays, signed out, and the credential is gone.
        let listed = devices::list(&f.state.db, f.alice).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].is_signed_out());
        let (status, _) = f
            .send(
                "DELETE",
                paths::DEVICE,
                &[("Authorization", &basic(&password))],
                String::new(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_frame_over_the_limit_is_closed_with_1009() {
        let f = fixture(true).await;
        let password = f.register(&key(4), "Laptop").await;
        let (mut client, welcome) = f.open(&key(4), &password).await;
        assert!(matches!(welcome, ServerMessage::Welcome(_)), "{welcome:?}");
        let huge = "x".repeat(limits::MAX_FRAME_BYTES + 1);
        let _ = client.send(tungstenite::Message::text(huge)).await;
        assert_eq!(closed(&mut client).await, Some(1009));
    }

    #[tokio::test]
    async fn the_consent_page_names_the_device_and_needs_two_step_verification() {
        for two_factor in [false, true] {
            let f = fixture(two_factor).await;
            let (started, token) = f.start(&key(4), "Work PC").await;
            let session = web_sessions::create(&f.state.db, f.alice, db::unix_now())
                .await
                .unwrap();
            let cookie = format!("gono_session={}", session.expose_secret());
            let page = format!("/login/v2/flow/{token}");
            let (status, body) = f
                .send("GET", &page, &[("Cookie", &cookie)], String::new())
                .await;
            assert_eq!(status, StatusCode::OK);
            let short = gono_protocol::connect::DeviceId::from(key(4).public()).short();
            assert!(body.contains(&short), "{body}");
            assert!(
                body.contains("Input Show") && body.contains("Windows"),
                "{body}"
            );

            let csrf = f.state.web.session_csrf(session.expose_secret());
            let (status, body) = f
                .send(
                    "POST",
                    &page,
                    &[
                        ("Cookie", &cookie),
                        ("Content-Type", "application/x-www-form-urlencoded"),
                    ],
                    format!("action=grant&csrf={csrf}"),
                )
                .await;
            let (poll_status, _) = f.poll(&key(4), &started).await;
            if two_factor {
                assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
                assert_eq!(poll_status, StatusCode::OK);
            } else {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(body.contains("Two-step verification needed"), "{body}");
                assert_eq!(poll_status, StatusCode::ACCEPTED, "still pending");
            }
        }
    }
}
