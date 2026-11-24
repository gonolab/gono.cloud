//! The WeChat mini program through the router: the panel of the account page, the mini
//! program's API with the fake WeChat API, the page of the QR links and the verification file.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
};
use gono_server_core::{
    Username, audit, db,
    users::{self, NewUser},
    wechat::{self as store, NewTicket},
};
use http_body_util::BodyExt as _;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use url::Url;

use super::{ALICE_PASSWORD, Browser, Fixture, fixture};
use crate::{
    app,
    i18n::{EN, Lang, Text, ZH, fill},
    wechat::{
        MAX_BODY_BYTES, VerifyFile, WeChat,
        api::{ApiError, FakeApi, Login},
    },
};

const APP_ID: &str = "wxd930ea5d5a258f4f";
const PREFIX: &str = "https://mp.example.cn/q/";
const ALICE_OPENID: &str = "oGZUI0egBJY1zhBYw2KhdUfwVJJE";
const BOB_OPENID: &str = "o6_bmasdasdsad6_2sgVt7hMZOPfL";

fn t() -> &'static Text {
    Lang::En.t()
}

/// Turns the mini program on in `f`, as `serve` does with `[wechat]`, with a fake WeChat API
/// and `verify`.
pub(super) fn wechat_on(
    f: &mut Fixture,
    verify: Option<VerifyFile>,
) -> (Arc<FakeApi>, Arc<WeChat>) {
    let api = Arc::new(FakeApi::default());
    let wechat = Arc::new(WeChat::new(
        APP_ID,
        Url::parse(PREFIX).unwrap(),
        api.clone(),
        verify,
    ));
    f.state.wechat = Some(wechat.clone());
    (api, wechat)
}

/// The fixture with the mini program, its fake WeChat API and `verify`.
async fn with_wechat(verify: Option<VerifyFile>) -> (Fixture, Arc<FakeApi>, Arc<WeChat>) {
    let mut f = fixture().await;
    let (api, wechat) = wechat_on(&mut f, verify);
    (f, api, wechat)
}

/// An answer of the mini program's API.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("JSON: {}", String::from_utf8_lossy(&self.body)))
    }

    /// The `error` of the answer, with its status.
    fn error(&self) -> (StatusCode, String) {
        let error = self.json()["error"]
            .as_str()
            .unwrap_or_else(|| panic!("no error in {}", self.json()))
            .to_owned();
        (self.status, error)
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }
}

/// The mini program: requests without cookies, from `peer`.
struct Mini {
    router: Router,
    peer: SocketAddr,
}

impl Mini {
    fn new(f: &Fixture) -> Self {
        Self {
            router: app::router(f.state.clone()),
            peer: SocketAddr::from(([198, 51, 100, 1], 5000)),
        }
    }

    /// The same mini program from the address `198.51.100.<last>`: every address has a token
    /// bucket of its own.
    fn at(&self, last: u8) -> Self {
        Self {
            router: self.router.clone(),
            peer: SocketAddr::from(([198, 51, 100, last], 5000)),
        }
    }

    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: Body) -> Answer {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(body).unwrap();
        request.extensions_mut().insert(ConnectInfo(self.peer));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Answer {
            status,
            headers,
            body: body.to_vec(),
        }
    }

    async fn post(&self, path: &str, body: &Value) -> Answer {
        self.send(
            "POST",
            path,
            &[("Content-Type", "application/json")],
            Body::from(body.to_string()),
        )
        .await
    }

    async fn session(&self, code: &str) -> Answer {
        self.post(
            "/gono/v1/wechat/session",
            &json!({ "code": code, "scene": 1011, "platform": "ios" }),
        )
        .await
    }

    async fn bind(&self, signup_token: &str, ticket: &str) -> Answer {
        self.post(
            "/gono/v1/wechat/bind",
            &json!({
                "signup_token": signup_token,
                "ticket": ticket,
                "scene": 1047,
                "platform": "android",
            }),
        )
        .await
    }

    async fn with_bearer(&self, method: &str, path: &str, session: &str) -> Answer {
        let bearer = format!("Bearer {session}");
        self.send(method, path, &[("Authorization", &bearer)], Body::empty())
            .await
    }

    async fn account(&self, session: &str) -> Answer {
        self.with_bearer("GET", "/gono/v1/wechat/account", session)
            .await
    }

    /// The signup token of the unbound user of `code`.
    async fn signup(&self, api: &FakeApi, code: &str, openid: &str) -> String {
        api.accept(code, openid);
        let answer = self.session(code).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.json());
        let body = answer.json();
        assert!(body.get("session").is_none(), "{body}");
        body["signup_token"].as_str().unwrap().to_owned()
    }
}

/// Shows a QR code on the overview of signed-in alice (with the session's CSRF token `csrf`);
/// returns its ticket.
async fn show_qr(browser: &mut Browser, csrf: &str, wechat: &WeChat) -> String {
    let before = wechat.shown_tickets();
    let shown = browser
        .post(
            "/account/identities/wechat/bind",
            &[("csrf", csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(shown.status, StatusCode::SEE_OTHER, "{}", shown.text());
    assert_eq!(shown.location(), "/account/?done=wechat-ticket");
    let mut new: Vec<String> = wechat
        .shown_tickets()
        .into_iter()
        .filter(|ticket| !before.contains(ticket))
        .collect();
    assert_eq!(new.len(), 1);
    new.remove(0)
}

/// Binds alice's WeChat through the page of signed-in `browser` and the mini program; returns
/// the session.
async fn bind_alice(
    browser: &mut Browser,
    csrf: &str,
    mini: &Mini,
    api: &FakeApi,
    wechat: &WeChat,
) -> String {
    let ticket = show_qr(browser, csrf, wechat).await;
    let token = mini.signup(api, "code-alice", ALICE_OPENID).await;
    let bound = mini.bind(&token, &ticket).await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.json());
    bound.json()["session"].as_str().unwrap().to_owned()
}

async fn add_user(f: &Fixture, name: &str) -> i64 {
    let username = Username::new(name).unwrap();
    users::create(
        &f.state.db,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: "x",
            is_admin: false,
            services: gono_server_core::services::Services::NONE,
        },
        |_| Ok(()),
    )
    .await
    .unwrap()
}

/// Inserts an identity directly, as a binding elsewhere would leave it.
async fn insert_identity(f: &Fixture, user: i64, openid: &str) {
    let mut tx = db::begin_immediate(&f.state.db).await.unwrap();
    let id = db::next_id(&mut tx, "external_identities").await.unwrap();
    sqlx::query(
        "INSERT INTO external_identities (id, user_id, provider, realm, subject, label, \
         created_at, last_seen_at) VALUES (?, ?, 'wechat', ?, ?, '', 0, 0)",
    )
    .bind(id)
    .bind(user)
    .bind(APP_ID)
    .bind(openid)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn alice(f: &Fixture) -> users::User {
    users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn without_wechat_the_panel_says_so_and_nothing_answers() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/").await.text();
    assert!(page.contains(t().wechat_unavailable), "{page}");
    assert!(!page.contains("/account/identities/wechat/bind"), "{page}");
    let posted = browser
        .post(
            "/account/identities/wechat/bind",
            &[("csrf", &csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(posted.status, StatusCode::NOT_FOUND);

    let mini = Mini::new(&f);
    for path in [
        "/gono/v1/wechat",
        "/gono/v1/wechat/session",
        "/gono/v1/wechat/bind",
        "/gono/v1/wechat/account",
    ] {
        let answer = mini.post(path, &json!({})).await;
        assert_eq!(
            answer.error(),
            (StatusCode::NOT_FOUND, "not_found".to_owned()),
            "{path}"
        );
    }
    assert_eq!(
        browser.get("/q/bind/AbCdEfGhIjKlMnOpQrStUv").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_qr_code_on_the_account_page_binds_the_mini_program() {
    let (f, api, wechat) = with_wechat(None).await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/").await.text();
    assert!(
        page.contains("href=\"/account/identities/wechat/bind\""),
        "{page}"
    );
    assert!(page.contains(t().methods_not_bound), "{page}");
    assert!(!page.contains("class=\"qr\""), "{page}");

    // The password is needed.
    let wrong = browser
        .post(
            "/account/identities/wechat/bind",
            &[("csrf", &csrf), ("password", "wrong")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(wrong.text().contains(t().err_current_password));
    let forged = browser
        .post(
            "/account/identities/wechat/bind",
            &[("csrf", "forged"), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert!(wechat.shown_tickets().is_empty());

    let ticket = show_qr(&mut browser, &csrf, &wechat).await;
    assert!(store::is_ticket(&ticket));
    let page = browser.get("/account/?done=wechat-ticket").await.text();
    assert!(page.contains(t().notice_wechat_ticket), "{page}");
    let qr = crate::qr::svg(&format!("{PREFIX}bind/{ticket}")).unwrap();
    assert!(page.contains(&qr), "the QR code carries the link: {page}");
    // With its expiry and the hint to scan it with WeChat.
    let hint = t().wechat_scan.split("{}").next().unwrap();
    assert!(page.contains(hint), "{page}");
    assert!(
        page.contains("href=\"/account/identities/wechat/bind\""),
        "a new one can be made: {page}"
    );
    assert!(!page.contains(&ticket), "the ticket is in the QR code only");
    // Reloading shows it again; another browser of the account sees none.
    assert!(browser.get("/account/").await.text().contains(&qr));
    let mut other = Browser::new(&f.state);
    other.sign_in().await;
    assert!(!other.get("/account/").await.text().contains("class=\"qr\""));

    let mini = Mini::new(&f);
    let token = mini.signup(&api, "code-1", ALICE_OPENID).await;
    let unbound = mini.signup(&api, "code-1b", ALICE_OPENID).await;
    assert!(store::is_token(&unbound));
    // The newer token replaced the first.
    assert_eq!(
        mini.bind(&token, &ticket).await.error(),
        (StatusCode::UNAUTHORIZED, "session_expired".to_owned())
    );
    let bound = mini.bind(&unbound, &ticket).await;
    assert_eq!(bound.status, StatusCode::OK);
    assert_eq!(bound.header("cache-control"), "no-store");
    let body = bound.json();
    let session = body["session"].as_str().unwrap().to_owned();
    assert!(store::is_token(&session));
    assert!(body["expires_at"].as_i64().unwrap() > db::unix_now());
    let account = json!({
        "username": "alice",
        "display_name": "Alice Example",
        "services": { "files": true, "webdav": true, "s3": true, "direct": true, "relay": true },
    });
    assert_eq!(body["account"], account);
    assert_eq!(api.asked(), ["code-1", "code-1b"]);

    // The account page shows the binding, and the session reads the account.
    let page = browser.get("/account/").await.text();
    assert!(page.contains("bound since"), "{page}");
    assert!(
        page.contains("href=\"/account/identities/wechat/unbind\""),
        "{page}"
    );
    assert!(!page.contains("class=\"qr\""), "{page}");
    let read = mini.account(&session).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json(), account);
    let entries = audit::list(&f.state.db, Some(alice(&f).await.id), None, 10)
        .await
        .unwrap();
    assert_eq!(entries[0].kind, "identity.bound");
    assert_eq!(entries[0].client_ip.as_deref(), Some("198.51.100.1"));
    assert_eq!(
        serde_json::from_str::<Value>(&entries[0].details).unwrap(),
        json!({ "provider": "wechat", "how": "mini_program", "app_id": APP_ID })
    );
    assert!(!entries[0].details.contains(ALICE_OPENID));

    // The ticket is used up.
    let bobs = mini.signup(&api, "code-bob", BOB_OPENID).await;
    assert_eq!(
        mini.bind(&bobs, &ticket).await.error(),
        (StatusCode::GONE, "ticket_expired".to_owned())
    );
    // The bound WeChat signs in again with a new code.
    api.accept("code-2", ALICE_OPENID);
    let again = mini.session("code-2").await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["account"], account);
    let second = again.json()["session"].as_str().unwrap().to_owned();
    assert_ne!(second, session);

    // A session reads nothing else: no page, no WebDAV.
    let bearer = format!("Bearer {session}");
    let dav = mini
        .send(
            "PROPFIND",
            "/remote.php/dav/files/alice/",
            &[("Authorization", &bearer), ("Depth", "0")],
            Body::empty(),
        )
        .await;
    assert_eq!(dav.status, StatusCode::UNAUTHORIZED);
    let files = mini
        .send(
            "GET",
            "/apps/files/",
            &[("Authorization", &bearer)],
            Body::empty(),
        )
        .await;
    assert_eq!(files.status, StatusCode::SEE_OTHER);

    // Logging out ends that session only.
    let out = mini
        .with_bearer("POST", "/gono/v1/wechat/logout", &session)
        .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert_eq!(
        mini.account(&session).await.error(),
        (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned())
    );
    assert_eq!(
        mini.with_bearer("POST", "/gono/v1/wechat/logout", &session)
            .await
            .error(),
        (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned())
    );
    assert_eq!(mini.account(&second).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_new_qr_code_ends_the_previous_one() {
    let (f, api, wechat) = with_wechat(None).await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let first = show_qr(&mut browser, &csrf, &wechat).await;
    let again = browser
        .post(
            "/account/identities/wechat/bind",
            &[("csrf", &csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(again.status, StatusCode::SEE_OTHER);
    let second = wechat.shown_tickets();
    assert_eq!(second.len(), 1);
    assert_ne!(second[0], first);
    let mini = Mini::new(&f);
    let token = mini.signup(&api, "code", ALICE_OPENID).await;
    assert_eq!(
        mini.bind(&token, &first).await.error(),
        (StatusCode::GONE, "ticket_expired".to_owned())
    );
    assert_eq!(mini.bind(&token, &second[0]).await.status, StatusCode::OK);
    // Bound, no QR code is made.
    let refused = browser
        .post(
            "/account/identities/wechat/bind",
            &[("csrf", &csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused.text().contains(t().err_wechat_bound));
}

#[tokio::test]
async fn signing_in_needs_a_phone_and_binding_a_scan_too() {
    let (f, api, _) = with_wechat(None).await;
    let mini = Mini::new(&f);
    let ticket = match store::create_ticket(&f.state.db, alice(&f).await.id, APP_ID, db::unix_now())
        .await
        .unwrap()
    {
        NewTicket::Ticket(ticket) => ticket.ticket.expose_secret().to_owned(),
        NewTicket::Bound => panic!("bound"),
    };
    let token = mini.signup(&api, "code-0", BOB_OPENID).await;
    let mut address = 10;
    // Refuses `path` with `body` from a new address with `expected`.
    let mut refuse = |path: &'static str, body: Value, expected: &'static str| {
        address += 1;
        let mini = mini.at(address);
        async move {
            assert_eq!(
                mini.post(path, &body).await.error(),
                (StatusCode::FORBIDDEN, expected.to_owned()),
                "{path} {body}"
            );
        }
    };
    let bind = |scene: Value, platform: &str| {
        json!({
            "signup_token": token,
            "ticket": ticket,
            "scene": scene,
            "platform": platform,
        })
    };
    let session = |scene: Value, platform: &str| {
        json!({
            "code": "code-x",
            "scene": scene,
            "platform": platform,
        })
    };
    // Not on a phone: refused whatever the scene, before WeChat is asked.
    for platform in ["windows", "mac", "ohos_pc", "devtools", "linux", "iOS", ""] {
        for scene in [1011, 1001] {
            refuse(
                "/gono/v1/wechat/session",
                session(json!(scene), platform),
                "desktop_client",
            )
            .await;
            refuse(
                "/gono/v1/wechat/bind",
                bind(json!(scene), platform),
                "desktop_client",
            )
            .await;
        }
    }
    // Binding takes only the scenes of scanning with the camera.
    for scene in [1012, 1013, 1048, 1049, 1007, 1008, 1001, 1089, 1036, 0] {
        refuse(
            "/gono/v1/wechat/bind",
            bind(json!(scene), "ios"),
            "wrong_scene",
        )
        .await;
    }
    // A desktop client is told so whatever its scene.
    refuse(
        "/gono/v1/wechat/bind",
        bind(json!(1013), "windows"),
        "desktop_client",
    )
    .await;
    // WeChat was never asked.
    assert_eq!(api.asked(), ["code-0"]);

    // Signing in takes every scene on a phone: the chat list (1001), a code in an image
    // (1012), a shared card (1007), ... An unbound WeChat gets a signup token.
    for (index, (scene, platform)) in [
        (1001, "ios"),
        (1012, "android"),
        (1007, "ohos"),
        (1089, "ios"),
        (1011, "android"),
        (1047, "ohos"),
    ]
    .into_iter()
    .enumerate()
    {
        let code = format!("code-{scene}-{platform}");
        api.accept(&code, &format!("oPhone{index}"));
        let answer = mini
            .at(100)
            .post(
                "/gono/v1/wechat/session",
                &json!({ "code": code, "scene": scene, "platform": platform }),
            )
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{scene} {platform}");
        assert!(store::is_token(
            answer.json()["signup_token"].as_str().unwrap()
        ));
    }
    // A bound WeChat gets a session from the chat list, and its token still binds nothing
    // without a scan.
    let bound = mini.bind(&token, &ticket).await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.json());
    api.accept("code-again", BOB_OPENID);
    let again = mini
        .post(
            "/gono/v1/wechat/session",
            &json!({ "code": "code-again", "scene": 1001, "platform": "ios" }),
        )
        .await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.json());
    assert_eq!(again.json()["account"]["username"], "alice");
    assert!(store::is_token(again.json()["session"].as_str().unwrap()));
}

#[tokio::test]
async fn requests_are_bounded_and_validated() {
    let (f, api, _) = with_wechat(None).await;
    let mini = Mini::new(&f);
    let token = "a".repeat(43);
    let ticket = "b".repeat(22);
    let mut address = 10;
    for (path, body) in [
        ("/gono/v1/wechat/session", "{}".to_owned()),
        ("/gono/v1/wechat/session", "not json".to_owned()),
        ("/gono/v1/wechat/session", String::new()),
        (
            "/gono/v1/wechat/session",
            json!({ "code": "c", "scene": "1011", "platform": "ios" }).to_string(),
        ),
        (
            "/gono/v1/wechat/session",
            json!({ "code": "c", "scene": -1, "platform": "ios" }).to_string(),
        ),
        (
            "/gono/v1/wechat/session",
            json!({ "code": "c", "scene": 1011 }).to_string(),
        ),
        (
            "/gono/v1/wechat/session",
            json!({ "code": "", "scene": 1011, "platform": "ios" }).to_string(),
        ),
        (
            "/gono/v1/wechat/session",
            json!({ "code": "a b", "scene": 1011, "platform": "ios" }).to_string(),
        ),
        (
            "/gono/v1/wechat/session",
            json!({ "code": "c".repeat(257), "scene": 1011, "platform": "ios" }).to_string(),
        ),
        (
            "/gono/v1/wechat/session",
            json!({ "code": "c", "scene": 1011, "platform": "ios", "pad": "x".repeat(MAX_BODY_BYTES) })
                .to_string(),
        ),
        (
            "/gono/v1/wechat/bind",
            json!({ "signup_token": "short", "ticket": ticket, "scene": 1011, "platform": "ios" })
                .to_string(),
        ),
        (
            "/gono/v1/wechat/bind",
            json!({ "signup_token": token, "ticket": "b".repeat(23), "scene": 1011, "platform": "ios" })
                .to_string(),
        ),
        (
            "/gono/v1/wechat/bind",
            json!({ "signup_token": token, "scene": 1011, "platform": "ios" }).to_string(),
        ),
    ] {
        address += 1;
        let answer = mini
            .at(address)
            .send(
                "POST",
                path,
                &[("Content-Type", "application/json")],
                Body::from(body.clone()),
            )
            .await;
        assert_eq!(
            answer.error(),
            (StatusCode::BAD_REQUEST, "bad_request".to_owned()),
            "{path} {body}"
        );
    }
    assert!(api.asked().is_empty());
    // Unknown endpoints and methods.
    for (method, path) in [
        ("GET", "/gono/v1/wechat/session"),
        ("POST", "/gono/v1/wechat/account"),
        ("GET", "/gono/v1/wechat/logout"),
        ("POST", "/gono/v1/wechat/nope"),
        ("GET", "/gono/v1/wechat/"),
    ] {
        let answer = mini.send(method, path, &[], Body::empty()).await;
        assert_eq!(
            answer.error(),
            (StatusCode::NOT_FOUND, "not_found".to_owned()),
            "{method} {path}"
        );
    }
    // A logout body is bounded too.
    let large = mini
        .send(
            "POST",
            "/gono/v1/wechat/logout",
            &[("Authorization", &format!("Bearer {token}"))],
            Body::from(vec![b'x'; MAX_BODY_BYTES + 1]),
        )
        .await;
    assert_eq!(
        large.error(),
        (StatusCode::BAD_REQUEST, "bad_request".to_owned())
    );
    // Bearer tokens that are none, or no Authorization header at all.
    for authorization in [
        None,
        Some("Basic YWxpY2U6eA==".to_owned()),
        Some("Bearer short".to_owned()),
        Some(format!("Bearer {token}")),
    ] {
        let headers: Vec<(&str, &str)> = authorization
            .iter()
            .map(|value| ("Authorization", value.as_str()))
            .collect();
        let answer = mini
            .send("GET", "/gono/v1/wechat/account", &headers, Body::empty())
            .await;
        assert_eq!(
            answer.error(),
            (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned()),
            "{authorization:?}"
        );
        assert_eq!(answer.header("www-authenticate"), "Bearer realm=\"gono\"");
    }
}

#[tokio::test]
async fn errors_of_wechat_have_codes_of_their_own() {
    let (f, api, _) = with_wechat(None).await;
    let mini = Mini::new(&f);
    api.answer("invalid", Err(ApiError::InvalidCode));
    api.answer("risky", Err(ApiError::RiskyUser));
    api.answer("limited", Err(ApiError::RateLimited));
    api.answer("failed", Err(ApiError::Failed("errcode -1".to_owned())));
    for (code, status, error) in [
        ("invalid", StatusCode::BAD_REQUEST, "code_invalid"),
        ("unknown", StatusCode::BAD_REQUEST, "code_invalid"),
        ("risky", StatusCode::FORBIDDEN, "risky_user"),
        ("limited", StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        ("failed", StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    ] {
        let answer = mini.session(code).await;
        assert_eq!(answer.error(), (status, error.to_owned()), "{code}");
        match error {
            "rate_limited" => assert_eq!(answer.header("retry-after"), "60"),
            "unavailable" => assert_eq!(answer.header("retry-after"), "30"),
            _ => {}
        }
    }
    // A unionid WeChat reports is kept with the binding.
    api.answer(
        "with-union",
        Ok(Login {
            openid: ALICE_OPENID.to_owned(),
            unionid: Some("oUnion".to_owned()),
        }),
    );
    let answer = mini.session("with-union").await;
    let token = answer.json()["signup_token"].as_str().unwrap().to_owned();
    let user = alice(&f).await.id;
    let NewTicket::Ticket(ticket) = store::create_ticket(&f.state.db, user, APP_ID, db::unix_now())
        .await
        .unwrap()
    else {
        panic!("bound");
    };
    let bound = mini.bind(&token, ticket.ticket.expose_secret()).await;
    assert_eq!(bound.status, StatusCode::OK);
    let unionid: Option<db::Text> =
        sqlx::query_scalar("SELECT unionid FROM external_identities WHERE user_id = ?")
            .bind(user)
            .fetch_one(&f.state.db)
            .await
            .unwrap();
    assert_eq!(unionid.as_deref(), Some("oUnion"));
}

#[tokio::test]
async fn binding_is_refused_with_the_reason() {
    let (f, api, wechat) = with_wechat(None).await;
    let mini = Mini::new(&f);
    let alice_id = alice(&f).await.id;
    let bob = add_user(&f, "bob").await;
    let now = db::unix_now();
    let ticket_of = |user: i64, at: i64| {
        let pool = f.state.db.clone();
        async move {
            match store::create_ticket(&pool, user, APP_ID, at).await.unwrap() {
                NewTicket::Ticket(ticket) => ticket.ticket.expose_secret().to_owned(),
                NewTicket::Bound => panic!("bound"),
            }
        }
    };

    // An unknown signup token, an unknown or expired ticket.
    let ticket = ticket_of(alice_id, now).await;
    assert_eq!(
        mini.bind(&"a".repeat(43), &ticket).await.error(),
        (StatusCode::UNAUTHORIZED, "session_expired".to_owned())
    );
    let token = mini.signup(&api, "code-1", ALICE_OPENID).await;
    assert_eq!(
        mini.bind(&token, &"b".repeat(22)).await.error(),
        (StatusCode::GONE, "ticket_expired".to_owned())
    );
    let expired = ticket_of(bob, now - 3600).await;
    assert_eq!(
        mini.bind(&token, &expired).await.error(),
        (StatusCode::GONE, "ticket_expired".to_owned())
    );

    // The openid was bound to another account meanwhile.
    insert_identity(&f, bob, ALICE_OPENID).await;
    assert_eq!(
        mini.bind(&token, &ticket).await.error(),
        (StatusCode::CONFLICT, "account_exists".to_owned())
    );

    // The ticket's account got another openid meanwhile.
    let token = mini.signup(&api, "code-2", "oCarol").await;
    insert_identity(&f, alice_id, "oAliceElsewhere").await;
    assert_eq!(
        mini.bind(&token, &ticket).await.error(),
        (StatusCode::CONFLICT, "bind_failed".to_owned())
    );

    // A disabled account binds nothing, and its bound WeChat signs in to nothing.
    let carol = add_user(&f, "carol").await;
    let carols = ticket_of(carol, db::unix_now()).await;
    users::set_enabled(&f.state.db, &Username::new("carol").unwrap(), false)
        .await
        .unwrap();
    assert_eq!(
        mini.bind(&token, &carols).await.error(),
        (StatusCode::FORBIDDEN, "account_disabled".to_owned())
    );
    users::set_enabled(&f.state.db, &Username::new("bob").unwrap(), false)
        .await
        .unwrap();
    api.accept("code-3", ALICE_OPENID);
    assert_eq!(
        mini.at(2).session("code-3").await.error(),
        (StatusCode::FORBIDDEN, "account_disabled".to_owned())
    );
    assert!(wechat.shown_tickets().is_empty());
}

#[tokio::test]
async fn sessions_end_when_unbound_disabled_deleted_or_unused() {
    let (f, api, wechat) = with_wechat(None).await;
    let mut browser = Browser::new(&f.state);
    let mini = Mini::new(&f);
    let csrf = browser.sign_in().await;
    let session = bind_alice(&mut browser, &csrf, &mini, &api, &wechat).await;

    // Unbinding needs the password.
    let wrong = browser
        .post(
            "/account/identities/wechat/unbind",
            &[("csrf", &csrf), ("password", "wrong")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(mini.account(&session).await.status, StatusCode::OK);
    let unbound = browser
        .post(
            "/account/identities/wechat/unbind",
            &[("csrf", &csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(unbound.status, StatusCode::SEE_OTHER);
    assert_eq!(unbound.location(), "/account/?done=unbound-wechat");
    let page = browser.get("/account/?done=unbound-wechat").await.text();
    assert!(page.contains(t().notice_wechat_unbound), "{page}");
    assert!(page.contains(t().methods_not_bound), "{page}");
    assert_eq!(
        mini.account(&session).await.error(),
        (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned())
    );
    let user = alice(&f).await;
    let kinds: Vec<String> = audit::list(&f.state.db, Some(user.id), None, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.kind)
        .collect();
    assert_eq!(kinds[..2], ["identity.unbound", "identity.bound"]);
    // Unbinding does not touch the web login.
    assert_eq!(alice(&f).await.updated_at, user.updated_at);

    // Bound again, disabling the account ends the session.
    let mut second = Browser::new(&f.state);
    let second_csrf = second.sign_in().await;
    let ticket = show_qr(&mut second, &second_csrf, &wechat).await;
    let token = mini.signup(&api, "code-again", ALICE_OPENID).await;
    let bound = mini.bind(&token, &ticket).await;
    let session = bound.json()["session"].as_str().unwrap().to_owned();
    assert_eq!(mini.account(&session).await.status, StatusCode::OK);
    users::set_enabled(&f.state.db, &user.username, false)
        .await
        .unwrap();
    assert_eq!(
        mini.account(&session).await.error(),
        (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned())
    );
    users::set_enabled(&f.state.db, &user.username, true)
        .await
        .unwrap();
    assert_eq!(
        mini.account(&session).await.error(),
        (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned())
    );

    // A session unused for 30 days has ended.
    let long_ago = db::unix_now() - store::SESSION_TTL_SECS - 60;
    let old = match store::sign_in(&f.state.db, APP_ID, ALICE_OPENID, None, long_ago)
        .await
        .unwrap()
    {
        store::SignIn::Session { session, .. } => session.token,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        mini.account(old.expose_secret()).await.error(),
        (StatusCode::UNAUTHORIZED, "session_expired".to_owned())
    );

    // Deleting the account ends what is left.
    api.accept("code-last", ALICE_OPENID);
    let last = mini.session("code-last").await.json()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(mini.account(&last).await.status, StatusCode::OK);
    users::delete(&f.state.db, &user.username).await.unwrap();
    assert_eq!(
        mini.account(&last).await.error(),
        (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned())
    );
}

#[tokio::test]
async fn clients_are_limited_per_address() {
    use crate::ratelimit::BURST;

    let (f, api, _) = with_wechat(None).await;
    let mini = Mini::new(&f);
    // Successful sign-ins cost nothing: the users of the mini program behind one address do not
    // lock each other out.
    for step in 0..BURST + 5 {
        let code = format!("code-ok-{step}");
        api.accept(&code, &format!("oUser{step}"));
        assert_eq!(mini.session(&code).await.status, StatusCode::OK, "{step}");
    }
    // Every one that fails costs a token, whatever the reason: sign-ins and bindings alike.
    for _ in 0..BURST / 2 {
        assert_eq!(mini.session("unknown").await.error().1, "code_invalid");
    }
    for _ in BURST / 2..BURST {
        assert_eq!(
            mini.bind(&"a".repeat(43), &"b".repeat(22)).await.error().1,
            "session_expired"
        );
    }
    // Then nothing gets through, not even a valid code, and WeChat is not asked.
    let asked = api.asked().len();
    api.accept("code-valid", ALICE_OPENID);
    let limited = mini.session("code-valid").await;
    assert_eq!(limited.error().0, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.header("retry-after").parse::<u64>().unwrap() >= 1);
    assert_eq!(
        mini.bind(&"a".repeat(43), &"b".repeat(22)).await.error().0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(api.asked().len(), asked);
    // Other addresses are not affected.
    let other = mini.at(2);
    assert_eq!(other.session("unknown").await.error().1, "code_invalid");
    assert_eq!(other.session("code-valid").await.status, StatusCode::OK);

    // Bearer tokens that are no session cost a token; live sessions get through all the same.
    let token = other.signup(&api, "code-1", ALICE_OPENID).await;
    let ticket = match store::create_ticket(&f.state.db, alice(&f).await.id, APP_ID, db::unix_now())
        .await
        .unwrap()
    {
        NewTicket::Ticket(ticket) => ticket.ticket.expose_secret().to_owned(),
        NewTicket::Bound => panic!("bound"),
    };
    let session = other.bind(&token, &ticket).await.json()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    let guesser = mini.at(3);
    for _ in 0..BURST - 1 {
        assert_eq!(
            guesser.account(&"c".repeat(43)).await.error().1,
            "not_signed_in"
        );
    }
    assert_eq!(
        guesser.account(&"c".repeat(43)).await.error().0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(guesser.account(&session).await.status, StatusCode::OK);
}

#[tokio::test]
async fn qr_links_open_a_page_that_says_to_scan_them() {
    let (f, _, _) = with_wechat(None).await;
    let mini = Mini::new(&f);
    for (language, first, second) in [("en", &EN, &ZH), ("zh-CN,zh", &ZH, &EN)] {
        let page = mini
            .send(
                "GET",
                "/q/bind/AbCdEfGhIjKlMnOpQrStUv",
                &[("Accept-Language", language)],
                Body::empty(),
            )
            .await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.header("content-type").starts_with("text/html"));
        assert!(page.headers.get("set-cookie").is_none());
        let text = String::from_utf8(page.body).unwrap();
        assert!(
            text.contains(&format!("<h1>{}</h1>", first.scan_title)),
            "{text}"
        );
        assert!(text.contains(second.scan_title), "both languages: {text}");
    }
    for path in ["/q/", "/q/AbCdEfGhIjKlMnOpQrStUv", "/q/a/b/c?x=1"] {
        assert_eq!(
            mini.send("GET", path, &[], Body::empty()).await.status,
            StatusCode::OK,
            "{path}"
        );
    }
    assert_eq!(
        mini.send("HEAD", "/q/bind/x", &[], Body::empty())
            .await
            .status,
        StatusCode::OK
    );
    // It starts nothing.
    let rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM wechat_bind_tickets) + \
         (SELECT COUNT(*) FROM pending_identities) + (SELECT COUNT(*) FROM mp_sessions)",
    )
    .fetch_one(&f.state.db)
    .await
    .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn the_verification_file_is_served_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("AbC123xyz.txt");
    std::fs::write(&path, b"0f1e2d3c4b5a\n").unwrap();
    let verify = VerifyFile::read(&path).unwrap();
    assert_eq!(verify.name, "AbC123xyz.txt");
    let (f, _, _) = with_wechat(Some(verify)).await;
    let mini = Mini::new(&f);
    let file = mini.send("GET", "/AbC123xyz.txt", &[], Body::empty()).await;
    assert_eq!(file.status, StatusCode::OK);
    assert_eq!(file.header("content-type"), "text/plain");
    assert_eq!(file.body, b"0f1e2d3c4b5a\n");
    // At the root only: below /q/ its name is a QR link like any other.
    let below = mini
        .send("GET", "/q/AbC123xyz.txt", &[], Body::empty())
        .await;
    assert_eq!(below.status, StatusCode::OK);
    assert!(below.header("content-type").starts_with("text/html"));
    let below = String::from_utf8(below.body).unwrap();
    assert!(below.contains(t().scan_title) && !below.contains("0f1e2d3c4b5a"));
    for path in ["/abc123xyz.txt", "/Other.txt", "/AbC123xyz.txt/"] {
        assert_eq!(
            mini.send("GET", path, &[], Body::empty()).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // Without the file, nothing is served under its name.
    let (f, _, _) = with_wechat(None).await;
    assert_eq!(
        Mini::new(&f)
            .send("GET", "/AbC123xyz.txt", &[], Body::empty())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // Too large or misnamed files stop the start.
    let large = dir.path().join("large.txt");
    std::fs::write(&large, vec![b'a'; 5000]).unwrap();
    assert!(VerifyFile::read(&large).is_err());
    assert!(VerifyFile::read(&dir.path().join("missing.txt")).is_err());
    let html = dir.path().join("verify.html");
    std::fs::write(&html, b"x").unwrap();
    assert!(VerifyFile::read(&html).is_err());
}

/// The id of the browser session that signed alice in last.
async fn session_of(f: &Fixture, user: i64) -> i64 {
    sqlx::query_scalar("SELECT id FROM web_sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1")
        .bind(user)
        .fetch_one(&f.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn confirming_it_is_you_lasts_five_minutes_for_the_browser() {
    let (f, _api, wechat) = with_wechat(None).await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;

    // Not confirmed: the forms ask for the password, and a form without it is refused.
    let page = browser.get("/account/").await.text();
    assert!(page.contains("id=\"tf-on-password\""), "{page}");
    let bind_page = browser.get("/account/identities/wechat/bind").await;
    assert_eq!(bind_page.status, StatusCode::OK);
    assert!(bind_page.text().contains("id=\"confirm-password\""));
    let refused = browser
        .post("/account/identities/wechat/bind", &[("csrf", &csrf)])
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(refused.text().contains(t().confirm_needed));
    assert!(wechat.shown_tickets().is_empty());

    // The confirmation page confirms and goes on to a page of the account only.
    let wrong = browser
        .post(
            "/account/confirm",
            &[
                ("csrf", &csrf),
                ("password", "wrong"),
                ("next", "/account/s3"),
            ],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(wrong.text().contains(t().err_current_password));
    let confirmed = browser
        .post(
            "/account/confirm",
            &[
                ("csrf", &csrf),
                ("password", ALICE_PASSWORD),
                ("next", "/account/s3"),
            ],
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::SEE_OTHER);
    assert_eq!(confirmed.location(), "/account/s3");

    // Confirmed: no password field, and the forms pass without one; a wrong one still fails.
    let page = browser.get("/account/").await.text();
    assert!(!page.contains("id=\"tf-on-password\""), "{page}");
    assert!(!page.contains("id=\"email-password\""), "{page}");
    assert!(
        !browser
            .get("/account/identities/wechat/bind")
            .await
            .text()
            .contains("id=\"confirm-password\"")
    );
    let wrong = browser
        .post(
            "/account/identities/wechat/bind",
            &[("csrf", &csrf), ("password", "wrong")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    let shown = browser
        .post("/account/identities/wechat/bind", &[("csrf", &csrf)])
        .await;
    assert_eq!(shown.status, StatusCode::SEE_OTHER, "{}", shown.text());
    assert_eq!(wechat.shown_tickets().len(), 1);

    // Another browser of the account is not confirmed.
    let mut other = Browser::new(&f.state);
    let other_csrf = other.sign_in().await;
    let refused = other
        .post("/account/identities/wechat/bind", &[("csrf", &other_csrf)])
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);

    // A confirmation of another account's session with the same id counts for nothing.
    let user = alice(&f).await;
    let session = session_of(&f, user.id).await;
    f.state.web.confirm_session(session, user.id + 1);
    let refused = other
        .post("/account/identities/wechat/bind", &[("csrf", &other_csrf)])
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn unbinding_says_what_it_does_and_keeps_the_last_way_in() {
    let (f, api, wechat) = with_wechat(None).await;
    let mut browser = Browser::new(&f.state);
    let mini = Mini::new(&f);
    let csrf = browser.sign_in().await;
    let session = bind_alice(&mut browser, &csrf, &mini, &api, &wechat).await;

    let page = browser.get("/account/identities/wechat/unbind").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.text().contains(t().unbind_wechat_lead),
        "{}",
        page.text()
    );
    assert!(
        page.text()
            .contains("action=\"/account/identities/wechat/unbind\"")
    );
    // Providers this server does not offer have no page.
    for path in [
        "/account/identities/google/bind",
        "/account/identities/facebook/unbind",
    ] {
        assert_eq!(
            browser.get(path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }

    // Without a password, WeChat is the last way in: it stays.
    let user = alice(&f).await;
    sqlx::query("UPDATE users SET password_hash = NULL WHERE id = ?")
        .bind(user.id)
        .execute(&f.state.db)
        .await
        .unwrap();
    let page = browser.get("/account/").await.text();
    assert!(page.contains(t().methods_password_none), "{page}");
    // The session confirmed with the password when the QR code was shown.
    let refused = browser
        .post("/account/identities/wechat/unbind", &[("csrf", &csrf)])
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert!(refused.text().contains(t().err_last_sign_in));
    assert_eq!(mini.account(&session).await.status, StatusCode::OK);
    assert!(
        store::lookup(&f.state.db, APP_ID, &session, db::unix_now())
            .await
            .unwrap()
            != store::Lookup::Unknown
    );
}

#[tokio::test]
async fn an_account_without_a_password_fails_a_password_sign_in_as_a_wrong_password_does() {
    let f = fixture().await;
    let user = alice(&f).await;
    sqlx::query("UPDATE users SET password_hash = NULL WHERE id = ?")
        .bind(user.id)
        .execute(&f.state.db)
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    let form = browser.get("/login").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    for password in [ALICE_PASSWORD, "", "anything"] {
        let reply = browser
            .post(
                "/login",
                &[("csrf", &csrf), ("user", "alice"), ("password", password)],
            )
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{password:?}");
        assert!(reply.text().contains(t().wrong_password));
    }
}

/// The fixture with the mini program and its sign-in on the web.
async fn with_web_sign_in() -> (Fixture, Arc<FakeApi>, Arc<WeChat>) {
    let mut f = fixture().await;
    let api = Arc::new(FakeApi::default());
    let wechat = Arc::new(
        WeChat::new(APP_ID, Url::parse(PREFIX).unwrap(), api.clone(), None).with_web_sign_in(true),
    );
    f.state.wechat = Some(wechat.clone());
    (f, api, wechat)
}

/// Opens the WeChat sign-in page of `browser` at `path`: its ticket.
async fn sign_in_ticket(browser: &mut Browser, wechat: &WeChat, path: &str) -> String {
    let before = wechat.shown_sign_ins().tickets();
    let page = browser.get(path).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let new: Vec<String> = wechat
        .shown_sign_ins()
        .tickets()
        .into_iter()
        .filter(|ticket| !before.contains(ticket))
        .collect();
    assert_eq!(new.len(), 1, "{}", page.text());
    new[0].clone()
}

impl Mini {
    async fn scan(&self, ticket: &str, code: &str) -> Answer {
        self.post(
            "/gono/v1/wechat/scan",
            &json!({ "ticket": ticket, "code": code, "scene": 1011, "platform": "ios" }),
        )
        .await
    }

    async fn confirm(&self, ticket: &str, code: &str) -> Answer {
        self.post(
            "/gono/v1/wechat/confirm",
            &json!({ "ticket": ticket, "code": code, "scene": 1011, "platform": "ios" }),
        )
        .await
    }

    async fn flow(&self, ticket: &str) -> Answer {
        self.send(
            "GET",
            &format!("/gono/v1/wechat/flow?ticket={ticket}"),
            &[],
            Body::empty(),
        )
        .await
    }
}

/// Enters `code` on the WeChat sign-in page of `browser`.
async fn enter(browser: &mut Browser, code: &str, next: &str) -> super::Reply {
    let page = browser.get("/login").await;
    let csrf = page.field("name=\"csrf\" value=\"");
    browser
        .post(
            "/login/wechat",
            &[("csrf", &csrf), ("code", code), ("next", next)],
        )
        .await
}

#[tokio::test]
async fn a_scan_and_the_digits_sign_a_browser_in() {
    let (f, api, wechat) = with_web_sign_in().await;
    let mini = Mini::new(&f);
    let mut owner = Browser::new(&f.state);
    let csrf = owner.sign_in().await;
    bind_alice(&mut owner, &csrf, &mini, &api, &wechat).await;

    let mut browser = Browser::new(&f.state);
    let login = browser.get("/login").await.text();
    assert!(
        login.contains("href=\"/login/wechat?next=%2Fapps%2Ffiles%2F\""),
        "{login}"
    );
    let ticket = sign_in_ticket(
        &mut browser,
        &wechat,
        "/login/wechat?next=%2Fapps%2Ffiles%2F",
    )
    .await;
    let page = browser
        .get("/login/wechat?next=%2Fapps%2Ffiles%2F")
        .await
        .text();
    let qr = crate::qr::svg(&format!("{PREFIX}{ticket}")).unwrap();
    assert!(page.contains(&qr), "the QR code carries the link: {page}");
    assert!(page.contains("<noscript><meta http-equiv=\"refresh\" content=\"3\"></noscript>"));
    assert!(!page.contains(&ticket), "only in the QR code");
    let status = browser.get("/login/wechat/status").await;
    assert_eq!(status.text(), r#"{"stage":"waiting"}"#);
    // The page shows the same ticket again while it has time left.
    assert_eq!(
        wechat.shown_sign_ins().tickets(),
        std::slice::from_ref(&ticket)
    );

    // The mini program scans: the account and the browser, and the sign-in is locked.
    api.accept("scan-1", ALICE_OPENID);
    let scanned = mini.scan(&ticket, "scan-1").await;
    assert_eq!(scanned.status, StatusCode::OK, "{}", scanned.json());
    let body = scanned.json();
    assert_eq!(body["kind"], "web_sign_in");
    assert_eq!(body["admin"], false);
    assert_eq!(body["account"]["username"], "alice");
    assert_eq!(body["account"]["display_name"], "Alice Example");
    assert_eq!(body["browser"]["same_network"], false);
    assert_eq!(mini.flow(&ticket).await.json()["stage"], "scanned");
    // Another WeChat finds it taken; the same one again finds it locked to itself.
    api.accept("scan-bob", BOB_OPENID);
    assert_eq!(
        mini.at(9).scan(&ticket, "scan-bob").await.json()["account"],
        Value::Null,
        "a WeChat without an account locks nothing"
    );
    api.accept("scan-1b", ALICE_OPENID);
    assert_eq!(mini.scan(&ticket, "scan-1b").await.status, StatusCode::OK);

    // The browser now asks for the digits and stops reloading.
    let page = browser
        .get("/login/wechat?next=%2Fapps%2Ffiles%2F")
        .await
        .text();
    assert!(page.contains(t().wechat_sign_in_enter), "{page}");
    assert!(!page.contains("http-equiv=\"refresh\""), "{page}");
    assert_eq!(
        browser.get("/login/wechat/status").await.text(),
        r#"{"stage":"code"}"#
    );

    // Confirmed on the phone: the digits.
    api.accept("confirm-1", ALICE_OPENID);
    let confirmed = mini.confirm(&ticket, "confirm-1").await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.json());
    let code = confirmed.json()["enter_code"].as_str().unwrap().to_owned();
    assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
    // Only digests are stored.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT code_hash FROM wechat_sign_in_tickets WHERE code_hash IS NOT NULL",
    )
    .fetch_all(&f.state.db)
    .await
    .unwrap();
    assert!(stored.len() == 1 && stored[0].len() == 32);

    // Another browser cannot enter them: the sign-in belongs to the browser that shows it.
    let mut stranger = Browser::new(&f.state);
    let foreign = enter(&mut stranger, &code, "%2Fapps%2Ffiles%2F").await;
    assert_ne!(foreign.status, StatusCode::SEE_OTHER);
    // A wrong try counts; the right digits sign in, without a second step.
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let refused = enter(&mut browser, wrong, "%2Fapps%2Ffiles%2F").await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        refused
            .text()
            .contains(&fill(t().wechat_sign_in_wrong, &["2"]))
    );
    let signed = enter(&mut browser, &code, "/apps/files/").await;
    assert_eq!(signed.status, StatusCode::SEE_OTHER, "{}", signed.text());
    assert_eq!(signed.location(), "/apps/files/");
    let account = browser.get("/account/").await;
    assert_eq!(account.status, StatusCode::OK);
    assert!(
        !account.text().contains("id=\"tf-on-password\""),
        "a fresh sign-in confirms"
    );
    assert_eq!(mini.flow(&ticket).await.json()["stage"], "done");
    // Done is done: the digits do not sign in twice.
    let mut again = Browser::new(&f.state);
    assert_ne!(
        enter(&mut again, &code, "/apps/files/").await.status,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn web_sign_ins_are_refused_with_the_reason() {
    let (f, api, wechat) = with_web_sign_in().await;
    let mini = Mini::new(&f);
    let mut owner = Browser::new(&f.state);
    let csrf = owner.sign_in().await;
    bind_alice(&mut owner, &csrf, &mini, &api, &wechat).await;
    let mut browser = Browser::new(&f.state);
    let ticket = sign_in_ticket(&mut browser, &wechat, "/login/wechat").await;

    // The phone rule and the scene rule; the in-app scanner counts as a scan.
    api.accept("desk", ALICE_OPENID);
    let desktop = mini
        .post(
            "/gono/v1/wechat/scan",
            &json!({ "ticket": ticket, "code": "desk", "scene": 1011, "platform": "windows" }),
        )
        .await;
    assert_eq!(
        desktop.error(),
        (StatusCode::FORBIDDEN, "desktop_client".to_owned())
    );
    let forwarded = mini
        .post(
            "/gono/v1/wechat/scan",
            &json!({ "ticket": ticket, "code": "desk", "scene": 1007, "platform": "ios" }),
        )
        .await;
    assert_eq!(
        forwarded.error(),
        (StatusCode::FORBIDDEN, "wrong_scene".to_owned())
    );
    api.accept("in-app", ALICE_OPENID);
    let scanner = mini
        .post(
            "/gono/v1/wechat/scan",
            &json!({
                "ticket": ticket, "code": "in-app", "scene": 1001, "platform": "android",
                "source": "scan_code",
            }),
        )
        .await;
    assert_eq!(scanner.status, StatusCode::OK, "{}", scanner.json());

    // Another WeChat with an account finds it taken, and cannot confirm or deny it.
    let carol = add_user(&f, "carol").await;
    insert_identity(&f, carol, "oCarol").await;
    api.accept("carol-scan", "oCarol");
    assert_eq!(
        mini.at(3).scan(&ticket, "carol-scan").await.error(),
        (StatusCode::CONFLICT, "ticket_taken".to_owned())
    );
    api.accept("carol-confirm", "oCarol");
    assert_eq!(
        mini.at(3).confirm(&ticket, "carol-confirm").await.error(),
        (StatusCode::FORBIDDEN, "not_permitted".to_owned())
    );

    // Denied on the phone: the browser says so and starts over on request.
    api.accept("deny", ALICE_OPENID);
    let denied = mini
        .post(
            "/gono/v1/wechat/deny",
            &json!({ "ticket": ticket, "code": "deny", "scene": 1011, "platform": "ios" }),
        )
        .await;
    assert_eq!(denied.status, StatusCode::NO_CONTENT);
    assert_eq!(mini.flow(&ticket).await.json()["stage"], "denied");
    let page = browser.get("/login/wechat").await;
    assert!(
        page.text().contains(t().wechat_sign_in_denied),
        "{}",
        page.text()
    );
    let csrf = page.field("name=\"csrf\" value=\"");
    let restarted = browser
        .post("/login/wechat/restart", &[("csrf", &csrf), ("next", "")])
        .await;
    assert_eq!(restarted.status, StatusCode::SEE_OTHER);
    let second = sign_in_ticket(&mut browser, &wechat, "/login/wechat").await;
    assert_ne!(second, ticket);
    api.accept("late", ALICE_OPENID);
    assert_eq!(
        mini.scan(&ticket, "late").await.error(),
        (StatusCode::GONE, "ticket_expired".to_owned())
    );

    // Three wrong tries end it.
    api.accept("s2", ALICE_OPENID);
    mini.scan(&second, "s2").await;
    api.accept("c2", ALICE_OPENID);
    let code = mini.confirm(&second, "c2").await.json()["enter_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..2 {
        assert_eq!(
            enter(&mut browser, wrong, "").await.status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let ended = enter(&mut browser, wrong, "").await;
    assert_eq!(ended.status, StatusCode::FORBIDDEN);
    assert!(ended.text().contains(t().wechat_sign_in_tries_out));
    let after = enter(&mut browser, &code, "").await;
    assert_eq!(after.status, StatusCode::OK, "nothing to enter any more");
    assert!(after.text().contains(t().wechat_sign_in_tries_out));
    assert_eq!(mini.flow(&second).await.json()["stage"], "tries");

    // A disabled account's WeChat signs in nowhere.
    let third = {
        let mut fresh = Browser::new(&f.state);
        sign_in_ticket(&mut fresh, &wechat, "/login/wechat").await
    };
    users::set_enabled(&f.state.db, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    api.accept("s3", ALICE_OPENID);
    assert_eq!(
        mini.at(4).scan(&third, "s3").await.error(),
        (StatusCode::FORBIDDEN, "account_disabled".to_owned())
    );
    // Unknown tickets.
    assert_eq!(
        mini.at(5).flow(&"x".repeat(22)).await.error(),
        (StatusCode::GONE, "ticket_expired".to_owned())
    );
}

#[tokio::test]
async fn without_web_sign_in_nothing_answers() {
    let (f, api, _) = with_wechat(None).await;
    let mut browser = Browser::new(&f.state);
    assert!(!browser.get("/login").await.text().contains("/login/wechat"));
    assert_eq!(
        browser.get("/login/wechat").await.status,
        StatusCode::NOT_FOUND
    );
    let mini = Mini::new(&f);
    api.accept("x", ALICE_OPENID);
    assert_eq!(
        mini.scan(&"a".repeat(22), "x").await.error(),
        (StatusCode::NOT_FOUND, "not_found".to_owned())
    );
}

#[tokio::test]
async fn an_account_confirms_it_is_you_with_a_scan() {
    let (f, api, wechat) = with_web_sign_in().await;
    let mini = Mini::new(&f);
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    bind_alice(&mut browser, &csrf, &mini, &api, &wechat).await;
    // Another browser session, not confirmed, of an account without a password.
    let mut other = Browser::new(&f.state);
    other.sign_in().await;
    sqlx::query("UPDATE users SET password_hash = NULL WHERE username = 'alice'")
        .execute(&f.state.db)
        .await
        .unwrap();
    let confirm = other.get("/account/identities/wechat/unbind").await.text();
    let link =
        "href=\"/login/wechat?purpose=reauth&#38;next=%2Faccount%2Fidentities%2Fwechat%2Funbind\"";
    assert!(confirm.contains(link), "{confirm}");
    let path = "/login/wechat?purpose=reauth&next=%2Faccount%2Fidentities%2Fwechat%2Funbind";
    let ticket = sign_in_ticket(&mut other, &wechat, path).await;
    // Another account's WeChat may not confirm it.
    let carol = add_user(&f, "carol").await;
    insert_identity(&f, carol, "oCarol").await;
    api.accept("carol", "oCarol");
    assert_eq!(
        mini.at(3).scan(&ticket, "carol").await.error(),
        (StatusCode::FORBIDDEN, "not_permitted".to_owned())
    );
    api.accept("scan", ALICE_OPENID);
    assert_eq!(mini.scan(&ticket, "scan").await.json()["kind"], "reauth");
    api.accept("confirm", ALICE_OPENID);
    let code = mini.confirm(&ticket, "confirm").await.json()["enter_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let page = other.get(path).await;
    let csrf = page.field("name=\"csrf\" value=\"");
    let confirmed = other
        .post(
            "/login/wechat",
            &[
                ("csrf", &csrf),
                ("code", &code),
                ("next", "/account/identities/wechat/unbind"),
                ("purpose", "reauth"),
            ],
        )
        .await;
    assert_eq!(confirmed.location(), "/account/identities/wechat/unbind");
    // Confirmed now, the unbind page asks for nothing more (and refuses the last way in).
    let page = other.get("/account/identities/wechat/unbind").await.text();
    assert!(!page.contains("/login/wechat?purpose=reauth"), "{page}");
}

#[tokio::test]
async fn the_mini_program_signs_up_renames_and_deletes_an_account() {
    let mut f = fixture().await;
    let api = Arc::new(FakeApi::default());
    let closed = Arc::new(WeChat::new(
        APP_ID,
        Url::parse(PREFIX).unwrap(),
        api.clone(),
        None,
    ));
    f.state.wechat = Some(closed);
    let mini = Mini::new(&f);
    api.accept("s0", "oNew");
    let answer = mini.session("s0").await.json();
    assert_eq!(answer["signup"], false);
    let token = answer["signup_token"].as_str().unwrap().to_owned();
    let refused = mini
        .post(
            "/gono/v1/wechat/signup",
            &json!({ "signup_token": token, "scene": 1011, "platform": "ios" }),
        )
        .await;
    assert_eq!(
        refused.error(),
        (StatusCode::FORBIDDEN, "signup_closed".to_owned())
    );

    let open = Arc::new(
        WeChat::new(APP_ID, Url::parse(PREFIX).unwrap(), api.clone(), None).with_signup(true),
    );
    f.state.wechat = Some(open);
    let mini = Mini::new(&f);
    let token = mini.signup(&api, "s1", "oNew").await;
    // Only on a phone, but from any scene, as `session`.
    let desktop = mini
        .post(
            "/gono/v1/wechat/signup",
            &json!({ "signup_token": token, "scene": 1001, "platform": "windows" }),
        )
        .await;
    assert_eq!(
        desktop.error(),
        (StatusCode::FORBIDDEN, "desktop_client".to_owned())
    );
    let created = mini
        .post(
            "/gono/v1/wechat/signup",
            &json!({ "signup_token": token, "scene": 1001, "platform": "ios" }),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.json());
    let body = created.json();
    let session = body["session"].as_str().unwrap().to_owned();
    let username = body["account"]["username"].as_str().unwrap().to_owned();
    assert!(
        username.starts_with("wx") && username.len() == 10,
        "{username}"
    );
    assert_eq!(body["account"]["display_name"], "新用户");
    assert_eq!(body["account"]["services"]["files"], false);
    assert_eq!(body["account"]["services"]["direct"], false);
    let user = users::get(&f.state.db, &Username::new(username.clone()).unwrap())
        .await
        .unwrap();
    assert!(!user.has_password);
    assert_eq!(user.created_via, users::CreatedVia::WeChat);
    // The token is used up.
    let again = mini
        .post(
            "/gono/v1/wechat/signup",
            &json!({ "signup_token": token, "scene": 1011, "platform": "ios" }),
        )
        .await;
    assert_eq!(
        again.error(),
        (StatusCode::UNAUTHORIZED, "session_expired".to_owned())
    );

    // Renaming, with the session.
    let rename = |name: &str| {
        let body = json!({ "username": name }).to_string();
        let bearer = format!("Bearer {session}");
        let mini = &mini;
        async move {
            mini.send(
                "PATCH",
                "/gono/v1/wechat/account",
                &[
                    ("Authorization", &bearer),
                    ("Content-Type", "application/json"),
                ],
                Body::from(body),
            )
            .await
        }
    };
    assert_eq!(
        rename("alice").await.error(),
        (StatusCode::CONFLICT, "username_taken".to_owned())
    );
    let renamed = rename("wanda").await;
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.json());
    assert_eq!(renamed.json()["username"], "wanda");
    assert_eq!(rename("wanda2").await.status, StatusCode::TOO_MANY_REQUESTS);

    // Deleting needs a fresh code of the same WeChat and the username.
    let delete = |code: &str, confirm: &str| {
        let body = json!({ "code": code, "platform": "ios", "confirm": confirm }).to_string();
        let bearer = format!("Bearer {session}");
        let mini = &mini;
        async move {
            mini.send(
                "POST",
                "/gono/v1/wechat/account/delete",
                &[
                    ("Authorization", &bearer),
                    ("Content-Type", "application/json"),
                ],
                Body::from(body),
            )
            .await
        }
    };
    api.accept("d0", "oNew");
    assert_eq!(
        delete("d0", "wrong").await.error(),
        (StatusCode::BAD_REQUEST, "bad_request".to_owned())
    );
    api.accept("d1", BOB_OPENID);
    insert_identity(&f, add_user(&f, "bob").await, BOB_OPENID).await;
    assert_eq!(
        delete("d1", "wanda").await.error(),
        (StatusCode::FORBIDDEN, "not_permitted".to_owned())
    );
    api.accept("d2", "oNew");
    assert_eq!(delete("d2", "wanda").await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        mini.account(&session).await.error(),
        (StatusCode::UNAUTHORIZED, "not_signed_in".to_owned()),
        "its sessions ended"
    );
    api.accept("s2", "oNew");
    let pending = mini.session("s2").await;
    assert_eq!(pending.status, StatusCode::CONFLICT);
    assert_eq!(pending.json()["error"], "deletion_pending");
    assert!(pending.json()["until"].as_i64().unwrap() > db::unix_now());
    // Undone within the 7 days: a session again.
    api.accept("r1", "oNew");
    let restored = mini
        .post(
            "/gono/v1/wechat/account/restore",
            &json!({ "code": "r1", "platform": "ios" }),
        )
        .await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.json());
    assert_eq!(restored.json()["account"]["username"], "wanda");
    let entries = audit::list(&f.state.db, Some(user.id), None, 10)
        .await
        .unwrap();
    let kinds: Vec<&str> = entries.iter().map(|entry| entry.kind.as_str()).collect();
    assert_eq!(
        kinds[..5],
        [
            "account.deletion_cancelled",
            "account.deletion_requested",
            "account.renamed",
            "identity.bound",
            "account.created"
        ]
    );
}

#[tokio::test]
async fn the_account_page_renames_a_self_service_account_until_it_is_used() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    assert!(
        !browser
            .get("/account/")
            .await
            .text()
            .contains("action=\"/account/username\""),
        "made by an admin"
    );
    sqlx::query("UPDATE users SET created_via = 'google' WHERE username = 'alice'")
        .execute(&f.state.db)
        .await
        .unwrap();
    // alice has an app password: her username is in use.
    assert!(
        !browser
            .get("/account/")
            .await
            .text()
            .contains("action=\"/account/username\"")
    );
    sqlx::query("DELETE FROM app_passwords")
        .execute(&f.state.db)
        .await
        .unwrap();
    let page = browser.get("/account/").await;
    assert!(
        page.text().contains("action=\"/account/username\""),
        "{}",
        page.text()
    );
    let csrf = page.csrf();
    let renamed = browser
        .post(
            "/account/username",
            &[("csrf", &csrf), ("username", "alicia")],
        )
        .await;
    assert_eq!(renamed.location(), "/account/?done=username");
    let page = browser.get("/account/?done=username").await.text();
    assert!(page.contains(t().notice_username_changed), "{page}");
    let soon = browser
        .post(
            "/account/username",
            &[("csrf", &csrf), ("username", "alicia2")],
        )
        .await;
    assert_eq!(soon.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(soon.text().contains(t().err_username_soon));
}
