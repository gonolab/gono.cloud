//! The admin UI through the router, with a small cookie-keeping client.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
};
use gono_server_core::{
    RelPath, Username,
    app_passwords::{self, Scope},
    config::RelayConfig,
    db,
    meta::MetaStore,
    password,
    storage::DataLayout,
    users::{self, NewUser},
    web_sessions::{self, SessionUser},
};
use gono_server_nextcloud::chunking::ChunkedUploads;
use gono_server_relay::Relay;
use http_body_util::BodyExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use tower::ServiceExt as _;
use url::Url;

use super::{Admin, ServerInfo, format_bytes};
use crate::{
    app::{self, AppState},
    auth::Authenticator,
    ratelimit::RateLimiter,
    web::{self, Web},
};

const PREFIX: &str = "/manage";
const ROOT_PASSWORD: &str = "root password";
const ALICE_PASSWORD: &str = "alice password";

struct Fixture {
    _dir: tempfile::TempDir,
    state: AppState,
    layout: DataLayout,
    root: i64,
    alice: i64,
    /// A full-scope app password of `root`.
    root_device: String,
}

async fn add_user(pool: &db::Pool, layout: &DataLayout, name: &str, pw: &str, admin: bool) -> i64 {
    let username = Username::new(name).unwrap();
    let hash = password::hash(&SecretString::from(pw.to_owned())).unwrap();
    users::create(
        pool,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: &hash,
            is_admin: admin,
            services: gono_server_core::services::Services::ALL,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap()
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let layout = DataLayout::new(dir.path().join("data"));
    layout.create().unwrap();
    let config = db::testing::config(dir.path()).await;
    let pool = db::testing::open(&config).await;
    let root = add_user(&pool, &layout, "root", ROOT_PASSWORD, true).await;
    let alice = add_user(&pool, &layout, "alice", ALICE_PASSWORD, false).await;
    let (_, device) = app_passwords::create(&pool, root, "laptop", Vec::new(), None)
        .await
        .unwrap();

    let dav = crate::commands::serve::dav_service(
        Duration::from_secs(600),
        layout.clone(),
        MetaStore::new(pool.clone()),
    )
    .await
    .unwrap();
    let uploads = ChunkedUploads::new(
        dav.fs().clone(),
        gono_server_core::locks::LockStore::new(pool.clone()),
    );
    let limiter = Arc::new(RateLimiter::new());
    let base_url = Url::parse("https://cloud.example.com").unwrap();
    let info = ServerInfo {
        started_at: db::unix_now() - 3600,
        instance_id: dav.fs().instance_id().to_owned(),
        bind: "127.0.0.1:16102".parse().unwrap(),
        trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
        config_path: dir.path().join("config.toml"),
        log: "info → stdout".into(),
        data_dir: layout.root().to_path_buf(),
        db_path: (config.backend == db::Backend::Sqlite).then(|| config.path.clone()),
        database: config.describe(),
        case_insensitive: Some(false),
        lock_timeout_secs: 3600,
        push: None,
        relay: None,
        warnings: vec!["a <b>warning</b>".into()],
    };
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
        admin: Some(Arc::new(Admin::new(PREFIX, info))),
        files: None,
        connect: None,
        s3: None,
        mailer: None,
        wechat: None,
    };
    Fixture {
        _dir: dir,
        state,
        layout,
        root,
        alice,
        root_device: device.expose_secret().to_owned(),
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> &str {
        self.headers
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn has_password_input(&self) -> bool {
        self.body.contains("type=\"password\"")
    }

    /// The first CSRF field of the page.
    fn csrf(&self) -> String {
        let start = self
            .body
            .find("name=\"csrf\" value=\"")
            .expect("csrf field")
            + 19;
        let rest = &self.body[start..];
        rest[..rest.find('"').unwrap()].to_owned()
    }
}

/// The session cookie of the fixture's `https` origin.
const SESSION_COOKIE: &str = "__Host-gono_session";

/// A browser: keeps cookies, sends forms.
struct Browser {
    router: Router,
    cookies: HashMap<String, String>,
}

impl Browser {
    fn new(state: &AppState) -> Self {
        Self {
            router: app::router(state.clone()),
            cookies: HashMap::new(),
        }
    }

    async fn send(
        &mut self,
        method: &str,
        uri: &str,
        extra: &[(&str, &str)],
        body: String,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(uri);
        if !self.cookies.is_empty() {
            let cookies: Vec<String> = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            request = request.header("Cookie", cookies.join("; "));
        }
        if method == "POST" {
            request = request.header("Content-Type", "application/x-www-form-urlencoded");
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let mut request = request.body(Body::from(body)).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 4000))));
        let response = self.router.clone().oneshot(request).await.unwrap();
        for value in response.headers().get_all("set-cookie") {
            let value = value.to_str().unwrap();
            let pair = value.split(';').next().unwrap();
            let (name, content) = pair.split_once('=').unwrap();
            if value.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), content.to_owned());
            }
        }
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    async fn get(&mut self, uri: &str) -> Reply {
        self.send("GET", uri, &[], String::new()).await
    }

    async fn post(&mut self, uri: &str, fields: &[(&str, &str)]) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send("POST", uri, &[], body).await
    }

    async fn sign_in(&mut self, user: &str, password: &str) -> Reply {
        let form = self.get(&format!("{PREFIX}/login")).await;
        let csrf = form.csrf();
        self.post(
            &format!("{PREFIX}/login"),
            &[("csrf", &csrf), ("user", user), ("password", password)],
        )
        .await
    }

    /// Signs in as `root` and returns the session's CSRF token.
    async fn root(&mut self) -> String {
        let reply = self.sign_in("root", ROOT_PASSWORD).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        self.get(&format!("{PREFIX}/")).await.csrf()
    }
}

fn path(rest: &str) -> String {
    format!("{PREFIX}{rest}")
}

#[tokio::test]
async fn only_admins_sign_in_and_only_with_the_web_password() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);

    let anonymous = browser.get(&path("/")).await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(anonymous.location(), path("/login"));
    assert_eq!(
        browser.get(PREFIX).await.location(),
        path("/"),
        "the bare prefix redirects"
    );

    // App passwords are ignored as Basic credentials and refused at the form.
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("root:{}", f.root_device)
        )
    );
    let with_basic = browser
        .send(
            "GET",
            &path("/"),
            &[("Authorization", &basic)],
            String::new(),
        )
        .await;
    assert_eq!(with_basic.location(), path("/login"));
    let device = browser.sign_in("root", &f.root_device).await;
    assert_eq!(device.status, StatusCode::FORBIDDEN);
    assert!(device.body.contains("Wrong username or password"));
    assert!(!browser.cookies.contains_key(SESSION_COOKIE));

    // A non-admin's correct password does not open the admin UI.
    let alice = browser.sign_in("alice", ALICE_PASSWORD).await;
    assert_eq!(alice.status, StatusCode::FORBIDDEN);
    assert!(
        alice.body.contains("not an administrator"),
        "{}",
        alice.body
    );
    assert!(!browser.cookies.contains_key(SESSION_COOKIE));

    let root = browser.sign_in("root", ROOT_PASSWORD).await;
    assert_eq!(root.status, StatusCode::SEE_OTHER);
    assert_eq!(root.location(), path("/"));
    let overview = browser.get(&path("/")).await;
    assert_eq!(overview.status, StatusCode::OK);
    assert!(!overview.has_password_input());
    assert!(overview.body.contains("cloud.example.com"));
    assert!(
        overview.body.contains("a &#60;b&#62;warning&#60;/b&#62;"),
        "escaped"
    );

    let csrf = overview.csrf();
    let out = browser.post(&path("/logout"), &[("csrf", &csrf)]).await;
    assert_eq!(out.location(), path("/login"));
    assert_eq!(browser.get(&path("/")).await.location(), path("/login"));
}

#[tokio::test]
async fn a_failing_database_is_not_a_wrong_password() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let form = browser.get(&path("/login")).await;
    let csrf = form.csrf();
    f.state.db.close().await;

    let reply = browser
        .post(
            &path("/login"),
            &[
                ("csrf", &csrf),
                ("user", "root"),
                ("password", ROOT_PASSWORD),
            ],
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("cannot check your password"),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("Wrong username or password"));
}

#[tokio::test]
async fn non_admin_sessions_are_refused() {
    let f = fixture().await;
    let token = web_sessions::create(&f.state.db, f.alice, db::unix_now())
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    browser
        .cookies
        .insert(SESSION_COOKIE.into(), token.expose_secret().to_owned());
    let page = browser.get(&path("/users")).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(page.body.contains("Not an administrator"));
    let csrf = page.csrf();
    let out = browser.post(&path("/logout"), &[("csrf", &csrf)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert!(
        web_sessions::lookup(&f.state.db, token.expose_secret(), db::unix_now())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn pages_have_unique_ids_and_the_security_headers() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let login = browser.get(&path("/login")).await;
    let mut pages = vec![("/login".to_owned(), login)];
    browser.root().await;
    for page in [
        "/",
        "/users",
        "/new-user",
        "/users/root",
        "/users/alice",
        "/users/alice/delete",
        "/users/nobody",
        "/created",
    ] {
        pages.push((page.to_owned(), browser.get(&path(page)).await));
    }
    for (page, reply) in &pages {
        assert!(
            reply.status.is_success() || reply.status.is_client_error(),
            "{page}: {}",
            reply.status
        );
        let ids = web::element_ids(&reply.body);
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "{page}: duplicate ids in {ids:?}");
        let csp = reply.header("content-security-policy");
        assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("unsafe-inline"), "{page}: {csp}");
        assert_eq!(reply.header("x-frame-options"), "DENY", "{page}");
        assert_eq!(reply.header("cache-control"), "no-store", "{page}");
        // The one script and its text carry the nonce of this response's policy.
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap_or_else(|| panic!("{page}: no script nonce in {csp}"));
        let scripts = reply.body.matches("<script").count();
        let with_nonce = reply.body.matches(&format!("nonce=\"{nonce}\"")).count();
        assert_eq!(scripts, 2, "{page}");
        assert_eq!(with_nonce, scripts, "{page}");
    }
}

#[tokio::test]
async fn forms_need_the_session_csrf_token_and_this_origin() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let fields = [
        ("username", "mallory"),
        ("password", "long enough"),
        ("password_repeat", "long enough"),
    ];
    let missing = browser.post(&path("/users"), &fields).await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    let mut with_token = fields.to_vec();
    with_token.push(("csrf", &csrf));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&with_token)
        .finish();
    let foreign = browser
        .send(
            "POST",
            &path("/users"),
            &[("Origin", "https://evil.example")],
            body,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    let username = Username::new("mallory").unwrap();
    assert!(users::find(&f.state.db, &username).await.unwrap().is_none());
}

#[tokio::test]
async fn accounts_are_created_changed_and_deleted_with_redirects() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let create = |name: &'static str, repeat: &'static str| {
        vec![
            ("csrf", csrf.clone()),
            ("username", name.to_owned()),
            ("display_name", "Carol C.".to_owned()),
            ("password", "carol's password".to_owned()),
            ("password_repeat", repeat.to_owned()),
        ]
    };
    let as_refs = |fields: &[(&'static str, String)]| {
        fields
            .iter()
            .map(|(name, value)| (*name, value.clone()))
            .collect::<Vec<_>>()
    };

    let mismatch = create("carol", "something else");
    let reply = browser
        .post(&path("/users"), &pairs(&as_refs(&mismatch)))
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(reply.body.contains("do not match"));
    assert!(
        reply.body.contains("value=\"carol\""),
        "the form keeps its values"
    );

    let fields = create("carol", "carol's password");
    let created = browser
        .post(&path("/users"), &pairs(&as_refs(&fields)))
        .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
    assert_eq!(created.location(), path("/users/carol?done=created"));
    let page = browser.get(created.location()).await;
    assert!(page.body.contains("User carol was created."));
    let again = browser
        .post(&path("/users"), &pairs(&as_refs(&fields)))
        .await;
    assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(again.body.contains("already exists"));
    let carol = users::find(&f.state.db, &Username::new("carol").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(carol.display_name, "Carol C.");
    assert!(!carol.is_admin);
    assert!(f.layout.user_files(carol.id).is_dir());

    // Disabling ends the account's browser sessions.
    let session = web_sessions::create(&f.state.db, carol.id, db::unix_now())
        .await
        .unwrap();
    let disabled = browser
        .post(&path("/users/carol/disable"), &[("csrf", &csrf)])
        .await;
    assert_eq!(disabled.location(), path("/users/carol?done=disabled"));
    assert!(
        !users::get(&f.state.db, &carol.username)
            .await
            .unwrap()
            .enabled
    );
    assert!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM web_sessions WHERE user_id = ?")
            .bind(carol.id)
            .fetch_one(&f.state.db)
            .await
            .unwrap()
            == 0,
        "{:?}",
        session.expose_secret().len()
    );
    let enabled = browser
        .post(&path("/users/carol/enable"), &[("csrf", &csrf)])
        .await;
    assert_eq!(enabled.location(), path("/users/carol?done=enabled"));

    // Setting the password signs the user out elsewhere.
    let session = web_sessions::create(&f.state.db, carol.id, db::unix_now())
        .await
        .unwrap();
    let short = browser
        .post(
            &path("/users/carol/password"),
            &[
                ("csrf", &csrf),
                ("password", "short"),
                ("password_repeat", "short"),
            ],
        )
        .await;
    assert_eq!(short.status, StatusCode::UNPROCESSABLE_ENTITY);
    let set = browser
        .post(
            &path("/users/carol/password"),
            &[
                ("csrf", &csrf),
                ("password", "a new password"),
                ("password_repeat", "a new password"),
            ],
        )
        .await;
    assert_eq!(set.location(), path("/users/carol?done=password"));
    assert!(
        web_sessions::lookup(&f.state.db, session.expose_secret(), db::unix_now())
            .await
            .unwrap()
            .is_none()
    );
    let (_, hash) = users::credentials(&f.state.db, &carol.username)
        .await
        .unwrap()
        .unwrap();
    assert!(password::verify(&SecretString::from("a new password".to_owned()), &hash).unwrap());

    // Deleting asks first and moves the files away.
    let confirm = browser.get(&path("/users/carol/delete")).await;
    assert_eq!(confirm.status, StatusCode::OK);
    assert!(confirm.body.contains("Delete carol?"));
    let deleted = browser
        .post(&path("/users/carol/delete"), &[("csrf", &csrf)])
        .await;
    assert_eq!(deleted.location(), path("/users?done=deleted"));
    assert!(
        users::find(&f.state.db, &carol.username)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!f.layout.user_files(carol.id).exists());
    assert_eq!(
        std::fs::read_dir(f.layout.deleted_root()).unwrap().count(),
        1
    );
    let list = browser.get(deleted.location()).await;
    assert!(list.body.contains("The user was deleted."));
}

fn pairs<'a>(fields: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    fields
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

#[tokio::test]
async fn admins_cannot_lock_themselves_out() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let disable = browser
        .post(&path("/users/root/disable"), &[("csrf", &csrf)])
        .await;
    assert_eq!(disable.status, StatusCode::CONFLICT);
    assert!(disable.body.contains("signed in with"));
    let delete = browser
        .post(&path("/users/root/delete"), &[("csrf", &csrf)])
        .await;
    assert_eq!(delete.status, StatusCode::CONFLICT);
    let root = users::get(&f.state.db, &Username::new("root").unwrap())
        .await
        .unwrap();
    assert!(root.enabled);
    assert_eq!(root.id, f.root);

    // Two admins disabling each other at the same moment: one of them stays.
    let ops = add_user(&f.state.db, &f.layout, "ops", "ops password", true).await;
    let mut other = Browser::new(&f.state);
    let reply = other.sign_in("ops", "ops password").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let other_csrf = other.get(&path("/")).await.csrf();
    let (ops_url, root_url) = (path("/users/ops/disable"), path("/users/root/disable"));
    let (root_fields, ops_fields) = ([("csrf", csrf.as_str())], [("csrf", other_csrf.as_str())]);
    let (first, second) = tokio::join!(
        browser.post(&ops_url, &root_fields),
        other.post(&root_url, &ops_fields)
    );
    let enabled_admins: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND enabled = 1")
            .fetch_one(&f.state.db)
            .await
            .unwrap();
    assert_eq!(
        enabled_admins, 1,
        "{} / {} (ops = {ops})",
        first.status, second.status
    );
}

#[tokio::test]
async fn admins_switch_the_services_of_accounts_and_their_own() {
    use gono_server_core::services::Services;
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let carol = add_user(&f.state.db, &f.layout, "carol", "carol password", false).await;
    let page = browser.get(&path("/users/carol")).await;
    assert!(
        page.body.contains(r#"name="relay" value="on""#),
        "{}",
        page.body
    );
    // The relay brings direct connections along.
    let saved = browser
        .post(
            &path("/users/carol/services"),
            &[("csrf", &csrf), ("webdav", "on"), ("relay", "on")],
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER);
    assert_eq!(saved.header("location"), path("/users/carol?done=services"));
    let stored = users::by_id(&f.state.db, carol).await.unwrap().unwrap();
    assert_eq!(
        stored.services,
        Services {
            webdav: true,
            direct: true,
            relay: true,
            ..Services::NONE
        }
    );
    let page = browser.get(&path("/users/carol?done=services")).await;
    assert!(page.body.contains("Services saved."), "{}", page.body);
    assert!(page.body.contains(r#"name="direct" value="on" checked>"#));
    let list = browser.get(&path("/users")).await;
    assert!(
        list.body.contains("WebDAV, Direct connections, Relay"),
        "{}",
        list.body
    );

    // An admin turns on their own services, which is how the first one gets any.
    let own = browser
        .post(
            &path("/users/root/services"),
            &[("csrf", &csrf), ("files", "on")],
        )
        .await;
    assert_eq!(own.status, StatusCode::SEE_OTHER);
    let root = users::by_id(&f.state.db, f.root).await.unwrap().unwrap();
    assert!(root.services.files && !root.services.webdav);

    // Like every form, it needs the session's token.
    let forged = browser
        .post(&path("/users/carol/services"), &[("csrf", "nope")])
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let unchanged = users::by_id(&f.state.db, carol).await.unwrap().unwrap();
    assert_eq!(unchanged.services, stored.services);
}

#[tokio::test]
async fn the_masthead_of_the_admin_ui_follows_the_admins_own_services() {
    use gono_server_core::services::{Service, Services};
    let mut f = fixture().await;
    // Without the web file UI the masthead has only the admin UI.
    let mut browser = Browser::new(&f.state);
    browser.root().await;
    let page = browser.get(&path("/")).await.body;
    assert!(!page.contains(r#"href="/account/""#), "{page}");
    assert!(!page.contains(r#"id="site-search""#), "{page}");
    assert!(
        page.contains(&format!(r#"<a class="masthead__brand" href="{PREFIX}""#)),
        "{page}"
    );

    f.state.files = Some(Arc::new(crate::files::Files::new()));
    let mut browser = Browser::new(&f.state);
    browser.root().await;
    let page = browser.get(&path("/")).await.body;
    for link in [
        r#"<a class="masthead__link" href="/apps/files/">Files</a>"#,
        r#"<a class="masthead__link" href="/account/">Account</a>"#,
        r#"<a class="menu__item" href="/account/">Account</a>"#,
    ] {
        assert!(page.contains(link), "{link} in {page}");
    }
    assert!(
        page.contains(&format!(
            r#"<a class="masthead__link" href="{PREFIX}/" aria-current="page">Admin</a>"#
        )),
        "{page}"
    );
    assert!(page.contains(r#"id="site-search""#), "{page}");
    assert!(
        page.contains(r#"<a class="masthead__brand" href="/apps/files/""#),
        "{page}"
    );

    // An admin without the files service: no search, and the brand leads to the account page.
    let root = Username::new("root").unwrap();
    users::set_services(
        &f.state.db,
        &root,
        Services::ALL.with(Service::Files, false),
    )
    .await
    .unwrap();
    let page = browser.get(&path("/users")).await.body;
    assert!(!page.contains(r#"id="site-search""#), "{page}");
    assert!(
        page.contains(r#"<a class="masthead__brand" href="/account/""#),
        "{page}"
    );
    assert!(
        page.contains(r#"<a class="masthead__link" href="/account/">Account</a>"#),
        "{page}"
    );
}

#[tokio::test]
async fn admins_are_promoted_and_demoted_but_not_themselves() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let alice = Username::new("alice").unwrap();

    // The buttons match the account's role; the own account has none.
    let page = browser.get(&path("/users/alice")).await;
    assert!(page.body.contains("/users/alice/promote"));
    assert!(!page.body.contains("/users/alice/demote"));
    let own = browser.get(&path("/users/root")).await;
    assert!(!own.body.contains("/users/root/demote"));

    // Forms need the CSRF token and this origin, like every other change.
    let missing = browser.post(&path("/users/alice/promote"), &[]).await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    let body = format!("csrf={csrf}");
    let foreign = browser
        .send(
            "POST",
            &path("/users/alice/promote"),
            &[("Origin", "https://evil.example")],
            body,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    assert!(!users::get(&f.state.db, &alice).await.unwrap().is_admin);

    let promoted = browser
        .post(&path("/users/alice/promote"), &[("csrf", &csrf)])
        .await;
    assert_eq!(promoted.location(), path("/users/alice?done=promoted"));
    assert!(users::get(&f.state.db, &alice).await.unwrap().is_admin);
    let page = browser.get(promoted.location()).await;
    assert!(page.body.contains("alice is now an admin"));
    assert!(page.body.contains("/users/alice/demote"));

    // The new admin can sign in to the admin UI.
    let mut other = Browser::new(&f.state);
    let reply = other.sign_in("alice", ALICE_PASSWORD).await;
    assert_eq!(reply.location(), path("/"));
    let alice_csrf = other.get(&path("/")).await.csrf();

    // Nobody demotes themself, even with another admin left.
    let own = browser
        .post(&path("/users/root/demote"), &[("csrf", &csrf)])
        .await;
    assert_eq!(own.status, StatusCode::CONFLICT);
    assert!(
        own.body
            .contains("cannot demote the account you are signed in with")
    );
    let root = Username::new("root").unwrap();
    assert!(users::get(&f.state.db, &root).await.unwrap().is_admin);

    // Another admin may, and the demoted admin is locked out of the admin UI at once.
    let demoted = other
        .post(&path("/users/root/demote"), &[("csrf", &alice_csrf)])
        .await;
    assert_eq!(demoted.location(), path("/users/root?done=demoted"));
    assert!(!users::get(&f.state.db, &root).await.unwrap().is_admin);
    let refused = browser.get(&path("/users")).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn two_admins_demoting_each_other_leave_one_admin() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    add_user(&f.state.db, &f.layout, "ops", "ops password", true).await;
    let mut other = Browser::new(&f.state);
    let reply = other.sign_in("ops", "ops password").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let other_csrf = other.get(&path("/")).await.csrf();
    let (ops_url, root_url) = (path("/users/ops/demote"), path("/users/root/demote"));
    let (root_fields, ops_fields) = ([("csrf", csrf.as_str())], [("csrf", other_csrf.as_str())]);
    let (first, second) = tokio::join!(
        browser.post(&ops_url, &root_fields),
        other.post(&root_url, &ops_fields)
    );
    let enabled_admins: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND enabled = 1")
            .fetch_one(&f.state.db)
            .await
            .unwrap();
    assert_eq!(enabled_admins, 1, "{} / {}", first.status, second.status);
    // The refused side sees why, or no longer reaches the admin UI at all.
    let statuses = [first.status, second.status];
    assert!(statuses.contains(&StatusCode::SEE_OTHER), "{statuses:?}");
}

#[tokio::test]
async fn display_names_are_changed_and_validated() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let alice = Username::new("alice").unwrap();

    let page = browser.get(&path("/users/alice")).await;
    assert!(page.body.contains("/users/alice/display-name"));

    let missing = browser
        .post(
            &path("/users/alice/display-name"),
            &[("display_name", "Mallory")],
        )
        .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);

    let renamed = browser
        .post(
            &path("/users/alice/display-name"),
            &[("csrf", &csrf), ("display_name", "  Alice <Example> ")],
        )
        .await;
    assert_eq!(renamed.location(), path("/users/alice?done=renamed"));
    assert_eq!(
        users::get(&f.state.db, &alice).await.unwrap().display_name,
        "Alice <Example>"
    );
    let page = browser.get(renamed.location()).await;
    assert!(page.body.contains("The display name was changed."));
    // Shown escaped.
    assert!(
        page.body.contains("Alice &#60;Example&#62;")
            || page.body.contains("Alice &lt;Example&gt;")
    );
    assert!(!page.body.contains("<Example>"));

    for bad in ["   ", "a\u{1}b"] {
        let reply = browser
            .post(
                &path("/users/alice/display-name"),
                &[("csrf", &csrf), ("display_name", bad)],
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}");
        assert!(
            reply.body.contains("The display name must not be empty"),
            "{bad:?}"
        );
    }
    assert_eq!(
        users::get(&f.state.db, &alice).await.unwrap().display_name,
        "Alice <Example>"
    );

    // Admins may rename their own account.
    let own = browser
        .post(
            &path("/users/root/display-name"),
            &[("csrf", &csrf), ("display_name", "Root Admin")],
        )
        .await;
    assert_eq!(own.location(), path("/users/root?done=renamed"));
}

#[tokio::test]
async fn app_passwords_are_created_shown_once_and_revoked() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;

    let nested = browser
        .post(
            &path("/users/alice/app-passwords"),
            &[
                ("csrf", &csrf),
                ("label", "scanner"),
                ("access", "custom"),
                ("mount_1", "/a"),
                ("storage_1", "/x"),
                ("mount_2", "/a/b"),
                ("storage_2", "/y"),
            ],
        )
        .await;
    assert_eq!(nested.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(nested.body.contains("overlap"), "{}", nested.body);
    assert!(
        nested.body.contains("value=\"scanner\""),
        "the form keeps its values"
    );

    let created = browser
        .post(
            &path("/users/alice/app-passwords"),
            &[
                ("csrf", &csrf),
                ("label", "scanner"),
                ("expires_in_days", "30"),
                ("access", "custom"),
                ("mount_1", "/Inbox"),
                ("storage_1", "/Scans/Inbox"),
                ("perm_1", "full"),
                ("mount_2", "/Archive"),
                ("storage_2", "/Scans/Archive"),
                ("perm_2", "view"),
            ],
        )
        .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
    assert_eq!(created.location(), path("/created"));
    assert!(!created.location().contains('?'), "no secret in the URL");

    let shown = browser.get(&path("/created")).await;
    assert_eq!(shown.status, StatusCode::OK);
    assert_eq!(shown.header("cache-control"), "no-store");
    let start = shown.body.find("<div class=\"secret\">").unwrap() + 20;
    let token = shown.body[start..start + 29].to_owned();
    let device = app_passwords::authenticate(
        &f.state.db,
        "alice",
        &SecretString::from(token.clone()),
        db::unix_now(),
    )
    .await
    .unwrap()
    .expect("the shown token authenticates alice");
    assert_eq!(
        device.scopes,
        [
            Scope {
                mount_path: RelPath::parse("Archive").unwrap(),
                storage_path: RelPath::parse("Scans/Archive").unwrap(),
                permission: gono_server_core::Permission::View,
            },
            Scope {
                mount_path: RelPath::parse("Inbox").unwrap(),
                storage_path: RelPath::parse("Scans/Inbox").unwrap(),
                permission: gono_server_core::Permission::Full,
            },
        ]
    );
    let again = browser.get(&path("/created")).await;
    assert_eq!(again.status, StatusCode::GONE);
    assert!(!again.body.contains(&token));

    // Another admin's session never sees it either.
    let listed = app_passwords::list(&f.state.db, f.alice).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].expires_at.is_some());
    let page = browser.get(&path("/users/alice")).await;
    assert!(page.body.contains("scanner"));
    assert!(!page.body.contains(&token));

    let revoke = browser
        .post(
            &path(&format!(
                "/users/alice/app-passwords/{}/delete",
                listed[0].id
            )),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(revoke.location(), path("/users/alice?done=revoked"));
    assert!(
        app_passwords::list(&f.state.db, f.alice)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_admin_ui_is_not_served_when_disabled() {
    let mut f = fixture().await;
    f.state.admin = None;
    let mut browser = Browser::new(&f.state);
    assert_eq!(browser.get(&path("/")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        browser.get(&path("/login")).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn pages_follow_the_browser_language() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.root().await;
    let zh = [("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")];
    let overview = browser.send("GET", &path("/"), &zh, String::new()).await;
    assert!(
        overview.body.contains("<html lang=\"zh-CN\""),
        "{}",
        overview.body
    );
    for text in ["概览", "管理用户", "实时推送连接", "网页文件界面"] {
        assert!(overview.body.contains(text), "{text}");
    }
    let users = browser
        .send("GET", &path("/users"), &zh, String::new())
        .await;
    assert!(users.body.contains("新建用户") && users.body.contains("个账号"));
    let alice = browser
        .send("GET", &path("/users/alice"), &zh, String::new())
        .await;
    assert!(alice.body.contains("删除 alice…"), "{}", alice.body);
    let english = browser.get(&path("/")).await;
    assert!(english.body.contains("Overview") && !english.body.contains("概览"));
}

#[tokio::test]
async fn the_overview_shows_the_relay() {
    let mut f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.root().await;
    let off = browser.get(&path("/")).await;
    assert!(off.body.contains("Turned off in [relay]"), "{}", off.body);

    let relay = Relay::spawn(
        &RelayConfig {
            enabled: true,
            public_url: Some("https://relay.example.com".parse().unwrap()),
            bind: "127.0.0.1:0".parse().unwrap(),
            ..RelayConfig::default()
        },
        None,
    )
    .await
    .unwrap();
    let status = relay.status();
    let mut info = f.state.admin.as_ref().unwrap().info.clone();
    info.relay = Some(status.clone());
    f.state.admin = Some(Arc::new(Admin::new(PREFIX, info)));
    let mut browser = Browser::new(&f.state);
    browser.root().await;

    let on = browser.get(&path("/")).await;
    assert!(
        on.body
            .contains("relay.example.com · 0 of 0 devices connected · 0 B relayed · 0 refused"),
        "{}",
        on.body
    );
    assert!(on.body.contains("no address discovery"), "{}", on.body);
    let zh = [("Accept-Language", "zh-CN")];
    let chinese = browser.send("GET", &path("/"), &zh, String::new()).await;
    assert!(
        chinese.body.contains("已连接 0/0 台设备"),
        "{}",
        chinese.body
    );

    relay.run_until(async {}).await.unwrap();
    let stopped = browser.get(&path("/")).await;
    assert!(
        stopped.body.contains("Stopped after an error"),
        "{}",
        stopped.body
    );
}

#[tokio::test]
async fn the_relay_page_shows_settings_sessions_and_refusals() {
    use gono_server_core::{
        audit::{self, Actor, Record},
        devices::EndpointId,
    };

    let mut f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.root().await;
    let off = browser.get(&path("/relay")).await;
    assert!(off.body.contains("The relay is off"), "{}", off.body);
    let overview = browser.get(&path("/")).await;
    assert!(
        !overview
            .body
            .contains(&format!("href=\"{}\"", path("/relay"))),
        "no tab while the relay is off"
    );

    let listed = EndpointId([9; 32]);
    let relay = Relay::spawn(
        &RelayConfig {
            enabled: true,
            public_url: Some("https://relay.example.com".parse().unwrap()),
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_endpoints: vec![listed.to_hex()],
            max_client_bytes_per_sec: Some(1_000_000),
            ..RelayConfig::default()
        },
        None,
    )
    .await
    .unwrap();
    let mut info = f.state.admin.as_ref().unwrap().info.clone();
    info.relay = Some(relay.status());
    f.state.admin = Some(Arc::new(Admin::new(PREFIX, info)));

    // Two reported sessions and a refused tombstone, as the control channel and the relay
    // record them.
    let (mac, phone) = (EndpointId([7; 32]), EndpointId([8; 32]));
    let now = db::unix_now();
    for (kind, details) in [
        (
            "session.started",
            serde_json::json!({ "service": "inputshow/1", "path": "relayed" }),
        ),
        (
            "session.ended",
            serde_json::json!({
                "service": "inputshow/1",
                "path": "direct",
                "bytes_direct": 1_048_576,
                "bytes_relayed": 2048,
            }),
        ),
    ] {
        audit::record(
            &f.state.db,
            &Record::new(f.alice, kind, Actor::Device)
                .device(mac)
                .peer(phone)
                .details(details),
            now,
        )
        .await
        .unwrap();
    }
    audit::record(
        &f.state.db,
        &Record::new(f.alice, "relay.refused_revoked", Actor::Server).device(phone),
        now,
    )
    .await
    .unwrap();

    let mut browser = Browser::new(&f.state);
    browser.root().await;
    let page = browser.get(&path("/relay")).await;
    assert_eq!(page.status, StatusCode::OK);
    let body = &page.body;
    assert!(
        body.contains(&format!(
            "href=\"{}\" aria-current=\"page\">Relay",
            path("/relay")
        )),
        "{body}"
    );
    assert!(body.contains("<h1>relay.example.com</h1>"), "{body}");
    assert!(body.contains("Only relay.allowed_endpoints (1)"), "{body}");
    assert!(
        body.contains("No device is connected to the relay."),
        "{body}"
    );
    assert!(
        body.contains("Relayed") && body.contains("Direct"),
        "{body}"
    );
    assert!(body.contains("inputshow/1"), "{body}");
    assert!(
        body.contains(&format!("{} / ", format_bytes(1_048_576))),
        "{body}"
    );
    assert!(body.contains(&phone.short()), "{body}");
    assert!(
        body.contains("Revoked devices that tried the relay"),
        "{body}"
    );
    let zh = [("Accept-Language", "zh-CN")];
    let chinese = browser
        .send("GET", &path("/relay"), &zh, String::new())
        .await;
    assert!(chinese.body.contains("已连接的设备"), "{}", chinese.body);
    relay.run_until(async {}).await.unwrap();
}

#[tokio::test]
async fn admins_revoke_devices_after_a_second_confirmation() {
    use gono_server_core::{
        devices::{self, EndpointId, NewDevice, Registration},
        login_flows,
    };

    let mut f = fixture().await;
    f.state.connect = Some(
        gono_server_connect::Connect::new(
            f.state.db.clone(),
            gono_server_connect::ConnectConfig {
                base_url: "https://cloud.example.com".parse().unwrap(),
                relay_url: "https://relay.example.com".parse().unwrap(),
                audit_retention_secs: 3600,
                require_two_factor: true,
            },
        )
        .await
        .unwrap(),
    );
    let now = db::unix_now();
    let new = NewDevice {
        endpoint_id: EndpointId([7; 32]),
        product: "input-show".to_owned(),
        platform: "macos".to_owned(),
        name: "Alice's Mac".to_owned(),
        version: String::new(),
    };
    let (flow, _) = login_flows::create_device(&f.state.db, &new, now)
        .await
        .unwrap()
        .unwrap();
    let found = login_flows::find(&f.state.db, flow.login_token.expose_secret(), now)
        .await
        .unwrap()
        .unwrap();
    login_flows::grant(&f.state.db, found.id, f.alice, None, now)
        .await
        .unwrap();
    let (_, Registration::Registered { device, .. }) =
        login_flows::complete_device(&f.state.db, flow.poll_token.expose_secret(), now)
            .await
            .unwrap()
            .done()
            .unwrap()
    else {
        panic!("registered");
    };

    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let page = browser.get(&path("/users/alice")).await;
    assert!(page.body.contains("Remote devices"), "{}", page.body);
    assert!(page.body.contains("Input Show · macOS"), "{}", page.body);
    let hex = device.endpoint_id.to_hex();
    let confirm = browser
        .get(&path(&format!("/users/alice/devices/{hex}/revoke")))
        .await;
    assert_eq!(confirm.status, StatusCode::OK);
    assert!(
        confirm.body.contains("This cannot be undone"),
        "{}",
        confirm.body
    );
    // Another account's path does not reach it.
    let elsewhere = browser
        .get(&path(&format!("/users/root/devices/{hex}/revoke")))
        .await;
    assert_eq!(elsewhere.status, StatusCode::NOT_FOUND);

    let revoked = browser
        .post(
            &path(&format!("/users/alice/devices/{hex}/revoke")),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(revoked.location(), path("/users/alice?done=device-revoked"));
    assert!(
        devices::get(&f.state.db, device.id)
            .await
            .unwrap()
            .unwrap()
            .is_revoked()
    );
    let records = gono_server_core::audit::list(&f.state.db, Some(f.alice), None, 5)
        .await
        .unwrap();
    assert_eq!(records[0].kind, "device.revoked");
    assert_eq!(records[0].actor, "admin");
}

#[tokio::test]
async fn admins_with_two_step_verification_pass_the_second_step_first() {
    let f = fixture().await;
    sqlx::query("INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (?, x'00', 0)")
        .bind(f.root)
        .execute(&f.state.db)
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    let reply = browser.sign_in("root", ROOT_PASSWORD).await;
    assert_eq!(reply.location(), "/login/two-step");
    let overview = browser.get(&path("/")).await;
    assert_ne!(
        overview.status,
        StatusCode::OK,
        "no session before the second step"
    );
    let page = browser.get("/login/two-step").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Two-step verification"), "{}", page.body);

    // The admin page shows it and resets it.
    let mut admin = Browser::new(&f.state);
    sqlx::query("DELETE FROM two_factor WHERE user_id = ?")
        .bind(f.root)
        .execute(&f.state.db)
        .await
        .unwrap();
    let csrf = admin.root().await;
    sqlx::query("INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (?, x'00', 0)")
        .bind(f.alice)
        .execute(&f.state.db)
        .await
        .unwrap();
    let page = admin.get(&path("/users/alice")).await;
    assert!(
        page.body.contains("Reset two-step verification"),
        "{}",
        page.body
    );
    let reset = admin
        .post(&path("/users/alice/two-factor/reset"), &[("csrf", &csrf)])
        .await;
    assert_eq!(reset.location(), path("/users/alice?done=two-factor-reset"));
    assert!(
        !gono_server_core::two_factor::is_enrolled(&f.state.db, f.alice)
            .await
            .unwrap()
    );
}

/// Turns two-step verification on for alice (if it is not) and starts a sign-in of hers
/// waiting for its second step.
async fn alice_waits_for_her_second_step(f: &Fixture) {
    sqlx::query(db::Backend::of(&f.state.db).pick(
        "INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (?, x'00', 0) \
         ON CONFLICT (user_id) DO NOTHING",
        "INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (?, x'00', 0) \
         ON DUPLICATE KEY UPDATE user_id = user_id",
    ))
    .bind(f.alice)
    .execute(&f.state.db)
    .await
    .unwrap();
    let alice = users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap();
    let started = f
        .state
        .web
        .start_session("192.0.2.9".parse().unwrap(), &alice, "/")
        .await;
    assert!(
        matches!(started, web::Started::SecondStep(_)),
        "{started:?}"
    );
    assert_eq!(f.state.web.pending_sign_ins(f.alice), 1);
}

#[tokio::test]
async fn new_app_passwords_are_shown_only_to_the_admin_who_created_them() {
    let f = fixture().await;
    let admin = f.state.admin.as_ref().unwrap();
    // Two sessions with the same row id, as SQLite handed one out again after a sign-out
    // before the ids came from a sequence that never goes back.
    let session = |user_id, name: &str| SessionUser {
        session_id: 7,
        user_id,
        username: Username::new(name).unwrap(),
        display_name: name.to_owned(),
        is_admin: true,
        services: gono_server_core::services::Services::ALL,
    };
    admin.remember(
        7,
        super::Created {
            by: f.root,
            username: "alice".into(),
            label: "laptop".into(),
            token: SecretString::from("secret".to_owned()),
            scopes: Vec::new(),
            expires_at: None,
            until: std::time::Instant::now() + Duration::from_secs(60),
        },
    );
    assert!(admin.take(&session(f.alice, "alice")).is_none());
    assert!(admin.take(&session(f.root, "root")).is_some());
}

#[tokio::test]
async fn admin_changes_end_the_pending_sign_ins_of_the_account() {
    let f = fixture().await;
    let mut admin = Browser::new(&f.state);
    let csrf = admin.root().await;

    alice_waits_for_her_second_step(&f).await;
    let reset = admin
        .post(&path("/users/alice/two-factor/reset"), &[("csrf", &csrf)])
        .await;
    assert_eq!(reset.location(), path("/users/alice?done=two-factor-reset"));
    assert_eq!(f.state.web.pending_sign_ins(f.alice), 0, "reset");

    alice_waits_for_her_second_step(&f).await;
    let password = admin
        .post(
            &path("/users/alice/password"),
            &[
                ("csrf", &csrf),
                ("password", "a new password"),
                ("password_repeat", "a new password"),
            ],
        )
        .await;
    assert_eq!(password.location(), path("/users/alice?done=password"));
    assert_eq!(f.state.web.pending_sign_ins(f.alice), 0, "new password");

    alice_waits_for_her_second_step(&f).await;
    let disabled = admin
        .post(&path("/users/alice/disable"), &[("csrf", &csrf)])
        .await;
    assert_eq!(disabled.location(), path("/users/alice?done=disabled"));
    assert_eq!(f.state.web.pending_sign_ins(f.alice), 0, "disabled");
    admin
        .post(&path("/users/alice/enable"), &[("csrf", &csrf)])
        .await;

    alice_waits_for_her_second_step(&f).await;
    let deleted = admin
        .post(&path("/users/alice/delete"), &[("csrf", &csrf)])
        .await;
    assert_eq!(deleted.location(), path("/users?done=deleted"));
    assert_eq!(f.state.web.pending_sign_ins(f.alice), 0, "deleted");
}

#[tokio::test]
async fn admins_see_revoke_and_remove_the_s3_keys_and_buckets_of_an_account() {
    use gono_server_core::s3::{self, Anonymous, BucketName, Grant};
    let mut f = fixture().await;

    // A bucket of alice's with anonymous reads, and one of her access keys.
    let identity = gono_server_dav::Identity::for_web_session(
        f.alice,
        Username::new("alice").unwrap(),
        "alice".to_owned(),
        gono_server_core::services::Services::ALL,
    );
    let folder = f
        .state
        .dav
        .fs()
        .put_folder(identity.clone(), &RelPath::parse("Buckets/photos").unwrap())
        .await
        .unwrap();
    let photos = s3::create_bucket(
        &f.state.db,
        f.alice,
        &BucketName::new("photos").unwrap(),
        folder.file_id.unwrap(),
    )
    .await
    .unwrap();
    s3::set_anonymous(&f.state.db, f.alice, photos.id, Anonymous::PublicRead, true)
        .await
        .unwrap();
    // Settings only the S3 API makes, stored as it stores them.
    s3::set_bucket_tags(&f.state.db, f.alice, photos.id, Some(r#"{"team":"web"}"#))
        .await
        .unwrap();
    s3::set_bucket_lifecycle(
        &f.state.db,
        f.alice,
        photos.id,
        Some(r#"[{"id":"cache","enabled":true,"prefix":"cache/","expiration_days":30}]"#),
    )
    .await
    .unwrap();
    s3::set_bucket_website(&f.state.db, f.alice, photos.id, Some("{}"))
        .await
        .unwrap();
    let sealing = gono_server_core::two_factor::Key::from_bytes(&[9; 32]);
    let (key, secret) = s3::create_key(
        &f.state.db,
        &sealing,
        f.alice,
        "rclone",
        vec![Grant {
            bucket_id: Some(photos.id),
            permission: gono_server_core::Permission::View,
        }],
        None,
    )
    .await
    .unwrap();

    // No S3 panel while the S3 API is off; its service switch says that it is not offered.
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let page = browser.get(&path("/users/alice")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains(r#"id="s3""#), "{}", page.body);
    assert!(
        page.body.contains("Not offered by this server"),
        "{}",
        page.body
    );
    let off = browser
        .post(
            &path(&format!("/users/alice/s3/keys/{}/delete", key.id)),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(off.status, StatusCode::NOT_FOUND);
    assert_eq!(s3::list_keys(&f.state.db, f.alice).await.unwrap().len(), 1);

    f.state.s3 = Some(Arc::new(crate::s3::S3Ui {
        public_url: Some(Url::parse("https://s3.example.com").unwrap()),
        region: "us-east-1".to_owned(),
        bucket_folder: "Buckets".to_owned(),
        allow_anonymous: true,
        virtual_host_domain: None,
        website_domain: Some("web.example.com".to_owned()),
    }));
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let page = browser.get(&path("/users/alice")).await;
    assert!(page.body.contains("S3 buckets"), "{}", page.body);
    assert!(page.body.contains("photos"));
    assert!(page.body.contains("/Buckets/photos"));
    assert!(page.body.contains("Every object · anonymous listing on"));
    assert!(page.body.contains("Tags: 1 (set through the S3 API)"));
    assert!(
        page.body
            .contains("Lifecycle: 1 rule (set through the S3 API)")
    );
    assert!(
        page.body
            .contains("Deletes objects written through S3, for good: cache/* after 30 days")
    );
    assert!(page.body.contains(
        "Website (set through the S3 API): <a href=\"https://photos.web.example.com/\">"
    ));
    assert!(page.body.contains(&key.access_key_id));
    assert!(page.body.contains("rclone"));
    assert!(!page.body.contains(secret.expose_secret()));
    let ids = web::element_ids(&page.body);
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(ids.len(), unique.len(), "duplicate ids in {ids:?}");

    // Every change needs the session's token.
    let refused = browser
        .post(
            &path(&format!("/users/alice/s3/buckets/{}/delete", photos.id)),
            &[],
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(s3::bucket(&f.state.db, "photos").await.unwrap().is_some());
    // A bucket of another account is not found under this one.
    let elsewhere = browser
        .post(
            &path(&format!("/users/root/s3/buckets/{}/delete", photos.id)),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(elsewhere.location(), path("/users/root"));
    assert!(s3::bucket(&f.state.db, "photos").await.unwrap().is_some());

    let private = browser
        .post(
            &path(&format!("/users/alice/s3/buckets/{}/private", photos.id)),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(
        private.location(),
        path("/users/alice?done=s3-bucket-private")
    );
    let stored = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    assert_eq!(
        (stored.anonymous, stored.anonymous_list),
        (Anonymous::Private, false)
    );

    let revoked = browser
        .post(
            &path(&format!("/users/alice/s3/keys/{}/delete", key.id)),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(revoked.location(), path("/users/alice?done=s3-key-revoked"));
    assert!(
        s3::list_keys(&f.state.db, f.alice)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        s3::signing_key(&f.state.db, &sealing, &key.access_key_id, db::unix_now())
            .await
            .unwrap()
            .is_none()
    );

    let removed = browser
        .post(
            &path(&format!("/users/alice/s3/buckets/{}/delete", photos.id)),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(
        removed.location(),
        path("/users/alice?done=s3-bucket-removed")
    );
    assert!(s3::bucket(&f.state.db, "photos").await.unwrap().is_none());
    assert!(
        f.state
            .dav
            .fs()
            .stat(identity, &RelPath::parse("Buckets/photos").unwrap())
            .await
            .is_ok(),
        "the folder stays"
    );
    let page = browser
        .get(&path("/users/alice?done=s3-bucket-removed"))
        .await;
    assert!(
        page.body
            .contains("The bucket was removed. Its folder and files stay.")
    );

    let records: Vec<(String, String)> =
        gono_server_core::audit::list(&f.state.db, Some(f.alice), None, 10)
            .await
            .unwrap()
            .into_iter()
            .rev()
            .map(|entry| (entry.kind, entry.actor))
            .collect();
    assert_eq!(
        records,
        [
            ("s3.bucket.anonymous", "admin"),
            ("s3.key.revoked", "admin"),
            ("s3.bucket.removed", "admin"),
        ]
        .map(|(kind, actor)| (kind.to_owned(), actor.to_owned()))
    );
}

#[tokio::test]
async fn the_page_of_an_account_shows_its_email_address() {
    use gono_server_core::email::{self, Bind, CodeFor, Key, NewCode};

    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.sign_in("root", ROOT_PASSWORD).await;
    let fact = |body: &str| {
        let start = body.find("<dt>Email</dt><dd>").expect("the email fact") + 18;
        body[start..start + body[start..].find("</dd>").unwrap()].to_owned()
    };
    let page = browser.get(&path("/users/alice")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(fact(&page.body), "None");

    let now = db::unix_now();
    let key = Key::from_bytes(&[1; 32]);
    let NewCode::Code(code) = email::send_code(
        &f.state.db,
        &key,
        f.alice,
        CodeFor::Bind,
        "alice@example.com",
        now,
    )
    .await
    .unwrap() else {
        panic!("no code");
    };
    let bound = email::bind(&f.state.db, &key, f.alice, &code.code, None, now)
        .await
        .unwrap();
    assert!(matches!(bound, Bind::Bound { .. }), "{bound:?}");
    let page = browser.get(&path("/users/alice")).await;
    assert_eq!(fact(&page.body), "alice@example.com");
}

#[tokio::test]
async fn the_page_of_an_account_shows_whether_it_has_wechat_bound() {
    use gono_server_core::wechat::{self, Bind, NewTicket, SignIn};
    use secrecy::ExposeSecret as _;

    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.sign_in("root", ROOT_PASSWORD).await;
    let fact = |body: &str| {
        let start = body.find("<dt>WeChat</dt><dd>").expect("the WeChat fact") + 19;
        body[start..start + body[start..].find("</dd>").unwrap()].to_owned()
    };
    let page = browser.get(&path("/users/alice")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(fact(&page.body), "Not bound");

    // Bound on 2027-01-15, whether or not this server has `[wechat]` now.
    let at = 1_800_000_000;
    let NewTicket::Ticket(ticket) =
        wechat::create_ticket(&f.state.db, f.alice, "wxd930ea5d5a258f4f", at)
            .await
            .unwrap()
    else {
        panic!("bound");
    };
    let SignIn::Unbound { token, .. } =
        wechat::sign_in(&f.state.db, "wxd930ea5d5a258f4f", "oAlice", None, at)
            .await
            .unwrap()
    else {
        panic!("bound");
    };
    let bound = wechat::bind(
        &f.state.db,
        "wxd930ea5d5a258f4f",
        token.expose_secret(),
        ticket.ticket.expose_secret(),
        None,
        at,
    )
    .await
    .unwrap();
    assert!(matches!(bound, Bind::Bound { .. }), "{bound:?}");
    let page = browser.get(&path("/users/alice")).await;
    assert_eq!(
        fact(&page.body),
        format!(
            "Bound since {} (wxd930ea5d5a258f4f)",
            super::pages::date(at)
        )
    );
    assert!(!page.body.contains("oAlice"), "the openid is not shown");
}
