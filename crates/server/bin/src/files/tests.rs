//! The web file UI and the account page through the router, with a cookie-keeping client.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
};
use base64::Engine as _;
use gono_server_core::{
    Username, app_passwords, db,
    meta::MetaStore,
    password,
    storage::DataLayout,
    users::{self, NewUser},
};
use gono_server_nextcloud::chunking::ChunkedUploads;
use http_body_util::BodyExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use tower::ServiceExt as _;
use url::Url;

use super::Files;
use crate::{
    app::{self, AppState},
    auth::Authenticator,
    ratelimit::RateLimiter,
    web::{self, Web},
};

const ORIGIN: &str = "https://cloud.example.com";
const ALICE_PASSWORD: &str = "alice password";

struct Fixture {
    _dir: tempfile::TempDir,
    state: AppState,
    /// A full-scope app password of `alice`.
    device: String,
}

async fn fixture_with(files: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let layout = DataLayout::new(dir.path().join("data"));
    layout.create().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let username = Username::new("alice").unwrap();
    let hash = password::hash(&SecretString::from(ALICE_PASSWORD.to_owned())).unwrap();
    let alice = users::create(
        &pool,
        &NewUser {
            username: &username,
            display_name: "Alice Example",
            password_hash: &hash,
            is_admin: false,
            services: gono_server_core::services::Services::ALL,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap();
    let (_, device) = app_passwords::create(&pool, alice, "laptop", Vec::new(), None)
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
    let base_url = Url::parse(ORIGIN).unwrap();
    let state = AppState {
        db: pool.clone(),
        auth: Arc::new(Authenticator::new(pool.clone(), limiter.clone())),
        dav,
        uploads,
        web: Arc::new(
            Web::new(pool, limiter, &base_url)
                .with_two_factor_key(gono_server_core::two_factor::Key::from_bytes(&[9; 32])),
        ),
        base_url: Arc::new(base_url),
        flow_starts: Arc::new(RateLimiter::new()),
        trusted_proxies: Arc::new(Vec::new()),
        push: None,
        admin: None,
        files: files.then(|| Arc::new(Files::new())),
        connect: None,
        s3: None,
        mailer: None,
    };
    Fixture {
        _dir: dir,
        state,
        device: device.expose_secret().to_owned(),
    }
}

async fn fixture() -> Fixture {
    fixture_with(true).await
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn location(&self) -> &str {
        self.header("location")
    }

    /// The value of the first `name="<field>"` hidden input or meta tag.
    fn field(&self, attribute: &str) -> String {
        let text = self.text();
        let start = text
            .find(attribute)
            .unwrap_or_else(|| panic!("{attribute} in {text}"))
            + attribute.len();
        let rest = &text[start..];
        rest[..rest.find('"').unwrap()].to_owned()
    }

    /// The session's CSRF token, from the page's meta tag.
    fn csrf(&self) -> String {
        self.field("name=\"gono-csrf\" content=\"")
    }
}

/// A browser: keeps cookies, sends forms from this origin.
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

    async fn send(&mut self, method: &str, uri: &str, extra: &[(&str, &str)], body: Body) -> Reply {
        let mut request = Request::builder().method(method).uri(uri);
        if !self.cookies.is_empty() {
            let cookies: Vec<String> = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            request = request.header("Cookie", cookies.join("; "));
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let mut request = request.body(body).unwrap();
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
            body: body.to_vec(),
        }
    }

    async fn get(&mut self, uri: &str) -> Reply {
        self.send("GET", uri, &[], Body::empty()).await
    }

    async fn post(&mut self, uri: &str, fields: &[(&str, &str)]) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send(
            "POST",
            uri,
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", ORIGIN),
            ],
            Body::from(body),
        )
        .await
    }

    /// Signs in as alice; returns the session's CSRF token.
    async fn sign_in(&mut self) -> String {
        let form = self.get("/login").await;
        let csrf = form.field("name=\"csrf\" value=\"");
        let reply = self
            .post(
                "/login",
                &[
                    ("csrf", &csrf),
                    ("user", "alice"),
                    ("password", ALICE_PASSWORD),
                ],
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text());
        self.get("/apps/files/").await.csrf()
    }

    /// A WebDAV request with alice's app password.
    async fn dav(&mut self, device: &str, method: &str, rest: &str, body: &str) -> Reply {
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("alice:{device}"))
        );
        let mut router = Browser {
            router: self.router.clone(),
            cookies: HashMap::new(),
        };
        router
            .send(
                method,
                &format!("/remote.php/dav/files/alice/{rest}"),
                &[("Authorization", &basic), ("Depth", "0")],
                Body::from(body.to_owned()),
            )
            .await
    }
}

/// The `getetag` of a WebDAV `PROPFIND` reply.
fn etag(reply: &Reply) -> String {
    let text = reply.text();
    let start = text.find("getetag>").expect("getetag") + 8;
    text[start..start + text[start..].find('<').unwrap()].to_owned()
}

#[tokio::test]
async fn pages_need_a_web_session_and_webdav_needs_an_app_password() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);

    let anonymous = browser.get("/apps/files/Documents/").await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(
        anonymous.location(),
        "/login?next=%2Fapps%2Ffiles%2FDocuments%2F"
    );
    assert_eq!(browser.get("/").await.location(), "/apps/files/");

    // App passwords neither open pages nor sign in.
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("alice:{}", f.device))
    );
    let with_basic = browser
        .send(
            "GET",
            "/apps/files/",
            &[("Authorization", &basic)],
            Body::empty(),
        )
        .await;
    assert_eq!(with_basic.status, StatusCode::SEE_OTHER);
    let form = browser.get("/login").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    let device = browser
        .post(
            "/login",
            &[("csrf", &csrf), ("user", "alice"), ("password", &f.device)],
        )
        .await;
    assert_eq!(device.status, StatusCode::FORBIDDEN);

    let token = browser.sign_in().await;
    assert_eq!(token.len(), 43);
    let page = browser.get("/apps/files/").await;
    assert_eq!(page.status, StatusCode::OK);
    let csp = page.header("content-security-policy");
    assert!(
        csp.contains("script-src 'nonce-") && !csp.contains("unsafe"),
        "{csp}"
    );
    // Signed in, the sign-in page sends the browser on.
    assert_eq!(
        browser.get("/login?next=/account/").await.location(),
        "/account/"
    );
    assert_eq!(
        browser.get("/login?next=//evil.example/").await.location(),
        "/apps/files/"
    );

    // The session cookie means nothing to the WebDAV routes.
    let cookie_dav = browser
        .send(
            "PROPFIND",
            "/remote.php/dav/files/alice/",
            &[("Depth", "0")],
            Body::empty(),
        )
        .await;
    assert_eq!(cookie_dav.status, StatusCode::UNAUTHORIZED);

    // Signing out ends the session.
    let out = browser.post("/logout", &[("csrf", &token)]).await;
    assert_eq!(out.location(), "/login?done=signed-out");
    assert_eq!(
        browser.get("/apps/files/").await.status,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn names_are_escaped_and_urls_encoded() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let evil = "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E%22.txt";
    assert_eq!(
        browser.dav(&f.device, "PUT", evil, "x").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        browser.dav(&f.device, "MKCOL", "a%20b", "").await.status,
        StatusCode::CREATED
    );
    browser.sign_in().await;
    let page = browser.get("/apps/files/").await;
    let text = page.text();
    assert!(!text.contains("<img src=x"), "{text}");
    assert!(
        text.contains("&#60;img src=x onerror=alert(1)&#62;&#34;.txt"),
        "{text}"
    );
    assert!(text.contains("href=\"/apps/files/a%20b/\""), "{text}");
    assert!(
        text.contains("href=\"/apps/files/%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%22.txt\""),
        "{text}"
    );
    // A folder without its slash, a file with one: redirects.
    assert_eq!(
        browser.get("/apps/files/a%20b").await.location(),
        "/apps/files/a%20b/"
    );
    // Dot segments never reach the file system.
    assert_eq!(
        browser.get("/apps/files/a%20b/%2e%2e/").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn forms_change_files_through_webdav() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let before = etag(&browser.dav(&f.device, "PROPFIND", "", "").await);

    let made = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "mkdir"), ("name", "Docs")],
        )
        .await;
    assert_eq!(made.location(), "/apps/files/?done=created&name=Docs");
    assert_eq!(
        browser.dav(&f.device, "PROPFIND", "Docs", "").await.status,
        StatusCode::MULTI_STATUS
    );
    // The sync clients see the change: the root's ETag moved.
    assert_ne!(
        etag(&browser.dav(&f.device, "PROPFIND", "", "").await),
        before
    );

    let again = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "mkdir"), ("name", "Docs")],
        )
        .await;
    assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY, "exists");
    let slash = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "mkdir"), ("name", "a/b")],
        )
        .await;
    assert_eq!(slash.status, StatusCode::UNPROCESSABLE_ENTITY, "bad name");

    browser.dav(&f.device, "PUT", "Docs/a.txt", "hello").await;
    let renamed = browser
        .post(
            "/apps/files/Docs/",
            &[
                ("csrf", &csrf),
                ("action", "rename"),
                ("item", "a.txt"),
                ("name", "b.txt"),
            ],
        )
        .await;
    assert_eq!(
        renamed.location(),
        "/apps/files/Docs/?done=renamed&name=b.txt"
    );
    assert_eq!(
        browser.dav(&f.device, "GET", "Docs/b.txt", "").await.text(),
        "hello"
    );

    // Moving is chosen on a page, then confirmed; a folder never goes into itself.
    let picker = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "move"), ("item", "Docs")],
        )
        .await;
    assert_eq!(picker.status, StatusCode::OK);
    browser.dav(&f.device, "MKCOL", "Archive", "").await;
    let into_itself = browser
        .post(
            "/apps/files/",
            &[
                ("csrf", &csrf),
                ("action", "move"),
                ("item", "Docs"),
                ("at", "/Docs"),
                ("confirm", "1"),
            ],
        )
        .await;
    assert_eq!(
        into_itself.status,
        StatusCode::OK,
        "the picker again, with the error"
    );
    let moved = browser
        .post(
            "/apps/files/",
            &[
                ("csrf", &csrf),
                ("action", "move"),
                ("item", "Docs"),
                ("at", "/Archive"),
                ("confirm", "1"),
            ],
        )
        .await;
    assert_eq!(moved.location(), "/apps/files/?done=moved&n=1");
    assert_eq!(
        browser
            .dav(&f.device, "GET", "Archive/Docs/b.txt", "")
            .await
            .status,
        StatusCode::OK
    );

    // Deleting asks first; GET never changes anything.
    let asked = browser
        .get("/apps/files/Archive/?action=delete&item=Docs")
        .await;
    assert_eq!(asked.status, StatusCode::OK);
    assert!(
        asked.text().contains("there is no trash"),
        "{}",
        asked.text()
    );
    assert_eq!(
        browser
            .dav(&f.device, "PROPFIND", "Archive/Docs", "")
            .await
            .status,
        StatusCode::MULTI_STATUS
    );
    let deleted = browser
        .post(
            "/apps/files/Archive/",
            &[
                ("csrf", &csrf),
                ("action", "delete"),
                ("item", "Docs"),
                ("item", "gone"),
                ("confirm", "1"),
            ],
        )
        .await;
    assert_eq!(
        deleted.location(),
        "/apps/files/Archive/?done=deleted&n=1&error=partial&f=1&of=2"
    );
    assert_eq!(
        browser
            .dav(&f.device, "PROPFIND", "Archive/Docs", "")
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // Without the token, or from another site: refused.
    let forged = browser
        .post(
            "/apps/files/",
            &[("csrf", "nope"), ("action", "mkdir"), ("name", "X")],
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let body = format!("csrf={csrf}&action=mkdir&name=X");
    let cross = browser
        .send(
            "POST",
            "/apps/files/",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "https://evil.example"),
            ],
            Body::from(body),
        )
        .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
    assert_eq!(
        browser.dav(&f.device, "PROPFIND", "X", "").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn downloads_are_sandboxed_attachments_and_previews_passive() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser
        .dav(&f.device, "PUT", "page.html", "<script>alert(1)</script>")
        .await;
    browser
        .dav(&f.device, "PUT", "x.svg", "<svg onload=alert(1)/>")
        .await;
    browser
        .dav(&f.device, "PUT", "pic.png", "not really a png")
        .await;
    browser.sign_in().await;

    let download = browser.get("/apps/files/page.html?download").await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(
        download.header("content-disposition"),
        "attachment; filename*=UTF-8''page.html"
    );
    assert_eq!(
        download.header("content-security-policy"),
        "default-src 'none'; sandbox"
    );
    assert_eq!(download.header("x-content-type-options"), "nosniff");
    assert_eq!(
        download.header("cross-origin-resource-policy"),
        "same-origin"
    );

    // Only images, video and audio open inline, with a type the server picks.
    assert_eq!(
        browser.get("/apps/files/page.html?raw").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        browser.get("/apps/files/x.svg?raw").await.status,
        StatusCode::NOT_FOUND
    );
    let png = browser.get("/apps/files/pic.png?raw").await;
    assert_eq!(png.header("content-type"), "image/png");
    assert_eq!(png.header("content-disposition"), "inline");
    assert_eq!(
        png.header("content-security-policy"),
        "default-src 'none'; sandbox"
    );

    // HTML is shown as escaped text inside the page, never as a page.
    let page = browser.get("/apps/files/page.html").await;
    assert!(
        page.text()
            .contains("&#60;script&#62;alert(1)&#60;/script&#62;")
    );
    assert!(!page.text().contains("<script>alert"));

    let range = browser
        .send(
            "GET",
            "/apps/files/page.html?download",
            &[("Range", "bytes=0-7")],
            Body::empty(),
        )
        .await;
    assert_eq!(range.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(range.text(), "<script>");
}

#[tokio::test]
async fn folders_download_as_zip_archives() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.dav(&f.device, "MKCOL", "Docs", "").await;
    browser.dav(&f.device, "MKCOL", "Docs/sub", "").await;
    browser.dav(&f.device, "PUT", "Docs/a.txt", "alpha").await;
    browser
        .dav(&f.device, "PUT", "Docs/sub/b.txt", "beta")
        .await;
    let csrf = browser.sign_in().await;

    let zip = browser.get("/apps/files/Docs/?download").await;
    assert_eq!(zip.status, StatusCode::OK);
    assert_eq!(zip.header("content-type"), "application/zip");
    assert_eq!(
        zip.header("content-disposition"),
        "attachment; filename*=UTF-8''Docs.zip"
    );
    let bytes = &zip.body;
    assert!(bytes.starts_with(b"PK\x03\x04"));
    let end = bytes.len() - 22;
    assert_eq!(&bytes[end..end + 4], b"PK\x05\x06");
    assert_eq!(
        u16::from_le_bytes([bytes[end + 10], bytes[end + 11]]),
        4,
        "entries"
    );
    let text = String::from_utf8_lossy(bytes);
    for name in [
        "Docs/",
        "Docs/a.txt",
        "Docs/sub/",
        "Docs/sub/b.txt",
        "alpha",
        "beta",
    ] {
        assert!(text.contains(name), "{name}");
    }

    // A selection, through the form.
    let selection = browser
        .post(
            "/apps/files/Docs/",
            &[("csrf", &csrf), ("action", "zip"), ("item", "a.txt")],
        )
        .await;
    assert_eq!(selection.header("content-type"), "application/zip");
    let text = String::from_utf8_lossy(&selection.body);
    assert!(text.contains("a.txt") && !text.contains("sub/b.txt"));
}

/// A `multipart/form-data` body with the given parts: `(name, file name, content)`.
fn multipart(parts: &[(&str, Option<&str>, &str)]) -> (String, String) {
    let boundary = "----gonoTestBoundary";
    let mut body = String::new();
    for (name, file, content) in parts {
        body.push_str(&format!("--{boundary}\r\n"));
        match file {
            Some(file) => body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"{file}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )),
            None => body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"
            )),
        }
        body.push_str(content);
        body.push_str("\r\n");
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    (format!("multipart/form-data; boundary={boundary}"), body)
}

#[tokio::test]
async fn uploads_from_forms_and_from_the_script() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;

    // Form upload: the token first, then the files; folders in names are dropped.
    let (kind, body) = multipart(&[
        ("csrf", None, &csrf),
        ("file", Some("one.txt"), "1"),
        ("file", Some("../evil/two.txt"), "22"),
    ]);
    let uploaded = browser
        .send(
            "POST",
            "/apps/files/?upload",
            &[("Content-Type", &kind), ("Origin", ORIGIN)],
            Body::from(body),
        )
        .await;
    assert_eq!(
        uploaded.location(),
        "/apps/files/?done=uploaded&n=2&skipped=0"
    );
    assert_eq!(
        browser.dav(&f.device, "GET", "two.txt", "").await.text(),
        "22"
    );
    let (kind, body) = multipart(&[("csrf", None, &csrf), ("file", Some("one.txt"), "x")]);
    let skipped = browser
        .send(
            "POST",
            "/apps/files/?upload",
            &[("Content-Type", &kind), ("Origin", ORIGIN)],
            Body::from(body),
        )
        .await;
    assert_eq!(
        skipped.location(),
        "/apps/files/?done=uploaded&n=0&skipped=1"
    );
    let (kind, body) = multipart(&[("file", Some("late.txt"), "x"), ("csrf", None, &csrf)]);
    let late_token = browser
        .send(
            "POST",
            "/apps/files/?upload",
            &[("Content-Type", &kind), ("Origin", ORIGIN)],
            Body::from(body),
        )
        .await;
    assert_eq!(
        late_token.status,
        StatusCode::FORBIDDEN,
        "the token must come first"
    );

    // Script: the token in a header.
    let headers = |extra: &'static [(&'static str, &'static str)]| {
        let mut all = vec![("Origin", ORIGIN)];
        all.extend_from_slice(extra);
        all
    };
    let without = browser
        .send("PUT", "/apps/files/s.txt", &headers(&[]), Body::from("s"))
        .await;
    assert_eq!(without.status, StatusCode::FORBIDDEN);
    let mut with = headers(&[("If-None-Match", "*")]);
    with.push(("X-Gono-CSRF", &csrf));
    assert_eq!(
        browser
            .send("PUT", "/apps/files/s.txt", &with, Body::from("s"))
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(
        browser
            .send("PUT", "/apps/files/s.txt", &with, Body::from("t"))
            .await
            .status,
        StatusCode::PRECONDITION_FAILED
    );
    let token = [("Origin", ORIGIN), ("X-Gono-CSRF", csrf.as_str())];
    assert_eq!(
        browser
            .send("MKCOL", "/apps/files/Up/", &token, Body::empty())
            .await
            .status,
        StatusCode::CREATED
    );

    // Chunked: start, two byte ranges, finish.
    let base = "/apps/files/Up/big.bin?id=abcdef0123456789";
    let start = browser
        .send(
            "POST",
            &format!("{base}&chunked=start&total=10"),
            &token,
            Body::empty(),
        )
        .await;
    assert_eq!(start.status, StatusCode::CREATED, "{}", start.text());
    for (range, data) in [("start=0&end=5", "012345"), ("start=6&end=9", "6789")] {
        let part = browser
            .send(
                "PUT",
                &format!("{base}&chunked=part&{range}"),
                &token,
                Body::from(data),
            )
            .await;
        assert!(part.status.is_success(), "{} {}", part.status, part.text());
    }
    let finish = browser
        .send(
            "POST",
            &format!("{base}&chunked=finish&total=10"),
            &token,
            Body::empty(),
        )
        .await;
    assert!(
        finish.status.is_success(),
        "{} {}",
        finish.status,
        finish.text()
    );
    assert_eq!(
        browser.dav(&f.device, "GET", "Up/big.bin", "").await.text(),
        "0123456789"
    );
    let bad_id = browser
        .send(
            "POST",
            "/apps/files/Up/x?id=../../x&chunked=start&total=1",
            &token,
            Body::empty(),
        )
        .await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn search_and_favorites() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.dav(&f.device, "MKCOL", "Trips", "").await;
    browser
        .dav(&f.device, "PUT", "Trips/Beach%20day.jpg", "x")
        .await;
    browser.dav(&f.device, "PUT", "beachball.txt", "x").await;
    let csrf = browser.sign_in().await;

    let found = browser.get("/apps/files/?q=BEACH").await.text();
    assert!(
        found.contains("Beach day.jpg") && found.contains("beachball.txt"),
        "{found}"
    );
    let scoped = browser.get("/apps/files/Trips/?q=beach").await.text();
    assert!(scoped.contains("Beach day.jpg") && !scoped.contains("beachball.txt"));

    let starred = browser
        .post(
            "/apps/files/Trips/",
            &[
                ("csrf", &csrf),
                ("action", "favorite"),
                ("item", "Beach day.jpg"),
                ("value", "1"),
            ],
        )
        .await;
    assert_eq!(starred.location(), "/apps/files/Trips/?done=favorite");
    let favorites = browser.get("/apps/files/?view=favorites").await.text();
    assert!(favorites.contains("Beach day.jpg") && !favorites.contains("beachball.txt"));
    // Shared with the sync clients.
    let props = browser
        .dav(
            &f.device,
            "PROPFIND",
            "Trips/Beach%20day.jpg",
            r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:favorite/></d:prop></d:propfind>"#,
        )
        .await
        .text();
    assert!(props.contains("favorite>1<"), "{props}");
}

#[tokio::test]
async fn the_account_page_manages_password_and_app_passwords() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/webdav").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("laptop"));
    // What a client needs to connect.
    let text = page.text();
    assert!(text.contains("https://cloud.example.com</dd>"), "{text}");
    assert!(
        text.contains("https://cloud.example.com/remote.php/dav/files/alice/</dd>"),
        "{text}"
    );

    let renamed = browser
        .post(
            "/account/display-name",
            &[("csrf", &csrf), ("display_name", "Alice B.")],
        )
        .await;
    assert_eq!(renamed.location(), "/account/?done=display-name");

    let wrong = browser
        .post(
            "/account/password",
            &[
                ("csrf", &csrf),
                ("current", "nope"),
                ("password", "new password"),
                ("password_repeat", "new password"),
            ],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    let changed = browser
        .post(
            "/account/password",
            &[
                ("csrf", &csrf),
                ("current", ALICE_PASSWORD),
                ("password", "new password"),
                ("password_repeat", "new password"),
            ],
        )
        .await;
    assert_eq!(changed.location(), "/account/?done=password");
    assert_eq!(
        browser.get("/account/").await.status,
        StatusCode::OK,
        "still signed in"
    );

    let created = browser
        .post(
            "/account/app-passwords",
            &[("csrf", &csrf), ("label", "rclone"), ("access", "view")],
        )
        .await;
    assert_eq!(created.location(), "/account/created");
    let shown = browser.get("/account/created").await;
    let text = shown.text();
    let start = text.find("<div class=\"secret\">").expect("secret") + 20;
    let token = text[start..start + text[start..].find('<').unwrap()].to_owned();
    assert!(token.len() >= 29, "{token}");
    assert_eq!(
        browser.get("/account/created").await.location(),
        "/account/webdav",
        "shown once"
    );
    // The new app password is read only.
    assert_eq!(
        browser.dav(&token, "PUT", "ro.txt", "x").await.status,
        StatusCode::FORBIDDEN
    );

    let list = app_passwords::list(&f.state.db, 1).await.unwrap();
    let id = list.iter().find(|p| p.label == "rclone").unwrap().id;
    let revoked = browser
        .post(
            &format!("/account/app-passwords/{id}/delete"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(revoked.location(), "/account/webdav?done=revoked");
    assert!(
        browser
            .get("/account/webdav?done=revoked")
            .await
            .text()
            .contains("The app password was revoked.")
    );
    assert_eq!(
        browser.dav(&token, "PROPFIND", "", "").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn theme_switch_and_assets() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let light = browser.post("/apps/theme", &[("back", "/login")]).await;
    assert_eq!(light.location(), "/login");
    assert_eq!(
        browser.cookies.get("gono_theme").map(String::as_str),
        Some("light")
    );
    let page = browser.get("/login").await;
    assert!(
        page.text()
            .contains("<html lang=\"en\" data-theme=\"light\">")
    );
    let json = browser
        .send(
            "POST",
            "/apps/theme",
            &[
                ("Accept", "application/json"),
                ("Origin", ORIGIN),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            Body::from("back=%2F"),
        )
        .await;
    assert_eq!(json.text(), r#"{"theme":"dark"}"#);
    let away = browser
        .post("/apps/theme", &[("back", "//evil.example/")])
        .await;
    assert_eq!(away.location(), "/", "only local pages");

    let style = web::style_url();
    let reply = browser.get(style).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.header("cache-control"),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        browser.get("/apps/assets/other.js").await.status,
        StatusCode::NOT_FOUND
    );

    // Chinese for browsers that prefer it.
    let zh = browser
        .send(
            "GET",
            "/login",
            &[("Accept-Language", "zh-CN,zh;q=0.9")],
            Body::empty(),
        )
        .await;
    assert!(zh.text().contains("<html lang=\"zh-CN\""), "{}", zh.text());
}

#[tokio::test]
async fn the_file_ui_can_be_turned_off() {
    let f = fixture_with(false).await;
    let mut browser = Browser::new(&f.state);
    assert_eq!(
        browser.get("/apps/files/").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(browser.get("/account/").await.status, StatusCode::NOT_FOUND);
    assert_eq!(browser.get("/login").await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        browser.get("/").await.status,
        StatusCode::NOT_FOUND,
        "no admin UI either"
    );
}

#[tokio::test]
async fn the_file_ui_needs_the_files_service_but_the_account_page_does_not() {
    use gono_server_core::{
        services::{Service, Services},
        users,
    };
    let f = fixture().await;
    let alice = Username::new("alice").unwrap();
    users::set_services(
        &f.state.db,
        &alice,
        Services::ALL.with(Service::Files, false),
    )
    .await
    .unwrap();
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;

    let files = browser.get("/apps/files/").await;
    assert_eq!(files.status, StatusCode::FORBIDDEN);
    assert!(
        files.text().contains("web file service is not enabled"),
        "{}",
        files.text()
    );
    // Under the entry of the masthead the visitor chose.
    assert!(
        files
            .text()
            .contains(r#"href="/apps/files/" aria-current="page""#)
    );
    let favorites = browser.get("/apps/files/?view=favorites").await;
    assert_eq!(favorites.status, StatusCode::FORBIDDEN);
    assert!(
        favorites
            .text()
            .contains(r#"href="/apps/files/?view=favorites" aria-current="page""#)
    );
    let account = browser.get("/account/").await;
    assert_eq!(account.status, StatusCode::OK);
    let root = browser.get("/").await;
    assert_eq!(root.location(), "/account/");
    // The script's requests are refused too.
    let csrf = account.csrf();
    let mkcol = browser
        .send(
            "MKCOL",
            "/apps/files/New",
            &[("X-Gono-CSRF", &csrf)],
            Body::empty(),
        )
        .await;
    assert_eq!(mkcol.status, StatusCode::FORBIDDEN);

    users::set_services(&f.state.db, &alice, Services::ALL)
        .await
        .unwrap();
    assert_eq!(browser.get("/apps/files/").await.status, StatusCode::OK);
    assert_eq!(browser.get("/").await.location(), "/apps/files/");
}

/// Registers a device for remote access through a device flow, as the browser would grant it.
async fn register_device(
    state: &AppState,
    user_id: i64,
    seed: u8,
    name: &str,
) -> gono_server_core::devices::Device {
    use gono_server_core::{
        devices::{EndpointId, NewDevice, Registration},
        login_flows,
    };
    let now = db::unix_now();
    let new = NewDevice {
        endpoint_id: EndpointId([seed; 32]),
        product: "input-show".to_owned(),
        platform: "windows".to_owned(),
        name: name.to_owned(),
        version: String::new(),
    };
    let (flow, _) = login_flows::create_device(&state.db, &new, now)
        .await
        .unwrap()
        .unwrap();
    let found = login_flows::find(&state.db, flow.login_token.expose_secret(), now)
        .await
        .unwrap()
        .unwrap();
    login_flows::grant(&state.db, found.id, user_id, None, now)
        .await
        .unwrap();
    let (_, registration) =
        login_flows::complete_device(&state.db, flow.poll_token.expose_secret(), now)
            .await
            .unwrap()
            .done()
            .unwrap();
    let Registration::Registered { device, .. } = registration else {
        panic!("registered");
    };
    *device
}

#[tokio::test]
async fn remote_devices_are_revoked_after_a_second_confirmation() {
    use gono_server_core::devices;

    let mut f = fixture().await;
    let connect = gono_server_connect::Connect::new(
        f.state.db.clone(),
        gono_server_connect::ConnectConfig {
            base_url: ORIGIN.parse().unwrap(),
            relay_url: "https://relay.example.com".parse().unwrap(),
            audit_retention_secs: 3600,
            require_two_factor: true,
        },
    )
    .await
    .unwrap();
    f.state.connect = Some(connect);
    let alice = users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap()
        .id;
    let phone = register_device(&f.state, alice, 1, "Phone").await;
    let work = register_device(&f.state, alice, 2, "Work PC").await;
    let laptop = register_device(&f.state, alice, 3, "Laptop").await;
    for subject in [&work, &laptop] {
        devices::record_approval(
            &f.state.db,
            alice,
            phone.id,
            subject.id,
            &serde_json::json!({}),
            1,
        )
        .await
        .unwrap();
    }

    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let page = browser.get("/account/direct").await;
    let text = page.text();
    assert!(text.contains("Remote devices"), "{text}");
    assert!(text.contains(&phone.endpoint_id.short()), "{text}");
    assert!(text.contains("Input Show · Windows"), "{text}");
    // The device credentials are not app passwords: only the fixture's own one is listed.
    let webdav = browser.get("/account/webdav").await.text();
    assert_eq!(webdav.matches("/delete\"").count(), 1, "{webdav}");
    let csrf = page.csrf();

    let hex = phone.endpoint_id.to_hex();
    let confirm = browser.get(&format!("/account/devices/{hex}/revoke")).await;
    assert_eq!(confirm.status, StatusCode::OK);
    let confirm_text = confirm.text();
    assert!(
        confirm_text.contains("This cannot be undone"),
        "{confirm_text}"
    );
    assert!(
        confirm_text.contains("Work PC") && confirm_text.contains("Laptop"),
        "{confirm_text}"
    );
    assert!(
        !devices::get(&f.state.db, phone.id)
            .await
            .unwrap()
            .unwrap()
            .is_revoked(),
        "the page alone changes nothing"
    );

    let also = format!("also_{}", work.endpoint_id.to_hex());
    let revoked = browser
        .post(
            &format!("/account/devices/{hex}/revoke"),
            &[("csrf", &csrf), (&also, "1")],
        )
        .await;
    assert_eq!(revoked.location(), "/account/direct?done=device-revoked");
    let state = |id| {
        let db = f.state.db.clone();
        async move { devices::get(&db, id).await.unwrap().unwrap().is_revoked() }
    };
    assert!(state(phone.id).await);
    assert!(state(work.id).await, "ticked, revoked along with it");
    assert!(!state(laptop.id).await, "not ticked, still trusted");
    let page = browser
        .get("/account/direct?done=device-revoked")
        .await
        .text();
    assert!(page.contains("Revoked."), "{page}");
    assert!(page.contains("Not applied yet by: Laptop"), "{page}");

    // A revoked device has no actions any more.
    assert_eq!(
        browser
            .get(&format!("/account/devices/{hex}/revoke"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    let laptop_hex = laptop.endpoint_id.to_hex();
    let pairing = browser
        .post(
            &format!("/account/devices/{laptop_hex}/pairing"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(pairing.location(), "/account/direct?done=pairing");
    assert!(
        devices::get(&f.state.db, laptop.id)
            .await
            .unwrap()
            .unwrap()
            .pairing_open(db::unix_now())
    );
    let forged = browser
        .post(
            &format!("/account/devices/{laptop_hex}/revoke"),
            &[("csrf", "forged")],
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert!(!state(laptop.id).await);
}

#[tokio::test]
async fn remote_access_stops_for_a_device_without_revoking_it() {
    use gono_server_core::devices;

    let mut f = fixture().await;
    let connect = gono_server_connect::Connect::new(
        f.state.db.clone(),
        gono_server_connect::ConnectConfig {
            base_url: ORIGIN.parse().unwrap(),
            relay_url: "https://relay.example.com".parse().unwrap(),
            audit_retention_secs: 3600,
            require_two_factor: true,
        },
    )
    .await
    .unwrap();
    f.state.connect = Some(connect);
    let alice = users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap()
        .id;
    let work = register_device(&f.state, alice, 4, "Work PC").await;

    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let page = browser.get("/account/direct").await;
    let text = page.text();
    assert!(text.contains("Stop remote access"), "{text}");
    let csrf = page.csrf();
    let hex = work.endpoint_id.to_hex();
    let path = format!("/account/devices/{hex}/sign-out");

    let forged = browser.post(&path, &[("csrf", "forged")]).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let stopped = browser.post(&path, &[("csrf", &csrf)]).await;
    assert_eq!(stopped.location(), "/account/direct?done=device-signed-out");
    let entry = devices::get(&f.state.db, work.id).await.unwrap().unwrap();
    assert!(entry.is_signed_out(), "signed out");
    assert!(!entry.is_revoked(), "not revoked");
    let page = browser
        .get("/account/direct?done=device-signed-out")
        .await
        .text();
    assert!(page.contains("It keeps its pairings"), "{page}");
    // A signed-out entry stays on the page and stays revocable (protocol 9.4).
    assert!(page.contains(&work.endpoint_id.short()), "{page}");
    assert!(
        page.contains(&format!("/account/devices/{hex}/revoke")),
        "{page}"
    );
}

/// Decodes RFC 4648 base32 (spaces allowed), the key the enrolment page shows.
fn base32_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let value = ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// The 6-digit code of `secret` at `step`.
fn step_code(secret: &[u8], step: i64) -> String {
    format!("{:06}", gono_server_core::two_factor::code_at(secret, step))
}

/// The 6-digit code of `secret` `steps` steps from now.
fn code(secret: &[u8], steps: i64) -> String {
    step_code(
        secret,
        gono_server_core::two_factor::step_of(db::unix_now()) + steps,
    )
}

/// Turns two-step verification on for alice in `browser` (signed in); returns the secret, the
/// recovery codes and the step whose code turned it on, which counts as used. Tests that need a
/// used code take that step's: the step of "now" may have moved on since.
async fn enrol(browser: &mut Browser, csrf: &str) -> (Vec<u8>, Vec<String>, i64) {
    let started = browser
        .post(
            "/account/two-factor/start",
            &[("csrf", csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(
        started.location(),
        "/account/two-factor",
        "{}",
        started.text()
    );
    let page = browser.get("/account/two-factor").await;
    let text = page.text();
    assert!(
        text.contains("<svg ") && text.contains("class=\"qr\""),
        "{text}"
    );
    let key = text
        .split("<code>")
        .nth(1)
        .unwrap()
        .split("</code>")
        .next()
        .unwrap();
    let secret = base32_decode(key);
    assert_eq!(secret.len(), 20);

    let wrong = browser
        .post(
            "/account/two-factor/confirm",
            &[("csrf", csrf), ("code", "000000")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    let step = gono_server_core::two_factor::step_of(db::unix_now());
    let confirmed = browser
        .post(
            "/account/two-factor/confirm",
            &[("csrf", csrf), ("code", &step_code(&secret, step))],
        )
        .await;
    assert_eq!(confirmed.location(), "/account/two-factor/recovery-codes");
    let shown = browser
        .get("/account/two-factor/recovery-codes")
        .await
        .text();
    let codes: Vec<String> = shown
        .split("<li>")
        .skip(1)
        .map(|item| item.split("</li>").next().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10, "{shown}");
    assert_eq!(
        browser
            .get("/account/two-factor/recovery-codes")
            .await
            .location(),
        "/account/",
        "shown once"
    );
    (secret, codes, step)
}

/// Signs alice in with her password; returns the reply of the password form.
async fn password_step(browser: &mut Browser) -> Reply {
    let form = browser.get("/login").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    browser
        .post(
            "/login",
            &[
                ("csrf", &csrf),
                ("user", "alice"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await
}

/// Enters `code` at the second step; returns the reply.
async fn code_step(browser: &mut Browser, code: &str) -> Reply {
    let page = browser.get("/login/two-step").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let csrf = page.field("name=\"csrf\" value=\"");
    browser
        .post("/login/two-step", &[("csrf", &csrf), ("code", code)])
        .await
}

#[tokio::test]
async fn two_step_verification_guards_every_later_sign_in() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/").await.text();
    assert!(page.contains("/account/two-factor/start"), "{page}");
    let refused = browser
        .post(
            "/account/two-factor/start",
            &[("csrf", &csrf), ("password", "wrong")],
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    let (secret, codes, enrolled) = enrol(&mut browser, &csrf).await;
    let page = browser.get("/account/?done=two-factor-on").await.text();
    assert!(page.contains("Two-step verification is on."), "{page}");
    assert!(page.contains("Recovery codes left: 10."), "{page}");

    // A new browser: the password alone opens no session.
    let mut other = Browser::new(&f.state);
    let first = password_step(&mut other).await;
    assert_eq!(first.location(), "/login/two-step");
    assert_eq!(
        other.get("/apps/files/").await.status,
        StatusCode::SEE_OTHER,
        "no session yet"
    );
    let wrong = code_step(&mut other, "123456").await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert!(
        wrong.text().contains("That code is not right"),
        "{}",
        wrong.text()
    );
    // The code of the enrolment was used up; the next step's works.
    let used = code_step(&mut other, &step_code(&secret, enrolled)).await;
    assert_eq!(used.status, StatusCode::FORBIDDEN, "a code works once");
    let signed_in = code_step(&mut other, &code(&secret, 1)).await;
    assert_eq!(signed_in.location(), "/apps/files/", "{}", signed_in.text());
    assert_eq!(other.get("/apps/files/").await.status, StatusCode::OK);
    assert_eq!(
        other.get("/login/two-step").await.status,
        StatusCode::NOT_FOUND,
        "the pending sign-in is gone"
    );

    // A recovery code signs in once, and the page after it says how many are left.
    let mut third = Browser::new(&f.state);
    password_step(&mut third).await;
    let recovered = code_step(&mut third, &codes[0].to_ascii_lowercase()).await;
    assert_eq!(recovered.status, StatusCode::OK, "{}", recovered.text());
    let notice = recovered.text();
    assert!(
        notice.contains("Signed in with a recovery code")
            && notice.contains("You have 9 recovery codes left.")
            && notice.contains("href=\"/apps/files/\""),
        "{notice}"
    );
    assert_eq!(third.get("/apps/files/").await.status, StatusCode::OK);
    let mut fourth = Browser::new(&f.state);
    password_step(&mut fourth).await;
    let again = code_step(&mut fourth, &codes[0]).await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    let page = browser.get("/account/").await.text();
    assert!(page.contains("Recovery codes left: 9."), "{page}");
    assert!(
        page.contains("the second step failed"),
        "failures are shown: {page}"
    );
    // The use of the recovery code is shown too, with the client's address.
    let used = page
        .split("Recovery codes were used to sign in")
        .nth(1)
        .unwrap_or_else(|| panic!("recovery code uses are shown: {page}"));
    assert!(
        used[..used.find("</div></div>").unwrap()].contains("from 192.0.2.7"),
        "{used}"
    );

    // Turning it off needs the password and a code.
    let without_code = browser
        .post(
            "/account/two-factor/disable",
            &[
                ("csrf", &csrf),
                ("password", ALICE_PASSWORD),
                ("code", "000000"),
            ],
        )
        .await;
    assert_eq!(without_code.status, StatusCode::UNPROCESSABLE_ENTITY);
    let off = browser
        .post(
            "/account/two-factor/disable",
            &[
                ("csrf", &csrf),
                ("password", ALICE_PASSWORD),
                ("code", &codes[1]),
            ],
        )
        .await;
    assert_eq!(off.location(), "/account/?done=two-factor-off");
    let mut fifth = Browser::new(&f.state);
    assert_eq!(password_step(&mut fifth).await.location(), "/apps/files/");
}

#[tokio::test]
async fn the_account_page_says_whether_remote_access_needs_two_step_verification() {
    for required in [true, false] {
        let mut f = fixture().await;
        let connect = gono_server_connect::Connect::new(
            f.state.db.clone(),
            gono_server_connect::ConnectConfig {
                base_url: ORIGIN.parse().unwrap(),
                relay_url: "https://relay.example.com".parse().unwrap(),
                audit_retention_secs: 3600,
                require_two_factor: required,
            },
        )
        .await
        .unwrap();
        f.state.connect = Some(connect);
        let mut browser = Browser::new(&f.state);
        browser.sign_in().await;
        let page = browser.get("/account/?done=two-factor-off").await.text();
        assert!(page.contains("Two-step verification is off."), "{page}");
        assert_eq!(
            page.contains("Remote access for your devices needs it."),
            required,
            "{page}"
        );
        assert_eq!(
            page.contains("Remote access for your devices stays off"),
            required,
            "{page}"
        );
    }
}

#[tokio::test]
async fn wrong_codes_lock_the_second_step() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let (secret, _, _) = enrol(&mut browser, &csrf).await;

    let mut other = Browser::new(&f.state);
    password_step(&mut other).await;
    for _ in 0..4 {
        assert_eq!(
            code_step(&mut other, "000000").await.status,
            StatusCode::FORBIDDEN
        );
    }
    // The fifth wrong code ends the pending sign-in; the account is locked for a while.
    assert_eq!(
        code_step(&mut other, "000000").await.status,
        StatusCode::NOT_FOUND
    );
    password_step(&mut other).await;
    let locked = code_step(&mut other, &code(&secret, 1)).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        locked.text().contains("Too many wrong codes"),
        "{}",
        locked.text()
    );
}

/// Turns two-step verification on for alice directly; returns her account and the secret.
async fn enrolled_alice(f: &Fixture) -> (users::User, [u8; 20]) {
    use gono_server_core::two_factor;
    let alice = users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap();
    let key = f.state.web.two_factor_key().unwrap().clone();
    let secret = two_factor::new_secret();
    two_factor::enable(
        &f.state.db,
        &key,
        alice.id,
        &secret,
        0,
        None,
        None,
        db::unix_now(),
    )
    .await
    .unwrap();
    (alice, secret)
}

/// Starts a sign-in of `user` waiting for its second step directly; returns the `Cookie`
/// header that names it.
async fn pending_cookie(f: &Fixture, user: &users::User) -> HeaderMap {
    let web::Started::SecondStep(cookie) = f
        .state
        .web
        .start_session("192.0.2.9".parse().unwrap(), user, "/apps/files/")
        .await
    else {
        panic!("a second step");
    };
    let pair = cookie
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut headers = HeaderMap::new();
    headers.insert("cookie", pair.parse().unwrap());
    headers
}

/// The failed second steps recorded for `user_id`.
async fn recorded_failures(f: &Fixture, user_id: i64) -> usize {
    gono_server_core::audit::list(&f.state.db, Some(user_id), None, 1000)
        .await
        .unwrap()
        .iter()
        .filter(|entry| entry.kind == "two_factor.failed")
        .count()
}

/// A code that is never right: a recovery code nobody was given.
const NEVER_RIGHT: &str = "0000-0000-0000-0000";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_wrong_codes_are_checked_no_more_than_the_limit() {
    let f = fixture().await;
    let (alice, _) = enrolled_alice(&f).await;
    // As many pending sign-ins as one account may have, each good for five codes.
    let mut cookies = Vec::new();
    for _ in 0..5 {
        cookies.push(pending_cookie(&f, &alice).await);
    }
    let tasks: Vec<_> = (0..300_usize)
        .map(|index| {
            let web = f.state.web.clone();
            let headers = cookies[index % cookies.len()].clone();
            // Many clients, so that the per-client limiter does not stop them first.
            let client =
                std::net::IpAddr::from([198, 51, (index / 200) as u8, (index % 200) as u8]);
            tokio::spawn(async move { web.second_step(client, &headers, NEVER_RIGHT).await })
        })
        .collect();
    let mut wrong = 0;
    for task in tasks {
        match task.await.unwrap() {
            web::SecondStep::Wrong => wrong += 1,
            web::SecondStep::Locked | web::SecondStep::Expired => {}
            other => panic!("{other:?}"),
        }
    }
    let limit = usize::try_from(gono_server_core::two_factor::FAILURES_PER_WINDOW).unwrap();
    assert_eq!(recorded_failures(&f, alice.id).await, limit);
    assert_eq!(wrong, limit, "only the codes before the lock were checked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_wrong_codes_on_the_account_page_are_limited_too() {
    let f = fixture().await;
    let (alice, _) = enrolled_alice(&f).await;
    let tasks: Vec<_> = (0..100_u8)
        .map(|index| {
            let web = f.state.web.clone();
            let client = std::net::IpAddr::from([203, 0, 113, index]);
            tokio::spawn(async move { web.check_code(client, alice.id, NEVER_RIGHT).await })
        })
        .collect();
    let mut wrong = 0;
    for task in tasks {
        match task.await.unwrap() {
            web::CodeCheck::Wrong => wrong += 1,
            web::CodeCheck::Locked => {}
            other => panic!("{other:?}"),
        }
    }
    let limit = usize::try_from(gono_server_core::two_factor::FAILURES_PER_WINDOW).unwrap();
    assert_eq!(wrong, limit);
    assert_eq!(recorded_failures(&f, alice.id).await, limit);
}

#[tokio::test]
async fn a_failure_that_cannot_be_recorded_does_not_pass_as_a_wrong_code() {
    let f = fixture().await;
    let (alice, _) = enrolled_alice(&f).await;
    // The database refuses the record of a failure, as it would when it stays busy. (MySQL
    // creates triggers through the text protocol only, which `raw_sql` uses.)
    sqlx::raw_sql(db::Backend::of(&f.state.db).pick(
        "CREATE TRIGGER refuse_failures BEFORE INSERT ON audit_log \
         WHEN NEW.kind = 'two_factor.failed' BEGIN SELECT RAISE(ABORT, 'database is locked'); END",
        "CREATE TRIGGER refuse_failures BEFORE INSERT ON audit_log FOR EACH ROW BEGIN \
         IF NEW.kind = 'two_factor.failed' THEN \
         SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'database is locked'; END IF; END",
    ))
    .execute(&f.state.db)
    .await
    .unwrap();
    let headers = pending_cookie(&f, &alice).await;
    let client = "198.51.100.1".parse().unwrap();
    assert!(matches!(
        f.state.web.second_step(client, &headers, NEVER_RIGHT).await,
        web::SecondStep::Unavailable
    ));
    assert_eq!(
        f.state.web.check_code(client, alice.id, NEVER_RIGHT).await,
        web::CodeCheck::Unavailable
    );
}

#[tokio::test]
async fn one_pending_sign_in_takes_five_codes_at_most() {
    let f = fixture().await;
    let (alice, _) = enrolled_alice(&f).await;
    let headers = pending_cookie(&f, &alice).await;
    let mut outcomes = Vec::new();
    for index in 0..7_u8 {
        // A client of its own each time: only the pending sign-in's count stops them.
        let client = std::net::IpAddr::from([198, 51, 100, index]);
        outcomes.push(f.state.web.second_step(client, &headers, NEVER_RIGHT).await);
    }
    assert!(
        matches!(
            outcomes.as_slice(),
            [
                web::SecondStep::Wrong,
                web::SecondStep::Wrong,
                web::SecondStep::Wrong,
                web::SecondStep::Wrong,
                web::SecondStep::Expired,
                web::SecondStep::Expired,
                web::SecondStep::Expired,
            ]
        ),
        "{outcomes:?}"
    );
}

#[tokio::test]
async fn pending_sign_ins_end_with_the_state_they_were_started_in() {
    use gono_server_core::two_factor::{self, TurnedOff};
    let f = fixture().await;
    let (alice, secret) = enrolled_alice(&f).await;
    let client: std::net::IpAddr = "192.0.2.9".parse().unwrap();

    // Each account keeps its newest five; a sixth ends the oldest instead of being refused.
    let oldest = pending_cookie(&f, &alice).await;
    for _ in 0..5 {
        pending_cookie(&f, &alice).await;
    }
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 5);
    assert!(matches!(
        f.state
            .web
            .second_step(client, &oldest, &code(&secret, 0))
            .await,
        web::SecondStep::Expired
    ));

    // A new password, even one set with the CLI (no process to tell): the sign-in that waits
    // for its code with the old one ends, although the code is right.
    let headers = pending_cookie(&f, &alice).await;
    // `updated_at` counts seconds.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let hash = password::hash(&SecretString::from("a new password".to_owned())).unwrap();
    users::set_password_hash(&f.state.db, &alice.username, &hash)
        .await
        .unwrap();
    assert!(matches!(
        f.state
            .web
            .second_step(client, &headers, &code(&secret, 0))
            .await,
        web::SecondStep::Expired
    ));
    let alice = users::get(&f.state.db, &alice.username).await.unwrap();

    // Disabled with the CLI: refused at the end.
    let headers = pending_cookie(&f, &alice).await;
    users::set_enabled(&f.state.db, &alice.username, false)
        .await
        .unwrap();
    assert!(matches!(
        f.state
            .web
            .second_step(client, &headers, &code(&secret, 1))
            .await,
        web::SecondStep::Expired
    ));
    users::set_enabled(&f.state.db, &alice.username, true)
        .await
        .unwrap();
    let alice = users::get(&f.state.db, &alice.username).await.unwrap();

    // Reset with the CLI: the password has to be entered again.
    let headers = pending_cookie(&f, &alice).await;
    two_factor::disable(&f.state.db, alice.id, TurnedOff::Cli, None, db::unix_now())
        .await
        .unwrap();
    assert!(matches!(
        f.state
            .web
            .second_step(client, &headers, &code(&secret, 1))
            .await,
        web::SecondStep::Expired
    ));
}

#[tokio::test]
async fn account_page_changes_end_the_pending_sign_ins() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let (secret, _, _) = enrol(&mut browser, &csrf).await;
    let alice = users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap();

    // Someone with the password waits at the second step; the user changes it.
    let mut other = Browser::new(&f.state);
    assert_eq!(
        password_step(&mut other).await.location(),
        "/login/two-step"
    );
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 1);
    let changed = browser
        .post(
            "/account/password",
            &[
                ("csrf", &csrf),
                ("current", ALICE_PASSWORD),
                ("password", "a new password"),
                ("password_repeat", "a new password"),
            ],
        )
        .await;
    assert_eq!(changed.location(), "/account/?done=password");
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 0);
    assert_eq!(
        other.get("/login/two-step").await.status,
        StatusCode::NOT_FOUND
    );

    // Turning two-step verification off ends them as well.
    let alice = users::get(&f.state.db, &alice.username).await.unwrap();
    pending_cookie(&f, &alice).await;
    let off = browser
        .post(
            "/account/two-factor/disable",
            &[
                ("csrf", &csrf),
                ("password", "a new password"),
                ("code", &code(&secret, 1)),
            ],
        )
        .await;
    assert_eq!(off.location(), "/account/?done=two-factor-off");
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 0);
}

#[tokio::test]
async fn enrolment_signs_out_sessions_opened_with_the_password_alone() {
    let f = fixture().await;
    // Someone who knows the password signs in while two-step verification is off.
    let mut earlier = Browser::new(&f.state);
    earlier.sign_in().await;
    assert_eq!(earlier.get("/account/").await.status, StatusCode::OK);
    let mut owner = Browser::new(&f.state);
    let csrf = owner.sign_in().await;
    enrol(&mut owner, &csrf).await;
    assert_eq!(
        earlier.get("/account/").await.status,
        StatusCode::SEE_OTHER,
        "the session from before the enrolment ended"
    );
    assert_eq!(
        owner.get("/account/").await.status,
        StatusCode::OK,
        "the enrolling session stays"
    );
}

#[tokio::test]
async fn secrets_shown_once_stay_with_the_account_of_their_session() {
    use gono_server_core::web_sessions::SessionUser;
    let f = fixture().await;
    // Another account's session that got the same row id after a sign-out.
    let session = |user_id, name: &str| SessionUser {
        session_id: 7,
        user_id,
        username: Username::new(name).unwrap(),
        display_name: name.to_owned(),
        is_admin: false,
        services: gono_server_core::services::Services::ALL,
    };
    let (alice, bob) = (session(1, "alice"), session(2, "bob"));
    f.state.web.start_enrolment(&alice, None);
    assert!(f.state.web.enrolment(&bob).is_none());
    f.state.web.end_enrolment(&bob);
    assert!(
        f.state.web.enrolment(&alice).is_some(),
        "not ended by another account"
    );
    f.state.web.show_once(&alice, vec!["CODE".into()], None);
    assert!(f.state.web.take_shown(&bob).is_none());
    assert_eq!(f.state.web.take_shown(&alice).unwrap().codes, ["CODE"]);

    // A new app password through the pages: alice creates one and signs out before reading
    // it; bob signs in on the same browser and finds nothing, whatever row id he gets.
    let layout = DataLayout::new(f._dir.path().join("data"));
    let hash = password::hash(&SecretString::from("bob password".to_owned())).unwrap();
    users::create(
        &f.state.db,
        &NewUser {
            username: &Username::new("bob").unwrap(),
            display_name: "Bob",
            password_hash: &hash,
            is_admin: false,
            services: gono_server_core::services::Services::ALL,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap();
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let created = browser
        .post(
            "/account/app-passwords",
            &[("csrf", &csrf), ("label", "rclone")],
        )
        .await;
    assert_eq!(created.location(), "/account/created");
    browser.post("/logout", &[("csrf", &csrf)]).await;
    let form = browser.get("/login").await;
    let login_csrf = form.field("name=\"csrf\" value=\"");
    let signed_in = browser
        .post(
            "/login",
            &[
                ("csrf", &login_csrf),
                ("user", "bob"),
                ("password", "bob password"),
            ],
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
    assert_eq!(
        browser.get("/account/created").await.location(),
        "/account/webdav",
        "nothing to show to bob"
    );
}

/// The S3 API as the pages see it: on, with anonymous access allowed or not.
fn s3_on(allow_anonymous: bool) -> Option<Arc<crate::s3::S3Ui>> {
    Some(Arc::new(crate::s3::S3Ui {
        public_url: Some(Url::parse("https://s3.example.com").unwrap()),
        region: "eu-test-1".to_owned(),
        bucket_folder: "Buckets".to_owned(),
        allow_anonymous,
        virtual_host_domain: None,
        website_domain: None,
    }))
}

/// The kinds of alice's audit records, oldest first.
async fn audit_kinds(f: &Fixture) -> Vec<(String, String)> {
    let mut kinds: Vec<(String, String)> =
        gono_server_core::audit::list(&f.state.db, Some(1), None, 1000)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| (entry.kind, entry.actor))
            .collect();
    kinds.reverse();
    kinds
}

/// Every S3 form of the account page, with fields that would change something.
const S3_FORMS: [(&str, &[(&str, &str)]); 6] = [
    ("/account/s3/buckets", &[("name", "photos")]),
    (
        "/account/s3/buckets/bind",
        &[("name", "photos"), ("folder", "/Photos")],
    ),
    (
        "/account/s3/buckets/1/anonymous",
        &[("anonymous", "public-read")],
    ),
    ("/account/s3/buckets/1/delete", &[]),
    ("/account/s3/keys", &[("label", "rclone")]),
    ("/account/s3/keys/1/delete", &[]),
];

#[tokio::test]
async fn the_s3_tab_says_when_the_server_does_not_offer_s3_or_the_account_lacks_it() {
    use gono_server_core::services::{Service, Services};
    let mut f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;

    // The S3 API is off: the tab is still listed and says so, and its forms answer 404.
    let page = browser.get("/account/s3").await;
    assert_eq!(page.status, StatusCode::OK);
    let text = page.text();
    assert!(
        text.contains("This server does not offer this service."),
        "{text}"
    );
    assert!(
        text.contains(r#"href="/account/s3" aria-current="page">S3</a>"#),
        "{text}"
    );
    assert!(!text.contains("/account/s3/"), "{text}");
    assert!(!text.contains("S3 buckets"), "{text}");
    for (uri, fields) in S3_FORMS {
        let mut fields = fields.to_vec();
        fields.push(("csrf", &csrf));
        assert_eq!(
            browser.post(uri, &fields).await.status,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
    assert_eq!(
        browser.get("/account/s3/created").await.status,
        StatusCode::NOT_FOUND
    );
    let overview = browser.get("/account/").await.text();
    assert!(
        overview.contains("Not offered by this server"),
        "{overview}"
    );

    // The API is on, but the account lacks the service: the tab shows only that, and its
    // forms are refused with the same notice.
    f.state.s3 = s3_on(true);
    let alice = Username::new("alice").unwrap();
    users::set_services(&f.state.db, &alice, Services::ALL.with(Service::S3, false))
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/s3").await;
    assert_eq!(page.status, StatusCode::OK);
    let text = page.text();
    assert!(
        text.contains(
            "This service is not enabled for your account. Ask an administrator to turn it on."
        ),
        "{text}"
    );
    assert!(!text.contains("S3 buckets"), "{text}");
    for (uri, fields) in S3_FORMS {
        let mut fields = fields.to_vec();
        fields.push(("csrf", &csrf));
        let refused = browser.post(uri, &fields).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{uri}");
        assert!(
            refused.text().contains("not enabled for your account"),
            "{uri}: {}",
            refused.text()
        );
    }
    let zh = browser
        .send(
            "GET",
            "/account/s3",
            &[("Accept-Language", "zh-CN,zh;q=0.9")],
            Body::empty(),
        )
        .await
        .text();
    assert!(
        zh.contains("你的账号未开通此服务，请联系管理员开通。"),
        "{zh}"
    );
    assert!(
        gono_server_core::s3::buckets_of(&f.state.db, 1)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        gono_server_core::s3::list_keys(&f.state.db, 1)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_account_page_shows_virtual_hosted_style_when_enabled() {
    let mut f = fixture().await;
    f.state.s3 = s3_on(true);
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let text = browser.get("/account/s3").await.text();
    assert!(!text.contains("Virtual-hosted style"), "{text}");

    let mut ui = (*s3_on(true).unwrap()).clone();
    ui.virtual_host_domain = Some("s3.example.com".to_owned());
    f.state.s3 = Some(Arc::new(ui));
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let text = browser.get("/account/s3").await.text();
    assert!(text.contains("Path style: https://s3.example.com/&#60;bucket&#62;/&#60;key&#62;"));
    assert!(
        text.contains(
            "<br>Virtual-hosted style: https://&#60;bucket&#62;.s3.example.com/&#60;key&#62;"
        ),
        "{text}"
    );
}

#[tokio::test]
async fn the_account_page_shows_tags_lifecycle_rules_and_websites_set_through_s3() {
    use gono_server_core::s3;
    let mut f = fixture().await;
    let ui = |website_domain: Option<&str>| {
        let mut ui = Arc::unwrap_or_clone(s3_on(true).unwrap());
        ui.website_domain = website_domain.map(str::to_owned);
        Some(Arc::new(ui))
    };
    f.state.s3 = ui(Some("web.example.com"));
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    browser
        .post(
            "/account/s3/buckets",
            &[("csrf", &csrf), ("name", "photos")],
        )
        .await;
    let photos = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    let text = browser.get("/account/s3").await.text();
    for absent in ["Tags:", "Lifecycle:", "Deletes", "Website"] {
        assert!(!text.contains(absent), "{absent} in {text}");
    }

    // Each setting is stored as the S3 API stores it; the page only sums it up.
    s3::set_bucket_tags(
        &f.state.db,
        1,
        photos.id,
        Some(r#"{"team":"web","env":"prod"}"#),
    )
    .await
    .unwrap();
    let rules = [
        r#"{"id":"cache","enabled":true,"prefix":"cache/","expiration_days":30}"#,
        // 2025-11-16, for objects with a tag.
        r#"{"id":"dated","enabled":true,"tags":{"kind":"tmp"},"expiration_date":1763251200}"#,
        r#"{"id":"off","enabled":false,"prefix":"old/","expiration_days":1}"#,
        r#"{"id":"uploads","enabled":true,"abort_days":7}"#,
        r#"{"id":"logs","enabled":true,"prefix":"logs/","expiration_days":1}"#,
        r#"{"id":"tmp","enabled":true,"prefix":"tmp/","size_less_than":100,"expiration_days":2}"#,
    ];
    let lifecycle = format!("[{}]", rules.join(","));
    s3::set_bucket_lifecycle(&f.state.db, 1, photos.id, Some(&lifecycle))
        .await
        .unwrap();
    s3::set_bucket_website(
        &f.state.db,
        1,
        photos.id,
        Some(r#"{"index_suffix":"index.html"}"#),
    )
    .await
    .unwrap();
    let text = browser.get("/account/s3").await.text();
    assert!(text.contains("Tags: 2 (set through the S3 API)"), "{text}");
    assert!(text.contains("Lifecycle: 6 rules (set through the S3 API)"));
    assert!(
        text.contains(
            "Deletes objects written through S3, for good: cache/* after 30 days · every object \
             (filtered by tags or size) on 2025-11-16 · logs/* after 1 day · 1 more"
        ),
        "{text}"
    );
    assert!(text.contains(
        "Website (set through the S3 API): <a href=\"https://photos.web.example.com/\">"
    ));

    // Rules that delete nothing say so; a website needs s3.website_domain to be served.
    s3::set_bucket_lifecycle(&f.state.db, 1, photos.id, Some(&format!("[{}]", rules[3])))
        .await
        .unwrap();
    f.state.s3 = ui(None);
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let text = browser.get("/account/s3").await.text();
    assert!(
        text.contains("Lifecycle: 1 rule (set through the S3 API)"),
        "{text}"
    );
    assert!(text.contains("Deletes no objects"));
    assert!(text.contains(
        "Website: set through the S3 API, but not served (s3.website_domain is not set)"
    ));
    assert!(!text.contains("web.example.com"));

    // Chinese pages say the same.
    let text = browser
        .send(
            "GET",
            "/account/s3",
            &[("Accept-Language", "zh-CN,zh;q=0.9")],
            Body::empty(),
        )
        .await
        .text();
    assert!(
        text.contains("生命周期：1 条规则（通过 S3 API 设置）"),
        "{text}"
    );
    assert!(text.contains("标签：2 个（通过 S3 API 设置）"));
}

#[tokio::test]
async fn buckets_are_created_bound_changed_and_removed_on_the_account_page() {
    use gono_server_core::s3::{self, Anonymous};
    let mut f = fixture().await;
    f.state.s3 = s3_on(true);
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/s3").await;
    let text = page.text();
    assert!(text.contains("S3 buckets"), "{text}");
    assert!(text.contains("https://s3.example.com"));
    assert!(text.contains("eu-test-1"));
    assert!(text.contains("Path style: https://s3.example.com/&#60;bucket&#62;/&#60;key&#62;"));
    assert!(text.contains("Creates the folder /Buckets/&#60;name&#62; in your files."));
    assert!(text.contains("the folder and its files stay"));

    // A new bucket gets a new folder.
    let created = browser
        .post(
            "/account/s3/buckets",
            &[("csrf", &csrf), ("name", "photos")],
        )
        .await;
    assert_eq!(created.location(), "/account/s3?done=s3-bucket-created");
    let photos = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    assert_eq!(photos.owner_id, 1);
    assert_eq!(photos.folder.as_str(), "Buckets/photos");
    // CORS rules come from the S3 API; the page only counts them.
    assert!(!browser.get("/account/s3").await.text().contains("CORS:"));
    s3::set_cors(&f.state.db, 1, photos.id, Some(r#"[{"allowed_origins":["*"],"allowed_methods":["GET"]},{"allowed_origins":["*"],"allowed_methods":["PUT"]}]"#))
        .await
        .unwrap();
    assert!(
        browser
            .get("/account/s3")
            .await
            .text()
            .contains("CORS: 2 rules (set through the S3 API)")
    );
    assert_eq!(photos.anonymous, Anonymous::Private);
    assert_eq!(
        browser
            .dav(&f.device, "PROPFIND", "Buckets/photos", "")
            .await
            .status,
        StatusCode::MULTI_STATUS
    );
    let page = browser.get("/account/s3?done=s3-bucket-created").await;
    assert!(page.text().contains("The bucket was created."));
    assert!(page.text().contains("href=\"/apps/files/Buckets/photos/\""));
    let ids = web::element_ids(&page.text());
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(ids.len(), unique.len(), "duplicate ids in {ids:?}");

    // Names follow the S3 rules and are unique; an existing folder is not taken over.
    for (name, error) in [
        ("photos", "You have a bucket named photos already."),
        ("Photos", "Bucket names have 3 to 63 characters"),
        ("ab", "Bucket names have 3 to 63 characters"),
    ] {
        let refused = browser
            .post("/account/s3/buckets", &[("csrf", &csrf), ("name", name)])
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY, "{name}");
        assert!(refused.text().contains(error), "{name}: {}", refused.text());
        assert!(
            refused.text().contains(&format!("value=\"{name}\"")),
            "kept"
        );
    }
    assert_eq!(
        browser
            .dav(&f.device, "MKCOL", "Buckets/backup", "")
            .await
            .status,
        StatusCode::CREATED
    );
    let exists = browser
        .post(
            "/account/s3/buckets",
            &[("csrf", &csrf), ("name", "backup")],
        )
        .await;
    assert_eq!(exists.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        exists
            .text()
            .contains("The folder /Buckets/backup exists already."),
        "{}",
        exists.text()
    );

    // An existing folder becomes a bucket.
    assert_eq!(
        browser.dav(&f.device, "MKCOL", "Media", "").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        browser.dav(&f.device, "PUT", "notes.txt", "x").await.status,
        StatusCode::CREATED
    );
    for (name, folder, error) in [
        ("media", "/Nope", "You have no folder /Nope."),
        ("media", "/notes.txt", "/notes.txt is a file, not a folder."),
        (
            "media",
            "/",
            "The top level of your files cannot be a bucket.",
        ),
        ("media", "/Buckets", "lies inside or above another bucket"),
        (
            "other",
            "/Buckets/photos",
            "The folder /Buckets/photos is a bucket already.",
        ),
    ] {
        let refused = browser
            .post(
                "/account/s3/buckets/bind",
                &[("csrf", &csrf), ("name", name), ("folder", folder)],
            )
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY, "{folder}");
        assert!(
            refused.text().contains(error),
            "{folder}: {}",
            refused.text()
        );
    }
    let bound = browser
        .post(
            "/account/s3/buckets/bind",
            &[("csrf", &csrf), ("name", "media"), ("folder", "/Media/")],
        )
        .await;
    assert_eq!(bound.location(), "/account/s3?done=s3-bucket-bound");
    let media = s3::bucket(&f.state.db, "media").await.unwrap().unwrap();
    assert_eq!(media.folder.as_str(), "Media");

    // Anonymous access; listing goes with some anonymous access only.
    let anonymous = format!("/account/s3/buckets/{}/anonymous", photos.id);
    let public = browser
        .post(
            &anonymous,
            &[
                ("csrf", &csrf),
                ("anonymous", "public-read"),
                ("list", "on"),
            ],
        )
        .await;
    assert_eq!(public.location(), "/account/s3?done=s3-bucket-anonymous");
    let changed = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    assert_eq!(
        (changed.anonymous, changed.anonymous_list),
        (Anonymous::PublicRead, true)
    );
    let page = browser.get("/account/s3").await;
    assert!(
        page.text()
            .contains("<option value=\"public-read\" selected>"),
        "{}",
        page.text()
    );
    let private = browser
        .post(
            &anonymous,
            &[("csrf", &csrf), ("anonymous", "private"), ("list", "on")],
        )
        .await;
    assert_eq!(private.status, StatusCode::SEE_OTHER);
    let changed = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    assert_eq!(
        (changed.anonymous, changed.anonymous_list),
        (Anonymous::Private, false)
    );
    let acl = browser
        .post(&anonymous, &[("csrf", &csrf), ("anonymous", "acl")])
        .await;
    assert_eq!(acl.status, StatusCode::SEE_OTHER);
    let bogus = browser
        .post(&anonymous, &[("csrf", &csrf), ("anonymous", "everyone")])
        .await;
    assert_eq!(bogus.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        s3::bucket(&f.state.db, "photos")
            .await
            .unwrap()
            .unwrap()
            .anonymous,
        Anonymous::Acl
    );

    // Removing unbinds: the folder and its files stay.
    assert_eq!(
        browser
            .dav(&f.device, "PUT", "Buckets/photos/cat.jpg", "meow")
            .await
            .status,
        StatusCode::CREATED
    );
    let removed = browser
        .post(
            &format!("/account/s3/buckets/{}/delete", photos.id),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(removed.location(), "/account/s3?done=s3-bucket-removed");
    assert!(s3::bucket(&f.state.db, "photos").await.unwrap().is_none());
    let file = browser
        .dav(&f.device, "GET", "Buckets/photos/cat.jpg", "")
        .await;
    assert_eq!(file.status, StatusCode::OK);
    assert_eq!(file.text(), "meow");
    let again = browser
        .post(
            &format!("/account/s3/buckets/{}/delete", photos.id),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(again.location(), "/account/s3", "nothing left to remove");

    assert_eq!(
        audit_kinds(&f).await,
        [
            ("s3.bucket.created", "user"),
            ("s3.bucket.created", "user"),
            ("s3.bucket.anonymous", "user"),
            ("s3.bucket.anonymous", "user"),
            ("s3.bucket.anonymous", "user"),
            ("s3.bucket.removed", "user"),
        ]
        .map(|(kind, actor)| (kind.to_owned(), actor.to_owned()))
    );
}

#[tokio::test]
async fn anonymous_access_needs_the_server_to_allow_it() {
    use gono_server_core::s3::{self, Anonymous};
    let mut f = fixture().await;
    f.state.s3 = s3_on(false);
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    browser
        .post(
            "/account/s3/buckets",
            &[("csrf", &csrf), ("name", "photos")],
        )
        .await;
    let photos = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    let page = browser.get("/account/s3").await;
    let text = page.text();
    assert!(
        text.contains("Anonymous access is off on this server"),
        "{text}"
    );
    assert!(text.contains(&format!(
        "<select id=\"s3-anon-{}\" name=\"anonymous\" aria-label=\"Anonymous access photos\" disabled>",
        photos.id
    )));
    assert!(!text.contains("Make private"), "private already");

    let anonymous = format!("/account/s3/buckets/{}/anonymous", photos.id);
    for fields in [
        vec![("anonymous", "public-read")],
        vec![("anonymous", "acl"), ("list", "on")],
    ] {
        let mut fields = fields;
        fields.push(("csrf", &csrf));
        let refused = browser.post(&anonymous, &fields).await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            refused
                .text()
                .contains("Anonymous access is off on this server: buckets can only be private.")
        );
    }
    let stored = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    assert_eq!(
        (stored.anonymous, stored.anonymous_list),
        (Anonymous::Private, false)
    );

    // A setting stored earlier is shown, and can still be made private.
    s3::set_anonymous(&f.state.db, 1, photos.id, Anonymous::PublicRead, true)
        .await
        .unwrap();
    let page = browser.get("/account/s3").await;
    assert!(
        page.text()
            .contains("<option value=\"public-read\" selected>")
    );
    assert!(page.text().contains("Make private"));
    let private = browser
        .post(&anonymous, &[("csrf", &csrf), ("anonymous", "private")])
        .await;
    assert_eq!(private.location(), "/account/s3?done=s3-bucket-anonymous");
    let stored = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    assert_eq!(
        (stored.anonymous, stored.anonymous_list),
        (Anonymous::Private, false)
    );
}

/// The text of the first `<dd class="mono">` after `label` on a page.
fn fact(text: &str, label: &str) -> String {
    let start = text
        .find(label)
        .unwrap_or_else(|| panic!("{label} in {text}"));
    let rest = &text[start..];
    let start = rest.find("<dd class=\"mono\">").unwrap() + 17;
    rest[start..start + rest[start..].find('<').unwrap()].to_owned()
}

#[tokio::test]
async fn s3_access_keys_are_created_shown_once_and_revoked() {
    use gono_server_core::{
        Permission,
        s3::{self, Grant},
    };
    let mut f = fixture().await;
    f.state.s3 = s3_on(true);
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    browser
        .post(
            "/account/s3/buckets",
            &[("csrf", &csrf), ("name", "photos")],
        )
        .await;
    let photos = s3::bucket(&f.state.db, "photos").await.unwrap().unwrap();
    let grant_field = format!("bucket_{}", photos.id);

    let nothing = browser
        .post(
            "/account/s3/keys",
            &[
                ("csrf", &csrf),
                ("label", "rclone"),
                ("access", "buckets"),
                (&grant_field, ""),
            ],
        )
        .await;
    assert_eq!(nothing.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        nothing
            .text()
            .contains("Choose view or full access for at least one bucket.")
    );
    assert!(nothing.text().contains("value=\"rclone\""), "kept");
    assert!(nothing.text().contains(
        "id=\"s3-access-buckets\" type=\"radio\" name=\"access\" value=\"buckets\" checked"
    ));
    let bad_expiry = browser
        .post(
            "/account/s3/keys",
            &[
                ("csrf", &csrf),
                ("label", "rclone"),
                ("expires_in_days", "0"),
            ],
        )
        .await;
    assert_eq!(bad_expiry.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(s3::list_keys(&f.state.db, 1).await.unwrap().is_empty());

    let created = browser
        .post(
            "/account/s3/keys",
            &[
                ("csrf", &csrf),
                ("label", "rclone"),
                ("expires_in_days", "30"),
                ("access", "buckets"),
                (&grant_field, "view"),
            ],
        )
        .await;
    assert_eq!(created.location(), "/account/s3/created");
    let shown = browser.get("/account/s3/created").await;
    assert_eq!(shown.status, StatusCode::OK);
    assert_eq!(shown.header("cache-control"), "no-store");
    let text = shown.text();
    let access_key_id = fact(&text, "Access key ID");
    assert!(s3::is_access_key_id(&access_key_id), "{access_key_id}");
    let start = text.find("<div class=\"secret\">").expect("secret") + 20;
    let secret = text[start..start + text[start..].find('<').unwrap()].to_owned();
    assert_eq!(secret.len(), 40, "{secret}");
    assert_eq!(fact(&text, "Endpoint"), "https://s3.example.com");
    assert_eq!(fact(&text, "Region"), "eu-test-1");
    assert!(text.contains("photos <span class=\"perm\">view</span>"));

    // The secret signs requests of this key, and is never shown again.
    let sealing = gono_server_core::two_factor::Key::from_bytes(&[9; 32]);
    let signing = s3::signing_key(&f.state.db, &sealing, &access_key_id, db::unix_now())
        .await
        .unwrap()
        .expect("the key signs");
    assert_eq!(signing.secret.expose_secret(), secret);
    let again = browser.get("/account/s3/created").await;
    assert_eq!(again.location(), "/account/s3", "shown once");
    let page = browser.get("/account/s3").await;
    assert!(page.text().contains(&access_key_id));
    assert!(page.text().contains("rclone"));
    assert!(!page.text().contains(&secret));
    let keys = s3::list_keys(&f.state.db, 1).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0].grants,
        [Grant {
            bucket_id: Some(photos.id),
            permission: Permission::View,
        }]
    );
    assert!(keys[0].expires_at.is_some());
    // S3 keys are not app passwords.
    assert!(
        app_passwords::list(&f.state.db, 1)
            .await
            .unwrap()
            .iter()
            .all(|password| password.label != "rclone")
    );

    let everything = browser
        .post(
            "/account/s3/keys",
            &[("csrf", &csrf), ("label", "backup"), ("access", "all")],
        )
        .await;
    assert_eq!(everything.location(), "/account/s3/created");
    let keys = s3::list_keys(&f.state.db, 1).await.unwrap();
    assert_eq!(keys[1].grants, [Grant::everything()]);
    assert_eq!(keys[1].expires_at, None);

    let revoked = browser
        .post(
            &format!("/account/s3/keys/{}/delete", keys[0].id),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(revoked.location(), "/account/s3?done=s3-key-revoked");
    assert!(
        s3::signing_key(&f.state.db, &sealing, &access_key_id, db::unix_now())
            .await
            .unwrap()
            .is_none()
    );
    let keys = s3::list_keys(&f.state.db, 1).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].label, "backup");
    assert!(
        browser
            .get("/account/s3?done=s3-key-revoked")
            .await
            .text()
            .contains("The access key was revoked.")
    );
    let kinds: Vec<String> = audit_kinds(&f)
        .await
        .into_iter()
        .map(|(kind, _)| kind)
        .filter(|kind| kind.starts_with("s3.key."))
        .collect();
    assert_eq!(
        kinds,
        ["s3.key.created", "s3.key.created", "s3.key.revoked"]
    );
}

#[tokio::test]
async fn s3_forms_need_the_session_csrf_token_and_the_users_own_buckets() {
    use gono_server_core::s3::{self, Anonymous, BucketName};
    let mut f = fixture().await;
    f.state.s3 = s3_on(true);
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let missing = browser
        .post("/account/s3/buckets", &[("name", "photos")])
        .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    let wrong = browser
        .post("/account/s3/keys", &[("csrf", "nope"), ("label", "rclone")])
        .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("csrf", csrf.as_str()), ("name", "photos")])
        .finish();
    let foreign = browser
        .send(
            "POST",
            "/account/s3/buckets",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "https://evil.example"),
            ],
            Body::from(body),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    assert!(s3::buckets_of(&f.state.db, 1).await.unwrap().is_empty());
    assert!(s3::list_keys(&f.state.db, 1).await.unwrap().is_empty());

    // Another account's bucket and key are out of reach.
    let layout = DataLayout::new(f._dir.path().join("data"));
    let hash = password::hash(&SecretString::from("bob password".to_owned())).unwrap();
    let bob = users::create(
        &f.state.db,
        &NewUser {
            username: &Username::new("bob").unwrap(),
            display_name: "Bob",
            password_hash: &hash,
            is_admin: false,
            services: gono_server_core::services::Services::ALL,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap();
    let bob_identity = gono_server_dav::Identity::for_web_session(
        bob,
        Username::new("bob").unwrap(),
        "Bob".to_owned(),
        gono_server_core::services::Services::ALL,
    );
    let folder = f
        .state
        .dav
        .fs()
        .put_folder(
            bob_identity,
            &gono_server_core::RelPath::parse("Shared").unwrap(),
        )
        .await
        .unwrap();
    let shared = s3::create_bucket(
        &f.state.db,
        bob,
        &BucketName::new("shared").unwrap(),
        folder.file_id.unwrap(),
    )
    .await
    .unwrap();
    let sealing = gono_server_core::two_factor::Key::from_bytes(&[9; 32]);
    let (bob_key, _) = s3::create_key(
        &f.state.db,
        &sealing,
        bob,
        "bob's",
        vec![s3::Grant::everything()],
        None,
    )
    .await
    .unwrap();
    let anonymous = browser
        .post(
            &format!("/account/s3/buckets/{}/anonymous", shared.id),
            &[("csrf", &csrf), ("anonymous", "public-read")],
        )
        .await;
    assert_eq!(anonymous.status, StatusCode::NOT_FOUND);
    browser
        .post(
            &format!("/account/s3/buckets/{}/delete", shared.id),
            &[("csrf", &csrf)],
        )
        .await;
    browser
        .post(
            &format!("/account/s3/keys/{}/delete", bob_key.id),
            &[("csrf", &csrf)],
        )
        .await;
    let taken = browser
        .post(
            "/account/s3/buckets",
            &[("csrf", &csrf), ("name", "shared")],
        )
        .await;
    assert!(
        taken
            .text()
            .contains("The bucket name shared is taken on this server."),
        "{}",
        taken.text()
    );
    let kept = s3::bucket(&f.state.db, "shared").await.unwrap().unwrap();
    assert_eq!(kept.anonymous, Anonymous::Private);
    assert_eq!(s3::list_keys(&f.state.db, bob).await.unwrap().len(), 1);
    // A grant for another account's bucket is ignored: it is not among alice's buckets.
    let foreign_grant = browser
        .post(
            "/account/s3/keys",
            &[
                ("csrf", &csrf),
                ("label", "sneaky"),
                ("access", "buckets"),
                (&format!("bucket_{}", shared.id), "full"),
            ],
        )
        .await;
    assert_eq!(foreign_grant.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(s3::list_keys(&f.state.db, 1).await.unwrap().is_empty());
}

#[tokio::test]
async fn published_files_offer_their_public_link() {
    use gono_server_core::s3::{self, Anonymous, BucketName};
    let mut f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    for dir in ["Buckets", "Buckets/media", "Buckets/media/2026", "Site"] {
        browser.dav(&f.device, "MKCOL", dir, "").await;
    }
    for file in [
        "Buckets/media/2026/a b.jpg",
        "Buckets/media/private.jpg",
        "Site/index.html",
    ] {
        browser
            .dav(&f.device, "PUT", &file.replace(' ', "%20"), "content")
            .await;
    }
    let meta = f.state.dav.fs().meta().clone();
    let folder = |rel: &str| {
        let meta = meta.clone();
        let rel = gono_server_core::RelPath::parse(rel).unwrap();
        async move { meta.get(1, &rel).await.unwrap().unwrap() }
    };
    let media = s3::create_bucket(
        &f.state.db,
        1,
        &BucketName::new("media").unwrap(),
        folder("Buckets/media").await.id,
    )
    .await
    .unwrap();
    s3::set_anonymous(&f.state.db, 1, media.id, Anonymous::Acl, false)
        .await
        .unwrap();
    let site = s3::create_bucket(
        &f.state.db,
        1,
        &BucketName::new("site").unwrap(),
        folder("Site").await.id,
    )
    .await
    .unwrap();
    s3::set_anonymous(&f.state.db, 1, site.id, Anonymous::PublicRead, false)
        .await
        .unwrap();
    // The public-read ACL of one object of the `acl` bucket.
    let photo = folder("Buckets/media/2026/a b.jpg").await;
    assert!(
        meta.set_object_public(photo.id, &photo.etag, true)
            .await
            .unwrap()
    );

    let links = |text: String| text.match_indices("data-copy-link").count();
    // While the S3 API or anonymous access is off, nothing is public.
    let page = browser.get("/apps/files/Site/").await.text();
    assert_eq!(links(page), 0);
    f.state.s3 = s3_on(false);
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    assert_eq!(links(browser.get("/apps/files/Site/").await.text()), 0);

    f.state.s3 = s3_on(true);
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let site_page = browser.get("/apps/files/Site/").await.text();
    assert!(
        site_page.contains("href=\"https://s3.example.com/site/index.html\""),
        "{site_page}"
    );
    assert!(site_page.contains("Copy public link"));
    // The link sits in the row menu, which opens below its row: the listing's pane must not
    // clip it, or the menus of the last rows of a short folder are cut off.
    assert!(
        site_page.contains("<section class=\"pane pane--list\""),
        "{site_page}"
    );
    assert!(web::STYLE.contains(".pane--list { overflow: visible; }"));
    let photos = browser.get("/apps/files/Buckets/media/2026/").await.text();
    assert!(
        photos.contains("href=\"https://s3.example.com/media/2026/a%20b.jpg\""),
        "{photos}"
    );
    let media_page = browser.get("/apps/files/Buckets/media/").await.text();
    assert_eq!(links(media_page), 0, "a private object and a folder");
    // The file page shows the link too.
    let file = browser.get("/apps/files/Site/index.html").await.text();
    assert!(file.contains("Public link"), "{file}");
    assert_eq!(links(file), 1);
    // Search results and favorites as well.
    let found = browser.get("/apps/files/?q=index").await.text();
    assert_eq!(links(found), 1);

    // An overwrite makes the object private again, and its link goes.
    browser
        .dav(
            &f.device,
            "PUT",
            "Buckets/media/2026/a%20b.jpg",
            "new content",
        )
        .await;
    let photos = browser.get("/apps/files/Buckets/media/2026/").await.text();
    assert_eq!(links(photos), 0);
}

/// Turns remote connectivity on in `f`, as `serve` does with the relay enabled.
async fn connect_on(f: &mut Fixture) -> Arc<gono_server_connect::Connect> {
    connect_with(f, false).await
}

/// Like [`connect_on`], with `connect.require_two_factor` set to `require_two_factor`.
async fn connect_with(
    f: &mut Fixture,
    require_two_factor: bool,
) -> Arc<gono_server_connect::Connect> {
    let connect = gono_server_connect::Connect::new(
        f.state.db.clone(),
        gono_server_connect::ConnectConfig {
            base_url: ORIGIN.parse().unwrap(),
            relay_url: "https://relay.example.com".parse().unwrap(),
            audit_retention_secs: 3600,
            require_two_factor,
        },
    )
    .await
    .unwrap();
    f.state.connect = Some(connect.clone());
    connect
}

/// The paths of the tabs of the account page, with a text only that tab shows.
const TABS: [(&str, &str); 5] = [
    ("/account/", "Two-step verification"),
    ("/account/webdav", "Connecting a client"),
    ("/account/s3", "S3 buckets"),
    ("/account/direct", "Remote devices"),
    ("/account/relay", "Relay address"),
];

#[tokio::test]
async fn every_tab_of_the_account_page_renders_for_an_account_with_every_service() {
    let mut f = fixture().await;
    f.state.s3 = s3_on(true);
    connect_on(&mut f).await;
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    for (path, own) in TABS {
        let page = browser.get(path).await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        let text = page.text();
        assert!(text.contains(own), "{path}: {text}");
        // Every tab is listed, and this one is current.
        for (other, _) in TABS {
            assert!(
                text.contains(&format!("href=\"{other}\"")),
                "{other} on {path}"
            );
        }
        assert!(
            text.contains(&format!(
                "class=\"tabs__item\" href=\"{path}\" aria-current=\"page\""
            )),
            "{path}: {text}"
        );
        assert_eq!(text.matches("class=\"tabs__item\"").count(), 5, "{path}");
        assert_eq!(
            text.matches("aria-current=\"page\"").count(),
            3,
            "tab, nav and drawer on {path}"
        );
        // The masthead marks Account as current.
        assert!(
            text.contains(
                r#"<a class="masthead__link" href="/account/" aria-current="page">Account</a>"#
            ),
            "{path}: {text}"
        );
        assert!(!text.contains("not enabled for your account"), "{path}");
        assert!(!text.contains("does not offer"), "{path}");
        let ids = web::element_ids(&text);
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate ids on {path}: {ids:?}");
        // Chinese too.
        let zh = browser
            .send("GET", path, &[("Accept-Language", "zh-CN")], Body::empty())
            .await;
        assert_eq!(zh.status, StatusCode::OK, "{path}");
        assert!(zh.text().contains(">概览</a>"), "{path}");
    }
    // The overview lists the services, each with a link to where it is used.
    let overview = browser.get("/account/").await.text();
    for (href, name) in [
        ("/apps/files/", "Web files"),
        ("/account/webdav", "WebDAV"),
        ("/account/s3", "S3"),
        ("/account/direct", "Direct connections"),
        ("/account/relay", "Relay"),
    ] {
        assert!(
            overview.contains(&format!("<b><a href=\"{href}\">{name}</a></b>")),
            "{name}: {overview}"
        );
    }
    assert_eq!(overview.matches(">On</span>").count(), 5, "{overview}");
    assert!(
        !overview.contains("Not offered by this server"),
        "{overview}"
    );
    assert!(overview.contains(r#"id="two-factor""#), "{overview}");
    assert!(overview.contains("/account/display-name"), "{overview}");
    assert!(overview.contains("/account/password"), "{overview}");
    // `/account` leads to the overview.
    assert_eq!(browser.get("/account").await.location(), "/account/");
}

#[tokio::test]
async fn the_overview_works_for_an_account_without_any_service() {
    use gono_server_core::services::Services;
    let mut f = fixture().await;
    f.state.s3 = s3_on(true);
    connect_on(&mut f).await;
    let alice = Username::new("alice").unwrap();
    users::set_services(&f.state.db, &alice, Services::NONE)
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/").await;
    assert_eq!(page.status, StatusCode::OK);
    let text = page.text();
    assert_eq!(text.matches(">Off</span>").count(), 5, "{text}");
    assert!(!text.contains(">On</span>"), "{text}");
    assert!(text.contains("/account/two-factor/start"), "{text}");
    // Signing in without a page to return to leads here rather than to the file UI.
    let mut other = Browser::new(&f.state);
    let form = other.get("/login").await;
    let login_csrf = form.field("name=\"csrf\" value=\"");
    let signed_in = other
        .post(
            "/login",
            &[
                ("csrf", &login_csrf),
                ("user", "alice"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(signed_in.location(), "/account/");

    // Its forms need no service.
    let renamed = browser
        .post(
            "/account/display-name",
            &[("csrf", &csrf), ("display_name", "Alice B.")],
        )
        .await;
    assert_eq!(renamed.location(), "/account/?done=display-name");
    assert!(
        browser
            .get("/account/?done=display-name")
            .await
            .text()
            .contains("Your display name was changed.")
    );
    let refused = browser
        .post(
            "/account/password",
            &[
                ("csrf", &csrf),
                ("current", "nope"),
                ("password", "new password"),
                ("password_repeat", "new password"),
            ],
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        refused.text().contains("The current password is wrong."),
        "the overview again: {}",
        refused.text()
    );
    assert!(refused.text().contains(r#"id="two-factor""#));
    let changed = browser
        .post(
            "/account/password",
            &[
                ("csrf", &csrf),
                ("current", ALICE_PASSWORD),
                ("password", "new password"),
                ("password_repeat", "new password"),
            ],
        )
        .await;
    assert_eq!(changed.location(), "/account/?done=password");
    let started = browser
        .post(
            "/account/two-factor/start",
            &[("csrf", &csrf), ("password", "new password")],
        )
        .await;
    assert_eq!(started.location(), "/account/two-factor");

    // Every other tab is listed and says that the service is not enabled, as a page. The direct
    // tab still lists the registered devices, which can be revoked.
    for (path, own) in &TABS[1..] {
        let page = browser.get(path).await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        let text = page.text();
        assert!(
            text.contains(
                "This service is not enabled for your account. Ask an administrator to turn it on."
            ),
            "{path}: {text}"
        );
        if *path == "/account/direct" {
            assert!(text.contains("you can still revoke a lost one"), "{text}");
            assert!(!text.contains("/pairing"), "{text}");
        } else {
            assert!(!text.contains(own), "{path}: {text}");
        }
    }
}

#[tokio::test]
async fn the_masthead_offers_search_and_files_as_home_only_with_the_files_service() {
    use gono_server_core::services::{Service, Services};
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let search = r#"id="site-search""#;
    let page = browser.get("/account/webdav").await.text();
    assert!(page.contains(search), "{page}");
    assert!(
        page.contains(r#"<a class="masthead__brand" href="/apps/files/""#),
        "{page}"
    );
    let files = browser.get("/apps/files/").await.text();
    assert!(
        files.contains(r#"<a class="masthead__link" href="/account/">Account</a>"#),
        "not current on the files: {files}"
    );
    assert!(files.contains(r#"<a class="menu__item" href="/account/">Account</a>"#));

    let alice = Username::new("alice").unwrap();
    users::set_services(
        &f.state.db,
        &alice,
        Services::ALL.with(Service::Files, false),
    )
    .await
    .unwrap();
    for path in ["/account/", "/apps/files/"] {
        let page = browser.get(path).await.text();
        assert!(!page.contains(search), "{path}: {page}");
        assert!(
            page.contains(r#"<a class="masthead__brand" href="/account/""#),
            "{path}: {page}"
        );
        // Files and favorites stay, and say that the service is off when chosen.
        assert!(
            page.contains(r#"class="masthead__link" href="/apps/files/""#),
            "{path}: {page}"
        );
        assert!(
            page.contains(r#"class="masthead__link" href="/apps/files/?view=favorites""#),
            "{path}: {page}"
        );
        assert!(page.contains(r#"<a href="/account/""#), "drawer on {path}");
    }
    // Signed out, the brand leads to the files, which ask to sign in.
    let anonymous = Browser::new(&f.state).get("/login").await.text();
    assert!(
        anonymous.contains(r#"<a class="masthead__brand" href="/apps/files/""#),
        "{anonymous}"
    );
}

#[tokio::test]
async fn the_forms_of_a_tab_need_its_service() {
    use gono_server_core::{
        devices,
        services::{Service, Services},
    };
    let mut f = fixture().await;
    f.state.s3 = s3_on(true);
    connect_on(&mut f).await;
    let alice = users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap();
    let work = register_device(&f.state, alice.id, 5, "Work PC").await;
    // The pairing window of the registration is closed, so that a new one would show.
    devices::open_pairing(&f.state.db, alice.id, work.endpoint_id, db::unix_now() - 1)
        .await
        .unwrap();
    let laptop = app_passwords::list(&f.state.db, alice.id).await.unwrap()[0].id;
    let only_files = Services::NONE.with(Service::Files, true);
    users::set_services(&f.state.db, &alice.username, only_files)
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;

    let hex = work.endpoint_id.to_hex();
    let refused = |reply: &Reply, what: &str| {
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{what}");
        assert!(
            reply.text().contains("not enabled for your account"),
            "{what}: {}",
            reply.text()
        );
    };
    // App passwords need WebDAV, and their refusal shows the WebDAV tab.
    let created = browser
        .post(
            "/account/app-passwords",
            &[("csrf", &csrf), ("label", "rclone"), ("access", "view")],
        )
        .await;
    refused(&created, "create an app password");
    assert!(
        created
            .text()
            .contains(r#"href="/account/webdav" aria-current="page""#)
    );
    let revoked = browser
        .post(
            &format!("/account/app-passwords/{laptop}/delete"),
            &[("csrf", &csrf)],
        )
        .await;
    refused(&revoked, "revoke an app password");
    assert_eq!(
        app_passwords::list(&f.state.db, alice.id)
            .await
            .unwrap()
            .len(),
        1
    );
    // S3 forms need S3.
    for (uri, fields) in S3_FORMS {
        let mut fields = fields.to_vec();
        fields.push(("csrf", &csrf));
        refused(&browser.post(uri, &fields).await, uri);
    }
    // Revoking only removes trust, so its confirmation stays open without direct connections.
    let confirm = browser.get(&format!("/account/devices/{hex}/revoke")).await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text());
    // The other device actions need direct connections, and their refusal shows the direct tab.
    for action in ["sign-out", "pairing"] {
        let reply = browser
            .post(
                &format!("/account/devices/{hex}/{action}"),
                &[("csrf", &csrf)],
            )
            .await;
        refused(&reply, action);
        assert!(
            reply
                .text()
                .contains(r#"href="/account/direct" aria-current="page""#),
            "{action}"
        );
    }
    let entry = devices::get(&f.state.db, work.id).await.unwrap().unwrap();
    assert!(entry.is_active(), "neither revoked nor signed out");
    assert!(!entry.pairing_open(db::unix_now()), "no pairing window");

    // With the services, the same forms go through.
    users::set_services(&f.state.db, &alice.username, Services::ALL)
        .await
        .unwrap();
    let pairing = browser
        .post(
            &format!("/account/devices/{hex}/pairing"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(pairing.location(), "/account/direct?done=pairing");
    let bucket = browser
        .post(
            "/account/s3/buckets",
            &[("csrf", &csrf), ("name", "photos")],
        )
        .await;
    assert_eq!(bucket.location(), "/account/s3?done=s3-bucket-created");
}

#[tokio::test]
async fn the_relay_tab_shows_the_rate_the_connected_devices_and_the_sessions() {
    use gono_server_core::{
        audit::{self, Actor, Record},
        config::RelayConfig,
        devices::EndpointId,
        services::{Service, Services},
    };
    let mut f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let off = browser.get("/account/relay").await;
    assert_eq!(off.status, StatusCode::OK);
    assert!(
        off.text()
            .contains("This server does not offer this service."),
        "{}",
        off.text()
    );

    let connect = connect_on(&mut f).await;
    let alice = users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap();
    let work = register_device(&f.state, alice.id, 6, "Work PC").await;
    let phone = register_device(&f.state, alice.id, 7, "Phone").await;
    let layout = DataLayout::new(f._dir.path().join("data"));
    let hash = password::hash(&SecretString::from("bob password".to_owned())).unwrap();
    let bob = users::create(
        &f.state.db,
        &NewUser {
            username: &Username::new("bob").unwrap(),
            display_name: "Bob",
            password_hash: &hash,
            is_admin: false,
            services: Services::ALL,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap();
    // Sessions as the control channel records them, and one of another account.
    let now = db::unix_now();
    for (user_id, kind, details) in [
        (
            alice.id,
            "session.started",
            serde_json::json!({ "service": "inputshow/1", "path": "relayed" }),
        ),
        (
            alice.id,
            "session.ended",
            serde_json::json!({
                "service": "inputshow/1",
                "path": "direct",
                "bytes_direct": 1_048_576,
                "bytes_relayed": 2048,
            }),
        ),
        (
            bob,
            "session.started",
            serde_json::json!({ "service": "elsewhere/1", "path": "direct" }),
        ),
    ] {
        audit::record(
            &f.state.db,
            &Record::new(user_id, kind, Actor::Device)
                .device(work.endpoint_id)
                .peer(phone.endpoint_id)
                .details(details),
            now,
        )
        .await
        .unwrap();
    }
    // Without a relay in this process, the tab has no connections to show.
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let text = browser.get("/account/relay").await.text();
    assert!(text.contains("https://relay.example.com/</dd>"), "{text}");
    assert!(text.contains("Full speed"), "{text}");
    assert!(!text.contains("Connected now"), "{text}");

    let relay = gono_server_relay::Relay::spawn(
        &RelayConfig {
            enabled: true,
            public_url: Some("https://relay.example.com".parse().unwrap()),
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_endpoints: vec![EndpointId([9; 32]).to_hex()],
            ..RelayConfig::default()
        },
        None,
    )
    .await
    .unwrap();
    connect.set_relay(relay.status());
    let page = browser.get("/account/relay").await;
    assert_eq!(page.status, StatusCode::OK);
    let text = page.text();
    assert!(text.contains("Connected now"), "{text}");
    assert!(
        text.contains("None of your devices is connected to the relay."),
        "{text}"
    );
    assert!(
        text.contains(&format!("Work PC ({})", work.endpoint_id.short())),
        "{text}"
    );
    assert!(
        text.contains(&format!("Phone ({})", phone.endpoint_id.short())),
        "{text}"
    );
    assert!(
        text.contains(r#"<span class="badge warn">Relayed</span>"#),
        "{text}"
    );
    assert!(
        text.contains(r#"<span class="badge ok">Direct</span>"#),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "{} / {}",
            crate::admin::format_bytes(1_048_576),
            crate::admin::format_bytes(2048)
        )),
        "{text}"
    );
    assert!(text.contains("inputshow/1"), "{text}");
    assert!(!text.contains("elsewhere/1"), "another account's: {text}");
    let zh = browser
        .send(
            "GET",
            "/account/relay",
            &[("Accept-Language", "zh-CN")],
            Body::empty(),
        )
        .await
        .text();
    assert!(zh.contains("中转地址") && zh.contains("全速"), "{zh}");

    // Direct connections alone: the relay only helps set them up.
    users::set_services(
        &f.state.db,
        &alice.username,
        Services::ALL.with(Service::Relay, false),
    )
    .await
    .unwrap();
    let text = browser.get("/account/relay").await.text();
    assert!(
        text.contains("Limited: your account has direct connections only"),
        "{text}"
    );
    assert!(!text.contains("Full speed"), "{text}");
    assert!(
        browser
            .get("/account/direct")
            .await
            .text()
            .contains("the relay only helps them set up the connection"),
    );
    // Without direct connections, the account's devices do not use the relay at all.
    users::set_services(
        &f.state.db,
        &alice.username,
        Services::ALL.with(Service::Direct, false),
    )
    .await
    .unwrap();
    let text = browser.get("/account/relay").await.text();
    assert!(text.contains("not enabled for your account"), "{text}");
    assert!(!text.contains("inputshow/1"), "{text}");
    relay.run_until(async {}).await.unwrap();
}

#[tokio::test]
async fn a_device_that_needs_two_step_verification_is_sent_to_the_overview_and_back() {
    use gono_server_core::{
        devices::{EndpointId, NewDevice},
        login_flows,
    };
    let mut f = fixture().await;
    connect_with(&mut f, true).await;
    let new = NewDevice {
        endpoint_id: EndpointId([8; 32]),
        product: "input-show".to_owned(),
        platform: "windows".to_owned(),
        name: "Work PC".to_owned(),
        version: String::new(),
    };
    let (flow, _) = login_flows::create_device(&f.state.db, &new, db::unix_now())
        .await
        .unwrap()
        .unwrap();
    let page = format!("/login/v2/flow/{}", flow.login_token.expose_secret());
    let mut browser = Browser::new(&f.state);
    browser.sign_in().await;
    let consent = browser.get(&page).await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.text());
    let csrf = consent.field("name=\"csrf\" value=\"");
    let refused = browser
        .post(&page, &[("csrf", &csrf), ("action", "grant")])
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let link = format!(
        "/account/?next={}#two-factor",
        super::view::encode_query(&page)
    );
    assert!(
        refused.text().contains(&format!("href=\"{link}\"")),
        "{link} in {}",
        refused.text()
    );
    // The overview's form starts the enrolment with the flow's page to come back to.
    let overview = browser.get(&link).await.text();
    assert!(
        overview.contains(&format!("name=\"next\" value=\"{page}\"")),
        "{overview}"
    );
}

mod email;
