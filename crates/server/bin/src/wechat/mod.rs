//! The WeChat mini program (`[wechat]`, `docs/wechat-miniprogram.md`): its JSON API, the page
//! of its QR links and the verification file of its admin console.
//!
//! | Request | Answer |
//! |---|---|
//! | `POST /gono/v1/wechat/session` | Exchanges the mini program's sign-in code with WeChat: a session for a bound openid, a signup token otherwise. |
//! | `POST /gono/v1/wechat/bind` | Binds the openid of a signup token to the account of a bind ticket from the account page, and opens a session. |
//! | `GET /gono/v1/wechat/account` | The name and services of the session's account (`Authorization: Bearer <session>`). |
//! | `POST /gono/v1/wechat/logout` | Ends the session. |
//! | `POST /gono/v1/wechat/signup` | With `[wechat] allow_signup`: creates an account (no service, no password, a generated username) for the WeChat of a signup token, and opens a session. |
//! | `PATCH /gono/v1/wechat/account` | Changes the username of an account made by a sign-up, until a device or app signed in to it. |
//! | `POST /gono/v1/wechat/account/delete` | An account without a web password asks for its deletion (a fresh code of its WeChat): disabled at once, deleted after 7 days. |
//! | `POST /gono/v1/wechat/account/restore` | Undoes that within the 7 days (a fresh code names the WeChat), and opens a session. |
//! | `POST /gono/v1/wechat/scan` | With `[wechat] web_sign_in`: the WeChat that scanned the QR code of a sign-in page (`{qr_url_prefix}<ticket>`) locks the sign-in, and learns which account and browser it is for. |
//! | `POST /gono/v1/wechat/confirm` | The same WeChat confirms: the answer holds the 6 digits to type into the browser. |
//! | `POST /gono/v1/wechat/deny` | The same WeChat cancels the sign-in. |
//! | `GET /gono/v1/wechat/flow?ticket=` | Where the sign-in is: `waiting`, `scanned`, `code`, `done`, `denied`, `tries`, `expired`. |
//! | `GET /q/<anything>` | A page that says to scan the QR code with WeChat, for whoever opens a QR link in a browser. It starts nothing. |
//! | `GET /<verify file name>` | The verification file of `wechat.verify_file`, as it is. |
//!
//! Without `[wechat]` every path below `/gono/v1/wechat/` answers `404 {"error":"not_found"}`
//! and the other routes do not exist. The bind tickets are made on the account page
//! ([`crate::files::account::wechat`]).
//!
//! # Security
//!
//! - The mini program is not a browser: there are no cookies, so neither the origin checks nor
//!   the CSRF tokens of the pages apply. Every body is JSON of at most [`MAX_BODY_BYTES`], and
//!   every field is checked before anything else happens.
//! - A session reads the account's name and services and nothing else; it opens no page and
//!   no file, WebDAV or S3 data.
//! - **Platform.** Every call that signs in or acts (`session`, `bind`, `signup`, `scan`,
//!   `confirm`, `deny`, `account/delete`, `account/restore`) takes only the phones' platforms,
//!   `ios`, `android` and `ohos` ([`check_platform`]): not desktop WeChat, not the developer
//!   tools.
//! - **Scene.** Binding gives a WeChat user the account's mini program sessions and the right
//!   to confirm sign-ins on the web, so a QR code forwarded to someone else must not bind.
//!   `bind` (and `scan`, `confirm`, `deny`) therefore also take only the scenes of scanning
//!   with the phone's camera, 1011 (a QR code) and 1047 (a mini program code) ([`check_client`]):
//!   not a code recognized in an image (1012, 1048) or picked from the album (1013, 1049), not a
//!   shared card (1007, 1008). `session` and `signup` take any scene: a WeChat that is bound
//!   already is the account's, so it signs in again however the mini program was opened, and a
//!   signup token binds nothing without a ticket and `bind`'s scene check.
//! - The mini program reports both (`wx.getEnterOptionsSync().scene`,
//!   `wx.getDeviceInfo().platform`): the checks are a safeguard against mistakes and lures, not
//!   proof.
//! - **Limits.** Each client address has a token bucket like the sign-in pages'
//!   ([`RateLimiter`]). `session` and `bind` are refused while the bucket is empty, before
//!   anything in them is checked or WeChat is asked, and every one that does not succeed takes
//!   a token (an invalid code, a refused scene, an expired ticket, ...). A successful one costs
//!   nothing, so that the users of the mini program behind one address (a carrier's NAT) do
//!   not lock each other out. `account` and `logout` cost a token only for a bearer token that
//!   is no session, and are refused for those only, as device authentication is.
//! - Tickets, tokens, codes and openids never reach the log (the paths below `/q/` are
//!   redacted by [`crate::request_log`]); lines name the account instead.

pub mod api;
pub mod sign_in;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context as _;
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State, rejection::BytesRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use gono_server_core::{
    config::{WeChatConfig, verify_file_name},
    db,
    identities::{self, Provider},
    users,
    web_sessions::SessionUser,
    wechat::{self as store, Account, Bind, Locked, Lookup, NewSession, Purpose, SignIn, Stage},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, de::DeserializeOwned};
use url::Url;

use self::api::{ApiError, HttpApi, WeChatApi};
use crate::{
    app::AppState,
    client_ip::client_ip,
    i18n::Lang,
    ratelimit::RateLimiter,
    web::{Chrome, Message},
};

/// Where the mini program's API lives.
pub const API_PATH: &str = "/gono/v1/wechat";

/// The path of the pages of QR links on this server.
pub const QR_PATH: &str = "/q/";

/// The largest request body, in bytes.
pub const MAX_BODY_BYTES: usize = 4 * 1024;

/// The largest verification file, in bytes; WeChat's hold a few dozen.
const MAX_VERIFY_FILE_BYTES: u64 = 4 * 1024;

/// The scenes `bind` (and `scan`, `confirm`, `deny`) take: scanning a QR code (1011) or a mini
/// program code (1047) with WeChat's scanner.
pub const SCENES: [u32; 2] = [1011, 1047];

/// The platforms every call that signs in or acts takes: WeChat on a phone.
pub const PLATFORMS: [&str; 3] = ["ios", "android", "ohos"];

/// How long a client waits after WeChat's own rate limit, in seconds.
const WECHAT_RETRY_AFTER: Duration = Duration::from_secs(60);

/// `Retry-After` of `unavailable`, in seconds.
const UNAVAILABLE_RETRY_AFTER: &str = "30";

/// Tickets shown on the account page at most (one per browser session).
const MAX_SHOWN: usize = 1000;

/// The verification file of `wechat.verify_file`.
#[derive(Debug, Clone)]
pub struct VerifyFile {
    /// Its file name, which is its path below `/`.
    pub name: String,
    /// Its content, as it is.
    pub content: Bytes,
}

impl VerifyFile {
    /// Reads `path` (at most [`MAX_VERIFY_FILE_BYTES`]).
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let name = verify_file_name(path)
            .with_context(|| format!("wechat.verify_file {} has no valid name", path.display()))?
            .to_owned();
        let size = std::fs::metadata(path)
            .with_context(|| format!("read wechat.verify_file {}", path.display()))?
            .len();
        anyhow::ensure!(
            size <= MAX_VERIFY_FILE_BYTES,
            "wechat.verify_file {} has {size} bytes; WeChat's verification files have a few \
             dozen",
            path.display()
        );
        let content = std::fs::read(path)
            .with_context(|| format!("read wechat.verify_file {}", path.display()))?;
        Ok(Self {
            name,
            content: Bytes::from(content),
        })
    }

    fn response(&self) -> Response {
        let mut response = (StatusCode::OK, self.content.clone()).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        response
    }
}

/// A bind ticket shown on the account page, kept for the browser session that made it so that
/// the page can show its QR code until it expires. Only its digest is in the database.
#[derive(Debug)]
struct Shown {
    user_id: i64,
    ticket: SecretString,
    expires_at: i64,
}

/// The mini program's state, while `[wechat]` is enabled.
#[derive(Debug)]
pub struct WeChat {
    app_id: String,
    qr_url_prefix: Url,
    api: Arc<dyn WeChatApi>,
    limiter: RateLimiter,
    verify: Option<VerifyFile>,
    /// Shown bind tickets by the id of the browser session that made them.
    shown: Mutex<HashMap<i64, Shown>>,
    /// `[wechat] web_sign_in`: the sign-in pages offer scanning.
    web_sign_in: bool,
    /// `[wechat] allow_signup`: a WeChat bound to no account may create one (`signup`).
    allow_signup: bool,
    /// The sign-in tickets the browsers show.
    sign_ins: sign_in::Shown,
}

/// Reads the AppSecret of `wechat.secret_file`: its first line, without the line break.
fn read_secret(path: &Path) -> anyhow::Result<SecretString> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read wechat.secret_file {}", path.display()))?;
    let secret = content.lines().next().unwrap_or_default().trim().to_owned();
    anyhow::ensure!(
        !secret.is_empty(),
        "wechat.secret_file {} is empty; put the mini program's AppSecret on its first line",
        path.display()
    );
    Ok(SecretString::from(secret))
}

impl WeChat {
    /// The mini program `app_id` with QR links below `qr_url_prefix`, asking `api`.
    pub fn new(
        app_id: &str,
        qr_url_prefix: Url,
        api: Arc<dyn WeChatApi>,
        verify: Option<VerifyFile>,
    ) -> Self {
        Self {
            app_id: app_id.to_owned(),
            qr_url_prefix,
            api,
            limiter: RateLimiter::new(),
            verify,
            shown: Mutex::new(HashMap::new()),
            web_sign_in: false,
            allow_signup: false,
            sign_ins: sign_in::Shown::default(),
        }
    }

    /// The same, with signing in on the web by scanning when `on`.
    #[must_use]
    pub fn with_web_sign_in(mut self, on: bool) -> Self {
        self.web_sign_in = on;
        self
    }

    /// The same, letting a WeChat bound to no account sign up when `allow`.
    #[must_use]
    pub fn with_signup(mut self, allow: bool) -> Self {
        self.allow_signup = allow;
        self
    }

    /// Whether the sign-in pages offer scanning (`[wechat] web_sign_in`).
    pub fn web_sign_in(&self) -> bool {
        self.web_sign_in
    }

    /// The sign-in tickets the browsers show.
    pub(crate) fn shown_sign_ins(&self) -> &sign_in::Shown {
        &self.sign_ins
    }

    /// The link of a sign-in ticket, which its QR code carries: `<prefix><ticket>`.
    pub fn sign_in_link(&self, ticket: &str) -> String {
        format!("{}{ticket}", self.qr_url_prefix)
    }

    /// The mini program of `config` (validated, enabled). Reads the AppSecret and the
    /// verification file now, so that a missing one stops the start.
    pub fn from_config(config: &WeChatConfig) -> anyhow::Result<Self> {
        let app_id = config
            .app_id
            .as_deref()
            .context("wechat.app_id is not set")?;
        let secret_file = config
            .secret_file
            .as_deref()
            .context("wechat.secret_file is not set")?;
        let prefix = config
            .qr_url_prefix
            .clone()
            .context("wechat.qr_url_prefix is not set")?;
        let api = HttpApi::new(app_id, read_secret(secret_file)?)?;
        let verify = config
            .verify_file
            .as_deref()
            .map(VerifyFile::read)
            .transpose()?;
        Ok(Self::new(app_id, prefix, Arc::new(api), verify)
            .with_web_sign_in(config.web_sign_in)
            .with_signup(config.allow_signup))
    }

    /// The mini program's AppID.
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// The prefix of the QR links.
    pub fn qr_url_prefix(&self) -> &Url {
        &self.qr_url_prefix
    }

    /// The name of the verification file, if one is served.
    pub fn verify_file_name(&self) -> Option<&str> {
        self.verify.as_ref().map(|verify| verify.name.as_str())
    }

    /// The link of a bind ticket, which its QR code carries: `<prefix>bind/<ticket>`.
    pub fn bind_link(&self, ticket: &str) -> String {
        format!("{}bind/{ticket}", self.qr_url_prefix)
    }

    /// Keeps `ticket` of `session` to show until `expires_at`, in place of the session's
    /// earlier one.
    pub(crate) fn show(&self, session: &SessionUser, ticket: SecretString, expires_at: i64) {
        let now = db::unix_now();
        let mut shown = self.shown.lock().unwrap_or_else(|e| e.into_inner());
        shown.retain(|_, entry| entry.expires_at > now);
        if shown.len() >= MAX_SHOWN {
            shown.clear();
        }
        shown.insert(
            session.session_id,
            Shown {
                user_id: session.user_id,
                ticket,
                expires_at,
            },
        );
    }

    /// The ticket `session` shows and when it ends, if it has one that has not expired.
    pub(crate) fn shown(&self, session: &SessionUser, now: i64) -> Option<(SecretString, i64)> {
        let shown = self.shown.lock().unwrap_or_else(|e| e.into_inner());
        shown
            .get(&session.session_id)
            .filter(|entry| entry.user_id == session.user_id && entry.expires_at > now)
            .map(|entry| (entry.ticket.clone(), entry.expires_at))
    }

    /// Forgets the ticket `session` shows.
    pub(crate) fn forget(&self, session: &SessionUser) {
        let mut shown = self.shown.lock().unwrap_or_else(|e| e.into_inner());
        if shown
            .get(&session.session_id)
            .is_some_and(|entry| entry.user_id == session.user_id)
        {
            shown.remove(&session.session_id);
        }
    }

    /// Every ticket shown, for tests that play the mini program.
    #[cfg(test)]
    pub(crate) fn shown_tickets(&self) -> Vec<String> {
        let shown = self.shown.lock().unwrap();
        shown
            .values()
            .map(|entry| entry.ticket.expose_secret().to_owned())
            .collect()
    }

    /// `rate_limited` while the bucket of `client` is empty: `session` and `bind` then do
    /// nothing at all.
    fn admit(&self, client: IpAddr) -> Result<(), Box<Response>> {
        match self.limiter.check(client) {
            Some(wait) => Err(Box::new(rate_limited(wait))),
            None => Ok(()),
        }
    }

    /// `response` of a `session` or `bind` of `client`, which takes a token unless it succeeded.
    fn charge(&self, client: IpAddr, response: Response) -> Response {
        if !response.status().is_success() {
            self.limiter.record_failure(client);
        }
        response
    }

    /// The answer to a bearer token that is no session: `not_signed_in`, or `rate_limited`
    /// once the client has sent too many.
    fn refused(&self, client: IpAddr) -> Response {
        self.limiter.record_failure(client);
        match self.limiter.check(client) {
            Some(wait) => rate_limited(wait),
            None => not_signed_in("not_signed_in"),
        }
    }
}

/// The routes of the mini program, of its QR links and of the verification file.
pub fn routes(wechat: Option<&WeChat>) -> Router<AppState> {
    let mut router = Router::new()
        .route(API_PATH, any(not_found))
        .route(&format!("{API_PATH}/"), any(not_found))
        .route(&format!("{API_PATH}/{{*rest}}"), any(not_found));
    if let Some(wechat) = wechat {
        router = router
            .route(
                &format!("{API_PATH}/session"),
                post(session).fallback(not_found),
            )
            .route(&format!("{API_PATH}/bind"), post(bind).fallback(not_found))
            .route(
                &format!("{API_PATH}/account"),
                get(account).patch(rename).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/signup"),
                post(signup).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/account/delete"),
                post(delete_account).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/account/restore"),
                post(restore).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/logout"),
                post(logout).fallback(not_found),
            )
            .route(&format!("{API_PATH}/scan"), post(scan).fallback(not_found))
            .route(
                &format!("{API_PATH}/confirm"),
                post(confirm).fallback(not_found),
            )
            .route(&format!("{API_PATH}/deny"), post(deny).fallback(not_found))
            .route(&format!("{API_PATH}/flow"), get(flow).fallback(not_found))
            .route(QR_PATH, get(scan_page))
            .route(&format!("{QR_PATH}{{*rest}}"), get(scan_page));
        if let Some(name) = wechat.verify_file_name() {
            router = router.route(&format!("/{name}"), get(verify_file));
        }
    }
    router.layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

fn json(status: StatusCode, value: &serde_json::Value) -> Response {
    let mut response = (status, serde_json::to_vec(value).unwrap_or_default()).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// `{"error": "<code>"}` with `status`.
fn error(status: StatusCode, code: &'static str) -> Response {
    json(status, &serde_json::json!({ "error": code }))
}

fn bad_request() -> Response {
    error(StatusCode::BAD_REQUEST, "bad_request")
}

/// `401` with `code` (`not_signed_in` or `session_expired`) and a Bearer challenge.
fn not_signed_in(code: &'static str) -> Response {
    let mut response = error(StatusCode::UNAUTHORIZED, code);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"gono\""),
    );
    response
}

fn rate_limited(wait: Duration) -> Response {
    let mut response = error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    if let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// `503 unavailable`: WeChat or the database failed.
fn unavailable() -> Response {
    let mut response = error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_static(UNAVAILABLE_RETRY_AFTER),
    );
    response
}

/// `404 not_found`: no such endpoint (or method), or no `[wechat]`.
pub async fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "not_found")
}

/// The mini program's state, or `not_found` without `[wechat]`.
fn wechat_of(state: &AppState) -> Result<Arc<WeChat>, Box<Response>> {
    state
        .wechat
        .clone()
        .ok_or_else(|| Box::new(error(StatusCode::NOT_FOUND, "not_found")))
}

/// The JSON body of a request, or `bad_request`.
fn parse<T: DeserializeOwned>(body: Result<Bytes, BytesRejection>) -> Result<T, Box<Response>> {
    let body = body.map_err(|_| Box::new(bad_request()))?;
    serde_json::from_slice(&body).map_err(|_| Box::new(bad_request()))
}

/// Refuses a client that is not WeChat on a phone (`desktop_client`). See the module
/// documentation.
fn check_platform(platform: &str) -> Result<(), Box<Response>> {
    if PLATFORMS.contains(&platform) {
        Ok(())
    } else {
        Err(Box::new(error(StatusCode::FORBIDDEN, "desktop_client")))
    }
}

/// Refuses a client that is not WeChat on a phone (`desktop_client`) or did not open the mini
/// program by scanning (`wrong_scene`). See the module documentation.
fn check_client(scene: u32, platform: &str) -> Result<(), Box<Response>> {
    check_platform(platform)?;
    if !SCENES.contains(&scene) {
        return Err(Box::new(error(StatusCode::FORBIDDEN, "wrong_scene")));
    }
    Ok(())
}

/// Whether `code` can be a sign-in code of `wx.login()`: 1 to 256 visible ASCII characters.
fn is_code(code: &str) -> bool {
    (1..=256).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_graphic())
}

/// What the mini program reads of `account`.
fn account_json(account: &Account) -> serde_json::Value {
    let services = account.services;
    serde_json::json!({
        "username": account.username.as_str(),
        "display_name": account.display_name,
        "services": {
            "files": services.files,
            "webdav": services.webdav,
            "s3": services.s3,
            "direct": services.direct,
            "relay": services.relay,
        },
    })
}

/// The answer that hands over a new session.
fn signed_in(session: &NewSession, account: &Account) -> Response {
    json(
        StatusCode::OK,
        &serde_json::json!({
            "session": session.token.expose_secret(),
            "expires_at": session.expires_at,
            "account": account_json(account),
        }),
    )
}

#[derive(Deserialize)]
struct SessionRequest {
    code: String,
    /// Reported by the mini program and still required, but of any value: `session` takes
    /// every scene.
    #[serde(rename = "scene")]
    _scene: u32,
    platform: String,
}

/// `POST /gono/v1/wechat/session`.
pub async fn session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = sign_in(&state, &wechat, client, body).await;
    wechat.charge(client, response)
}

/// The answer of `session` to an admitted `client`.
async fn sign_in(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request: SessionRequest = match parse(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !is_code(&request.code) {
        return bad_request();
    }
    // Any scene: see the module documentation.
    if let Err(response) = check_platform(&request.platform) {
        return *response;
    }
    let login = match wechat.api.code_to_session(&request.code).await {
        Ok(login) => login,
        Err(ApiError::InvalidCode) => return error(StatusCode::BAD_REQUEST, "code_invalid"),
        Err(ApiError::RiskyUser) => return error(StatusCode::FORBIDDEN, "risky_user"),
        Err(ApiError::RateLimited) => {
            tracing::warn!(%client, "WeChat's rate limit refused a mini program's sign-in");
            return rate_limited(WECHAT_RETRY_AFTER);
        }
        Err(ApiError::Failed(why)) => {
            tracing::warn!(%client, error = %why, "cannot exchange a mini program's sign-in code with WeChat");
            return unavailable();
        }
    };
    let signed = store::sign_in(
        &state.db,
        &wechat.app_id,
        &login.openid,
        login.unionid.as_deref(),
        db::unix_now(),
    )
    .await;
    match signed {
        Ok(SignIn::Session { session, account }) => {
            tracing::info!(%client, user = %account.username, "WeChat mini program signed in");
            signed_in(&session, &account)
        }
        Ok(SignIn::Unbound { token, expires_at }) => json(
            StatusCode::OK,
            &serde_json::json!({
                "signup_token": token.expose_secret(),
                "expires_at": expires_at,
                "signup": wechat.allow_signup,
            }),
        ),
        Ok(SignIn::Disabled) => error(StatusCode::FORBIDDEN, "account_disabled"),
        Ok(SignIn::DeletionPending(until)) => deletion_pending(until),
        Err(err) => {
            tracing::error!(error = %err, "cannot sign a WeChat mini program in");
            unavailable()
        }
    }
}

#[derive(Deserialize)]
struct BindRequest {
    signup_token: String,
    ticket: String,
    scene: u32,
    platform: String,
}

/// `POST /gono/v1/wechat/bind`.
pub async fn bind(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = bind_with(&state, &wechat, client, body).await;
    wechat.charge(client, response)
}

/// The answer of `bind` to an admitted `client`.
async fn bind_with(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request: BindRequest = match parse(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !store::is_token(&request.signup_token) || !store::is_ticket(&request.ticket) {
        return bad_request();
    }
    if let Err(response) = check_client(request.scene, &request.platform) {
        return *response;
    }
    let bound = store::bind(
        &state.db,
        &wechat.app_id,
        &request.signup_token,
        &request.ticket,
        Some(client),
        db::unix_now(),
    )
    .await;
    match bound {
        Ok(Bind::Bound { session, account }) => {
            tracing::info!(%client, user = %account.username, app_id = %wechat.app_id, "WeChat bound to an account");
            signed_in(&session, &account)
        }
        Ok(Bind::SessionExpired) => not_signed_in("session_expired"),
        Ok(Bind::TicketExpired) => error(StatusCode::GONE, "ticket_expired"),
        Ok(Bind::Disabled) => error(StatusCode::FORBIDDEN, "account_disabled"),
        Ok(Bind::AccountExists) => error(StatusCode::CONFLICT, "account_exists"),
        Ok(Bind::BindFailed) => error(StatusCode::CONFLICT, "bind_failed"),
        Err(err) => {
            tracing::error!(error = %err, "cannot bind WeChat to an account");
            unavailable()
        }
    }
}

/// The bearer token of `headers`, if it has the shape of one: `Ok(None)` without an
/// `Authorization` header, `Err` for one that is not a token.
fn bearer(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    let (scheme, token) = value.split_once(' ').ok_or(())?;
    let token = token.trim();
    if scheme.eq_ignore_ascii_case("bearer") && store::is_token(token) {
        Ok(Some(token))
    } else {
        Err(())
    }
}

/// `GET /gono/v1/wechat/account`.
pub async fn account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let token = match bearer(&headers) {
        Ok(Some(token)) => token,
        // No credentials cost nothing.
        Ok(None) => return not_signed_in("not_signed_in"),
        Err(()) => return wechat.refused(client),
    };
    match store::lookup(&state.db, &wechat.app_id, token, db::unix_now()).await {
        Ok(Lookup::Live(account)) => json(StatusCode::OK, &account_json(&account)),
        Ok(Lookup::Expired) => not_signed_in("session_expired"),
        Ok(Lookup::Disabled) => error(StatusCode::FORBIDDEN, "account_disabled"),
        Ok(Lookup::Unknown) => wechat.refused(client),
        Err(err) => {
            tracing::error!(error = %err, "cannot look a mini program session up");
            unavailable()
        }
    }
}

/// `POST /gono/v1/wechat/logout`.
pub async fn logout(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    // The body is ignored, but bounded like every other.
    if body.is_err() {
        return bad_request();
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let token = match bearer(&headers) {
        Ok(Some(token)) => token,
        Ok(None) => return not_signed_in("not_signed_in"),
        Err(()) => return wechat.refused(client),
    };
    match store::logout(&state.db, &wechat.app_id, token).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => wechat.refused(client),
        Err(err) => {
            tracing::error!(error = %err, "cannot end a mini program session");
            unavailable()
        }
    }
}

#[derive(Deserialize)]
struct ScanRequest {
    ticket: String,
    code: String,
    #[serde(default)]
    scene: u32,
    platform: String,
    /// `scan_code` for the in-app scanner (`wx.scanCode({onlyFromCamera: true})`), whose scene
    /// is not a scan's.
    #[serde(default)]
    source: Option<String>,
}

/// [`check_client`] that takes the in-app scanner as a scan.
fn check_scan(request: &ScanRequest) -> Result<(), Box<Response>> {
    check_platform(&request.platform)?;
    match request.source.as_deref() {
        None | Some("enter") => check_client(request.scene, &request.platform),
        Some("scan_code") => Ok(()),
        Some(_) => Err(Box::new(bad_request())),
    }
}

/// What a sign-in mini program call found: the WeChat that asks, bound to an account.
struct Asking {
    request: ScanRequest,
    openid: String,
}

/// Parses and checks a request of `scan`, `confirm` or `deny`, and asks WeChat whose code it
/// carries.
async fn asking(
    wechat: &WeChat,
    client: IpAddr,
    body: Result<Bytes, BytesRejection>,
) -> Result<Asking, Box<Response>> {
    if !wechat.web_sign_in {
        return Err(Box::new(error(StatusCode::NOT_FOUND, "not_found")));
    }
    let request: ScanRequest = parse(body)?;
    if !store::is_ticket(&request.ticket) || !is_code(&request.code) {
        return Err(Box::new(bad_request()));
    }
    check_scan(&request)?;
    let openid = match wechat.api.code_to_session(&request.code).await {
        Ok(login) => login.openid,
        Err(ApiError::InvalidCode) => {
            return Err(Box::new(error(StatusCode::BAD_REQUEST, "code_invalid")));
        }
        Err(ApiError::RiskyUser) => {
            return Err(Box::new(error(StatusCode::FORBIDDEN, "risky_user")));
        }
        Err(ApiError::RateLimited) => {
            tracing::warn!(%client, "WeChat's rate limit refused a web sign-in");
            return Err(Box::new(rate_limited(WECHAT_RETRY_AFTER)));
        }
        Err(ApiError::Failed(why)) => {
            tracing::warn!(%client, error = %why, "cannot exchange a mini program's sign-in code with WeChat");
            return Err(Box::new(unavailable()));
        }
    };
    Ok(Asking { request, openid })
}

/// The answer to a database failure of a sign-in call.
fn failed(err: &gono_server_core::Error) -> Response {
    tracing::error!(error = %err, "a WeChat sign-in on the web failed");
    unavailable()
}

/// `POST /gono/v1/wechat/scan`.
pub async fn scan(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = scan_with(&state, &wechat, client, body).await;
    wechat.charge(client, response)
}

async fn scan_with(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Asking { request, openid } = match asking(wechat, client, body).await {
        Ok(asking) => asking,
        Err(response) => return *response,
    };
    let now = db::unix_now();
    let ticket = match store::sign_in_ticket(&state.db, &request.ticket, now).await {
        Ok(Some(ticket)) if !ticket.stage.ended() && ticket.stage != Stage::Done => ticket,
        Ok(_) => return error(StatusCode::GONE, "ticket_expired"),
        Err(err) => return failed(&err),
    };
    let kind = match ticket.purpose {
        Purpose::Reauth => "reauth",
        Purpose::SignIn | Purpose::Admin => "web_sign_in",
    };
    let browser = serde_json::json!({
        "name": ticket.browser_name,
        "same_network": gono_server_core::email::client_net(client) == ticket.browser_net,
    });
    let identity =
        match identities::find(&state.db, Provider::WeChat, &wechat.app_id, &openid).await {
            Ok(identity) => identity,
            Err(err) => return failed(&err),
        };
    let Some(identity) = identity else {
        // This WeChat has no account: the mini program says how to bind it. Nothing is locked.
        return json(
            StatusCode::OK,
            &serde_json::json!({
                "kind": kind,
                "admin": ticket.purpose == Purpose::Admin,
                "account": null,
                "signup": wechat.allow_signup,
                "browser": browser,
                "expires_at": ticket.expires_at,
            }),
        );
    };
    let user = match users::by_id(&state.db, identity.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::GONE, "ticket_expired"),
        Err(err) => return failed(&err),
    };
    if let Some(until) = user.deleting_at {
        return deletion_pending(until);
    }
    if !user.enabled {
        return error(StatusCode::FORBIDDEN, "account_disabled");
    }
    let permitted = match ticket.purpose {
        Purpose::SignIn => true,
        Purpose::Admin => user.is_admin,
        Purpose::Reauth => ticket.user_id == Some(user.id),
    };
    if !permitted {
        return error(StatusCode::FORBIDDEN, "not_permitted");
    }
    match store::lock_sign_in(&state.db, &request.ticket, identity.id, now).await {
        Ok(Locked::Locked(locked)) => {
            tracing::info!(%client, user = %user.username, "a WeChat scanned a sign-in on the web");
            json(
                StatusCode::OK,
                &serde_json::json!({
                    "kind": kind,
                    "admin": ticket.purpose == Purpose::Admin,
                    "account": {
                        "username": user.username.as_str(),
                        "display_name": user.display_name,
                    },
                    "browser": browser,
                    "expires_at": locked.expires_at,
                }),
            )
        }
        Ok(Locked::Taken) => error(StatusCode::CONFLICT, "ticket_taken"),
        Ok(Locked::Expired) => error(StatusCode::GONE, "ticket_expired"),
        Err(err) => failed(&err),
    }
}

/// The identity of `openid` that locked the sign-in of `ticket`, or the answer to refuse with.
async fn locker(
    state: &AppState,
    wechat: &WeChat,
    ticket: &str,
    openid: &str,
    now: i64,
) -> Result<i64, Box<Response>> {
    let found = store::sign_in_ticket(&state.db, ticket, now)
        .await
        .map_err(|err| Box::new(failed(&err)))?;
    let Some(identity_id) = found
        .filter(|found| matches!(found.stage, Stage::Scanned | Stage::Code))
        .and_then(|found| found.identity_id)
    else {
        return Err(Box::new(error(StatusCode::GONE, "ticket_expired")));
    };
    match store::identity_of(&state.db, identity_id, &wechat.app_id, openid).await {
        Ok(true) => Ok(identity_id),
        Ok(false) => Err(Box::new(error(StatusCode::FORBIDDEN, "not_permitted"))),
        Err(err) => Err(Box::new(failed(&err))),
    }
}

/// `POST /gono/v1/wechat/confirm`: the digits for the browser.
pub async fn confirm(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = async {
        let Asking { request, openid } = match asking(&wechat, client, body).await {
            Ok(asking) => asking,
            Err(response) => return *response,
        };
        let now = db::unix_now();
        let identity_id = match locker(&state, &wechat, &request.ticket, &openid, now).await {
            Ok(identity_id) => identity_id,
            Err(response) => return *response,
        };
        match store::issue_code(&state.db, &request.ticket, identity_id, now).await {
            Ok(Some((code, expires_at))) => {
                tracing::info!(%client, "a WeChat confirmed a sign-in on the web");
                json(
                    StatusCode::OK,
                    &serde_json::json!({ "enter_code": code, "expires_at": expires_at }),
                )
            }
            Ok(None) => error(StatusCode::GONE, "ticket_expired"),
            Err(err) => failed(&err),
        }
    }
    .await;
    wechat.charge(client, response)
}

/// `POST /gono/v1/wechat/deny`: the phone cancels the sign-in.
pub async fn deny(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = async {
        let Asking { request, openid } = match asking(&wechat, client, body).await {
            Ok(asking) => asking,
            Err(response) => return *response,
        };
        let now = db::unix_now();
        let identity_id = match locker(&state, &wechat, &request.ticket, &openid, now).await {
            Ok(identity_id) => identity_id,
            Err(response) => return *response,
        };
        match store::deny_sign_in(&state.db, &request.ticket, identity_id, now).await {
            Ok(true) => {
                tracing::info!(%client, "a WeChat cancelled a sign-in on the web");
                StatusCode::NO_CONTENT.into_response()
            }
            Ok(false) => error(StatusCode::GONE, "ticket_expired"),
            Err(err) => failed(&err),
        }
    }
    .await;
    wechat.charge(client, response)
}

#[derive(Deserialize)]
pub struct FlowQuery {
    #[serde(default)]
    ticket: String,
}

/// `GET /gono/v1/wechat/flow?ticket=`.
pub async fn flow(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    query: Result<axum::extract::Query<FlowQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    if !wechat.web_sign_in {
        return error(StatusCode::NOT_FOUND, "not_found");
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let Ok(axum::extract::Query(query)) = query else {
        return bad_request();
    };
    if !store::is_ticket(&query.ticket) {
        return wechat.charge(client, bad_request());
    }
    match store::sign_in_ticket(&state.db, &query.ticket, db::unix_now()).await {
        Ok(Some(ticket)) => json(
            StatusCode::OK,
            &serde_json::json!({ "stage": ticket.stage.as_str(), "expires_at": ticket.expires_at }),
        ),
        Ok(None) => wechat.charge(client, error(StatusCode::GONE, "ticket_expired")),
        Err(err) => failed(&err),
    }
}

/// `409 {"error": "deletion_pending", "until": <unix>}`.
fn deletion_pending(until: i64) -> Response {
    json(
        StatusCode::CONFLICT,
        &serde_json::json!({ "error": "deletion_pending", "until": until }),
    )
}

/// The display name of accounts made in the mini program, until the user changes it.
const NEW_USER: &str = "新用户";

/// Tries at a generated username that is free.
const NAME_TRIES: usize = 5;

#[derive(Deserialize)]
struct SignupRequest {
    signup_token: String,
    #[serde(default)]
    terms_version: Option<String>,
    /// Reported by the mini program and still required, but of any value: `signup` takes
    /// every scene, as `session` does.
    #[serde(rename = "scene")]
    _scene: u32,
    platform: String,
}

/// `POST /gono/v1/wechat/signup`.
pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = signup_with(&state, &wechat, client, body).await;
    wechat.charge(client, response)
}

async fn signup_with(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request: SignupRequest = match parse(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !store::is_token(&request.signup_token)
        || request
            .terms_version
            .as_deref()
            .is_some_and(|terms| terms.len() > 64 || terms.chars().any(char::is_control))
    {
        return bad_request();
    }
    // Any scene, as `session`.
    if let Err(response) = check_platform(&request.platform) {
        return *response;
    }
    if !wechat.allow_signup {
        return error(StatusCode::FORBIDDEN, "signup_closed");
    }
    // With terms, the user must have accepted a version of them.
    let terms = request.terms_version.filter(|terms| !terms.is_empty());
    if state.terms_url.is_some() && terms.is_none() {
        return bad_request();
    }
    let now = db::unix_now();
    let pending = identities::pending(
        &state.db,
        identities::Holder::MiniProgram,
        &request.signup_token,
        now,
    )
    .await;
    let pending = match pending {
        Ok(Some(pending))
            if pending.claims.provider == Provider::WeChat
                && pending.claims.realm == wechat.app_id =>
        {
            pending
        }
        Ok(_) => return not_signed_in("session_expired"),
        Err(err) => return failed(&err),
    };
    let layout = state.dav.fs().layout().clone();
    for _ in 0..NAME_TRIES {
        let username = users::generated_username(users::CreatedVia::WeChat);
        let created = users::sign_up(
            &state.db,
            &pending.claims,
            &username,
            NEW_USER,
            terms.as_deref(),
            Some(client),
            now,
            |id| layout.create_user(id),
        )
        .await;
        match created {
            Ok(users::SignedUp::Created(user, identity)) => {
                if let Err(err) = identities::end_pending(
                    &state.db,
                    identities::Holder::MiniProgram,
                    &request.signup_token,
                )
                .await
                {
                    tracing::warn!(error = %err, "cannot end a signup token");
                }
                tracing::info!(%client, user = %user.username, "account created by sign-up in the mini program");
                return match store::open_session_of(&state.db, identity.id, now).await {
                    Ok(Some((session, account))) => signed_in(&session, &account),
                    Ok(None) => unavailable(),
                    Err(err) => failed(&err),
                };
            }
            Ok(users::SignedUp::UsernameTaken) => {}
            Ok(users::SignedUp::AlreadyBound) => {
                return error(StatusCode::CONFLICT, "account_exists");
            }
            Ok(users::SignedUp::Limited) => {
                tracing::warn!(%client, "sign-up refused: the daily cap is reached");
                return error(StatusCode::TOO_MANY_REQUESTS, "signup_limited");
            }
            Err(err) => return failed(&err),
        }
    }
    unavailable()
}

#[derive(Deserialize)]
struct RenameRequest {
    username: String,
}

/// `PATCH /gono/v1/wechat/account`: a new username.
pub async fn rename(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let token = match bearer(&headers) {
        Ok(Some(token)) => token,
        Ok(None) => return not_signed_in("not_signed_in"),
        Err(()) => return wechat.refused(client),
    };
    let now = db::unix_now();
    let account = match store::lookup(&state.db, &wechat.app_id, token, now).await {
        Ok(Lookup::Live(account)) => account,
        Ok(Lookup::Expired) => return not_signed_in("session_expired"),
        Ok(Lookup::Disabled) => return error(StatusCode::FORBIDDEN, "account_disabled"),
        Ok(Lookup::Unknown) => return wechat.refused(client),
        Err(err) => return failed(&err),
    };
    let request: RenameRequest = match parse(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let Ok(username) = gono_server_core::Username::new(request.username.trim()) else {
        return bad_request();
    };
    match users::rename(
        &state.db,
        account.user_id,
        &username,
        gono_server_core::audit::Actor::User,
        Some(client),
        now,
    )
    .await
    {
        Ok(users::Renamed::Done) => match store::account(&state.db, account.user_id).await {
            Ok(Some(account)) => json(StatusCode::OK, &account_json(&account)),
            Ok(None) => error(StatusCode::FORBIDDEN, "account_disabled"),
            Err(err) => failed(&err),
        },
        Ok(users::Renamed::Taken) => error(StatusCode::CONFLICT, "username_taken"),
        Ok(users::Renamed::Locked) => error(StatusCode::CONFLICT, "username_locked"),
        Ok(users::Renamed::TooSoon) => rate_limited(Duration::from_secs(
            users::RENAME_INTERVAL_SECS.unsigned_abs(),
        )),
        Err(err) => failed(&err),
    }
}

#[derive(Deserialize)]
struct CodeRequest {
    code: String,
    platform: String,
    #[serde(default)]
    confirm: Option<String>,
}

/// The identity of the fresh code of `request` and its account, or the answer to refuse
/// with: the phone rule, and WeChat's refusals as in `session`.
async fn fresh_identity(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    request: &CodeRequest,
) -> Result<identities::Identity, Box<Response>> {
    if !is_code(&request.code) {
        return Err(Box::new(bad_request()));
    }
    check_platform(&request.platform)?;
    let openid = match wechat.api.code_to_session(&request.code).await {
        Ok(login) => login.openid,
        Err(ApiError::InvalidCode) => {
            return Err(Box::new(error(StatusCode::BAD_REQUEST, "code_invalid")));
        }
        Err(ApiError::RiskyUser) => {
            return Err(Box::new(error(StatusCode::FORBIDDEN, "risky_user")));
        }
        Err(ApiError::RateLimited) => return Err(Box::new(rate_limited(WECHAT_RETRY_AFTER))),
        Err(ApiError::Failed(why)) => {
            tracing::warn!(%client, error = %why, "cannot exchange a mini program's sign-in code with WeChat");
            return Err(Box::new(unavailable()));
        }
    };
    match identities::find(&state.db, Provider::WeChat, &wechat.app_id, &openid).await {
        Ok(Some(identity)) => Ok(identity),
        Ok(None) => Err(Box::new(error(StatusCode::FORBIDDEN, "not_permitted"))),
        Err(err) => Err(Box::new(failed(&err))),
    }
}

/// `POST /gono/v1/wechat/account/delete`.
pub async fn delete_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let token = match bearer(&headers) {
        Ok(Some(token)) => token,
        Ok(None) => return not_signed_in("not_signed_in"),
        Err(()) => return wechat.refused(client),
    };
    let now = db::unix_now();
    let account = match store::lookup(&state.db, &wechat.app_id, token, now).await {
        Ok(Lookup::Live(account)) => account,
        Ok(Lookup::Expired) => return not_signed_in("session_expired"),
        Ok(Lookup::Disabled) => return error(StatusCode::FORBIDDEN, "account_disabled"),
        Ok(Lookup::Unknown) => return wechat.refused(client),
        Err(err) => return failed(&err),
    };
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = async {
        let request: CodeRequest = match parse(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        if request.confirm.as_deref() != Some(account.username.as_str()) {
            return bad_request();
        }
        let identity = match fresh_identity(&state, &wechat, client, &request).await {
            Ok(identity) => identity,
            Err(response) => return *response,
        };
        if identity.user_id != account.user_id {
            return error(StatusCode::FORBIDDEN, "not_permitted");
        }
        match users::request_deletion(
            &state.db,
            account.user_id,
            gono_server_core::audit::Actor::User,
            Some(client),
            now,
        )
        .await
        {
            Ok(Some(_)) => {
                tracing::info!(%client, user = %account.username, "account deletion requested in the mini program");
                if let Some(connect) = &state.connect {
                    connect.poke();
                }
                StatusCode::NO_CONTENT.into_response()
            }
            // An account with a web password (or an admin) is deleted by an administrator.
            Ok(None) => error(StatusCode::FORBIDDEN, "not_permitted"),
            Err(err) => failed(&err),
        }
    }
    .await;
    wechat.charge(client, response)
}

/// `POST /gono/v1/wechat/account/restore`.
pub async fn restore(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = async {
        let request: CodeRequest = match parse(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        let identity = match fresh_identity(&state, &wechat, client, &request).await {
            Ok(identity) => identity,
            Err(response) => return *response,
        };
        let now = db::unix_now();
        match users::cancel_deletion(
            &state.db,
            identity.user_id,
            gono_server_core::audit::Actor::User,
            Some(client),
            now,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return error(StatusCode::CONFLICT, "not_pending"),
            Err(err) => return failed(&err),
        }
        tracing::info!(%client, "account deletion undone in the mini program");
        if let Some(connect) = &state.connect {
            connect.poke();
        }
        match store::open_session_of(&state.db, identity.id, now).await {
            Ok(Some((session, account))) => signed_in(&session, &account),
            Ok(None) => error(StatusCode::FORBIDDEN, "account_disabled"),
            Err(err) => failed(&err),
        }
    }
    .await;
    wechat.charge(client, response)
}

/// `GET /q/...`: the page for whoever opens a QR link in a browser, whatever the path below
/// `/q/`. It reads nothing of the path (a ticket in it stays unused) and starts nothing.
pub async fn scan_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if state.wechat.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let chrome = Chrome::for_request(&headers);
    let t = chrome.t;
    // Both languages: whoever opens the link may not have chosen the browser.
    let other = match chrome.lang {
        Lang::En => Lang::Zh,
        Lang::Zh => Lang::En,
    }
    .t();
    let mut page = Message::new(chrome, t.scan_title, t.scan_title, t.scan_lead);
    page.note = Some(format!("{} {}", other.scan_title, other.scan_lead));
    page.respond(StatusCode::OK)
}

/// `GET /<verify file name>`.
pub async fn verify_file(State(state): State<AppState>) -> Response {
    match state
        .wechat
        .as_ref()
        .and_then(|wechat| wechat.verify.as_ref())
    {
        Some(verify) => verify.response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
