//! The WeChat mini program (`[wechat]`, `docs/wechat-miniprogram.md`): its JSON API, the page
//! of its QR links and the verification file of its admin console.
//!
//! | Request | Answer |
//! |---|---|
//! | `POST /gono/v1/wechat/session` | Exchanges the mini program's sign-in code with WeChat: a session for a bound openid, a signup token otherwise. |
//! | `POST /gono/v1/wechat/bind` | Binds the openid of a signup token to the account of a bind ticket from the account page, and opens a session. |
//! | `POST /gono/v1/wechat/bind/preview` | The account `bind` would bind to, after `bind`'s checks, changing nothing. |
//! | `GET /gono/v1/wechat/account` | The name and services of the session's account (`Authorization: Bearer <session>`), which services this server offers, and since when the WeChat is bound. |
//! | `POST /gono/v1/wechat/logout` | Ends the session. |
//! | `GET /gono/v1/wechat/devices` | The devices of the session's account, as the account page lists them: active, signed out and revoked. |
//! | `GET /gono/v1/wechat/devices/<endpoint id>` | One of them, with the devices it introduced (its approvals), which revoking it can take along. |
//! | `POST /gono/v1/wechat/devices/<endpoint id>/sign-out` | Stops remote access for the device (protocol 9.4), with a fresh code of the account's WeChat. |
//! | `POST /gono/v1/wechat/devices/<endpoint id>/revoke` | Revokes the device and the introduced devices ticked with it (protocol 9.1, 9.2), with a fresh code. |
//! | `POST /gono/v1/wechat/unbind` | Unbinds the WeChat from the account (every session of it ends), with a fresh code; never its last way in. |
//! | `POST /gono/v1/wechat/signup` | With `[wechat] allow_signup`: creates an account (no service, no password, a generated username) for the WeChat of a signup token, and opens a session. |
//! | `PATCH /gono/v1/wechat/account` | Changes the display name, and the username of an account made by a sign-up until a device or app signed in to it. |
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
//! - A session reads the account's name, services and devices and changes its display name;
//!   with a fresh code of the account's WeChat it signs out and revokes the account's devices
//!   and unbinds the WeChat (the actions below). Nothing else: it opens no page and no file,
//!   WebDAV or S3 data.
//! - **Platform.** Every call that signs in or acts (`session`, `bind`, `bind/preview`,
//!   `signup`, `scan`, `confirm`, `deny`, `account/delete`, `account/restore`) takes only the
//!   phones' platforms, `ios`, `android` and `ohos` ([`check_platform`]): not desktop WeChat,
//!   not the developer tools.
//! - **Scene.** Binding gives a WeChat user the account's mini program sessions and the right
//!   to confirm sign-ins on the web, so a QR code forwarded to someone else must not bind.
//!   `bind` (and `bind/preview`, `scan`, `confirm`, `deny`) therefore also take only the scenes
//!   of scanning with the phone's camera, 1011 (a QR code) and 1047 (a mini program code)
//!   ([`check_client`]): not a code recognized in an image (1012, 1048) or picked from the
//!   album (1013, 1049), not a shared card (1007, 1008). `session` and `signup` take any scene:
//!   a WeChat that is bound already is the account's, so it signs in again however the mini
//!   program was opened, and a signup token binds nothing without a ticket and `bind`'s scene
//!   check.
//! - **The in-app scanner.** A code read by the mini program's own scanner
//!   (`wx.scanCode({onlyFromCamera: true})`: the camera only, no album, no image) is as good as
//!   a scan, but the scene then says how the mini program was opened (the chat list, say). So
//!   `bind`, `bind/preview`, `scan`, `confirm` and `deny` take `"source": "scan_code"` in place
//!   of the scene ([`check_scanned`]); the platform rule stays.
//! - The mini program reports all of this (`wx.getEnterOptionsSync().scene`,
//!   `wx.getDeviceInfo().platform`, `source`): the checks are a safeguard against mistakes and
//!   lures, not proof.
//! - **Limits.** Each client address has a token bucket like the sign-in pages'
//!   ([`RateLimiter`]). `session`, `bind`, `bind/preview` and the other calls that sign in or
//!   act are refused while the bucket is empty, before anything in them is checked or WeChat is
//!   asked, and every one that does not succeed takes a token (an invalid code, a refused
//!   scene, an expired ticket, ...). A successful one costs nothing, so that the users of the
//!   mini program behind one address (a carrier's NAT) do not lock each other out. `account`
//!   and `logout` cost a token only for a bearer token that is no session, and are refused for
//!   those only, as device authentication is.
//! - **Actions on the account** (`devices/<id>/sign-out`, `devices/<id>/revoke`, `unbind`)
//!   need, beside the session, a fresh
//!   code of `wx.login()` from the WeChat bound to the account, on a phone ([`fresh_code_of`]):
//!   it stands in for the second step that the account page asks for (protocol 10). Each
//!   account may act [`MAX_ACTIONS`] times a minute ([`ActionLimiter`]), beside the client's
//!   bucket, and the audit log names the actor `mini_program`.
//! - Tickets, tokens, codes and openids never reach the log (the paths below `/q/` are
//!   redacted by [`crate::request_log`]); lines name the account instead.

pub mod api;
pub mod sign_in;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
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
    audit::Actor,
    config::{WeChatConfig, verify_file_name},
    db,
    devices::{self, Device, EndpointId},
    identities::{self, Provider},
    services::Service,
    users,
    web_sessions::SessionUser,
    wechat::{
        self as store, Account, Bind, Locked, Lookup, NewSession, Preview, Purpose, SignIn, Stage,
    },
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
    service_view,
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

/// The scenes `bind` (and `bind/preview`, `scan`, `confirm`, `deny`) take: scanning a QR code
/// (1011) or a mini program code (1047) with WeChat's scanner.
pub const SCENES: [u32; 2] = [1011, 1047];

/// The platforms every call that signs in or acts takes: WeChat on a phone.
pub const PLATFORMS: [&str; 3] = ["ios", "android", "ohos"];

/// How long a client waits after WeChat's own rate limit, in seconds.
const WECHAT_RETRY_AFTER: Duration = Duration::from_secs(60);

/// `Retry-After` of `unavailable`, in seconds.
const UNAVAILABLE_RETRY_AFTER: &str = "30";

/// Tickets shown on the account page at most (one per browser session).
const MAX_SHOWN: usize = 1000;

/// Actions on one account at most per [`ACTION_WINDOW`], beside the client's bucket.
pub const MAX_ACTIONS: u32 = 10;

/// The window of [`MAX_ACTIONS`].
const ACTION_WINDOW: Duration = Duration::from_secs(60);

/// Counts the actions on each account in windows of [`ACTION_WINDOW`].
#[derive(Debug, Default)]
struct ActionLimiter {
    /// Each account's window: when it started and the actions in it so far.
    windows: Mutex<HashMap<i64, (Instant, u32)>>,
}

impl ActionLimiter {
    /// Counts an action on account `user_id` at `now`, or says how long to wait when the
    /// account had [`MAX_ACTIONS`] in its window already.
    fn take(&self, user_id: i64, now: Instant) -> Option<Duration> {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        windows.retain(|_, (start, _)| now.saturating_duration_since(*start) < ACTION_WINDOW);
        let (start, count) = windows.entry(user_id).or_insert((now, 0));
        if *count >= MAX_ACTIONS {
            return Some(ACTION_WINDOW.saturating_sub(now.saturating_duration_since(*start)));
        }
        *count += 1;
        None
    }
}

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
    /// The actions on each account.
    actions: ActionLimiter,
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
            actions: ActionLimiter::default(),
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

    /// [`Self::admit`], then counts an action on account `user_id`: `rate_limited` once it had
    /// [`MAX_ACTIONS`] this minute.
    fn admit_action(&self, client: IpAddr, user_id: i64) -> Result<(), Box<Response>> {
        self.admit(client)?;
        match self.actions.take(user_id, Instant::now()) {
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
                &format!("{API_PATH}/bind/preview"),
                post(bind_preview).fallback(not_found),
            )
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
            .route(
                &format!("{API_PATH}/devices"),
                get(list_devices).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/devices/{{endpoint_id}}"),
                get(show_device).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/devices/{{endpoint_id}}/sign-out"),
                post(sign_out_device).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/devices/{{endpoint_id}}/revoke"),
                post(revoke_device).fallback(not_found),
            )
            .route(
                &format!("{API_PATH}/unbind"),
                post(unbind).fallback(not_found),
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

/// What the mini program reads of `account` on the server of `state`: the account's switches
/// (`services`), whether this server offers each service at all (`offered`, as the account page
/// shows it), and since when the WeChat is bound.
fn account_json(state: &AppState, account: &Account) -> serde_json::Value {
    let services = account.services;
    let offered = |service| service_view::offered(state, service);
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
        "offered": {
            "files": offered(Service::Files),
            "webdav": offered(Service::Webdav),
            "s3": offered(Service::S3),
            "direct": offered(Service::Direct),
            "relay": offered(Service::Relay),
        },
        "wechat": { "bound_at": account.bound_at },
    })
}

/// The answer that hands over a new session.
fn signed_in(state: &AppState, session: &NewSession, account: &Account) -> Response {
    json(
        StatusCode::OK,
        &serde_json::json!({
            "session": session.token.expose_secret(),
            "expires_at": session.expires_at,
            "account": account_json(state, account),
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
            signed_in(state, &session, &account)
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
    /// `scan_code` for the in-app scanner; see [`check_scanned`].
    #[serde(default)]
    source: Option<String>,
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

/// The request of `bind` or `bind/preview`, parsed and checked: its shapes, then the platform
/// and the scene (or the in-app scanner).
fn bind_request(body: Result<Bytes, BytesRejection>) -> Result<BindRequest, Box<Response>> {
    let request: BindRequest = parse(body)?;
    if !store::is_token(&request.signup_token) || !store::is_ticket(&request.ticket) {
        return Err(Box::new(bad_request()));
    }
    check_scanned(request.scene, &request.platform, request.source.as_deref())?;
    Ok(request)
}

/// The answer to a refusal of `bind` (or of `bind/preview`, which refuses as `bind` would).
fn bind_refused(refused: &Bind) -> Response {
    match refused {
        Bind::SessionExpired => not_signed_in("session_expired"),
        Bind::TicketExpired | Bind::Bound { .. } => error(StatusCode::GONE, "ticket_expired"),
        Bind::Disabled => error(StatusCode::FORBIDDEN, "account_disabled"),
        Bind::AccountExists => error(StatusCode::CONFLICT, "account_exists"),
        Bind::BindFailed => error(StatusCode::CONFLICT, "bind_failed"),
    }
}

/// The answer of `bind` to an admitted `client`.
async fn bind_with(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request = match bind_request(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
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
            signed_in(state, &session, &account)
        }
        Ok(refused) => bind_refused(&refused),
        Err(err) => {
            tracing::error!(error = %err, "cannot bind WeChat to an account");
            unavailable()
        }
    }
}

/// `POST /gono/v1/wechat/bind/preview`: the account the ticket binds to, so that the mini
/// program can name it before the user binds. It takes `bind`'s body, makes `bind`'s checks in
/// `bind`'s order and refuses with `bind`'s errors, but changes nothing and uses nothing up
/// ([`store::preview`]). A refusal takes a token of the client's bucket, as in `bind`. It tells
/// the account's name to whoever holds the ticket, who could bind with it anyway.
pub async fn bind_preview(
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
    let response = preview_with(&state, &wechat, body).await;
    wechat.charge(client, response)
}

/// The answer of `bind/preview` to an admitted client.
async fn preview_with(
    state: &AppState,
    wechat: &WeChat,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request = match bind_request(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let previewed = store::preview(
        &state.db,
        &wechat.app_id,
        &request.signup_token,
        &request.ticket,
        db::unix_now(),
    )
    .await;
    match previewed {
        Ok(Preview::Ready(found)) => json(
            StatusCode::OK,
            &serde_json::json!({
                "account": {
                    "username": found.username.as_str(),
                    "display_name": found.display_name,
                },
                "expires_at": found.expires_at,
            }),
        ),
        Ok(Preview::Refused(refused)) => bind_refused(&refused),
        Err(err) => {
            tracing::error!(error = %err, "cannot look a bind ticket up");
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
        Ok(Lookup::Live(account)) => json(StatusCode::OK, &account_json(&state, &account)),
        Ok(Lookup::Expired) => not_signed_in("session_expired"),
        Ok(Lookup::Disabled) => error(StatusCode::FORBIDDEN, "account_disabled"),
        Ok(Lookup::Unknown) => wechat.refused(client),
        Err(err) => {
            tracing::error!(error = %err, "cannot look a mini program session up");
            unavailable()
        }
    }
}

/// The account of the live session whose bearer token `headers` carry, or the answer to refuse
/// with, as `account` refuses: `not_signed_in` (a token that is no session takes a token of the
/// client's bucket), `session_expired`, `account_disabled`. Each use extends the session.
async fn session_account(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    headers: &HeaderMap,
) -> Result<Account, Box<Response>> {
    let token = match bearer(headers) {
        Ok(Some(token)) => token,
        // No credentials cost nothing.
        Ok(None) => return Err(Box::new(not_signed_in("not_signed_in"))),
        Err(()) => return Err(Box::new(wechat.refused(client))),
    };
    match store::lookup(&state.db, &wechat.app_id, token, db::unix_now()).await {
        Ok(Lookup::Live(account)) => Ok(account),
        Ok(Lookup::Expired) => Err(Box::new(not_signed_in("session_expired"))),
        Ok(Lookup::Disabled) => Err(Box::new(error(StatusCode::FORBIDDEN, "account_disabled"))),
        Ok(Lookup::Unknown) => Err(Box::new(wechat.refused(client))),
        Err(err) => Err(Box::new(database(&err, "look a mini program session up"))),
    }
}

/// The answer to a database failure while doing `what`.
fn database(err: &gono_server_core::Error, what: &str) -> Response {
    tracing::error!(error = %err, "mini program: cannot {what}");
    unavailable()
}

/// What the mini program reads of `device`: the directory entry of protocol 6.1 without
/// `services` (never an address: entries have none), with its short ID, the readable names of
/// its product and platform, and its state: `active`, `signed_out` (since `signed_out_at`) or
/// `revoked` (since `revoked_at`).
fn device_json(device: &Device, online: bool) -> serde_json::Value {
    let state = if device.is_revoked() {
        "revoked"
    } else if device.is_signed_out() {
        "signed_out"
    } else {
        "active"
    };
    let mut entry = device.entry(online);
    if let Some(fields) = entry.as_object_mut() {
        fields.remove("services");
        fields.insert("short_id".into(), device.endpoint_id.short().into());
        fields.insert(
            "product_name".into(),
            crate::login_flow::product_name(&device.product).into(),
        );
        fields.insert(
            "platform_name".into(),
            crate::login_flow::platform_name(&device.platform).into(),
        );
        fields.insert("state".into(), state.into());
        fields.insert(
            "signed_out_at".into(),
            device.left_at.filter(|_| device.is_signed_out()).into(),
        );
    }
    entry
}

/// `GET /gono/v1/wechat/devices`: what the account page's "Remote devices" lists, signed-out and
/// revoked entries included. Without remote connectivity on this server (`offered.direct` is
/// `false`) the list is empty, as the account page then shows none.
pub async fn list_devices(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let account = match session_account(&state, &wechat, client, &headers).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    let listed = match &state.connect {
        Some(connect) => match connect.devices_with_presence(account.user_id).await {
            Ok(listed) => listed,
            Err(err) => return database(&err, "list the devices"),
        },
        None => Vec::new(),
    };
    let entries: Vec<serde_json::Value> = listed
        .iter()
        .map(|(device, online)| device_json(device, *online))
        .collect();
    json(
        StatusCode::OK,
        &serde_json::json!({
            "devices": entries,
            "limit": devices::MAX_DEVICES_PER_ACCOUNT,
        }),
    )
}

/// The device `hex` of `account` (revoked or not), or `not_found`: for a device of another
/// account, one that does not exist, an ID that is not one, and on a server without remote
/// access (protocol 10: a refusal never tells whether another account's device exists).
async fn own_device(
    state: &AppState,
    account: &Account,
    hex: &str,
) -> Result<Device, Box<Response>> {
    let not_found = || Box::new(error(StatusCode::NOT_FOUND, "not_found"));
    if state.connect.is_none() {
        return Err(not_found());
    }
    let key = EndpointId::parse(hex).ok_or_else(not_found)?;
    match devices::find(&state.db, key).await {
        Ok(Some(device)) if device.user_id == account.user_id => Ok(device),
        Ok(_) => Err(not_found()),
        Err(err) => Err(Box::new(database(&err, "find a device"))),
    }
}

/// Whether `device` has its control connection now.
fn is_online(state: &AppState, device: &Device) -> bool {
    state
        .connect
        .as_ref()
        .is_some_and(|connect| connect.is_online(device.user_id, device.endpoint_id))
}

/// `GET /gono/v1/wechat/devices/<endpoint id>`: the entry of [`device_json`] with
/// `introduced`, the unrevoked devices this one vouched for through approvals (protocol 8.4,
/// 9.1), as the account page's revocation step lists them, in the same form.
pub async fn show_device(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(hex): axum::extract::Path<String>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let account = match session_account(&state, &wechat, client, &headers).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    let device = match own_device(&state, &account, &hex).await {
        Ok(device) => device,
        Err(response) => return *response,
    };
    let introduced = match devices::introduced_by(&state.db, device.id).await {
        Ok(introduced) => introduced,
        Err(err) => return database(&err, "list the devices a device introduced"),
    };
    let mut entry = device_json(&device, is_online(&state, &device));
    if let Some(fields) = entry.as_object_mut() {
        let introduced: Vec<serde_json::Value> = introduced
            .iter()
            .map(|other| device_json(other, is_online(&state, other)))
            .collect();
        fields.insert("introduced".into(), introduced.into());
    }
    json(StatusCode::OK, &entry)
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
    /// `scan_code` for the in-app scanner; see [`check_scanned`].
    #[serde(default)]
    source: Option<String>,
}

/// [`check_client`] that takes the in-app scanner as a scan: `source` `scan_code` says that the
/// mini program read the code with `wx.scanCode({onlyFromCamera: true})`, so its scene (how it
/// was opened) is not checked. `enter`, or no `source`, checks the scene; any other value is
/// `bad_request`. The platform is checked first, whatever the source.
fn check_scanned(scene: u32, platform: &str, source: Option<&str>) -> Result<(), Box<Response>> {
    check_platform(platform)?;
    match source {
        None | Some("enter") => check_client(scene, platform),
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
    check_scanned(request.scene, &request.platform, request.source.as_deref())?;
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
                    Ok(Some((session, account))) => signed_in(state, &session, &account),
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
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

/// `PATCH /gono/v1/wechat/account` `{username, display_name}`, either or both: a new username
/// (an account made by a sign-up, until a device or app signed in to it, once a day) and a new
/// display name (the account page's rules: not empty, at most 255 characters, no control
/// characters, trimmed). The session is enough, no fresh code (decided on 2026-11-24), and each
/// request counts against the account's [`MAX_ACTIONS`] a minute. The username changes first,
/// so a refused one leaves the display name as it was too. The answer is the account.
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
    if let Some(wait) = wechat.actions.take(account.user_id, Instant::now()) {
        return rate_limited(wait);
    }
    let request: RenameRequest = match parse(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if request.username.is_none() && request.display_name.is_none() {
        return bad_request();
    }
    let display_name = match request
        .display_name
        .as_deref()
        .map(users::validate_display_name)
    {
        None => None,
        Some(Ok(display_name)) => Some(display_name),
        Some(Err(_)) => return bad_request(),
    };
    let mut username = account.username.clone();
    if let Some(wanted) = &request.username {
        let Ok(wanted) = gono_server_core::Username::new(wanted.trim()) else {
            return bad_request();
        };
        match users::rename(
            &state.db,
            account.user_id,
            &wanted,
            Actor::User,
            Some(client),
            now,
        )
        .await
        {
            Ok(users::Renamed::Done) => username = wanted,
            Ok(users::Renamed::Taken) => return error(StatusCode::CONFLICT, "username_taken"),
            Ok(users::Renamed::Locked) => return error(StatusCode::CONFLICT, "username_locked"),
            Ok(users::Renamed::TooSoon) => {
                return rate_limited(Duration::from_secs(
                    users::RENAME_INTERVAL_SECS.unsigned_abs(),
                ));
            }
            Err(err) => return failed(&err),
        }
    }
    if let Some(display_name) = display_name {
        if let Err(err) = users::set_display_name(&state.db, &username, &display_name).await {
            return database(&err, "change a display name");
        }
        tracing::info!(%client, user = %username, "display name changed in the mini program");
    }
    // Read again through the session, as `account` would.
    match store::lookup(&state.db, &wechat.app_id, token, now).await {
        Ok(Lookup::Live(account)) => json(StatusCode::OK, &account_json(&state, &account)),
        Ok(Lookup::Expired | Lookup::Unknown) => not_signed_in("not_signed_in"),
        Ok(Lookup::Disabled) => error(StatusCode::FORBIDDEN, "account_disabled"),
        Err(err) => failed(&err),
    }
}

#[derive(Deserialize)]
struct CodeRequest {
    code: String,
    platform: String,
    #[serde(default)]
    confirm: Option<String>,
    /// `devices/<id>/revoke`: the introduced devices to revoke along with it.
    #[serde(default)]
    also: Vec<String>,
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

/// Refuses unless the fresh code of `request` is of the WeChat of the session that reads
/// `account`: `not_permitted` for another WeChat's (bound elsewhere or to nothing), and the
/// refusals of [`fresh_identity`] (the phone, WeChat's).
async fn fresh_code_of(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    request: &CodeRequest,
    account: &Account,
) -> Result<(), Box<Response>> {
    let identity = fresh_identity(state, wechat, client, request).await?;
    if identity.id == account.identity_id {
        Ok(())
    } else {
        Err(Box::new(error(StatusCode::FORBIDDEN, "not_permitted")))
    }
}

/// `409 device_revoked`.
fn device_revoked() -> Response {
    error(StatusCode::CONFLICT, "device_revoked")
}

/// `POST /gono/v1/wechat/devices/<endpoint id>/sign-out` `{code, platform}`: stops remote access
/// for the device as the account page's "Stop remote access" does (protocol 9.4): its credential
/// is deleted, the entry stays (bound to the account, revocable), the account's other devices
/// get `device.removed`, and its connections end. Unlike the account page it needs no service
/// (decided on 2026-11-24): taking access away is never refused for a switch. A device that is
/// signed out already answers `204` as well; a revoked one `device_revoked`.
pub async fn sign_out_device(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(hex): axum::extract::Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let account = match session_account(&state, &wechat, client, &headers).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    if let Err(response) = wechat.admit_action(client, account.user_id) {
        return *response;
    }
    let response = async {
        let request: CodeRequest = match parse(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        let device = match own_device(&state, &account, &hex).await {
            Ok(device) => device,
            Err(response) => return *response,
        };
        if device.is_revoked() {
            return device_revoked();
        }
        if let Err(response) = fresh_code_of(&state, &wechat, client, &request, &account).await {
            return *response;
        }
        let Some(connect) = &state.connect else {
            return error(StatusCode::NOT_FOUND, "not_found");
        };
        match connect.sign_out(&device, Actor::MiniProgram).await {
            Ok(_) => {
                tracing::info!(
                    %client,
                    user = %account.username,
                    device = %device.endpoint_id.short(),
                    "remote access stopped for a device in the mini program"
                );
                StatusCode::NO_CONTENT.into_response()
            }
            Err(err) => database(&err, "sign a device out"),
        }
    }
    .await;
    wechat.charge(client, response)
}

/// `POST /gono/v1/wechat/devices/<endpoint id>/revoke` `{code, platform, confirm, also}`: revokes
/// the device (protocol 9.1, 9.2) after the mini program's second confirmation, which `confirm`
/// repeats: the device's full ID, as `--confirm` of `gono-cloud device revoke`. `also` names
/// devices it introduced (those of `introduced`) to revoke along with it, as the account page's
/// boxes do. Another `confirm`, or an `also` that is not among `introduced`, is `bad_request`
/// and revokes nothing. Revoking needs no service, as on the account page; a revoked device
/// answers `device_revoked`.
pub async fn revoke_device(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Path(hex): axum::extract::Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let wechat = match wechat_of(&state) {
        Ok(wechat) => wechat,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let account = match session_account(&state, &wechat, client, &headers).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    if let Err(response) = wechat.admit_action(client, account.user_id) {
        return *response;
    }
    let response = async {
        let request: CodeRequest = match parse(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        let device = match own_device(&state, &account, &hex).await {
            Ok(device) => device,
            Err(response) => return *response,
        };
        if device.is_revoked() {
            return device_revoked();
        }
        if request.confirm.as_deref() != Some(device.endpoint_id.to_hex().as_str()) {
            return bad_request();
        }
        let introduced = match devices::introduced_by(&state.db, device.id).await {
            Ok(introduced) => introduced,
            Err(err) => return database(&err, "list the devices a device introduced"),
        };
        let mut keys = vec![device.endpoint_id];
        for hex in &request.also {
            match introduced
                .iter()
                .find(|other| other.endpoint_id.to_hex() == *hex)
            {
                Some(other) if !keys.contains(&other.endpoint_id) => keys.push(other.endpoint_id),
                Some(_) => {}
                None => return bad_request(),
            }
        }
        if let Err(response) = fresh_code_of(&state, &wechat, client, &request, &account).await {
            return *response;
        }
        let revoked = devices::revoke(
            &state.db,
            account.user_id,
            &keys,
            devices::RevokedBy::MiniProgram,
            Some(client),
            db::unix_now(),
        )
        .await;
        match revoked {
            Ok(revoked) => {
                for device in &revoked {
                    tracing::info!(
                        %client,
                        user = %account.username,
                        device = %device.endpoint_id.short(),
                        "device revoked in the mini program"
                    );
                }
                // The running server closes their connections and tells the other devices.
                if let Some(connect) = &state.connect {
                    connect.poke();
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(err) => database(&err, "revoke a device"),
        }
    }
    .await;
    wechat.charge(client, response)
}

/// `POST /gono/v1/wechat/unbind` `{code, platform}`: unbinds the session's WeChat from its
/// account, as "Unbind" on the account page does: every mini program session of the WeChat
/// ends, on every phone, and `identity.unbound` is recorded with `how: "mini_program"` (plan
/// `third-party-sign-in-design.md` 8). It is refused with `last_sign_in` when WeChat is the
/// account's last way in: no web login password and no other identity.
pub async fn unbind(
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
    let account = match session_account(&state, &wechat, client, &headers).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    if let Err(response) = wechat.admit_action(client, account.user_id) {
        return *response;
    }
    let response = async {
        let request: CodeRequest = match parse(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        if let Err(response) = fresh_code_of(&state, &wechat, client, &request, &account).await {
            return *response;
        }
        let unbound = identities::unbind(
            &state.db,
            account.user_id,
            identities::Which::Id(account.identity_id),
            identities::How::MiniProgram,
            Actor::MiniProgram,
            Some(client),
            db::unix_now(),
        )
        .await;
        match unbound {
            Ok(identities::Unbound::Done(_)) => {
                tracing::info!(%client, user = %account.username, app_id = %wechat.app_id, "WeChat unbound in the mini program");
                StatusCode::NO_CONTENT.into_response()
            }
            Ok(identities::Unbound::LastSignIn) => error(StatusCode::CONFLICT, "last_sign_in"),
            // Unbound in the meantime: the session ended with it.
            Ok(identities::Unbound::NotBound) => not_signed_in("not_signed_in"),
            Err(err) => database(&err, "unbind a WeChat"),
        }
    }
    .await;
    wechat.charge(client, response)
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
            Actor::User,
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
        match users::cancel_deletion(&state.db, identity.user_id, Actor::User, Some(client), now)
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
            Ok(Some((session, account))) => signed_in(&state, &session, &account),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_account_may_act_ten_times_a_minute() {
        let limiter = ActionLimiter::default();
        let start = Instant::now();
        for _ in 0..MAX_ACTIONS {
            assert_eq!(limiter.take(1, start), None);
        }
        let wait = limiter.take(1, start + Duration::from_secs(20)).unwrap();
        assert_eq!(wait, Duration::from_secs(40));
        // Another account has a window of its own.
        assert_eq!(limiter.take(2, start + Duration::from_secs(20)), None);
        // A new window starts once the minute is over.
        assert_eq!(limiter.take(1, start + ACTION_WINDOW), None);
    }
}
