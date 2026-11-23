//! Signing in on the web by scanning a QR code with the mini program (`[wechat]
//! web_sign_in`; `plan/third-party-sign-in-design.md`, 4.3 and 5.3).
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /login/wechat?next=` | The QR code of a sign-in ticket for this browser; once the mini program scanned it, the form for the 6 digits; or how it ended. `purpose=reauth` confirms it is the signed-in account's user instead (the account page). |
//! | `POST /login/wechat` | The 6 digits: signed in (or confirmed), on to `next`. |
//! | `POST /login/wechat/restart` | Ends this browser's sign-in, for a new QR code. |
//! | `GET /login/wechat/status` | `{"stage": ...}` of this browser's sign-in, which the page's script polls. |
//!
//! - **The ticket** is 128 random bits, valid for [`wechat::SIGN_IN_TTL_SECS`], shown as the QR
//!   code of `{qr_url_prefix}<ticket>`. It is bound to this browser by the [`WECHAT_COOKIE`]: the
//!   database holds the digests of both, and only this browser can finish the sign-in. The
//!   ticket itself waits in memory for the browser, so that the page can show it again; a new
//!   one is made before it runs out, until the user leaves. A restart loses them; the user
//!   reloads.
//! - **The 6 digits** are always asked, on the same network too (decided): a forwarded or
//!   phished QR code signs in nothing without the digits typed into the browser that shows it.
//!   They live [`wechat::CODE_TTL_SECS`] and take [`wechat::CODE_TRIES`] tries; each wrong one
//!   counts against the browser's address in the sign-in limiter, and the last ends the sign-in.
//! - **Without JavaScript** the page reloads itself every 3 seconds while it waits, and stops
//!   once it asks for the digits; the script polls `status` every 2 seconds instead.
//! - **What it gives:** a web session without the second step, as every third-party sign-in;
//!   the admin UI's sign-in admits admin accounts only (the mini program refuses others when it
//!   scans), and a confirmation needs the identity bound to the signed-in account.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, PoisonError},
};

use askama::Template;
use axum::{
    Form, Json,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    db, email,
    identities::{self, Provider, SignedIn},
    secret,
    wechat::{self, Entered, Purpose, Stage},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::{
    app::AppState,
    client_ip::client_ip,
    i18n::{Text, fill},
    oauth::{self, Button},
    site::{self, FILES_HOME},
    web::{self, CSRF_COOKIE, Chrome, Message, PENDING_COOKIE, WECHAT_COOKIE, page},
};

/// Where the sign-in page lives.
pub const PATH: &str = "/login/wechat";

/// A shown ticket is replaced when it has less than this left, in seconds, so that the user
/// has time to scan it.
const RENEW_BEFORE_SECS: i64 = 30;

/// Tickets shown at most (one per browser).
const MAX_SHOWN: usize = 1000;

/// Characters of the browser's cookie: 256 random bits.
const COOKIE_CHARS: usize = 43;

/// The tickets the browsers show, by the digest of their cookie: the ticket and when it ends.
#[derive(Debug, Default)]
pub struct Shown(Mutex<HashMap<[u8; 32], (SecretString, i64)>>);

impl Shown {
    fn get(&self, browser: &str, now: i64) -> Option<SecretString> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&secret::digest(browser))
            .filter(|(_, until)| *until > now)
            .map(|(ticket, _)| ticket.clone())
    }

    fn put(&self, browser: &str, ticket: SecretString, until: i64, now: i64) {
        let mut shown = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        shown.retain(|_, (_, at)| *at > now);
        if shown.len() >= MAX_SHOWN {
            shown.clear();
        }
        shown.insert(secret::digest(browser), (ticket, until));
    }

    fn forget(&self, browser: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&secret::digest(browser));
    }

    /// Every ticket shown, for tests that play the mini program.
    #[cfg(test)]
    pub fn tickets(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .values()
            .map(|(ticket, _)| ticket.expose_secret().to_owned())
            .collect()
    }
}

/// A browser's name from its `User-Agent`, as the mini program shows it: "Chrome · Windows".
pub fn browser_name(headers: &HeaderMap) -> String {
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let browser = if agent.contains("Edg/") {
        "Edge"
    } else if agent.contains("Firefox/") {
        "Firefox"
    } else if agent.contains("Chrome/") || agent.contains("CriOS/") {
        "Chrome"
    } else if agent.contains("Safari/") {
        "Safari"
    } else {
        ""
    };
    let system = if agent.contains("Windows") {
        "Windows"
    } else if agent.contains("iPhone") || agent.contains("iPad") {
        "iOS"
    } else if agent.contains("Mac OS X") || agent.contains("Macintosh") {
        "macOS"
    } else if agent.contains("Android") {
        "Android"
    } else if agent.contains("HarmonyOS") || agent.contains("OpenHarmony") {
        "HarmonyOS"
    } else if agent.contains("Linux") {
        "Linux"
    } else {
        ""
    };
    match (browser, system) {
        ("", "") => "?".to_owned(),
        (one, "") | ("", one) => one.to_owned(),
        (browser, system) => format!("{browser} · {system}"),
    }
}

/// The button of the sign-in pages that leads here, going on to `next`, while this server
/// offers it.
pub fn sign_in_button(state: &AppState, t: &Text, next: &str) -> Option<Button> {
    state.wechat.as_ref().filter(|mini| mini.web_sign_in())?;
    Some(Button {
        action: format!("{PATH}?next={}", encode(next)),
        label: t.sign_in_wechat.to_owned(),
        link: true,
    })
}

/// The link that confirms it is the signed-in user with WeChat, coming back to `next` (a page
/// of the account), while this server offers it.
pub fn reauth_button(state: &AppState, t: &Text, next: &str) -> Option<Button> {
    state.wechat.as_ref().filter(|mini| mini.web_sign_in())?;
    Some(Button {
        action: format!("{PATH}?purpose=reauth&next={}", encode(next)),
        label: fill(t.confirm_with, &[t.provider_wechat]),
        link: true,
    })
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// What a request asks for: the purpose and where to go on to.
struct Asked {
    purpose: Purpose,
    next: String,
}

/// The purpose and `next` of `purpose`, `next` and the request's session: a confirmation goes
/// back to a page of the account and needs a session; the admin UI's sign-in is one going on
/// to the admin UI.
async fn asked(
    state: &AppState,
    headers: &HeaderMap,
    purpose: &str,
    next: &str,
) -> Result<(Asked, Option<gono_server_core::web_sessions::SessionUser>), Box<Response>> {
    if purpose == "reauth" {
        let Some((user, _)) = state.web.session(headers).await else {
            return Err(Box::new(web::see_other("/login?next=%2Faccount%2F", &[])));
        };
        let next = site::local_path(next)
            .filter(|next| next.starts_with(crate::files::account::OVERVIEW))
            .unwrap_or(crate::files::account::OVERVIEW)
            .to_owned();
        return Ok((
            Asked {
                purpose: Purpose::Reauth,
                next,
            },
            Some(user),
        ));
    }
    let next = site::local_path(next)
        .filter(|next| *next != "/login" && !next.starts_with(PATH))
        .unwrap_or(FILES_HOME)
        .to_owned();
    let admin = state.admin.as_ref().is_some_and(|admin| {
        next == admin.prefix() || next.starts_with(&format!("{}/", admin.prefix()))
    });
    let purpose = if admin {
        Purpose::Admin
    } else {
        Purpose::SignIn
    };
    Ok((Asked { purpose, next }, None))
}

/// `templates/wechat_sign_in.html`.
#[derive(Template)]
#[template(path = "wechat_sign_in.html")]
struct SignInPage {
    chrome: Chrome,
    csrf: String,
    next: String,
    purpose: &'static str,
    /// The stage the script compares with `status`.
    stage: &'static str,
    /// Reload without the script: while waiting for the scan.
    reload: bool,
    /// The QR code, while waiting.
    qr: Option<String>,
    /// How it ended.
    ended: Option<&'static str>,
    error: Option<String>,
    /// Back to the password.
    back: String,
}

page!(SignInPage);

/// How the page and `status` name `stage`: the digits are asked from the scan on.
fn shown_stage(stage: Stage) -> &'static str {
    match stage {
        Stage::Waiting => "waiting",
        Stage::Scanned | Stage::Code => "code",
        Stage::Done => "done",
        Stage::Denied | Stage::Tries => "ended",
        Stage::Expired => "expired",
    }
}

/// The browser's cookie value of `headers`, or a new one.
fn browser_cookie(state: &AppState, headers: &HeaderMap) -> (String, bool) {
    match web::cookie(headers, &state.web.cookie_name(WECHAT_COOKIE)).filter(|value| {
        value.len() == COOKIE_CHARS && value.bytes().all(|b| b.is_ascii_alphanumeric())
    }) {
        Some(value) => (value, false),
        None => (
            secret::random_token(COOKIE_CHARS)
                .expose_secret()
                .to_owned(),
            true,
        ),
    }
}

fn purpose_name(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::Reauth => "reauth",
        Purpose::SignIn | Purpose::Admin => "sign_in",
    }
}

/// The ticket this browser shows and what the database says of it.
async fn current(
    state: &AppState,
    browser: &str,
    now: i64,
) -> Option<(SecretString, wechat::SignInTicket)> {
    let mini = state.wechat.as_ref()?;
    let ticket = mini.shown_sign_ins().get(browser, now)?;
    match wechat::browser_sign_in(&state.db, ticket.expose_secret(), browser, now).await {
        Ok(found) => found.map(|found| (ticket, found)),
        Err(err) => {
            tracing::error!(error = %err, "cannot read a WeChat sign-in");
            None
        }
    }
}

/// Renders the page of this browser's sign-in, making a new ticket when it has none to show.
async fn show(
    state: &AppState,
    headers: &HeaderMap,
    client: std::net::IpAddr,
    asked: Asked,
    user_id: Option<i64>,
    status: StatusCode,
    error: Option<String>,
) -> Response {
    let Some(mini) = state.wechat.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = db::unix_now();
    let (browser, _) = browser_cookie(state, headers);
    let mut found = current(state, &browser, now)
        .await
        .filter(|(_, ticket)| ticket.purpose == asked.purpose && ticket.user_id == user_id);
    let renew = match &found {
        None => true,
        Some((_, ticket)) => match ticket.stage {
            Stage::Waiting => ticket.expires_at - now < RENEW_BEFORE_SECS,
            Stage::Expired | Stage::Done => true,
            _ => false,
        },
    };
    if renew {
        let made = wechat::create_sign_in(
            &state.db,
            &browser,
            asked.purpose,
            user_id,
            &browser_name(headers),
            &email::client_net(client),
            now,
        )
        .await;
        let ticket = match made {
            Ok(ticket) => ticket,
            Err(err) => {
                tracing::error!(error = %err, "cannot make a WeChat sign-in ticket");
                return web::unavailable(Chrome::for_request(headers));
            }
        };
        mini.shown_sign_ins()
            .put(&browser, ticket.ticket.clone(), ticket.expires_at, now);
        found = current(state, &browser, now).await;
    }
    let Some((ticket, sign_in)) = found else {
        return web::unavailable(Chrome::for_request(headers));
    };
    let (csrf, csrf_cookie) = state.web.login_csrf(headers);
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let stage = shown_stage(sign_in.stage);
    let ended = match sign_in.stage {
        Stage::Denied => Some(t.wechat_sign_in_denied),
        Stage::Tries => Some(t.wechat_sign_in_tries_out),
        _ => None,
    };
    let qr = (sign_in.stage == Stage::Waiting)
        .then(|| crate::qr::svg(&mini.sign_in_link(ticket.expose_secret())))
        .flatten();
    let back = match asked.purpose {
        Purpose::Reauth => asked.next.clone(),
        _ => oauth::sign_in_page(state, &asked.next),
    };
    let page = SignInPage {
        csrf,
        next: asked.next,
        purpose: purpose_name(asked.purpose),
        stage,
        reload: sign_in.stage == Stage::Waiting,
        qr,
        ended,
        error,
        back,
        chrome,
    };
    let mut response = web::render(status, &page);
    let headers = response.headers_mut();
    headers.append(header::SET_COOKIE, csrf_cookie);
    // A new cookie, or a new lifetime for this one as long as the page is in use.
    headers.append(header::SET_COOKIE, state.web.wechat_cookie(&browser));
    response
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    next: String,
    #[serde(default)]
    purpose: String,
}

/// Whether the sign-in pages exist: `[wechat] web_sign_in`, with the file UI or the admin UI.
fn offered(state: &AppState) -> bool {
    state.wechat.as_ref().is_some_and(|mini| mini.web_sign_in())
        && (state.files.is_some() || state.admin.is_some())
}

/// `GET /login/wechat`.
pub async fn page(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if !offered(&state) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let (asked, user) = match asked(&state, &headers, &query.purpose, &query.next).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let user_id = user.map(|user| user.user_id);
    show(
        &state,
        &headers,
        client,
        asked,
        user_id,
        StatusCode::OK,
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct CodeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    next: String,
    #[serde(default)]
    purpose: String,
}

/// `POST /login/wechat`: the 6 digits.
pub async fn enter(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    if !offered(&state) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Some(wait) = state.web.rate_limited(client) {
        return web::too_many_attempts(Chrome::for_request(&headers), wait);
    }
    let (asked, user) = match asked(&state, &headers, &form.purpose, &form.next).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let user_id = user.as_ref().map(|user| user.user_id);
    let t = Chrome::for_request(&headers).t;
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        let error = Some(t.form_expired_sign_in.to_owned());
        return show(
            &state,
            &headers,
            client,
            asked,
            user_id,
            StatusCode::FORBIDDEN,
            error,
        )
        .await;
    }
    let (browser, _) = browser_cookie(&state, &headers);
    let now = db::unix_now();
    let Some((ticket, _)) = current(&state, &browser, now).await else {
        return show(
            &state,
            &headers,
            client,
            asked,
            user_id,
            StatusCode::OK,
            None,
        )
        .await;
    };
    let code: String = form.code.chars().filter(|c| !c.is_whitespace()).collect();
    let entered =
        match wechat::enter_code(&state.db, ticket.expose_secret(), &browser, &code, now).await {
            Ok(entered) => entered,
            Err(err) => {
                tracing::error!(error = %err, "cannot check the digits of a WeChat sign-in");
                return web::unavailable(Chrome::for_request(&headers));
            }
        };
    let sign_in = match entered {
        Entered::Right(sign_in) => sign_in,
        Entered::Wrong(left) => {
            state.web.record_failure(client);
            tracing::info!(%client, "wrong digits of a WeChat sign-in");
            let error = Some(fill(t.wechat_sign_in_wrong, &[&left.to_string()]));
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            return show(&state, &headers, client, asked, user_id, status, error).await;
        }
        Entered::Ended => {
            state.web.record_failure(client);
            tracing::info!(%client, "a WeChat sign-in ended after wrong digits");
            let status = StatusCode::FORBIDDEN;
            return show(&state, &headers, client, asked, user_id, status, None).await;
        }
        Entered::NoCode => {
            return show(
                &state,
                &headers,
                client,
                asked,
                user_id,
                StatusCode::OK,
                None,
            )
            .await;
        }
    };
    if let Some(mini) = &state.wechat {
        mini.shown_sign_ins().forget(&browser);
    }
    finish(&state, &headers, client, sign_in, asked, user).await
}

/// The digits were right: sign the identity's account in, or confirm it is the user.
async fn finish(
    state: &AppState,
    headers: &HeaderMap,
    client: std::net::IpAddr,
    sign_in: wechat::SignInTicket,
    asked: Asked,
    session: Option<gono_server_core::web_sessions::SessionUser>,
) -> Response {
    let now = db::unix_now();
    let Some(identity_id) = sign_in.identity_id else {
        return web::unavailable(Chrome::for_request(headers));
    };
    let (outcome, _) = match identities::sign_in_identity(&state.db, identity_id, now).await {
        Ok(found) => found,
        Err(err) => {
            tracing::error!(error = %err, "cannot sign in with WeChat");
            return web::unavailable(Chrome::for_request(headers));
        }
    };
    let removal = state.web.removal_cookie(WECHAT_COOKIE);
    let SignedIn::Account(user) = outcome else {
        let chrome = Chrome::for_request(headers);
        let t = chrome.t;
        return Message::new(
            chrome,
            t.account_cannot_sign_in,
            t.account_cannot_sign_in,
            t.account_cannot_sign_in_lead,
        )
        .respond(StatusCode::FORBIDDEN);
    };
    match sign_in.purpose {
        Purpose::Reauth => {
            let same = session
                .filter(|session| session.user_id == user.id && sign_in.user_id == Some(user.id));
            let Some(session) = same else {
                state.web.record_failure(client);
                return web::see_other(
                    &format!("{}?failed=other-wechat", crate::files::account::OVERVIEW),
                    &[removal],
                );
            };
            state.web.confirm(&session);
            tracing::info!(%client, user = %user.username, provider = "wechat", "confirmed with a third-party identity");
            web::see_other(&asked.next, &[removal])
        }
        Purpose::Admin if !user.is_admin => {
            tracing::info!(%client, user = %user.username, "admin sign-in refused: not an admin");
            let chrome = Chrome::for_request(headers);
            let t = chrome.t;
            Message::new(
                chrome,
                t.request_blocked,
                t.request_blocked,
                t.a_not_admin_error,
            )
            .respond(StatusCode::FORBIDDEN)
        }
        Purpose::SignIn | Purpose::Admin => {
            let Some(token) = state
                .web
                .open_session_with(client, &user, Provider::WeChat)
                .await
            else {
                return web::unavailable(Chrome::for_request(headers));
            };
            let next = if sign_in.purpose == Purpose::Admin {
                asked.next
            } else {
                site::landing(Some(&asked.next), user.services)
            };
            web::see_other(
                &next,
                &[
                    state.web.session_cookie(&token),
                    state.web.removal_cookie(CSRF_COOKIE),
                    state.web.removal_cookie(PENDING_COOKIE),
                    removal,
                ],
            )
        }
    }
}

#[derive(Deserialize)]
pub struct RestartForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    next: String,
    #[serde(default)]
    purpose: String,
}

/// `POST /login/wechat/restart`.
pub async fn restart(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RestartForm>,
) -> Response {
    if !offered(&state) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        return site::blocked(&headers, |t| t.form_expired_sign_in);
    }
    let (browser, _) = browser_cookie(&state, &headers);
    if let Some(mini) = &state.wechat {
        mini.shown_sign_ins().forget(&browser);
    }
    if let Err(err) = wechat::end_browser_sign_ins(&state.db, &browser).await {
        tracing::warn!(error = %err, "cannot end a WeChat sign-in");
    }
    let mut target = format!("{PATH}?next={}", encode(&form.next));
    if form.purpose == "reauth" {
        target.push_str("&purpose=reauth");
    }
    web::see_other(&target, &[])
}

/// `GET /login/wechat/status`.
pub async fn status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !offered(&state) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (browser, _) = browser_cookie(&state, &headers);
    let stage = match current(&state, &browser, db::unix_now()).await {
        Some((_, sign_in)) => shown_stage(sign_in.stage),
        None => "expired",
    };
    let mut response = Json(serde_json::json!({ "stage": stage })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_are_named_by_their_user_agent() {
        let named = |agent: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::USER_AGENT, HeaderValue::from_str(agent).unwrap());
            browser_name(&headers)
        };
        assert_eq!(
            named(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Chrome · Windows"
        );
        assert_eq!(
            named(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
            ),
            "Safari · macOS"
        );
        assert_eq!(
            named("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"),
            "Firefox · Linux"
        );
        assert_eq!(
            named(
                "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131 Safari/537.36 Edg/131"
            ),
            "Edge · Windows"
        );
        assert_eq!(named("curl/8.7.1"), "?");
        assert_eq!(browser_name(&HeaderMap::new()), "?");
    }
}
