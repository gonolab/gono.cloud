//! Self-service accounts on the web (`plan/third-party-sign-in-design.md`, 4.5 and 4.6): signing
//! up with a Google or GitHub identity bound to no account, and undoing the deletion an account
//! without a password asked for.
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /login/signup`, `POST /login/signup` | Create an account with the identity waiting in this browser, while its provider's `allow_signup` is on. |
//! | `POST /login/restore` | Undo the deletion of the account that just signed in during its cooling-off period, and sign it in. |
//!
//! - **Accounts made here** have a generated username (the provider's prefix, `gg` or `gh`, and
//!   8 random lower-case letters and digits; never a retired one), which the user may change here
//!   and later on the account page until the account has an app password or a device; the
//!   provider's name as the display name; no web login password; and no service, like every
//!   account: an administrator turns them on. `created_via` names the provider, and the audit
//!   log records `account.created` and `identity.bound` with `how: "signup"`.
//! - **The terms box** shows only when `[sign_in] terms_url` is set, and must be ticked then.
//! - **Limits.** A client network signs up [`users::SIGNUPS_PER_NET_PER_DAY`] accounts a day at
//!   most, and the server [`users::SIGNUPS_PER_DAY`].
//! - **Undoing a deletion.** A sign-in with a bound identity of an account that waits for its
//!   deletion opens no session: it leads to one page, which says when the account goes and
//!   offers to undo it. The page's form is bound to the browser by the [`RESTORE_COOKIE`] (in
//!   memory for 10 minutes), so only the browser that just signed in can undo it.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, PoisonError},
};

use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use gono_server_core::{
    Username,
    audit::Actor,
    db,
    identities::{self, Holder, Provider},
    secret,
    users::{self, SignedUp},
};
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use crate::{
    app::AppState,
    client_ip::client_ip,
    i18n::fill,
    oauth,
    site::{self, FILES_HOME},
    web::{self, CSRF_COOKIE, Chrome, Message, PENDING_COOKIE, page},
};

/// Where the sign-up page lives.
pub const SIGNUP_PATH: &str = "/login/signup";

/// Where a deletion is undone.
pub const RESTORE_PATH: &str = "/login/restore";

/// Cookie binding the page that undoes a deletion to the browser that signed in.
pub const RESTORE_COOKIE: &str = "gono_restore";

/// How long that page waits, in seconds.
const RESTORE_TTL_SECS: i64 = 10 * 60;

/// Accounts waiting to be restored at most.
const MAX_RESTORES: usize = 1000;

/// The accounts that signed in during their cooling-off period, by the digest of the browser's
/// [`RESTORE_COOKIE`]: the account and until when.
#[derive(Debug, Default)]
pub struct Restores(Mutex<HashMap<[u8; 32], (i64, i64)>>);

impl Restores {
    fn put(&self, token: &str, user_id: i64, now: i64) {
        let mut restores = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        restores.retain(|_, (_, until)| *until > now);
        if restores.len() >= MAX_RESTORES {
            restores.clear();
        }
        restores.insert(secret::digest(token), (user_id, now + RESTORE_TTL_SECS));
    }

    fn take(&self, token: &str, now: i64) -> Option<i64> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&secret::digest(token))
            .filter(|(_, until)| *until > now)
            .map(|(user_id, _)| user_id)
    }
}

/// Whether an identity of `provider` bound to no account may create one on the web.
pub fn offered(state: &AppState, provider: Provider) -> bool {
    state.files.is_some()
        && state
            .oauth
            .as_ref()
            .and_then(|oauth| oauth.provider(provider))
            .is_some_and(|configured| configured.allow_signup)
}

/// `templates/signup.html`.
#[derive(Template)]
#[template(path = "signup.html")]
struct SignupPage {
    chrome: Chrome,
    csrf: String,
    lead: String,
    username: String,
    display_name: String,
    next: String,
    /// The terms to accept, when the server has them.
    terms: Option<String>,
    error: Option<String>,
}

/// `templates/restore.html`.
#[derive(Template)]
#[template(path = "restore.html")]
struct RestorePage {
    chrome: Chrome,
    csrf: String,
    lead: String,
}

page!(SignupPage, RestorePage);

#[derive(Deserialize)]
pub struct NextQuery {
    #[serde(default)]
    next: String,
}

/// The identity waiting in this browser, if its provider lets it sign up, and its token.
async fn waiting(state: &AppState, headers: &HeaderMap) -> Option<(identities::Pending, String)> {
    let token = web::cookie(headers, &state.web.cookie_name(PENDING_COOKIE))
        .filter(|value| identities::is_token(value))?;
    let pending = identities::pending(&state.db, Holder::Web, &token, db::unix_now())
        .await
        .ok()
        .flatten()?;
    offered(state, pending.claims.provider).then_some((pending, token))
}

/// Renders the sign-up form.
#[allow(clippy::too_many_arguments)]
fn form(
    state: &AppState,
    headers: &HeaderMap,
    pending: &identities::Pending,
    username: &str,
    display_name: &str,
    next: &str,
    status: StatusCode,
    error: Option<String>,
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let provider = pending.claims.provider;
    let lead = fill(t.signup_lead, &[provider.name(), &pending.claims.label]);
    let page = SignupPage {
        csrf,
        lead,
        username: username.to_owned(),
        display_name: display_name.to_owned(),
        next: next.to_owned(),
        terms: state.terms_url.as_ref().map(ToString::to_string),
        error,
        chrome,
    };
    let mut response = web::render(status, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

/// The local page `next` names, the file UI otherwise.
fn local_next(next: &str) -> String {
    site::local_path(next)
        .filter(|next| *next != "/login")
        .unwrap_or(FILES_HOME)
        .to_owned()
}

/// `GET /login/signup`.
pub async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = local_next(&query.next);
    let Some((pending, _)) = waiting(&state, &headers).await else {
        return web::see_other(&oauth::sign_in_page(&state, &next), &[]);
    };
    let via = pending.claims.provider.created_via();
    let username = users::generated_username(via);
    let display_name = pending
        .claims
        .name
        .clone()
        .unwrap_or_else(|| username.to_string());
    form(
        &state,
        &headers,
        &pending,
        username.as_str(),
        &display_name,
        &next,
        StatusCode::OK,
        None,
    )
}

#[derive(Deserialize)]
pub struct SignupForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    terms: Option<String>,
    #[serde(default)]
    next: String,
}

/// `POST /login/signup`.
pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form_data): Form<SignupForm>,
) -> Response {
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    let next = local_next(&form_data.next);
    let Some((pending, token)) = waiting(&state, &headers).await else {
        return web::see_other(&oauth::sign_in_page(&state, &next), &[]);
    };
    let t = Chrome::for_request(&headers).t;
    let again = |status: StatusCode, error: &str| {
        form(
            &state,
            &headers,
            &pending,
            form_data.username.trim(),
            form_data.display_name.trim(),
            &next,
            status,
            Some(error.to_owned()),
        )
    };
    if !state.web.check_login_csrf(&headers, &form_data.csrf) {
        return again(StatusCode::FORBIDDEN, t.form_expired_sign_in);
    }
    let Ok(username) = Username::new(form_data.username.trim()) else {
        return again(StatusCode::UNPROCESSABLE_ENTITY, t.err_username);
    };
    if users::validate_display_name(&form_data.display_name).is_err() {
        return again(StatusCode::UNPROCESSABLE_ENTITY, t.err_display_name);
    }
    let terms = state.terms_url.as_ref().map(ToString::to_string);
    if terms.is_some() && form_data.terms.is_none() {
        return again(StatusCode::UNPROCESSABLE_ENTITY, t.signup_terms_needed);
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let layout = state.dav.fs().layout().clone();
    let created = users::sign_up(
        &state.db,
        &pending.claims,
        &username,
        &form_data.display_name,
        terms.as_deref(),
        Some(client),
        db::unix_now(),
        |id| layout.create_user(id),
    )
    .await;
    let user = match created {
        Ok(SignedUp::Created(user, _)) => user,
        Ok(SignedUp::UsernameTaken) => {
            return again(
                StatusCode::CONFLICT,
                &fill(t.err_user_exists, &[username.as_str()]),
            );
        }
        Ok(SignedUp::AlreadyBound) => {
            return web::see_other(&oauth::sign_in_page(&state, &next), &[]);
        }
        Ok(SignedUp::Limited) => {
            tracing::warn!(%client, "sign-up refused: the daily cap is reached");
            return again(StatusCode::TOO_MANY_REQUESTS, t.signup_limited);
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot create an account by sign-up");
            return web::unavailable(Chrome::for_request(&headers));
        }
    };
    if let Err(err) = identities::end_pending(&state.db, Holder::Web, &token).await {
        tracing::warn!(error = %err, "cannot forget a pending identity");
    }
    tracing::info!(%client, user = %user.username, via = user.created_via.as_str(), "account created by sign-up");
    let provider = pending.claims.provider;
    let Some(session) = state.web.open_session_with(client, &user, provider).await else {
        return web::unavailable(Chrome::for_request(&headers));
    };
    web::see_other(
        &format!("{}?done=signed-up", crate::files::account::OVERVIEW),
        &[
            state.web.session_cookie(&session),
            state.web.removal_cookie(CSRF_COOKIE),
            state.web.removal_cookie(PENDING_COOKIE),
        ],
    )
}

/// The page of a sign-in of account `user_id`, which waits for its deletion `until`: when it
/// goes, and the form that undoes it, bound to this browser.
pub fn deletion_pending(
    state: &AppState,
    headers: &HeaderMap,
    user_id: i64,
    until: i64,
) -> Response {
    let token = secret::random_token(43).expose_secret().to_owned();
    let now = db::unix_now();
    state.restores.put(&token, user_id, now);
    let (csrf, csrf_cookie) = state.web.login_csrf(headers);
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let when = crate::files::view::when(chrome.lang, now, until).0;
    let page = RestorePage {
        csrf,
        lead: fill(t.deletion_pending_lead, &[&when]),
        chrome,
    };
    let mut response = web::render(StatusCode::FORBIDDEN, &page);
    let headers = response.headers_mut();
    headers.append(header::SET_COOKIE, csrf_cookie);
    headers.append(header::SET_COOKIE, state.web.restore_cookie(&token));
    response
}

#[derive(Deserialize)]
pub struct RestoreForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /login/restore`.
pub async fn restore(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form_data): Form<RestoreForm>,
) -> Response {
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    if !state.web.check_login_csrf(&headers, &form_data.csrf) {
        return site::blocked(&headers, |t| t.form_expired_sign_in);
    }
    let now = db::unix_now();
    let user_id = web::cookie(&headers, &state.web.cookie_name(RESTORE_COOKIE))
        .and_then(|token| state.restores.take(&token, now));
    let chrome = Chrome::for_request(&headers);
    let Some(user_id) = user_id else {
        let t = chrome.t;
        let mut page = Message::new(
            chrome,
            t.unbound_expired,
            t.unbound_expired,
            t.restore_expired,
        );
        page.link = Some(("/login".to_owned(), t.oauth_back.to_owned()));
        return page.respond(StatusCode::NOT_FOUND);
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match users::cancel_deletion(&state.db, user_id, Actor::User, Some(client), now).await {
        Ok(true) => {}
        Ok(false) => {
            return web::see_other("/login", &[state.web.removal_cookie(RESTORE_COOKIE)]);
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot undo a deletion");
            return web::unavailable(chrome);
        }
    }
    let user = match users::by_id(&state.db, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return web::see_other("/login", &[]),
        Err(err) => {
            tracing::error!(error = %err, "cannot read an account");
            return web::unavailable(chrome);
        }
    };
    tracing::info!(%client, user = %user.username, "deletion undone by its user");
    if let Some(connect) = &state.connect {
        connect.poke();
    }
    let Some(session) = state.web.open_session(client, &user).await else {
        return web::unavailable(chrome);
    };
    web::see_other(
        &format!("{}?done=restored", crate::files::account::OVERVIEW),
        &[
            state.web.session_cookie(&session),
            state.web.removal_cookie(RESTORE_COOKIE),
            state.web.removal_cookie(CSRF_COOKIE),
        ],
    )
}
