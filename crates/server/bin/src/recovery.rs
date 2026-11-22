//! Resetting a forgotten web login password with a code mailed to the account's email address
//! (`gono_server_core::email`). The pages exist while the web file UI is on and mail can be sent
//! (`[smtp]`); otherwise they answer `404` and the sign-in page has no link to them.
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /login/forgot` | The form: username or email address. |
//! | `POST /login/forgot` | Sends a reset code to the account's address, if it has one, and answers with the reset form. |
//! | `GET /login/reset` | The reset form: username or email address, the code and the new password twice. |
//! | `POST /login/reset` | Resets the password and leads to `/login`, or shows the form again. |
//!
//! # Nothing to enumerate
//!
//! Whoever asks for a code gets the same page, "if this account has an email address, a code was
//! sent to it", whether the account exists, has an address, is disabled or has used up its codes
//! for the day. The answer does not wait for anything account-dependent either: the lookup, the
//! code and the mail happen on a task of their own after the page is answered. Requests are
//! limited per client ([`Web::allow_reset_request`](crate::web::Web::allow_reset_request)) and,
//! through the limits of codes, per account.
//!
//! A reset is checked by [`Web::reset_password`](crate::web::Web::reset_password): the
//! failed-attempt limiter of the sign-in pages, the same work and the same answer for every
//! failure, and at most a few tries per code. A reset sets the password, ends every browser
//! session and pending sign-in of the account, is recorded in the audit log (`password.reset`)
//! and mailed to the address. It leaves two-step verification alone: the next sign-in of an
//! account that has it still asks for its code. Disabled accounts cannot reset.
//!
//! The forms are those of the sign-in page: the double-submit CSRF token of
//! [`Web::login_csrf`](crate::web::Web::login_csrf), and only from this origin.

use std::{net::SocketAddr, sync::Arc};

use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    db,
    email::{self, NewCode, Purpose},
    password,
};
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    admin::core_message,
    app::AppState,
    client_ip::client_ip,
    i18n::{Lang, fill},
    mail::{self, Mailer},
    site::blocked,
    web::{self, Chrome, Message, PasswordReset, page},
};

/// `forgot.html`.
#[derive(Template)]
#[template(path = "forgot.html")]
struct ForgotPage {
    chrome: Chrome,
    csrf: String,
    login: String,
    error: Option<String>,
}

/// `reset.html`.
#[derive(Template)]
#[template(path = "reset.html")]
struct ResetPage {
    chrome: Chrome,
    csrf: String,
    login: String,
    notice: Option<&'static str>,
    error: Option<String>,
}

page!(ForgotPage, ResetPage);

/// The mailer, while the pages exist.
fn mailer(state: &AppState) -> Option<Arc<dyn Mailer>> {
    state.files.as_ref()?;
    state.mailer.clone()
}

fn forgot_form(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    login: &str,
    error: Option<String>,
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let page = ForgotPage {
        chrome: Chrome::for_request(headers),
        csrf,
        login: login.to_owned(),
        error,
    };
    let mut response = web::render(status, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn reset_form(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    login: &str,
    message: (Option<&'static str>, Option<String>),
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let page = ResetPage {
        chrome: Chrome::for_request(headers),
        csrf,
        login: login.to_owned(),
        notice: message.0,
        error: message.1,
    };
    let mut response = web::render(status, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

/// `GET /login/forgot`.
pub async fn forgot_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if mailer(&state).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    forgot_form(&state, &headers, StatusCode::OK, "", None)
}

#[derive(Deserialize)]
pub struct ForgotForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    login: String,
}

/// `POST /login/forgot`.
pub async fn forgot(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<ForgotForm>,
) -> Response {
    let Some(mailer) = mailer(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !state.web.same_origin(&headers) {
        return blocked(&headers, |t| t.from_other_site);
    }
    let chrome = Chrome::for_request(&headers);
    let t = chrome.t;
    let login = form.login.trim().to_owned();
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        let error = Some(t.form_expired_sign_in.to_owned());
        return forgot_form(&state, &headers, StatusCode::FORBIDDEN, &login, error);
    }
    if login.is_empty() || login.len() > email::MAX_ADDRESS_BYTES {
        let error = Some(t.err_forgot_login.to_owned());
        return forgot_form(
            &state,
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            &login,
            error,
        );
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(wait) = state.web.allow_reset_request(client) {
        return too_many_requests(chrome, wait);
    }
    // Everything that depends on the account happens on a task the answer does not wait for.
    let base_url = state.base_url.clone();
    let pool = state.db.clone();
    let lang = chrome.lang;
    let named = login.clone();
    tokio::spawn(async move {
        send_reset_code(&pool, &mailer, &base_url, lang, client, &named).await;
    });
    reset_form(
        &state,
        &headers,
        StatusCode::OK,
        &login,
        (Some(t.forgot_sent), None),
    )
}

/// Mails a reset code to the address of the account `login` names, if it has one and may still
/// get a code today. Nothing of it reaches the page.
async fn send_reset_code(
    pool: &db::Pool,
    mailer: &Arc<dyn Mailer>,
    base_url: &url::Url,
    lang: Lang,
    client: std::net::IpAddr,
    login: &str,
) {
    let account = match email::find_account(pool, login).await {
        Ok(account) => account,
        Err(err) => {
            tracing::error!(error = %err, "password reset lookup failed");
            return;
        }
    };
    let Some((user, Some(address))) = account.filter(|(user, _)| user.enabled) else {
        tracing::info!(%client, "no password reset code sent: no enabled account with an address");
        return;
    };
    let now = db::unix_now();
    let code = match email::send_code(pool, user.id, Purpose::Reset, &address, now).await {
        Ok(NewCode::Code(code)) => code,
        Ok(NewCode::TooSoon(_) | NewCode::DailyLimit) => {
            tracing::info!(%client, user = %user.username, "no password reset code sent: the account's limit is reached");
            return;
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot make a password reset code");
            return;
        }
    };
    let message = mail::reset_code(lang, base_url, user.username.as_str(), &code.code);
    match mailer.send(&address, &message.subject, &message.text).await {
        Ok(()) => {
            tracing::info!(%client, user = %user.username, "password reset code sent");
        }
        Err(err) => {
            tracing::warn!(error = %err, user = %user.username, "cannot send a password reset code");
            if let Err(err) = email::discard(pool, code.id, db::unix_now()).await {
                tracing::warn!(error = %err, "cannot end an unsent code");
            }
        }
    }
}

/// The page shown while a client asked for too many codes, with `Retry-After`.
fn too_many_requests(chrome: Chrome, wait: std::time::Duration) -> Response {
    let t = chrome.t;
    let seconds = wait.as_secs().max(1).to_string();
    let mut response = Message::new(
        chrome,
        t.too_many_attempts,
        t.too_many_attempts,
        &fill(t.too_many_requests_lead, &[&seconds]),
    )
    .respond(StatusCode::TOO_MANY_REQUESTS);
    if let Ok(value) = seconds.parse() {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// `GET /login/reset`.
pub async fn reset_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if mailer(&state).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    reset_form(&state, &headers, StatusCode::OK, "", (None, None))
}

#[derive(Deserialize)]
pub struct ResetForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    login: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
}

/// `POST /login/reset`.
pub async fn reset(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Response {
    let Some(mailer) = mailer(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !state.web.same_origin(&headers) {
        return blocked(&headers, |t| t.from_other_site);
    }
    let chrome = Chrome::for_request(&headers);
    let t = chrome.t;
    let login = form.login.trim().to_owned();
    let refuse = |status: StatusCode, error: String| {
        reset_form(&state, &headers, status, &login, (None, Some(error)))
    };
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        return refuse(StatusCode::FORBIDDEN, t.form_expired_sign_in.to_owned());
    }
    // What does not depend on the account is checked first, as on the account page.
    if form.password != form.password_repeat {
        return refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            t.err_passwords_differ.to_owned(),
        );
    }
    let new = SecretString::from(form.password);
    if let Err(err) = password::check_policy(&new) {
        return refuse(StatusCode::UNPROCESSABLE_ENTITY, core_message(t, &err));
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match state
        .web
        .reset_password(client, &login, &form.code, new)
        .await
    {
        PasswordReset::Done { username, email } => {
            let message = mail::password_reset(chrome.lang, &state.base_url, &username);
            mail::send_later(&mailer, email, message, "a password reset");
            web::see_other("/login?done=password-reset", &[])
        }
        PasswordReset::Wrong => refuse(StatusCode::FORBIDDEN, t.reset_wrong.to_owned()),
        PasswordReset::RateLimited(wait) => web::too_many_attempts(chrome, wait),
        PasswordReset::Unavailable => web::unavailable(chrome),
    }
}
