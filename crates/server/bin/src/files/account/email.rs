//! The email panel of the account page's overview: the account's address
//! (`gono_server_core::email`), and the forms that add, replace and remove it.
//!
//! | Request | Action |
//! |---|---|
//! | `POST /account/email` | Mail a code to a new address (needs confirming it is you). The overview then shows the form for the code. |
//! | `POST /account/email/confirm` | Make the address of the code the account's. |
//! | `POST /account/email/remove` | Remove the address (needs confirming it is you). |
//!
//! The address is a recovery credential: whoever has it can reset the password. Adding,
//! replacing and removing it therefore need confirming it is you (the current password, checked
//! through the failed-attempt limiter of the sign-in pages, or a recent confirmation, see
//! [`super::confirmation`]), the new address must receive its code, and the
//! address it replaces or that is removed gets a notice. A change ends the account's sign-ins
//! waiting for their second step and its codes still waiting, the reset codes sent to the old
//! address among them.
//!
//! Whether another account has the address is found out only when the code is entered, so that
//! only the owner of an address can learn it; the error does not say which account. Without a
//! mailer (`[smtp]` off), or without the key the codes are keyed with (`two_factor.key_file`,
//! see [`AppState::email`]), the panel says so and offers no form, and the forms answer `404`.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Form,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    db,
    email::{self, Bind, CodeFor, Key, NewCode, Purpose},
};
use serde::Deserialize;

use super::{Tab, confirm_you, form_visitor, internal, show_error};
use crate::{
    app::AppState,
    client_ip::client_ip,
    files::{Visitor, view::when},
    i18n::{Text, fill},
    mail::{self, Mailer},
};

/// What the overview shows of the account's address.
#[derive(Debug, Clone, Default)]
pub struct EmailView {
    /// This server can send mail: the forms are offered.
    pub available: bool,
    /// The account's address.
    pub address: Option<String>,
    /// "A code was sent to … Enter it here before …", while a bind code waits.
    pub waiting: Option<String>,
}

/// The panel of the visitor's account.
pub(super) async fn view(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
) -> gono_server_core::Result<EmailView> {
    let user_id = visitor.user.user_id;
    let address = email::address(&state.db, user_id).await?;
    let available = state.email().is_some();
    let waiting = if available {
        email::pending(&state.db, user_id, Purpose::Bind, now)
            .await?
            .map(|(address, until)| {
                fill(
                    visitor.t().email_waiting,
                    &[&address, &when(visitor.lang(), now, until).0],
                )
            })
    } else {
        None
    };
    Ok(EmailView {
        available,
        address,
        waiting,
    })
}

/// The notice of `?done=<done>` after one of the panel's forms.
pub(super) fn notice(t: &'static Text, done: &str) -> Option<&'static str> {
    Some(match done {
        "email-sent" => t.notice_email_sent,
        "email-bound" => t.notice_email_bound,
        "email-removed" => t.notice_email_removed,
        _ => return None,
    })
}

/// The visitor of a form of the panel, the mailer and the key of the codes, or the page to
/// answer with: `404` while this server cannot send codes ([`AppState::email`]).
async fn panel_visitor(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    csrf: &str,
) -> Result<(Visitor, Arc<dyn Mailer>, Key), Box<Response>> {
    let visitor = form_visitor(state, headers, uri, csrf).await?;
    match state.email() {
        Some((mailer, key)) => Ok((visitor, mailer, key)),
        None => Err(Box::new(StatusCode::NOT_FOUND.into_response())),
    }
}

#[derive(Deserialize)]
pub struct StartForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

/// `POST /account/email`: mails a code to a new address.
pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<StartForm>,
) -> Response {
    let (visitor, mailer, key) = match panel_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let fail = |message: String| show_error(&state, &visitor, Tab::Overview, message);
    let Some(address) = email::normalize_address(&form.email) else {
        return fail(t.err_email_invalid.to_owned()).await;
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = confirm_you(&state, &visitor, client, form.password).await {
        return *response;
    }
    let user_id = visitor.user.user_id;
    match email::address(&state.db, user_id).await {
        Ok(current) if current.as_deref() == Some(address.as_str()) => {
            return fail(t.err_email_same.to_owned()).await;
        }
        Ok(_) => {}
        Err(err) => return internal(&visitor, "email address", &err),
    }
    let now = db::unix_now();
    let code = match email::send_code(&state.db, &key, user_id, CodeFor::Bind, &address, now).await
    {
        Ok(NewCode::Code(code)) => code,
        Ok(NewCode::TooSoon(wait)) => {
            return fail(fill(t.err_email_too_soon, &[&wait.to_string()])).await;
        }
        Ok(NewCode::DailyLimit) => return fail(t.err_email_daily.to_owned()).await,
        Err(err) => return internal(&visitor, "email code", &err),
    };
    // The user waits for this one: whether the mail went out is what the next page says.
    let message = mail::bind_code(visitor.lang(), &state.base_url, &code.code);
    if let Err(err) = mailer.send(&address, &message.subject, &message.text).await {
        tracing::warn!(error = %err, user = %visitor.user.username, "cannot send the code of an email address");
        if let Err(err) = email::discard(&state.db, code.id, db::unix_now()).await {
            tracing::warn!(error = %err, "cannot end an unsent code");
        }
        return fail(t.err_email_send.to_owned()).await;
    }
    tracing::info!(%client, user = %visitor.user.username, "code sent to a new email address");
    Tab::Overview.done("email-sent")
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    code: String,
}

/// `POST /account/email/confirm`: makes the address of the code the account's.
pub async fn confirm(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let (visitor, mailer, key) = match panel_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let fail =
        |message: &'static str| show_error(&state, &visitor, Tab::Overview, message.to_owned());
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let user_id = visitor.user.user_id;
    // A code that is not six digits is not tried: it cannot be right.
    let Some(code) = email::parse_code(&form.code) else {
        return fail(t.err_email_code).await;
    };
    match email::bind(
        &state.db,
        &key,
        user_id,
        &code,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(Bind::Bound { email, previous }) => {
            // A recovery credential changed.
            state.web.end_pending_sign_ins(user_id);
            tracing::info!(%client, user = %visitor.user.username, "email address bound");
            if let Some(previous) = previous.filter(|previous| *previous != email) {
                let message = mail::address_replaced(
                    visitor.lang(),
                    &state.base_url,
                    visitor.user.username.as_str(),
                );
                mail::send_later(&mailer, previous, message, "a replaced email address");
            }
            Tab::Overview.done("email-bound")
        }
        Ok(Bind::Wrong(left)) if left > 0 => fail(t.err_email_code).await,
        Ok(Bind::Wrong(_) | Bind::Expired) => fail(t.err_email_expired).await,
        Ok(Bind::Taken) => fail(t.err_email_taken).await,
        Err(err) => internal(&visitor, "bind an email address", &err),
    }
}

#[derive(Deserialize)]
pub struct RemoveForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
}

/// `POST /account/email/remove`: removes the account's address.
pub async fn remove(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<RemoveForm>,
) -> Response {
    let (visitor, mailer, _) = match panel_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = confirm_you(&state, &visitor, client, form.password).await {
        return *response;
    }
    let user_id = visitor.user.user_id;
    match email::remove(&state.db, user_id, Some(client), db::unix_now()).await {
        Ok(Some(previous)) => {
            state.web.end_pending_sign_ins(user_id);
            tracing::info!(%client, user = %visitor.user.username, "email address removed");
            let message = mail::address_removed(
                visitor.lang(),
                &state.base_url,
                visitor.user.username.as_str(),
            );
            mail::send_later(&mailer, previous, message, "a removed email address");
            Tab::Overview.done("email-removed")
        }
        Ok(None) => Tab::Overview.back(),
        Err(err) => internal(&visitor, "remove an email address", &err),
    }
}
