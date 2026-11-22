//! The WeChat panel of the account page's overview: whether the account has its WeChat bound
//! for the mini program of `[wechat]` (`gono_server_core::wechat`), and the forms that bind
//! and unbind it.
//!
//! | Request | Action |
//! |---|---|
//! | `POST /account/wechat` | Make a bind ticket (needs the web login password). The overview then shows its QR code until it expires. |
//! | `POST /account/wechat/unbind` | Unbind the WeChat identity and sign the mini program out (needs the web login password). |
//!
//! A ticket binds whichever WeChat user scans it (from a phone, by scanning, see
//! [`crate::wechat`]), so it is a credential of the account: making one needs the current
//! password (checked through the failed-attempt limiter of the sign-in pages), a new one ends
//! the earlier one, and it is valid for ten minutes and once. Only its digest is stored; the
//! ticket itself waits in memory for the browser session that made it, so that the overview
//! can show its QR code again on reload. The QR code carries `<wechat.qr_url_prefix>bind/<ticket>`.
//!
//! Unbinding ends every mini program session of the account. Neither changes `updated_at`:
//! WeChat is not a credential of the web pages. Without `[wechat]` the panel says that the
//! server does not offer it, and the forms answer `404`.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Form,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    db,
    wechat::{self, NewTicket},
};
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use super::{Tab, check_password, form_visitor, internal, show_error};
use crate::{
    app::AppState,
    client_ip::client_ip,
    files::{Visitor, view::when},
    i18n::{Text, fill},
    wechat::WeChat,
};

/// What the overview shows of the account's WeChat.
#[derive(Debug, Clone, Default)]
pub struct WeChatView {
    /// This server offers the mini program: the forms are offered.
    pub available: bool,
    /// "Bound since …", while the account has its WeChat bound.
    pub bound: Option<String>,
    /// The QR code of the ticket this browser session made, an SVG generated here.
    pub qr: Option<String>,
    /// "Scan this code … before …", with the QR code.
    pub scan: String,
}

/// The panel of the visitor's account.
pub(super) async fn view(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
) -> gono_server_core::Result<WeChatView> {
    let Some(mini) = &state.wechat else {
        return Ok(WeChatView::default());
    };
    let t = visitor.t();
    let lang = visitor.lang();
    let user = &visitor.user;
    if let Some(identity) = wechat::identity(&state.db, user.user_id, mini.app_id()).await? {
        mini.forget(user);
        return Ok(WeChatView {
            available: true,
            bound: Some(fill(
                t.wechat_bound,
                &[&when(lang, now, identity.created_at).0],
            )),
            ..WeChatView::default()
        });
    }
    let mut view = WeChatView {
        available: true,
        ..WeChatView::default()
    };
    if let Some((ticket, until)) = mini.shown(user, now) {
        // A ticket that was used, or replaced from another browser, shows nothing.
        if wechat::ticket_is_live(&state.db, user.user_id, ticket.expose_secret(), now).await? {
            view.qr = crate::qr::svg(&mini.bind_link(ticket.expose_secret()));
            view.scan = fill(t.wechat_scan, &[&when(lang, now, until).0]);
        } else {
            mini.forget(user);
        }
    }
    Ok(view)
}

/// The notice of `?done=<done>` after one of the panel's forms.
pub(super) fn notice(t: &'static Text, done: &str) -> Option<&'static str> {
    Some(match done {
        "wechat-ticket" => t.notice_wechat_ticket,
        "wechat-unbound" => t.notice_wechat_unbound,
        _ => return None,
    })
}

/// The visitor of a form of the panel and the mini program, or the page to answer with: `404`
/// while this server does not offer the mini program.
async fn panel_visitor(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    csrf: &str,
) -> Result<(Visitor, Arc<WeChat>), Box<Response>> {
    let visitor = form_visitor(state, headers, uri, csrf).await?;
    match state.wechat.clone() {
        Some(mini) => Ok((visitor, mini)),
        None => Err(Box::new(StatusCode::NOT_FOUND.into_response())),
    }
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
}

/// `POST /account/wechat`: makes a bind ticket, whose QR code the overview shows.
pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<PasswordForm>,
) -> Response {
    let (visitor, mini) = match panel_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = check_password(&state, &visitor, client, form.password).await {
        return *response;
    }
    let user = &visitor.user;
    match wechat::create_ticket(&state.db, user.user_id, mini.app_id(), db::unix_now()).await {
        Ok(NewTicket::Ticket(ticket)) => {
            mini.show(user, ticket.ticket, ticket.expires_at);
            tracing::info!(%client, user = %user.username, "WeChat bind ticket made");
            Tab::Overview.done("wechat-ticket")
        }
        Ok(NewTicket::Bound) => {
            let error = visitor.t().err_wechat_bound.to_owned();
            show_error(&state, &visitor, Tab::Overview, error).await
        }
        Err(err) => internal(&visitor, "WeChat bind ticket", &err),
    }
}

/// `POST /account/wechat/unbind`: unbinds the account's WeChat.
pub async fn unbind(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<PasswordForm>,
) -> Response {
    let (visitor, mini) = match panel_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = check_password(&state, &visitor, client, form.password).await {
        return *response;
    }
    let user = &visitor.user;
    match wechat::unbind(
        &state.db,
        user.user_id,
        mini.app_id(),
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(true) => {
            tracing::info!(%client, user = %user.username, "WeChat unbound from an account");
            Tab::Overview.done("wechat-unbound")
        }
        Ok(false) => Tab::Overview.back(),
        Err(err) => internal(&visitor, "unbind WeChat", &err),
    }
}
