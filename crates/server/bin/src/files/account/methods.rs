//! The ways to sign in (登录方式) on the account page's overview: the web login password and the
//! third-party identities of the account (`gono_server_core::identities`), with the pages that
//! bind and unbind them, and the page that confirms it is the account's user.
//!
//! | Request | Page or action |
//! |---|---|
//! | `GET /account/identities/wechat/bind`, `POST` the same | Confirm, then make a bind ticket of the mini program of `[wechat]`. The overview then shows its QR code until it expires. |
//! | `GET /account/identities/<provider>/unbind`, `POST` the same | Say what unbinding does, confirm, then unbind the identity. For WeChat it signs the mini program out. |
//! | `GET /account/confirm`, `POST /account/confirm` | Confirm it is you, then go on to `next` (a page of the account). |
//!
//! **Confirming it is you** (`plan/third-party-sign-in-design.md`, 3.5). Every form that
//! changes how the account signs in or is recovered asks for it: binding and unbinding an
//! identity, adding, replacing and removing the email address, and turning two-step
//! verification on and off or renewing its recovery codes. The web login password typed into
//! the form (checked through the failed-attempt limiter of the sign-in pages) confirms it; so
//! does a confirmation of the same browser session less than [`web::CONFIRM_TTL_SECS`] ago,
//! after which the forms need no password. An account without a password confirms with a
//! fresh sign-in of one of its identities.
//!
//! **The last way in.** An account keeps its web login password or one identity at least:
//! unbinding the last identity of an account without a password is refused (`last_sign_in`).
//!
//! **WeChat.** A bind ticket binds whichever WeChat user scans it (from a phone, by scanning,
//! see [`crate::wechat`]), so it is a credential of the account: a new one ends the earlier
//! one, and it is valid for ten minutes and once. Only its digest is stored; the ticket itself
//! waits in memory for the browser session that made it, so that the overview can show its QR
//! code again on reload. The QR code carries `<wechat.qr_url_prefix>bind/<ticket>`. Unbinding
//! ends every mini program session of the identity. Neither changes `updated_at`. Without
//! `[wechat]` the panel says that the server does not offer it, and its pages answer `404`.

use std::{net::SocketAddr, sync::Arc};

use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    audit::Actor,
    db,
    identities::{self, GITHUB_REALM, GOOGLE_REALM, How, Provider, Unbound, Which},
    two_factor,
    wechat::{self, NewTicket},
};
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use super::{
    ACCOUNT, Confirmation, OVERVIEW, Tab, account_visitor, confirmation, form_visitor, internal,
    next_path, show_error,
};
use crate::{
    app::AppState,
    client_ip::client_ip,
    files::{Visitor, view::when},
    i18n::{Text, fill},
    web::{self, Chrome, Nav, page},
    wechat::WeChat,
};

/// One way to sign in, as the panel lists it.
#[derive(Debug, Clone)]
pub struct MethodRow {
    /// The provider's key, for the links.
    pub key: &'static str,
    /// Its name: 微信, Google, GitHub.
    pub name: &'static str,
    /// What identifies the account's identity there ('' for WeChat).
    pub label: String,
    /// "bound since …", while bound.
    pub bound: Option<String>,
    /// The server offers it: binding is offered while unbound.
    pub offered: bool,
    /// Why it cannot be bound here, when the server does not offer it.
    pub unavailable: Option<&'static str>,
}

/// What the overview shows of the ways to sign in.
#[derive(Debug, Clone, Default)]
pub struct MethodsView {
    /// The account has a web login password.
    pub has_password: bool,
    /// The providers.
    pub rows: Vec<MethodRow>,
    /// Say that the providers ask for no second step: the account has two-step verification.
    pub no_two_step: bool,
    /// The QR code of the WeChat bind ticket this browser session made, an SVG generated here.
    pub qr: Option<String>,
    /// "Scan this code … before …", with the QR code.
    pub scan: String,
}

/// The realm the server offers `provider` in, if it offers it: the AppID of the mini program
/// for WeChat.
pub(crate) fn offered_realm(state: &AppState, provider: Provider) -> Option<String> {
    match provider {
        Provider::WeChat => state.wechat.as_ref().map(|mini| mini.app_id().to_owned()),
        // Google and GitHub sign-in are not offered yet.
        Provider::Google | Provider::GitHub => None,
    }
}

/// The realm of `provider` whose identity the account page shows and unbinds.
fn shown_realm(state: &AppState, provider: Provider) -> Option<String> {
    match provider {
        Provider::WeChat => offered_realm(state, provider),
        Provider::Google => Some(GOOGLE_REALM.to_owned()),
        Provider::GitHub => Some(GITHUB_REALM.to_owned()),
    }
}

/// The name of `provider` on the pages.
pub(crate) fn provider_name(t: &Text, provider: Provider) -> &'static str {
    match provider {
        Provider::WeChat => t.provider_wechat,
        Provider::Google => "Google",
        Provider::GitHub => "GitHub",
    }
}

/// The panel of the visitor's account.
pub(super) async fn view(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
) -> gono_server_core::Result<MethodsView> {
    let t = visitor.t();
    let lang = visitor.lang();
    let user = &visitor.user;
    let bound = identities::list(&state.db, user.user_id).await?;
    let mut view = MethodsView {
        has_password: user.has_password,
        ..MethodsView::default()
    };
    for provider in Provider::ALL {
        let offered = offered_realm(state, provider);
        let realm = shown_realm(state, provider);
        let identity = bound.iter().find(|identity| {
            Some(&identity.realm) == realm.as_ref() && identity.provider == provider
        });
        // Providers the server does not offer are left out, unless the account has an
        // identity of one (it can still unbind it). WeChat says that it is not offered.
        if offered.is_none() && identity.is_none() && provider != Provider::WeChat {
            continue;
        }
        view.rows.push(MethodRow {
            key: provider.as_str(),
            name: provider_name(t, provider),
            label: identity
                .map(|identity| identity.label.clone())
                .unwrap_or_default(),
            bound: identity.map(|identity| {
                fill(
                    t.methods_bound_since,
                    &[&when(lang, now, identity.created_at).0],
                )
            }),
            offered: offered.is_some(),
            unavailable: (offered.is_none() && identity.is_none()).then_some(t.wechat_unavailable),
        });
    }
    view.no_two_step = view
        .rows
        .iter()
        .any(|row| row.offered || row.bound.is_some())
        && two_factor::is_enrolled(&state.db, user.user_id).await?;
    if let Some(mini) = &state.wechat {
        if bound.iter().any(|identity| {
            identity.provider == Provider::WeChat && identity.realm == mini.app_id()
        }) {
            mini.forget(user);
        } else if let Some((ticket, until)) = mini.shown(user, now) {
            // A ticket that was used, or replaced from another browser, shows nothing.
            if wechat::ticket_is_live(&state.db, user.user_id, ticket.expose_secret(), now).await? {
                view.qr = crate::qr::svg(&mini.bind_link(ticket.expose_secret()));
                view.scan = fill(t.wechat_scan, &[&when(lang, now, until).0]);
            } else {
                mini.forget(user);
            }
        }
    }
    Ok(view)
}

/// The notice of `?done=<done>` after one of the panel's pages.
pub(super) fn notice(t: &'static Text, done: &str) -> Option<String> {
    Some(match done {
        "wechat-ticket" => t.notice_wechat_ticket.to_owned(),
        "unbound-wechat" => t.notice_wechat_unbound.to_owned(),
        "confirmed" => t.notice_confirmed.to_owned(),
        done => {
            let provider = Provider::parse(done.strip_prefix("unbound-")?)?;
            fill(t.notice_identity_unbound, &[provider_name(t, provider)])
        }
    })
}

/// `account/identity.html`: a page that confirms it is you before an action, saying what the
/// action does.
#[derive(Template)]
#[template(path = "account/identity.html")]
struct ActionPage {
    chrome: Chrome,
    username: String,
    title: String,
    lead: String,
    /// A second, smaller text.
    note: Option<&'static str>,
    /// Where the form posts.
    action: String,
    button: &'static str,
    danger: bool,
    /// Where to go on, for the confirmation page.
    next: String,
    /// Ask for the web login password: the account has one and the session is not confirmed.
    ask_password: bool,
    /// The session is not confirmed and the account has no password: it confirms with a
    /// sign-in of one of its identities.
    no_password: bool,
    error: Option<String>,
}

page!(ActionPage);

/// What an action page needs besides its texts.
struct Action {
    title: String,
    lead: String,
    note: Option<&'static str>,
    action: String,
    button: &'static str,
    danger: bool,
    next: String,
}

/// Renders the page of `action` for `visitor`, with `error`.
fn action_page(
    state: &AppState,
    visitor: &Visitor,
    action: Action,
    status: StatusCode,
    error: Option<String>,
) -> Response {
    let confirmed = state.web.is_confirmed(&visitor.user);
    let page = ActionPage {
        chrome: visitor.chrome(Nav::Account),
        username: visitor.user.username.to_string(),
        title: action.title,
        lead: action.lead,
        note: action.note,
        action: action.action,
        button: action.button,
        danger: action.danger,
        next: action.next,
        ask_password: !confirmed && visitor.user.has_password,
        no_password: !confirmed && !visitor.user.has_password,
        error,
    };
    web::render(status, &page)
}

/// The provider of a path, offered (or, for unbinding, bound) on this server, with the realm
/// of its identity; `404` otherwise.
fn provider_of(state: &AppState, key: &str) -> Result<(Provider, String), Box<Response>> {
    let not_found = || Box::new(StatusCode::NOT_FOUND.into_response());
    let provider = Provider::parse(key).ok_or_else(not_found)?;
    let realm = shown_realm(state, provider).ok_or_else(not_found)?;
    Ok((provider, realm))
}

/// The page of unbinding `provider`.
fn unbind_action(t: &'static Text, provider: Provider) -> Action {
    Action {
        title: fill(t.unbind_title, &[provider_name(t, provider)]),
        lead: if provider == Provider::WeChat {
            t.unbind_wechat_lead
        } else {
            t.unbind_lead
        }
        .to_owned(),
        note: None,
        action: format!("{ACCOUNT}/identities/{}/unbind", provider.as_str()),
        button: t.unbind_confirm,
        danger: true,
        next: String::new(),
    }
}

/// The page that makes a WeChat bind ticket.
fn wechat_bind_action(t: &'static Text) -> Action {
    Action {
        title: t.wechat_bind_title.to_owned(),
        lead: t.wechat_note.to_owned(),
        note: Some(t.wechat_show_note),
        action: format!("{ACCOUNT}/identities/wechat/bind"),
        button: t.wechat_show,
        danger: false,
        next: String::new(),
    }
}

/// `GET /account/identities/<provider>/unbind`.
pub async fn unbind_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(key): Path<String>,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let (provider, _) = match provider_of(&state, &key) {
        Ok(found) => found,
        Err(response) => return *response,
    };
    action_page(
        &state,
        &visitor,
        unbind_action(visitor.t(), provider),
        StatusCode::OK,
        None,
    )
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    next: String,
}

/// `POST /account/identities/<provider>/unbind`.
pub async fn unbind(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Path(key): Path<String>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let (provider, realm) = match provider_of(&state, &key) {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match confirmation(&state, &visitor, client, form.password).await {
        Confirmation::Confirmed => {}
        Confirmation::Refused(error) => {
            let action = unbind_action(t, provider);
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            return action_page(&state, &visitor, action, status, Some(error.to_owned()));
        }
        Confirmation::Halt(response) => return *response,
    }
    let user = &visitor.user;
    match identities::unbind(
        &state.db,
        user.user_id,
        Which::Realm(provider, &realm),
        How::AccountPage,
        Actor::User,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(Unbound::Done(_)) => {
            tracing::info!(%client, user = %user.username, provider = provider.as_str(), "identity unbound from an account");
            Tab::Overview.done(&format!("unbound-{}", provider.as_str()))
        }
        Ok(Unbound::NotBound) => Tab::Overview.back(),
        Ok(Unbound::LastSignIn) => {
            let action = unbind_action(t, provider);
            let error = Some(t.err_last_sign_in.to_owned());
            action_page(&state, &visitor, action, StatusCode::CONFLICT, error)
        }
        Err(err) => internal(&visitor, "unbind an identity", &err),
    }
}

/// The visitor of a WeChat page and the mini program, or the page to answer with: `404` while
/// this server does not offer the mini program.
fn mini_program(state: &AppState) -> Result<Arc<WeChat>, Box<Response>> {
    state
        .wechat
        .clone()
        .ok_or_else(|| Box::new(StatusCode::NOT_FOUND.into_response()))
}

/// `GET /account/identities/wechat/bind`.
pub async fn wechat_bind_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    if let Err(response) = mini_program(&state) {
        return *response;
    }
    action_page(
        &state,
        &visitor,
        wechat_bind_action(visitor.t()),
        StatusCode::OK,
        None,
    )
}

/// `POST /account/identities/wechat/bind`: makes a bind ticket, whose QR code the overview
/// shows.
pub async fn wechat_bind(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let mini = match mini_program(&state) {
        Ok(mini) => mini,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match confirmation(&state, &visitor, client, form.password).await {
        Confirmation::Confirmed => {}
        Confirmation::Refused(error) => {
            let action = wechat_bind_action(t);
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            return action_page(&state, &visitor, action, status, Some(error.to_owned()));
        }
        Confirmation::Halt(response) => return *response,
    }
    let user = &visitor.user;
    match wechat::create_ticket(&state.db, user.user_id, mini.app_id(), db::unix_now()).await {
        Ok(NewTicket::Ticket(ticket)) => {
            mini.show(user, ticket.ticket, ticket.expires_at);
            tracing::info!(%client, user = %user.username, "WeChat bind ticket made");
            Tab::Overview.done("wechat-ticket")
        }
        Ok(NewTicket::Bound) => {
            let error = t.err_wechat_bound.to_owned();
            show_error(&state, &visitor, Tab::Overview, error).await
        }
        Err(err) => internal(&visitor, "WeChat bind ticket", &err),
    }
}

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

/// Where the confirmation page goes on to: a page of the account, the overview otherwise.
fn confirm_next(next: Option<&str>) -> String {
    next_path(next)
        .filter(|next| next.starts_with(OVERVIEW))
        .unwrap_or_else(|| OVERVIEW.to_owned())
}

/// The confirmation page, going on to `next`.
fn confirm_action(t: &'static Text, next: String) -> Action {
    Action {
        title: t.confirm_title.to_owned(),
        lead: t.confirm_lead.to_owned(),
        note: None,
        action: format!("{ACCOUNT}/confirm"),
        button: t.confirm_button,
        danger: false,
        next,
    }
}

/// `GET /account/confirm?next=<page of the account>`.
pub async fn confirm_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<NextQuery>,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let next = confirm_next(query.next.as_deref());
    action_page(
        &state,
        &visitor,
        confirm_action(visitor.t(), next),
        StatusCode::OK,
        None,
    )
}

/// `POST /account/confirm`.
pub async fn confirm(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let next = confirm_next(Some(&form.next));
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    // Only the password confirms here; a session confirmed already goes on.
    match confirmation(&state, &visitor, client, form.password).await {
        Confirmation::Confirmed => web::see_other(&next, &[]),
        Confirmation::Refused(error) => {
            let action = confirm_action(visitor.t(), next);
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            action_page(&state, &visitor, action, status, Some(error.to_owned()))
        }
        Confirmation::Halt(response) => *response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_goes_on_to_pages_of_the_account_only() {
        assert_eq!(confirm_next(None), OVERVIEW);
        assert_eq!(confirm_next(Some("")), OVERVIEW);
        assert_eq!(
            confirm_next(Some("/account/?next=x#email")),
            "/account/?next=x#email"
        );
        assert_eq!(confirm_next(Some("/apps/files/")), OVERVIEW);
        assert_eq!(confirm_next(Some("//evil.example/account/")), OVERVIEW);
    }
}
