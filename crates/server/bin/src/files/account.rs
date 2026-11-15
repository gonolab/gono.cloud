//! The account page of the signed-in user, part of the web file UI.
//!
//! | Request | Page or action |
//! |---|---|
//! | `GET /apps/account/` | Profile, web login password and the user's app passwords. |
//! | `POST /apps/account/display-name` | Change the display name. |
//! | `POST /apps/account/password` | Change the web login password (needs the current one). The other browser sessions end; this one stays. |
//! | `POST /apps/account/app-passwords` | Create an app password, then show it once at `/apps/account/created`. |
//! | `POST /apps/account/app-passwords/<id>/delete` | Revoke one of the user's app passwords. |
//! | `GET /apps/account/devices/<endpoint id>/revoke` | The second confirmation of revoking a device for remote access. |
//! | `POST /apps/account/devices/<endpoint id>/revoke` | Revoke it, and the devices it introduced that are ticked. |
//! | `POST /apps/account/devices/<endpoint id>/pairing` | Let the device send pairing requests for an hour. |
//! | `POST /apps/account/two-factor/start` | Start enrolling two-step verification (needs the password). |
//! | `GET /apps/account/two-factor` | The QR code and key of the enrolment, and the form for its first code. |
//! | `POST /apps/account/two-factor/confirm` | Turn it on with the first code; the recovery codes follow once. The other browser sessions end; this one stays. |
//! | `GET /apps/account/two-factor/recovery-codes` | New recovery codes, shown once. |
//! | `POST /apps/account/two-factor/renew` | New recovery codes (password and a code). |
//! | `POST /apps/account/two-factor/disable` | Turn it off (password and a code). |
//!
//! Devices registered for remote access (`docs/connect-protocol.md`, sections 6 and 9) are
//! listed only when remote connectivity is on. Their credentials are not app passwords and do
//! not appear among them. Revoking one is final for its key, so it is never one click: the
//! revoke button opens a confirmation page.
//!
//! Every change is a POST with the session's CSRF token from this origin, answered with a
//! redirect. A new app password is kept in memory for its session only and shown once; the
//! URL carries no secret. Changing the password checks the current one through the
//! failed-attempt limiter of the sign-in pages.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    app_passwords::{self, Scope},
    audit, db,
    devices::{self, Device, EndpointId, RevokedBy},
    password,
    two_factor::{self, TurnedOff},
    users, web_sessions,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use super::{Visitor, blocked, internal, view::when, visitor};
use crate::{
    admin::{AppPasswordFields, AppPasswordForm, ScopeChip, core_message, parse_app_password},
    app::AppState,
    client_ip::client_ip,
    i18n::{Text, fill},
    web::{self, Chrome, CodeCheck, Nav, Verified, page},
};

/// Where the account page lives.
pub const ACCOUNT: &str = "/apps/account";

/// How long a new app password waits to be shown.
const CREATED_TTL: Duration = Duration::from_secs(10 * 60);

/// New app passwords waiting to be shown, at most.
const MAX_CREATED: usize = 1000;

/// A new app password waiting to be shown once.
#[derive(Debug)]
pub struct Created {
    /// The account of the session that created it: should a session of another account ever
    /// get the same row id, it sees nothing.
    user_id: i64,
    label: String,
    token: SecretString,
    scopes: Vec<Scope>,
    expires_at: Option<i64>,
    until: Instant,
}

/// New app passwords by the id of the session that created them.
#[derive(Debug, Default)]
pub struct CreatedStore(Mutex<HashMap<i64, Created>>);

impl CreatedStore {
    fn put(&self, session_id: i64, created: Created) {
        let now = Instant::now();
        let mut waiting = self.0.lock().unwrap_or_else(|e| e.into_inner());
        waiting.retain(|_, entry| entry.until > now);
        if waiting.len() >= MAX_CREATED {
            waiting.clear();
        }
        waiting.insert(session_id, created);
    }

    fn take(&self, session: &web_sessions::SessionUser) -> Option<Created> {
        let mut waiting = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !waiting
            .get(&session.session_id)
            .is_some_and(|entry| entry.user_id == session.user_id)
        {
            return None;
        }
        waiting
            .remove(&session.session_id)
            .filter(|entry| entry.until > Instant::now())
    }
}

/// One app password in the list.
#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: i64,
    pub label: String,
    pub created: String,
    pub scopes: Vec<ScopeChip>,
    pub last_used: String,
    pub expiry: String,
}

/// One device registered for remote access in the list.
#[derive(Debug, Clone)]
pub struct RemoteRow {
    /// Endpoint ID, 64 hex digits (the URLs of its actions).
    pub hex: String,
    pub name: String,
    /// "Input Show · Windows".
    pub what: String,
    pub short: String,
    /// "Online", "Last seen …", "Revoked …".
    pub status: String,
    pub online: bool,
    pub revoked: bool,
    /// Registered: neither revoked nor signed out.
    pub active: bool,
    /// What the device reported about remote access.
    pub remote: Vec<&'static str>,
    /// "May ask to pair until …".
    pub pairing: Option<String>,
    /// For a revoked device: which devices have applied the revocation.
    pub applied: Option<String>,
}

/// What the account page shows of two-step verification.
#[derive(Debug, Clone, Default)]
pub struct TwoFactorView {
    /// The server has its key file.
    pub available: bool,
    /// "On since …", when it is on.
    pub on: Option<String>,
    /// "Recovery codes left: …".
    pub recovery_left: String,
    /// Recent failed second steps: "…, from …".
    pub failures: Vec<String>,
    /// Recent uses of recovery codes: "…, from …".
    pub recovery_used: Vec<String>,
    /// Where to continue once it is on (a local path).
    pub next: String,
}

/// `account/page.html`.
#[derive(Template)]
#[template(path = "account/page.html")]
struct AccountPage {
    chrome: Chrome,
    username: String,
    display_name: String,
    two_factor: TwoFactorView,
    /// `None` when remote connectivity is off.
    remote: Option<Vec<RemoteRow>>,
    devices: Vec<DeviceRow>,
    form: AppPasswordForm,
    notice: Option<String>,
    error: Option<String>,
}

/// `account/created.html`.
#[derive(Template)]
#[template(path = "account/created.html")]
struct CreatedPage {
    chrome: Chrome,
    username: String,
    label: String,
    token: String,
    scopes: Vec<ScopeChip>,
    expiry: String,
    server: String,
    webdav: String,
}

/// `account/revoke.html`: the second confirmation of a revocation.
#[derive(Template)]
#[template(path = "account/revoke.html")]
struct RevokePage {
    chrome: Chrome,
    device: RemoteRow,
    /// The devices it introduced: `(endpoint ID, name, short ID)`.
    introduced: Vec<(String, String, String)>,
}

/// `account/two_factor.html`: the enrolment's QR code and key.
#[derive(Template)]
#[template(path = "account/two_factor.html")]
struct EnrolPage {
    chrome: Chrome,
    /// The QR code, an SVG generated here.
    qr: String,
    key: String,
    error: Option<&'static str>,
}

/// `account/recovery_codes.html`: recovery codes, once.
#[derive(Template)]
#[template(path = "account/recovery_codes.html")]
struct RecoveryCodesPage {
    chrome: Chrome,
    codes: Vec<String>,
    next: String,
}

page!(
    AccountPage,
    CreatedPage,
    RevokePage,
    EnrolPage,
    RecoveryCodesPage
);

/// The signed-in user, or a redirect to the sign-in page.
async fn account_visitor(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<Visitor, Box<Response>> {
    if state.files.is_none() {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    }
    match visitor(state, headers, uri).await {
        Some(visitor) => Ok(visitor),
        None => Err(Box::new(web::see_other(
            &format!(
                "/login?next={}",
                super::view::encode_query(&format!("{ACCOUNT}/"))
            ),
            &[],
        ))),
    }
}

/// Like [`account_visitor`] for a form post: also checks the origin and the token.
async fn form_visitor(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    csrf: &str,
) -> Result<Visitor, Box<Response>> {
    let visitor = account_visitor(state, headers, uri).await?;
    if !state.web.same_origin(headers) {
        return Err(Box::new(blocked(&visitor, |t| t.from_other_site)));
    }
    if !state.web.check_session_csrf(&visitor.token, csrf) {
        return Err(Box::new(blocked(&visitor, |t| t.form_expired)));
    }
    Ok(visitor)
}

/// The expiry of an app password in words.
fn expiry(t: &Text, visitor: &Visitor, now: i64, expires_at: Option<i64>) -> String {
    match expires_at {
        Some(at) => fill(t.expires, &[&when(visitor.lang(), now, at).0]),
        None => t.no_expiry.to_owned(),
    }
}

async fn render_page(
    state: &AppState,
    visitor: &Visitor,
    form: AppPasswordForm,
    notice: Option<String>,
    error: Option<String>,
) -> Response {
    render_page_next(state, visitor, form, notice, error, None).await
}

async fn render_page_next(
    state: &AppState,
    visitor: &Visitor,
    form: AppPasswordForm,
    notice: Option<String>,
    error: Option<String>,
    next: Option<String>,
) -> Response {
    let t = visitor.t();
    let passwords = match app_passwords::list(&state.db, visitor.user.user_id).await {
        Ok(passwords) => passwords,
        Err(err) => return internal(visitor, "app password list", &err),
    };
    let now = db::unix_now();
    let devices = passwords
        .into_iter()
        .map(|password| DeviceRow {
            id: password.id,
            label: password.label,
            created: fill(
                t.created,
                &[&when(visitor.lang(), now, password.created_at).0],
            ),
            scopes: password.scopes.iter().map(ScopeChip::new).collect(),
            last_used: password.last_used_at.map_or_else(
                || t.never_used.to_owned(),
                |at| when(visitor.lang(), now, at).0,
            ),
            expiry: expiry(t, visitor, now, password.expires_at),
        })
        .collect();
    let remote = match remote_rows(state, visitor, now).await {
        Ok(remote) => remote,
        Err(err) => return internal(visitor, "device list", &err),
    };
    let two_factor = match two_factor_view(state, visitor, now, next).await {
        Ok(view) => view,
        Err(err) => return internal(visitor, "two-step verification", &err),
    };
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    let page = AccountPage {
        chrome: visitor.chrome(Nav::Account),
        username: visitor.user.username.to_string(),
        display_name: visitor.user.display_name.clone(),
        two_factor,
        remote,
        devices,
        form,
        notice,
        error,
    };
    web::render(status, &page)
}

/// The two-step verification of the visitor's account.
async fn two_factor_view(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
    next: Option<String>,
) -> gono_server_core::Result<TwoFactorView> {
    let t = visitor.t();
    let lang = visitor.lang();
    let status = two_factor::status(&state.db, visitor.user.user_id).await?;
    let at_from = |at: i64, client_ip: Option<&str>| {
        fill(
            t.tf_failure_at,
            &[&when(lang, now, at).0, client_ip.unwrap_or("?")],
        )
    };
    let failures = audit::list(&state.db, Some(visitor.user.user_id), None, 200)
        .await?
        .into_iter()
        .filter(|entry| entry.kind == "two_factor.failed" && entry.at > now - 30 * 86_400)
        .take(5)
        .map(|entry| at_from(entry.at, entry.client_ip.as_deref()))
        .collect();
    let recovery_used =
        two_factor::recovery_code_uses(&state.db, visitor.user.user_id, now - 30 * 86_400, 5)
            .await?
            .into_iter()
            .map(|(at, client_ip)| at_from(at, client_ip.as_deref()))
            .collect();
    Ok(TwoFactorView {
        available: state.web.two_factor_key().is_some(),
        on: status.map(|status| fill(t.tf_on_since, &[&when(lang, now, status.enabled_at).0])),
        recovery_left: status
            .map(|status| {
                fill(
                    t.tf_recovery_left,
                    &[&status.recovery_codes_left.to_string()],
                )
            })
            .unwrap_or_default(),
        failures,
        recovery_used,
        next: next.unwrap_or_default(),
    })
}

/// A local path to continue to, from a form or query field.
fn next_path(next: Option<&str>) -> Option<String> {
    next.filter(|next| !next.is_empty())
        .and_then(crate::site::local_path)
        .map(str::to_owned)
}

/// Checks the visitor's web login password; `Err` is the page to answer with.
async fn check_password(
    state: &AppState,
    visitor: &Visitor,
    client: std::net::IpAddr,
    password: String,
) -> Result<(), Box<Response>> {
    match state
        .web
        .verify_password(
            client,
            visitor.user.username.as_str(),
            SecretString::from(password),
        )
        .await
    {
        Verified::Ok(user) if user.id == visitor.user.user_id => Ok(()),
        Verified::Ok(_) | Verified::Invalid => Err(Box::new(
            render_page(
                state,
                visitor,
                AppPasswordForm::default(),
                None,
                Some(visitor.t().err_current_password.to_owned()),
            )
            .await,
        )),
        Verified::RateLimited(wait) => Err(Box::new(web::too_many_attempts(
            visitor.chrome(Nav::Account),
            wait,
        ))),
        Verified::Unavailable => Err(Box::new(web::unavailable(visitor.chrome(Nav::Account)))),
    }
}

/// Checks a code (TOTP or recovery) of the visitor's account; `Err` is the page to answer with.
/// The same limits as at the second step of a sign-in apply ([`web::Web::check_code`]).
async fn check_code(
    state: &AppState,
    visitor: &Visitor,
    client: std::net::IpAddr,
    code: &str,
) -> Result<(), Box<Response>> {
    let fail = |message: &'static str| async move {
        Box::new(
            render_page(
                state,
                visitor,
                AppPasswordForm::default(),
                None,
                Some(message.to_owned()),
            )
            .await,
        )
    };
    match state
        .web
        .check_code(client, visitor.user.user_id, code)
        .await
    {
        CodeCheck::Right { .. } => Ok(()),
        CodeCheck::Wrong => Err(fail(visitor.t().two_step_wrong).await),
        CodeCheck::Locked => Err(fail(visitor.t().two_step_locked).await),
        CodeCheck::NotEnrolled => Err(Box::new(web::see_other(&format!("{ACCOUNT}/"), &[]))),
        CodeCheck::RateLimited(wait) => Err(Box::new(web::too_many_attempts(
            visitor.chrome(Nav::Account),
            wait,
        ))),
        CodeCheck::Unavailable => Err(Box::new(web::unavailable(visitor.chrome(Nav::Account)))),
    }
}

#[derive(Deserialize)]
pub struct PasswordOnlyForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    next: String,
}

/// `POST /apps/account/two-factor/start`.
pub async fn two_factor_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<PasswordOnlyForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    if state.web.two_factor_key().is_none() {
        return web::unavailable(visitor.chrome(Nav::Account));
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = check_password(&state, &visitor, client, form.password).await {
        return *response;
    }
    state
        .web
        .start_enrolment(&visitor.user, next_path(Some(&form.next)));
    web::see_other(&format!("{ACCOUNT}/two-factor"), &[])
}

async fn enrol_page(
    state: &AppState,
    visitor: &Visitor,
    status: StatusCode,
    error: Option<&'static str>,
) -> Response {
    let Some(enrolment) = state.web.enrolment(&visitor.user) else {
        let message = Some(visitor.t().tf_setup_expired.to_owned());
        return render_page(state, visitor, AppPasswordForm::default(), None, message).await;
    };
    let uri = two_factor::otpauth_uri(visitor.user.username.as_str(), &enrolment.secret);
    let Some(qr) = crate::qr::svg(&uri) else {
        return internal(
            visitor,
            "QR code",
            &"the enrolment URI does not fit a QR code",
        );
    };
    let page = EnrolPage {
        chrome: visitor.chrome(Nav::Account),
        qr,
        key: two_factor::grouped(&two_factor::base32(&enrolment.secret)),
        error,
    };
    web::render(status, &page)
}

/// `GET /apps/account/two-factor`.
pub async fn two_factor_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    enrol_page(&state, &visitor, StatusCode::OK, None).await
}

#[derive(Deserialize)]
pub struct CodeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    password: String,
}

/// `POST /apps/account/two-factor/confirm`.
pub async fn two_factor_confirm(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<CodeForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(key) = state.web.two_factor_key() else {
        return web::unavailable(visitor.chrome(Nav::Account));
    };
    let Some(enrolment) = state.web.enrolment(&visitor.user) else {
        return enrol_page(&state, &visitor, StatusCode::OK, None).await;
    };
    let now = db::unix_now();
    let step = two_factor::parse_code(&form.code)
        .and_then(|code| two_factor::matching_step(&enrolment.secret, code, now, 0));
    let Some(step) = step else {
        return enrol_page(
            &state,
            &visitor,
            StatusCode::UNPROCESSABLE_ENTITY,
            Some(visitor.t().two_step_wrong),
        )
        .await;
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    // Every other browser session of the account ends with it, in the same transaction: one
    // opened with the password alone before must not keep what needs a second step from now
    // on (device registrations, revocations, pairing). This one stays.
    let codes = match two_factor::enable(
        &state.db,
        key,
        visitor.user.user_id,
        &enrolment.secret,
        step,
        Some(visitor.user.session_id),
        Some(client),
        now,
    )
    .await
    {
        Ok(codes) => codes,
        Err(gono_server_core::Error::TwoFactorEnrolled) => {
            state.web.end_enrolment(&visitor.user);
            return web::see_other(&format!("{ACCOUNT}/"), &[]);
        }
        Err(err) => return internal(&visitor, "two-step verification", &err),
    };
    state.web.end_enrolment(&visitor.user);
    state.web.end_pending_sign_ins(visitor.user.user_id);
    tracing::info!(user = %visitor.user.username, "two-step verification turned on");
    if let Some(connect) = &state.connect {
        connect.poke();
    }
    state.web.show_once(&visitor.user, codes, enrolment.next);
    web::see_other(&format!("{ACCOUNT}/two-factor/recovery-codes"), &[])
}

/// `GET /apps/account/two-factor/recovery-codes`.
pub async fn recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(shown) = state.web.take_shown(&visitor.user) else {
        return web::see_other(&format!("{ACCOUNT}/"), &[]);
    };
    let page = RecoveryCodesPage {
        chrome: visitor.chrome(Nav::Account),
        codes: shown.codes,
        next: shown
            .next
            .unwrap_or_else(|| format!("{ACCOUNT}/?done=two-factor-on")),
    };
    web::render(StatusCode::OK, &page)
}

/// `POST /apps/account/two-factor/renew`.
pub async fn two_factor_renew(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<CodeForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = check_password(&state, &visitor, client, form.password).await {
        return *response;
    }
    if let Err(response) = check_code(&state, &visitor, client, &form.code).await {
        return *response;
    }
    match two_factor::renew_recovery_codes(
        &state.db,
        visitor.user.user_id,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(codes) => {
            state.web.show_once(&visitor.user, codes, None);
            web::see_other(&format!("{ACCOUNT}/two-factor/recovery-codes"), &[])
        }
        Err(err) => internal(&visitor, "recovery codes", &err),
    }
}

/// `POST /apps/account/two-factor/disable`.
pub async fn two_factor_disable(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<CodeForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = check_password(&state, &visitor, client, form.password).await {
        return *response;
    }
    if let Err(response) = check_code(&state, &visitor, client, &form.code).await {
        return *response;
    }
    match two_factor::disable(
        &state.db,
        visitor.user.user_id,
        TurnedOff::User,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(_) => {
            tracing::info!(user = %visitor.user.username, "two-step verification turned off");
            state.web.end_pending_sign_ins(visitor.user.user_id);
            if let Some(connect) = &state.connect {
                connect.poke();
            }
            web::see_other(&format!("{ACCOUNT}/?done=two-factor-off"), &[])
        }
        Err(err) => internal(&visitor, "two-step verification", &err),
    }
}

/// The rows of the remote devices, or `None` when remote connectivity is off.
async fn remote_rows(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
) -> gono_server_core::Result<Option<Vec<RemoteRow>>> {
    let Some(connect) = &state.connect else {
        return Ok(None);
    };
    let listed = connect.devices_with_presence(visitor.user.user_id).await?;
    let applied = devices::applied(&state.db, visitor.user.user_id).await?;
    let rows = listed
        .iter()
        .map(|(device, online)| {
            let applied = device.revoked_at.map(|revoked_at| {
                // The devices that existed when it was revoked and have not applied it.
                let pending: Vec<&str> = listed
                    .iter()
                    .map(|(other, _)| other)
                    .filter(|other| {
                        other.id != device.id
                            && other.is_active()
                            && other.registered_at <= revoked_at
                            && !applied.contains(&(device.id, other.id))
                    })
                    .map(|other| other.name.as_str())
                    .collect();
                if pending.is_empty() {
                    visitor.t().applied_by_all.to_owned()
                } else {
                    fill(visitor.t().applied_pending, &[&pending.join(", ")])
                }
            });
            remote_row(visitor, device, *online, now, applied)
        })
        .collect();
    Ok(Some(rows))
}

fn remote_row(
    visitor: &Visitor,
    device: &Device,
    online: bool,
    now: i64,
    applied: Option<String>,
) -> RemoteRow {
    let t = visitor.t();
    let lang = visitor.lang();
    let status = match (
        device.revoked_at,
        device.left_at,
        online,
        device.last_seen_at,
    ) {
        (Some(at), _, _, _) => fill(t.revoked_on, &[&when(lang, now, at).0]),
        (None, Some(at), _, _) => fill(t.signed_out_on, &[&when(lang, now, at).0]),
        (None, None, true, _) => t.online.to_owned(),
        (None, None, false, Some(at)) => fill(t.last_seen, &[&when(lang, now, at).0]),
        (None, None, false, None) => t.never_connected.to_owned(),
    };
    let mut remote = Vec::new();
    if device.is_active() {
        if device.accept_remote {
            remote.push(t.accepts_remote);
        }
        if device.unattended {
            remote.push(t.unattended_on);
        }
    }
    RemoteRow {
        hex: device.endpoint_id.to_hex(),
        name: device.name.clone(),
        what: format!(
            "{} · {}",
            crate::login_flow::product_name(&device.product),
            crate::login_flow::platform_name(&device.platform)
        ),
        short: device.endpoint_id.short(),
        status,
        online,
        revoked: device.is_revoked(),
        active: device.is_active(),
        remote,
        pairing: device
            .pairing_open(now)
            .then_some(device.pairing_open_until)
            .flatten()
            .map(|until| fill(t.pairing_open_until, &[&when(lang, now, until).0])),
        applied,
    }
}

/// The unrevoked remote device `hex` of the visitor, or the page that says there is none.
async fn own_device(
    state: &AppState,
    visitor: &Visitor,
    hex: &str,
) -> Result<Device, Box<Response>> {
    if state.connect.is_none() {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    }
    let not_found = || Box::new(super::not_found(visitor));
    let key = EndpointId::parse(hex).ok_or_else(not_found)?;
    match devices::find(&state.db, key).await {
        Ok(Some(device)) if device.user_id == visitor.user.user_id && !device.is_revoked() => {
            Ok(device)
        }
        Ok(_) => Err(not_found()),
        Err(err) => Err(Box::new(internal(visitor, "device", &err))),
    }
}

/// `GET /apps/account/devices/<endpoint id>/revoke`.
pub async fn revoke_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(hex): Path<String>,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let device = match own_device(&state, &visitor, &hex).await {
        Ok(device) => device,
        Err(response) => return *response,
    };
    let introduced = match devices::introduced_by(&state.db, device.id).await {
        Ok(introduced) => introduced,
        Err(err) => return internal(&visitor, "device approvals", &err),
    };
    let online = state
        .connect
        .as_ref()
        .is_some_and(|connect| connect.is_online(device.user_id, device.endpoint_id));
    let page = RevokePage {
        chrome: visitor.chrome(Nav::Account),
        device: remote_row(&visitor, &device, online, db::unix_now(), None),
        introduced: introduced
            .iter()
            .map(|other| {
                (
                    other.endpoint_id.to_hex(),
                    other.name.clone(),
                    other.endpoint_id.short(),
                )
            })
            .collect(),
    };
    web::render(StatusCode::OK, &page)
}

/// `POST /apps/account/devices/<endpoint id>/revoke`: the device, and every introduced device
/// ticked as `also_<endpoint id>`.
pub async fn revoke_device(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Path(hex): Path<String>,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let csrf = fields.get("csrf").cloned().unwrap_or_default();
    let visitor = match form_visitor(&state, &headers, &uri, &csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let device = match own_device(&state, &visitor, &hex).await {
        Ok(device) => device,
        Err(response) => return *response,
    };
    let mut keys = vec![device.endpoint_id];
    keys.extend(
        fields
            .keys()
            .filter_map(|name| name.strip_prefix("also_"))
            .filter_map(EndpointId::parse),
    );
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match devices::revoke(
        &state.db,
        visitor.user.user_id,
        &keys,
        RevokedBy::AccountPage,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(revoked) => {
            for device in &revoked {
                tracing::info!(
                    user = %visitor.user.username,
                    device = %device.endpoint_id.short(),
                    "user revoked a device"
                );
            }
            if let Some(connect) = &state.connect {
                connect.poke();
            }
            web::see_other(&format!("{ACCOUNT}/?done=device-revoked"), &[])
        }
        Err(err) => internal(&visitor, "revoke a device", &err),
    }
}

/// `POST /apps/account/devices/<endpoint id>/pairing`.
pub async fn allow_pairing(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(hex): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let device = match own_device(&state, &visitor, &hex).await {
        Ok(device) => device,
        Err(response) => return *response,
    };
    let until = db::unix_now() + devices::PAIRING_WINDOW_SECS;
    match devices::open_pairing(&state.db, visitor.user.user_id, device.endpoint_id, until).await {
        Ok(_) => web::see_other(&format!("{ACCOUNT}/?done=pairing"), &[]),
        Err(err) => internal(&visitor, "allow pairing", &err),
    }
}

#[derive(Deserialize)]
pub struct DoneQuery {
    done: Option<String>,
    next: Option<String>,
}

/// `GET /apps/account/`.
pub async fn show(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DoneQuery>,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let notice = match query.done.as_deref() {
        Some("display-name") => Some(t.notice_display_name.to_owned()),
        Some("password") => Some(t.notice_password_changed.to_owned()),
        Some("revoked") => Some(t.notice_revoked.to_owned()),
        Some("device-revoked") => Some(t.notice_device_revoked.to_owned()),
        Some("pairing") => Some(t.notice_pairing_open.to_owned()),
        Some("two-factor-on") => Some(t.notice_tf_on.to_owned()),
        Some("two-factor-off") => Some(t.notice_tf_off.to_owned()),
        _ => None,
    };
    let next = next_path(query.next.as_deref());
    render_page_next(
        &state,
        &visitor,
        AppPasswordForm::default(),
        notice,
        None,
        next,
    )
    .await
}

/// `GET /apps/account`.
pub async fn to_page() -> Response {
    web::see_other(&format!("{ACCOUNT}/"), &[])
}

#[derive(Deserialize)]
pub struct DisplayNameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    display_name: String,
}

/// `POST /apps/account/display-name`.
pub async fn set_display_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<DisplayNameForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    if users::validate_display_name(&form.display_name).is_err() {
        let error = Some(t.err_display_name.to_owned());
        return render_page(&state, &visitor, AppPasswordForm::default(), None, error).await;
    }
    match users::set_display_name(&state.db, &visitor.user.username, &form.display_name).await {
        Ok(_) => web::see_other(&format!("{ACCOUNT}/?done=display-name"), &[]),
        Err(err) => internal(&visitor, "display name", &err),
    }
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    current: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
}

/// `POST /apps/account/password`.
pub async fn set_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<PasswordForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let fail = |message: String| {
        let state = state.clone();
        let visitor = &visitor;
        async move {
            render_page(
                &state,
                visitor,
                AppPasswordForm::default(),
                None,
                Some(message),
            )
            .await
        }
    };
    if form.password != form.password_repeat {
        return fail(t.err_passwords_differ.to_owned()).await;
    }
    let new = SecretString::from(form.password);
    if let Err(err) = password::check_policy(&new) {
        return fail(core_message(t, &err)).await;
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match state
        .web
        .verify_password(
            client,
            visitor.user.username.as_str(),
            SecretString::from(form.current),
        )
        .await
    {
        Verified::Ok(user) if user.id == visitor.user.user_id => {}
        Verified::Ok(_) | Verified::Invalid => {
            return fail(t.err_current_password.to_owned()).await;
        }
        Verified::RateLimited(wait) => {
            return web::too_many_attempts(visitor.chrome(Nav::Account), wait);
        }
        Verified::Unavailable => return web::unavailable(visitor.chrome(Nav::Account)),
    }
    let hash = match tokio::task::spawn_blocking(move || password::hash(&new)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(err)) => return internal(&visitor, "password hash", &err),
        Err(err) => return internal(&visitor, "password hash", &err),
    };
    if let Err(err) = users::set_password_hash(&state.db, &visitor.user.username, &hash).await {
        return internal(&visitor, "password change", &err);
    }
    // Sign-ins that were waiting for their second step with the old password end.
    state.web.end_pending_sign_ins(visitor.user.user_id);
    // Every other browser signs out; this one stays signed in.
    if let Err(err) = web_sessions::delete_for_user(
        &state.db,
        visitor.user.user_id,
        Some(visitor.user.session_id),
    )
    .await
    {
        tracing::warn!(error = %err, "cannot end the browser sessions after a password change");
    }
    tracing::info!(user = %visitor.user.username, "web login password changed by its user");
    web::see_other(&format!("{ACCOUNT}/?done=password"), &[])
}

/// `POST /apps/account/app-passwords`.
pub async fn create_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let fields = AppPasswordFields { fields };
    let visitor = match form_visitor(&state, &headers, &uri, &fields.field("csrf")).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let form = fields.form();
    let (label, scopes, expires_at) = match parse_app_password(visitor.t(), &form, db::unix_now()) {
        Ok(parsed) => parsed,
        Err(error) => return render_page(&state, &visitor, form, None, Some(error)).await,
    };
    let (id, token) = match app_passwords::create(
        &state.db,
        visitor.user.user_id,
        &label,
        scopes.clone(),
        expires_at,
    )
    .await
    {
        Ok(created) => created,
        Err(err) => return internal(&visitor, "app password", &err),
    };
    tracing::info!(user = %visitor.user.username, app_password = id, "user created an app password");
    files.created.put(
        visitor.user.session_id,
        Created {
            user_id: visitor.user.user_id,
            label,
            token,
            scopes,
            expires_at,
            until: Instant::now() + CREATED_TTL,
        },
    );
    web::see_other(&format!("{ACCOUNT}/created"), &[])
}

/// `GET /apps/account/created`: the new app password, once.
pub async fn created(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(created) = files.created.take(&visitor.user) else {
        return web::see_other(&format!("{ACCOUNT}/"), &[]);
    };
    let t = visitor.t();
    let origin = state.base_url.as_str().trim_end_matches('/').to_owned();
    let page = CreatedPage {
        chrome: visitor.chrome(Nav::Account),
        username: visitor.user.username.to_string(),
        label: created.label,
        token: created.token.expose_secret().to_owned(),
        scopes: created.scopes.iter().map(ScopeChip::new).collect(),
        expiry: expiry(t, &visitor, db::unix_now(), created.expires_at),
        webdav: format!(
            "{origin}/remote.php/dav/files/{}/",
            super::view::encode_segment(visitor.user.username.as_str())
        ),
        server: origin,
    };
    web::render(StatusCode::OK, &page)
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /apps/account/app-passwords/<id>/delete`.
pub async fn revoke_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    // Only the user's own: the query names the owner.
    match app_passwords::delete(&state.db, visitor.user.user_id, id).await {
        Ok(_) => {
            tracing::info!(user = %visitor.user.username, app_password = id, "user revoked an app password");
            web::see_other(&format!("{ACCOUNT}/?done=revoked"), &[])
        }
        Err(err) => internal(&visitor, "revoke", &err),
    }
}
