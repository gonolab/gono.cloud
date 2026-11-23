//! The account page of the signed-in user, part of the web file UI. It has a tab for the
//! account itself and one for each service a user sets up here:
//!
//! | Request | Page or action |
//! |---|---|
//! | `GET /account/` | Overview: the account's services, its ways to sign in (password and third-party identities), its email address, two-step verification, display name and web login password. |
//! | `GET /account/webdav` | WebDAV: the addresses clients connect to, and the user's app passwords. |
//! | `GET /account/s3` | S3: the user's buckets and access keys (see [`s3`]). |
//! | `GET /account/direct` | Direct connections: the devices registered for remote access. |
//! | `GET /account/relay` | Relay: its address, the rate it reads the account's devices at, those connected to it now and the sessions they reported (see [`relay`]). |
//! | `POST /account/display-name` | Change the display name. |
//! | `POST /account/password` | Change the web login password (needs the current one). The other browser sessions end; this one stays. |
//! | `POST /account/username` | Change the username of an account made by a sign-up, until a device or app signed in to it (once a day). |
//! | `POST /account/delete` | An account without a web login password asks for its deletion: disabled at once, deleted after 7 days unless a sign-in undoes it. |
//! | `POST /account/password/set` | Set the first web login password of an account without one, after confirming it is you with one of its identities. The other browser sessions stay. |
//! | `POST /account/email`, `POST /account/email/confirm`, `POST /account/email/remove` | Add, replace or remove the email address with a mailed code (see [`email`]). |
//! | `GET`/`POST /account/identities/wechat/bind`, `GET`/`POST /account/identities/<provider>/unbind` | Show a QR code that binds WeChat for the mini program, or unbind an identity (see [`methods`]). |
//! | `GET /account/confirm`, `POST /account/confirm` | Confirm it is you, then go on (see [`methods`]). |
//! | `POST /account/app-passwords` | Create an app password, then show it once at `/account/created`. |
//! | `POST /account/app-passwords/<id>/delete` | Revoke one of the user's app passwords. |
//! | `GET /account/devices/<endpoint id>/revoke` | The second confirmation of revoking a device for remote access. |
//! | `POST /account/devices/<endpoint id>/revoke` | Revoke it, and the devices it introduced that are ticked. |
//! | `POST /account/devices/<endpoint id>/sign-out` | Stop remote access for a device that stays in use: sign it out (protocol 9.4). |
//! | `POST /account/devices/<endpoint id>/pairing` | Let the device send pairing requests for an hour. |
//! | `POST /account/two-factor/start` | Start enrolling two-step verification (needs confirming it is you). |
//! | `GET /account/two-factor` | The QR code and key of the enrolment, and the form for its first code. |
//! | `POST /account/two-factor/confirm` | Turn it on with the first code; the recovery codes follow once. The other browser sessions end; this one stays. |
//! | `GET /account/two-factor/recovery-codes` | New recovery codes, shown once. |
//! | `POST /account/two-factor/renew` | New recovery codes (confirming it is you, and a code). |
//! | `POST /account/two-factor/disable` | Turn it off (confirming it is you, and a code). |
//! | `POST /account/s3/buckets` | Create an S3 bucket with a new folder `<s3.bucket_folder>/<name>`. |
//! | `POST /account/s3/buckets/bind` | Make an existing folder an S3 bucket. |
//! | `POST /account/s3/buckets/<id>/anonymous` | Change what anonymous requests may read and list in a bucket. |
//! | `POST /account/s3/buckets/<id>/delete` | Remove a bucket: only the binding goes, the folder and its files stay. |
//! | `POST /account/s3/keys` | Create an S3 access key, then show it once at `/account/s3/created`. |
//! | `GET /account/s3/created` | The new access key with its secret key, once. |
//! | `POST /account/s3/keys/<id>/delete` | Revoke one of the user's S3 access keys. |
//!
//! # Tabs and services
//!
//! Every tab is listed for every account, so that its user sees what exists. The overview
//! belongs to the account itself and works without any service
//! (`gono_server_core::services`). Each other tab belongs to a service: while the account
//! lacks it, the tab shows only a notice that an administrator turns it on, and while this
//! server does not offer it at all ([`service_view::offered`]: the S3 API or remote
//! connectivity is off) a notice that says so. Both are pages, answered with `200`. The relay
//! tab belongs to direct connections, which admit the account's devices to the relay already,
//! at the limited rate; the tab says whether the relay service raises that to the full rate.
//!
//! The forms of a tab need its service as well: without it they answer the tab's notice with
//! `403`, and so does the confirmation page of a device's revocation. While the server does
//! not offer the feature, the S3 and device forms answer `404`, as they did before accounts
//! had services.
//!
//! Devices registered for remote access (`docs/connect-protocol.md`, sections 6 and 9) are not
//! app passwords and do not appear among them. Revoking one is final for its key, so it is
//! never one click: the revoke button opens a confirmation page.
//!
//! Every change is a POST with the session's CSRF token from this origin, answered with `303`
//! to the tab of its form with `?done=<what>`, which that tab shows as a notice; a form that is
//! refused shows its tab again with the error (`422`). A new app password or S3 access key is
//! kept in memory for its session only and shown once; the URL carries no secret. Changing the
//! password checks the current one through the failed-attempt limiter of the sign-in pages.
//! The forms that change how the account signs in or is recovered ask to confirm it is you
//! first ([`confirmation`], `plan/third-party-sign-in-design.md` 3.5): the password typed into
//! the form, or a confirmation of the same browser session in the last
//! [`web::CONFIRM_TTL_SECS`].

pub(crate) mod email;
pub(crate) mod methods;
pub(crate) mod relay;
pub(crate) mod s3;

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
    audit::{self, Actor},
    db,
    devices::{self, Device, EndpointId, RevokedBy},
    password,
    services::Service,
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
    service_view,
    site::FILES_HOME,
    web::{self, Chrome, CodeCheck, Nav, Verified, page},
};

/// Where the account page lives.
pub const ACCOUNT: &str = "/account";

/// Its overview tab, where the masthead's entry leads.
pub const OVERVIEW: &str = "/account/";

/// A tab of the account page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    /// The account itself: its services, two-step verification, display name and password.
    #[default]
    Overview,
    /// WebDAV clients and their app passwords.
    Webdav,
    /// S3 buckets and access keys.
    S3,
    /// The devices registered for remote access.
    Direct,
    /// The relay, as the account's devices use it.
    Relay,
}

impl Tab {
    /// Every tab, in the order of the tab bar.
    const ALL: [Self; 5] = [
        Self::Overview,
        Self::Webdav,
        Self::S3,
        Self::Direct,
        Self::Relay,
    ];

    /// Where the tab lives: [`OVERVIEW`], `/account/webdav`, ...
    pub fn path(self) -> String {
        match self {
            Self::Overview => OVERVIEW.to_owned(),
            Self::Webdav => format!("{ACCOUNT}/webdav"),
            Self::S3 => format!("{ACCOUNT}/s3"),
            Self::Direct => format!("{ACCOUNT}/direct"),
            Self::Relay => format!("{ACCOUNT}/relay"),
        }
    }

    /// `303` to the tab.
    fn back(self) -> Response {
        web::see_other(&self.path(), &[])
    }

    /// `303` to the tab with `?done=<done>`, which it shows as a notice ([`notice`]).
    fn done(self, done: &str) -> Response {
        web::see_other(&format!("{}?done={done}", self.path()), &[])
    }

    /// The service the tab needs, `None` for the overview. The relay tab needs direct
    /// connections: they admit the account's devices to the relay already, at the limited
    /// rate, and the tab says whether the relay service raises it.
    fn service(self) -> Option<Service> {
        match self {
            Self::Overview => None,
            Self::Webdav => Some(Service::Webdav),
            Self::S3 => Some(Service::S3),
            Self::Direct | Self::Relay => Some(Service::Direct),
        }
    }

    /// Its name in the tab bar.
    fn label(self, t: &Text) -> &'static str {
        match self {
            Self::Overview => t.account_overview,
            Self::Webdav => t.svc_webdav,
            Self::S3 => t.svc_s3,
            Self::Direct => t.svc_direct,
            Self::Relay => t.svc_relay,
        }
    }

    /// Where the overview links `service` to: its tab, or the file UI for the web files.
    fn href(service: Service) -> String {
        match service {
            Service::Files => FILES_HOME.to_owned(),
            Service::Webdav => Self::Webdav.path(),
            Service::S3 => Self::S3.path(),
            Service::Direct => Self::Direct.path(),
            Service::Relay => Self::Relay.path(),
        }
    }
}

/// How long a new app password or S3 access key waits to be shown.
const CREATED_TTL: Duration = Duration::from_secs(10 * 60);

/// New secrets of one kind waiting to be shown, at most.
const MAX_CREATED: usize = 1000;

/// A new app password waiting to be shown once.
#[derive(Debug)]
pub struct NewAppPassword {
    label: String,
    token: SecretString,
    scopes: Vec<Scope>,
    expires_at: Option<i64>,
}

/// A new secret waiting to be shown once.
#[derive(Debug)]
struct Waiting<T> {
    /// The account of the session that created it: should a session of another account ever
    /// get the same row id, it sees nothing.
    user_id: i64,
    until: Instant,
    value: T,
}

/// New secrets of one kind (app passwords, S3 access keys) by the id of the session that
/// created them; a session has one of each kind waiting at most.
#[derive(Debug)]
pub struct CreatedStore<T>(Mutex<HashMap<i64, Waiting<T>>>);

impl<T> Default for CreatedStore<T> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<T> CreatedStore<T> {
    fn put(&self, session: &web_sessions::SessionUser, value: T) {
        let now = Instant::now();
        let mut waiting = self.0.lock().unwrap_or_else(|e| e.into_inner());
        waiting.retain(|_, entry| entry.until > now);
        if waiting.len() >= MAX_CREATED {
            waiting.clear();
        }
        waiting.insert(
            session.session_id,
            Waiting {
                user_id: session.user_id,
                until: now + CREATED_TTL,
                value,
            },
        );
    }

    fn take(&self, session: &web_sessions::SessionUser) -> Option<T> {
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
            .map(|entry| entry.value)
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
    /// What it is for: with or without "remote access needs it" (`connect.require_two_factor`).
    pub note: &'static str,
}

/// One link of the tab bar.
struct TabLink {
    href: String,
    label: &'static str,
    current: bool,
}

/// What every tab shows around its content (`account/frame.html`): the tab bar, the heading
/// and the flash messages.
struct AccountFrame {
    tabs: Vec<TabLink>,
    /// "Account" on the overview, the tab's name on the others.
    heading: &'static str,
    username: String,
    notice: Option<String>,
    error: Option<String>,
}

impl AccountFrame {
    fn new(visitor: &Visitor, tab: Tab, notice: Option<String>, error: Option<String>) -> Self {
        let t = visitor.t();
        Self {
            tabs: Tab::ALL
                .into_iter()
                .map(|each| TabLink {
                    href: each.path(),
                    label: each.label(t),
                    current: each == tab,
                })
                .collect(),
            heading: if tab == Tab::Overview {
                t.account_title
            } else {
                tab.label(t)
            },
            username: visitor.user.username.to_string(),
            notice,
            error,
        }
    }
}

/// One service of the account on the overview.
struct ServiceLine {
    name: &'static str,
    note: &'static str,
    /// The account has it.
    on: bool,
    /// This server offers it ([`service_view::offered`]).
    offered: bool,
    /// Its tab, or the file UI ([`Tab::href`]).
    href: String,
}

/// Whether the overview's forms ask to confirm it is you ([`confirmation`]).
#[derive(Debug, Clone, Copy, Default)]
struct ConfirmView {
    /// The browser session confirmed it recently: the forms need no password.
    confirmed: bool,
    /// The account has a web login password.
    has_password: bool,
}

impl ConfirmView {
    /// The forms carry a password field.
    fn ask_password(&self) -> bool {
        !self.confirmed && self.has_password
    }

    /// The account has no password and must confirm with a sign-in of an identity first.
    fn needs_sign_in(&self) -> bool {
        !self.confirmed && !self.has_password
    }
}

/// `account/overview.html`.
#[derive(Template)]
#[template(path = "account/overview.html")]
struct OverviewPage {
    chrome: Chrome,
    frame: AccountFrame,
    services: Vec<ServiceLine>,
    methods: methods::MethodsView,
    email: email::EmailView,
    display_name: String,
    two_factor: TwoFactorView,
    confirm: ConfirmView,
    /// The account may still change its username (made by a sign-up, no device or app yet).
    rename: bool,
    /// The account deletes itself (it has no web login password and is no admin).
    deletable: bool,
}

/// `account/webdav.html`.
#[derive(Template)]
#[template(path = "account/webdav.html")]
struct WebdavPage {
    chrome: Chrome,
    frame: AccountFrame,
    /// The server address, for the Nextcloud apps.
    server: String,
    /// The user's WebDAV address, for other clients.
    webdav: String,
    devices: Vec<DeviceRow>,
    form: AppPasswordForm,
}

/// `account/s3.html`.
#[derive(Template)]
#[template(path = "account/s3.html")]
struct S3Page {
    chrome: Chrome,
    frame: AccountFrame,
    s3: s3::S3View,
}

/// `account/direct.html`.
#[derive(Template)]
#[template(path = "account/direct.html")]
struct DirectPage {
    chrome: Chrome,
    frame: AccountFrame,
    remote: Vec<RemoteRow>,
    /// Set while the account lacks direct connections: the notice that says so. The devices it
    /// registered before stay listed, and can still be revoked (revoking only removes trust),
    /// but nothing else.
    off: Option<&'static str>,
}

/// `account/relay.html`.
#[derive(Template)]
#[template(path = "account/relay.html")]
struct RelayPage {
    chrome: Chrome,
    frame: AccountFrame,
    relay: relay::RelayView,
}

/// `account/off.html`: a tab the visitor cannot use, with the notice that says why.
#[derive(Template)]
#[template(path = "account/off.html")]
struct OffPage {
    chrome: Chrome,
    frame: AccountFrame,
    lead: &'static str,
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
    OverviewPage,
    WebdavPage,
    S3Page,
    DirectPage,
    RelayPage,
    OffPage,
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
            &format!("/login?next={}", super::view::encode_query(OVERVIEW)),
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

/// The notice a tab shows in place of its content, if the visitor cannot use it: this server
/// does not offer its service, or the account lacks it.
fn unavailable(state: &AppState, visitor: &Visitor, tab: Tab) -> Option<&'static str> {
    let service = tab.service()?;
    let t = visitor.t();
    if !service_view::offered(state, service) {
        Some(t.account_not_offered)
    } else if !visitor.user.services.has(service) {
        Some(t.account_not_enabled)
    } else {
        None
    }
}

/// `frame` with `lead` in place of the tab's content.
fn off_page(
    visitor: &Visitor,
    frame: AccountFrame,
    lead: &'static str,
    status: StatusCode,
) -> Response {
    let page = OffPage {
        chrome: visitor.chrome(Nav::Account),
        frame,
        lead,
    };
    web::render(status, &page)
}

/// For the forms of `tab`: `Err` with the tab's notice and `403` while the account lacks the
/// tab's service. While this server does not offer it, the handlers answer `404` themselves.
fn needs_service(visitor: &Visitor, tab: Tab) -> Result<(), Box<Response>> {
    match tab.service() {
        Some(service) if !visitor.user.services.has(service) => {
            let frame = AccountFrame::new(visitor, tab, None, None);
            let lead = visitor.t().account_not_enabled;
            Err(Box::new(off_page(
                visitor,
                frame,
                lead,
                StatusCode::FORBIDDEN,
            )))
        }
        _ => Ok(()),
    }
}

/// What a tab shows besides its own content.
#[derive(Default)]
struct PageOptions {
    tab: Tab,
    /// The new app password form, as entered.
    form: AppPasswordForm,
    /// The S3 forms, as entered.
    s3: s3::S3Forms,
    notice: Option<String>,
    /// An error makes the page answer 422.
    error: Option<String>,
    /// An error of an earlier request, shown after its redirect (the page answers 200).
    failed: Option<String>,
    /// Where to continue once two-step verification is on.
    next: Option<String>,
}

/// Shows `tab` again with `error`: the form was refused and nothing changed.
async fn show_error(state: &AppState, visitor: &Visitor, tab: Tab, error: String) -> Response {
    let options = PageOptions {
        tab,
        error: Some(error),
        ..PageOptions::default()
    };
    render(state, visitor, options).await
}

/// The tab of `options`, reading only what that tab shows.
async fn render(state: &AppState, visitor: &Visitor, options: PageOptions) -> Response {
    let PageOptions {
        tab,
        form,
        s3: s3_forms,
        notice,
        error,
        failed,
        next,
    } = options;
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    let error = error.or(failed);
    let chrome = visitor.chrome(Nav::Account);
    let frame = AccountFrame::new(visitor, tab, notice, error);
    // Without direct connections, the tab still lists the registered devices so that a lost
    // one can be revoked; every other tab of a service that is off shows only the notice.
    let off = unavailable(state, visitor, tab);
    let direct_off = tab == Tab::Direct && state.connect.is_some() && off.is_some();
    if let Some(lead) = off.filter(|_| !direct_off) {
        return off_page(visitor, frame, lead, StatusCode::OK);
    }
    let not_offered = visitor.t().account_not_offered;
    let now = db::unix_now();
    match tab {
        Tab::Overview => {
            let two_factor = match two_factor_view(state, visitor, now, next).await {
                Ok(view) => view,
                Err(err) => return internal(visitor, "two-step verification", &err),
            };
            let email = match email::view(state, visitor, now).await {
                Ok(view) => view,
                Err(err) => return internal(visitor, "email address", &err),
            };
            let methods = match methods::view(state, visitor, now).await {
                Ok(view) => view,
                Err(err) => return internal(visitor, "ways to sign in", &err),
            };
            let rename = match users::can_rename(&state.db, visitor.user.user_id).await {
                Ok(rename) => rename,
                Err(err) => return internal(visitor, "username", &err),
            };
            let page = OverviewPage {
                rename,
                deletable: !visitor.user.has_password && !visitor.user.is_admin,
                chrome,
                frame,
                services: service_lines(state, visitor),
                methods,
                email,
                display_name: visitor.user.display_name.clone(),
                two_factor,
                confirm: ConfirmView {
                    confirmed: state.web.is_confirmed(&visitor.user),
                    has_password: visitor.user.has_password,
                },
            };
            web::render(status, &page)
        }
        Tab::Webdav => {
            let devices = match app_password_rows(state, visitor, now).await {
                Ok(devices) => devices,
                Err(err) => return internal(visitor, "app password list", &err),
            };
            let (server, webdav) = addresses(state, visitor);
            let page = WebdavPage {
                chrome,
                frame,
                server,
                webdav,
                devices,
                form,
            };
            web::render(status, &page)
        }
        Tab::S3 => match s3::view(state, visitor, now, s3_forms).await {
            Ok(Some(s3)) => web::render(status, &S3Page { chrome, frame, s3 }),
            Ok(None) => off_page(visitor, frame, not_offered, StatusCode::OK),
            Err(err) => internal(visitor, "S3 buckets and keys", &err),
        },
        Tab::Direct => match remote_rows(state, visitor, now).await {
            Ok(Some(remote)) => web::render(
                status,
                &DirectPage {
                    chrome,
                    frame,
                    remote,
                    off: off.filter(|_| direct_off),
                },
            ),
            Ok(None) => off_page(visitor, frame, not_offered, StatusCode::OK),
            Err(err) => internal(visitor, "device list", &err),
        },
        Tab::Relay => match relay::view(state, visitor, now).await {
            Ok(Some(relay)) => web::render(
                status,
                &RelayPage {
                    chrome,
                    frame,
                    relay,
                },
            ),
            Ok(None) => off_page(visitor, frame, not_offered, StatusCode::OK),
            Err(err) => internal(visitor, "relay", &err),
        },
    }
}

/// The services of the visitor's account, for the overview.
fn service_lines(state: &AppState, visitor: &Visitor) -> Vec<ServiceLine> {
    let t = visitor.t();
    Service::ALL
        .into_iter()
        .map(|service| ServiceLine {
            name: service_view::name(t, service),
            note: service_view::note(t, service),
            on: visitor.user.services.has(service),
            offered: service_view::offered(state, service),
            href: Tab::href(service),
        })
        .collect()
}

/// The visitor's app passwords.
async fn app_password_rows(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
) -> gono_server_core::Result<Vec<DeviceRow>> {
    let t = visitor.t();
    let passwords = app_passwords::list(&state.db, visitor.user.user_id).await?;
    Ok(passwords
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
        .collect())
}

/// The server address the Nextcloud apps are set up with, and the visitor's WebDAV address for
/// other clients.
fn addresses(state: &AppState, visitor: &Visitor) -> (String, String) {
    let origin = state.base_url.as_str().trim_end_matches('/').to_owned();
    let webdav = format!(
        "{origin}/remote.php/dav/files/{}/",
        super::view::encode_segment(visitor.user.username.as_str())
    );
    (origin, webdav)
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
        note: if state.remote_access_needs_two_factor() {
            t.tf_note
        } else {
            t.tf_note_optional
        },
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

/// Outcome of [`confirmation`].
enum Confirmation {
    /// It is the account's user.
    Confirmed,
    /// Not confirmed; the error to show with the form again.
    Refused(&'static str),
    /// The page to answer with instead (too many attempts, the database failed).
    Halt(Box<Response>),
}

/// Confirms that the visitor is the account's user before a form that needs it
/// (`plan/third-party-sign-in-design.md`, 3.5). A password typed into the form is checked
/// through the failed-attempt limiter of the sign-in pages, and a right one confirms the
/// browser session for [`web::CONFIRM_TTL_SECS`]. Without one, the form passes while the
/// session is confirmed, by a password or a fresh sign-in with a bound identity.
async fn confirmation(
    state: &AppState,
    visitor: &Visitor,
    client: std::net::IpAddr,
    password: String,
) -> Confirmation {
    let t = visitor.t();
    if password.is_empty() {
        return if state.web.is_confirmed(&visitor.user) {
            Confirmation::Confirmed
        } else {
            Confirmation::Refused(t.confirm_needed)
        };
    }
    match state
        .web
        .verify_password(
            client,
            visitor.user.username.as_str(),
            SecretString::from(password),
        )
        .await
    {
        Verified::Ok(user) if user.id == visitor.user.user_id => {
            state.web.confirm(&visitor.user);
            Confirmation::Confirmed
        }
        Verified::Ok(_) | Verified::Invalid => Confirmation::Refused(t.err_current_password),
        Verified::RateLimited(wait) => Confirmation::Halt(Box::new(web::too_many_attempts(
            visitor.chrome(Nav::Account),
            wait,
        ))),
        Verified::Unavailable => {
            Confirmation::Halt(Box::new(web::unavailable(visitor.chrome(Nav::Account))))
        }
    }
}

/// [`confirmation`] for a form of the overview: `Err` is the overview again with the error,
/// or the page to answer with.
async fn confirm_you(
    state: &AppState,
    visitor: &Visitor,
    client: std::net::IpAddr,
    password: String,
) -> Result<(), Box<Response>> {
    match confirmation(state, visitor, client, password).await {
        Confirmation::Confirmed => Ok(()),
        Confirmation::Refused(error) => Err(Box::new(
            show_error(state, visitor, Tab::Overview, error.to_owned()).await,
        )),
        Confirmation::Halt(response) => Err(response),
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
        Box::new(show_error(state, visitor, Tab::Overview, message.to_owned()).await)
    };
    match state
        .web
        .check_code(client, visitor.user.user_id, code)
        .await
    {
        CodeCheck::Right { .. } => Ok(()),
        CodeCheck::Wrong => Err(fail(visitor.t().two_step_wrong).await),
        CodeCheck::Locked => Err(fail(visitor.t().two_step_locked).await),
        CodeCheck::NotEnrolled => Err(Box::new(Tab::Overview.back())),
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

/// `POST /account/two-factor/start`.
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
    if let Err(response) = confirm_you(&state, &visitor, client, form.password).await {
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
        let message = visitor.t().tf_setup_expired.to_owned();
        return show_error(state, visitor, Tab::Overview, message).await;
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

/// `GET /account/two-factor`.
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

/// `POST /account/two-factor/confirm`.
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
            return Tab::Overview.back();
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

/// `GET /account/two-factor/recovery-codes`.
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
        return Tab::Overview.back();
    };
    let page = RecoveryCodesPage {
        chrome: visitor.chrome(Nav::Account),
        codes: shown.codes,
        next: shown
            .next
            .unwrap_or_else(|| format!("{OVERVIEW}?done=two-factor-on")),
    };
    web::render(StatusCode::OK, &page)
}

/// `POST /account/two-factor/renew`.
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
    if let Err(response) = confirm_you(&state, &visitor, client, form.password).await {
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

/// `POST /account/two-factor/disable`.
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
    if let Err(response) = confirm_you(&state, &visitor, client, form.password).await {
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
            Tab::Overview.done("two-factor-off")
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

/// The unrevoked remote device `hex` of the visitor, or the page that says there is none, or
/// that the account lacks direct connections, which every action on a device needs.
/// What a request does with one of the visitor's devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceAction {
    /// Revoking it: only removes trust, so it needs no service, and an account whose direct
    /// connections were turned off can still revoke a lost device.
    Revoke,
    /// Stopping its remote access or opening pairing: needs direct connections.
    Manage,
}

async fn own_device(
    state: &AppState,
    visitor: &Visitor,
    hex: &str,
    action: DeviceAction,
) -> Result<Device, Box<Response>> {
    if state.connect.is_none() {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    }
    if action == DeviceAction::Manage {
        needs_service(visitor, Tab::Direct)?;
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

/// `GET /account/devices/<endpoint id>/revoke`.
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
    let device = match own_device(&state, &visitor, &hex, DeviceAction::Revoke).await {
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

/// `POST /account/devices/<endpoint id>/revoke`: the device, and every introduced device
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
    let device = match own_device(&state, &visitor, &hex, DeviceAction::Revoke).await {
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
            Tab::Direct.done("device-revoked")
        }
        Err(err) => internal(&visitor, "revoke a device", &err),
    }
}

/// `POST /account/devices/<endpoint id>/sign-out`: stops remote access for a device that
/// is not lost, without revoking it (protocol 9.4). The device keeps its key, its pairings and
/// its place in the account, and can register again; the entry stays revocable.
pub async fn stop_remote_access(
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
    let device = match own_device(&state, &visitor, &hex, DeviceAction::Manage).await {
        Ok(device) => device,
        Err(response) => return *response,
    };
    let result = match &state.connect {
        // A running server also tells the other devices and ends the device's access at once.
        Some(connect) => connect.sign_out(&device, Actor::User).await,
        None => devices::leave(&state.db, device.id, Actor::User, db::unix_now())
            .await
            .map(|left| left.is_some()),
    };
    match result {
        Ok(_) => {
            tracing::info!(
                user = %visitor.user.username,
                device = %device.endpoint_id.short(),
                "user stopped remote access for a device"
            );
            Tab::Direct.done("device-signed-out")
        }
        Err(err) => internal(&visitor, "stop remote access", &err),
    }
}

/// `POST /account/devices/<endpoint id>/pairing`.
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
    let device = match own_device(&state, &visitor, &hex, DeviceAction::Manage).await {
        Ok(device) => device,
        Err(response) => return *response,
    };
    let until = db::unix_now() + devices::PAIRING_WINDOW_SECS;
    match devices::open_pairing(&state.db, visitor.user.user_id, device.endpoint_id, until).await {
        Ok(_) => Tab::Direct.done("pairing"),
        Err(err) => internal(&visitor, "allow pairing", &err),
    }
}

#[derive(Deserialize)]
pub struct DoneQuery {
    done: Option<String>,
    next: Option<String>,
    /// What went wrong on a round trip to a provider ([`methods::failure`]).
    failed: Option<String>,
}

/// The notice of `?done=<done>` on `tab`, after a change made with one of its forms.
fn notice(state: &AppState, t: &'static Text, tab: Tab, done: &str) -> Option<String> {
    let text = match (tab, done) {
        (Tab::Overview, "display-name") => t.notice_display_name,
        (Tab::Overview, "password") => t.notice_password_changed,
        (Tab::Overview, "two-factor-on") => t.notice_tf_on,
        (Tab::Overview, "two-factor-off") if state.remote_access_needs_two_factor() => {
            t.notice_tf_off
        }
        (Tab::Overview, "two-factor-off") => t.notice_tf_off_optional,
        (Tab::Overview, done) if done.starts_with("email-") => email::notice(t, done)?,
        (Tab::Overview, done) => return methods::notice(t, done),
        (Tab::Webdav, "revoked") => t.notice_revoked,
        (Tab::S3, done) => s3::notice(t, done)?,
        (Tab::Direct, "device-revoked") => t.notice_device_revoked,
        (Tab::Direct, "device-signed-out") => t.notice_device_signed_out,
        (Tab::Direct, "pairing") => t.notice_pairing_open,
        _ => return None,
    };
    Some(text.to_owned())
}

/// `GET` of `tab`, with the notice of its `?done=` and, on the overview, the `?next=` page
/// that turning on two-step verification continues to.
async fn show(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    query: DoneQuery,
    tab: Tab,
) -> Response {
    let visitor = match account_visitor(state, headers, uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let notice = query
        .done
        .as_deref()
        .and_then(|done| notice(state, visitor.t(), tab, done));
    let failed = query
        .failed
        .as_deref()
        .filter(|_| tab == Tab::Overview)
        .and_then(|failed| methods::failure(visitor.t(), failed));
    let options = PageOptions {
        tab,
        notice,
        failed,
        next: next_path(query.next.as_deref()),
        ..PageOptions::default()
    };
    render(state, &visitor, options).await
}

/// `GET /account/`.
pub async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DoneQuery>,
) -> Response {
    show(&state, &headers, &uri, query, Tab::Overview).await
}

/// `GET /account/webdav`.
pub async fn webdav_tab(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DoneQuery>,
) -> Response {
    show(&state, &headers, &uri, query, Tab::Webdav).await
}

/// `GET /account/s3`.
pub async fn s3_tab(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DoneQuery>,
) -> Response {
    show(&state, &headers, &uri, query, Tab::S3).await
}

/// `GET /account/direct`.
pub async fn direct_tab(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DoneQuery>,
) -> Response {
    show(&state, &headers, &uri, query, Tab::Direct).await
}

/// `GET /account/relay`.
pub async fn relay_tab(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DoneQuery>,
) -> Response {
    show(&state, &headers, &uri, query, Tab::Relay).await
}

/// `GET /account`.
pub async fn to_page() -> Response {
    Tab::Overview.back()
}

#[derive(Deserialize)]
pub struct DisplayNameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    display_name: String,
}

/// `POST /account/display-name`.
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
        let error = t.err_display_name.to_owned();
        return show_error(&state, &visitor, Tab::Overview, error).await;
    }
    match users::set_display_name(&state.db, &visitor.user.username, &form.display_name).await {
        Ok(_) => Tab::Overview.done("display-name"),
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

/// `POST /account/password`.
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
        async move { show_error(&state, visitor, Tab::Overview, message).await }
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
    if let Err(err) =
        users::set_password_hash(&state.db, &visitor.user.username, &hash, Actor::User).await
    {
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
    Tab::Overview.done("password")
}

#[derive(Deserialize)]
pub struct UsernameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    username: String,
}

/// `POST /account/username`: a new username for an account made by a sign-up that no device
/// or app signed in to yet (devices' pairing statements name the account by its username),
/// once a day.
pub async fn set_username(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<UsernameForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let Ok(username) = gono_server_core::Username::new(form.username.trim()) else {
        return show_error(&state, &visitor, Tab::Overview, t.err_username.to_owned()).await;
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let renamed = users::rename(
        &state.db,
        visitor.user.user_id,
        &username,
        Actor::User,
        Some(client),
        db::unix_now(),
    )
    .await;
    let error = match renamed {
        Ok(users::Renamed::Done) => {
            tracing::info!(%client, from = %visitor.user.username, to = %username, "username changed by its user");
            return Tab::Overview.done("username");
        }
        Ok(users::Renamed::Taken) => t.err_username_taken,
        Ok(users::Renamed::Locked) => t.err_username_locked,
        Ok(users::Renamed::TooSoon) => t.err_username_soon,
        Err(err) => return internal(&visitor, "username", &err),
    };
    show_error(&state, &visitor, Tab::Overview, error.to_owned()).await
}

#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

/// `POST /account/delete`: an account without a web login password asks for its deletion
/// (`plan/third-party-sign-in-design.md`, 4.6), after confirming it is you and typing its
/// username. It is disabled at once and deleted after 7 days unless a sign-in undoes it.
pub async fn delete_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<DeleteForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    if visitor.user.has_password || visitor.user.is_admin {
        return Tab::Overview.back();
    }
    if !state.web.is_confirmed(&visitor.user) {
        return show_error(
            &state,
            &visitor,
            Tab::Overview,
            t.password_set_confirm.to_owned(),
        )
        .await;
    }
    if form.confirm.trim() != visitor.user.username.as_str() {
        return show_error(
            &state,
            &visitor,
            Tab::Overview,
            t.err_delete_name.to_owned(),
        )
        .await;
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let now = db::unix_now();
    let until = match users::request_deletion(
        &state.db,
        visitor.user.user_id,
        Actor::User,
        Some(client),
        now,
    )
    .await
    {
        Ok(Some(until)) => until,
        Ok(None) => return Tab::Overview.back(),
        Err(err) => return internal(&visitor, "account deletion", &err),
    };
    tracing::info!(%client, user = %visitor.user.username, "account deletion requested by its user");
    state.web.end_pending_sign_ins(visitor.user.user_id);
    if let Some(connect) = &state.connect {
        connect.poke();
    }
    let chrome = Chrome::for_request(&headers);
    let lead = fill(t.deleted_lead, &[&when(visitor.lang(), now, until).0]);
    let mut response =
        web::Message::new(chrome, t.deleted_title, t.deleted_title, &lead).respond(StatusCode::OK);
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        state.web.removal_cookie(web::SESSION_COOKIE),
    );
    response
}

#[derive(Deserialize)]
pub struct FirstPasswordForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
}

/// `POST /account/password/set`: the first web login password of an account without one
/// (`plan/third-party-sign-in-design.md`, 5.4). It needs a confirmation of the session, by a
/// sign-in with one of the account's identities in the last [`web::CONFIRM_TTL_SECS`]; the
/// account's other sessions stay.
pub async fn set_first_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<FirstPasswordForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    if visitor.user.has_password {
        return Tab::Overview.back();
    }
    if !state.web.is_confirmed(&visitor.user) {
        let error = t.password_set_confirm.to_owned();
        return show_error(&state, &visitor, Tab::Overview, error).await;
    }
    if form.password != form.password_repeat {
        return show_error(
            &state,
            &visitor,
            Tab::Overview,
            t.err_passwords_differ.to_owned(),
        )
        .await;
    }
    let new = SecretString::from(form.password);
    if let Err(err) = password::check_policy(&new) {
        return show_error(&state, &visitor, Tab::Overview, core_message(t, &err)).await;
    }
    let hash = match tokio::task::spawn_blocking(move || password::hash(&new)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(err)) => return internal(&visitor, "password hash", &err),
        Err(err) => return internal(&visitor, "password hash", &err),
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match users::set_first_password(
        &state.db,
        visitor.user.user_id,
        &hash,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(true) => {
            tracing::info!(%client, user = %visitor.user.username, "first web login password set by its user");
            Tab::Overview.done("password-set")
        }
        Ok(false) => Tab::Overview.back(),
        Err(err) => internal(&visitor, "first password", &err),
    }
}

/// `POST /account/app-passwords`.
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
    if let Err(response) = needs_service(&visitor, Tab::Webdav) {
        return *response;
    }
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let form = fields.form();
    let (label, scopes, expires_at) = match parse_app_password(visitor.t(), &form, db::unix_now()) {
        Ok(parsed) => parsed,
        Err(error) => {
            let options = PageOptions {
                tab: Tab::Webdav,
                form,
                error: Some(error),
                ..PageOptions::default()
            };
            return render(&state, &visitor, options).await;
        }
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
        &visitor.user,
        NewAppPassword {
            label,
            token,
            scopes,
            expires_at,
        },
    );
    web::see_other(&format!("{ACCOUNT}/created"), &[])
}

/// `GET /account/created`: the new app password, once.
pub async fn created(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(created) = files.created.take(&visitor.user) else {
        return Tab::Webdav.back();
    };
    let t = visitor.t();
    let (server, webdav) = addresses(&state, &visitor);
    let page = CreatedPage {
        chrome: visitor.chrome(Nav::Account),
        username: visitor.user.username.to_string(),
        label: created.label,
        token: created.token.expose_secret().to_owned(),
        scopes: created.scopes.iter().map(ScopeChip::new).collect(),
        expiry: expiry(t, &visitor, db::unix_now(), created.expires_at),
        server,
        webdav,
    };
    web::render(StatusCode::OK, &page)
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /account/app-passwords/<id>/delete`.
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
    if let Err(response) = needs_service(&visitor, Tab::Webdav) {
        return *response;
    }
    // Only the user's own: the query names the owner.
    match app_passwords::delete(&state.db, visitor.user.user_id, id).await {
        Ok(_) => {
            tracing::info!(user = %visitor.user.username, app_password = id, "user revoked an app password");
            Tab::Webdav.done("revoked")
        }
        Err(err) => internal(&visitor, "revoke", &err),
    }
}
