//! The web admin UI, served under `admin.path` (default `/manage`) when `admin.enabled`.
//!
//! | Request | Page or action |
//! |---|---|
//! | `GET  <p>/login`, `POST <p>/login` | Sign in with the web login password (admins only). |
//! | `POST <p>/logout` | Sign out. |
//! | `GET  <p>/` | Overview of this server. |
//! | `GET  <p>/users` | All accounts. |
//! | `GET  <p>/new-user`, `POST <p>/users` | Create an account. |
//! | `GET  <p>/users/<name>` | One account with its app passwords. |
//! | `POST <p>/users/<name>/enable`, `.../disable` | Enable or disable the account. |
//! | `POST <p>/users/<name>/promote`, `.../demote` | Grant or withdraw admin access. |
//! | `POST <p>/users/<name>/display-name` | Change the display name. |
//! | `POST <p>/users/<name>/password` | Set the web login password. |
//! | `POST <p>/users/<name>/identities/<id>/unbind` | Unbind a third-party identity; refused for the last way in of an account without a password. |
//! | `GET  <p>/users/<name>/delete`, `POST` the same | Confirm and delete the account. |
//! | `POST <p>/users/<name>/app-passwords` | Create an app password, then show it once at `<p>/created`. |
//! | `POST <p>/users/<name>/app-passwords/<id>/delete` | Revoke an app password. |
//! | `POST <p>/users/<name>/s3/keys/<id>/delete` | Revoke an S3 access key (see [`s3`]). |
//! | `POST <p>/users/<name>/s3/buckets/<id>/private` | Make an S3 bucket private. |
//! | `POST <p>/users/<name>/s3/buckets/<id>/delete` | Remove an S3 bucket: the folder and its files stay. |
//!
//! The S3 requests answer 404 while the S3 API is off, and the user page shows S3 buckets and
//! access keys only while it is on.
//!
//! # Security
//!
//! - **Sign-in** uses the web login password through [`Web::verify_password`](crate::web::Web::verify_password) (Argon2, the
//!   shared failed-attempt limiter) and only accounts with the admin flag get a session. App
//!   passwords are never looked at, whether sent as Basic credentials or typed into the form.
//! - **Every page** needs a live session of an enabled admin (checked on each request, so a
//!   demoted or disabled admin is locked out at once). Pages carry the headers of
//!   [`crate::web`]: a strict CSP without scripts, `X-Frame-Options: DENY`, `no-store`.
//! - **Every change** is a POST with the session's CSRF token and a same-origin check, and is
//!   answered with a redirect (Post/Redirect/Get), so reloading a page never repeats it. Errors
//!   show the form again without changing anything.
//! - **New app passwords** are kept in memory, bound to the session that created them, and
//!   shown exactly once at `<p>/created` (`Cache-Control: no-store`); the URL carries no
//!   secret, so nothing sensitive reaches logs or history.
//! - **The last enabled admin** cannot be disabled, demoted or deleted
//!   ([`users::set_enabled`], [`users::set_admin`] and [`users::delete`] check it in the same
//!   transaction), and an admin cannot disable, demote or delete the account they are signed in
//!   with.

mod pages;
mod s3;

pub(crate) use self::pages::format_bytes;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Form, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gono_server_core::{
    Error as CoreError, Permission, RelPath, Username,
    app_passwords::{self, Scope},
    audit, db,
    devices::{self, Device, EndpointId, RevokedBy},
    password,
    services::Services,
    stats,
    users::{self, NewUser, User},
    web_sessions::{self, SessionUser},
};
use gono_server_nextcloud::{
    notify_push::{Endpoints, PushSettings},
    status,
};
use gono_server_relay::RelayStatus;
use ipnet::IpNet;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

pub(crate) use self::pages::{AppPasswordForm, ScopeChip};
use self::pages::{
    AppPasswordRow, CreatedPage, DeletePage, Fact, Feature, Frame, IdentityRow, LoginPage,
    MOUNT_ROWS, MessagePage, MountInput, NewUserPage, NotAdminPage, OverviewPage, RefusalRow,
    RelayDeviceRow, RelayPage, RelayView, RemoteDeviceRow, RevokeDevicePage, SessionRow, UserPage,
    UserRow, UserView, UsersPage,
};
use crate::{
    app::AppState,
    client_ip::client_ip,
    i18n::{Text, ago, count, duration, fill},
    service_view, site,
    web::{self, CSRF_COOKIE, Chrome, Nav, SESSION_COOKIE, Verified},
};

/// How long a new app password waits to be shown.
const CREATED_TTL: Duration = Duration::from_secs(10 * 60);

/// New app passwords waiting to be shown, at most.
const MAX_CREATED: usize = 1000;

/// Facts about the running server shown on the overview, collected at startup.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// Start of the process, UNIX seconds.
    pub started_at: i64,
    /// The instance id (`oc:id` suffix).
    pub instance_id: String,
    /// `server.bind`.
    pub bind: SocketAddr,
    /// `server.trusted_proxies`.
    pub trusted_proxies: Vec<IpNet>,
    /// The configuration file.
    pub config_path: PathBuf,
    /// Log level and destination.
    pub log: String,
    /// `storage.data_dir`.
    pub data_dir: PathBuf,
    /// `db.path` of a SQLite database; `None` for MySQL.
    pub db_path: Option<PathBuf>,
    /// The database as the overview names it: the SQLite file or the MySQL URL, which carries
    /// no password ([`gono_server_core::config::DbConfig::describe`]).
    pub database: String,
    /// Whether the data directory ignores case (`None`: could not be determined).
    pub case_insensitive: Option<bool>,
    /// `webdav.max_lock_timeout_secs`.
    pub lock_timeout_secs: u64,
    /// The notify_push settings, when enabled.
    pub push: Option<PushSettings>,
    /// The relay, when enabled.
    pub relay: Option<RelayStatus>,
    /// Configuration warnings to show.
    pub warnings: Vec<String>,
}

/// A new app password waiting to be shown once.
#[derive(Debug)]
struct Created {
    /// The admin account of the session that created it: should a session of another account
    /// ever get the same row id, it sees nothing.
    by: i64,
    username: String,
    label: String,
    token: SecretString,
    scopes: Vec<Scope>,
    expires_at: Option<i64>,
    until: Instant,
}

/// The admin UI's state.
#[derive(Debug)]
pub struct Admin {
    /// `admin.path`.
    prefix: String,
    info: ServerInfo,
    /// New app passwords by the id of the session that created them.
    created: Mutex<HashMap<i64, Created>>,
}

impl Admin {
    /// The admin UI under `prefix`.
    pub fn new(prefix: &str, info: ServerInfo) -> Self {
        Self {
            prefix: prefix.trim_end_matches('/').to_owned(),
            info,
            created: Mutex::new(HashMap::new()),
        }
    }

    /// The admin path.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.prefix)
    }

    fn user_url(&self, username: &str) -> String {
        format!("{}/users/{username}", self.prefix)
    }

    fn frame(&self, session: &Session, on_overview: bool, on_users: bool) -> Frame {
        Frame {
            prefix: self.prefix.clone(),
            on_overview,
            on_users,
            relay_tab: self.info.relay.is_some(),
            on_relay: false,
            csrf: session.csrf.clone(),
            version: env!("CARGO_PKG_VERSION"),
            nextcloud: status::version_string(),
            instance_id: self.info.instance_id.clone(),
        }
    }

    /// The frame of an admin page, in the browser's language.
    fn chrome(&self, state: &AppState, headers: &HeaderMap) -> Chrome {
        let mut chrome = Chrome::for_request(headers);
        chrome.nav = Nav::Admin;
        chrome.files = state.files.is_some();
        chrome.logout = self.url("/logout");
        chrome.here = self.url("/");
        chrome
    }

    fn remember(&self, session_id: i64, created: Created) {
        let now = Instant::now();
        let mut waiting = self
            .created
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        waiting.retain(|_, entry| entry.until > now);
        if waiting.len() >= MAX_CREATED {
            waiting.clear();
        }
        waiting.insert(session_id, created);
    }

    fn take(&self, session: &SessionUser) -> Option<Created> {
        let mut waiting = self
            .created
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !waiting
            .get(&session.session_id)
            .is_some_and(|entry| entry.by == session.user_id)
        {
            return None;
        }
        waiting
            .remove(&session.session_id)
            .filter(|entry| entry.until > Instant::now())
    }
}

/// The routes of the admin UI under its prefix.
pub fn routes(prefix: &str) -> Router<AppState> {
    let p = prefix.trim_end_matches('/');
    Router::new()
        .route(p, get(to_root))
        .route(&format!("{p}/"), get(overview))
        .route(&format!("{p}/login"), get(login_page).post(login))
        .route(&format!("{p}/logout"), post(logout))
        .route(&format!("{p}/users"), get(users_page).post(create_user))
        .route(&format!("{p}/relay"), get(relay_page))
        .route(&format!("{p}/new-user"), get(new_user_page))
        .route(&format!("{p}/users/{{name}}"), get(user_page))
        .route(&format!("{p}/users/{{name}}/enable"), post(enable))
        .route(&format!("{p}/users/{{name}}/services"), post(set_services))
        .route(&format!("{p}/users/{{name}}/disable"), post(disable))
        .route(&format!("{p}/users/{{name}}/promote"), post(promote))
        .route(&format!("{p}/users/{{name}}/demote"), post(demote))
        .route(
            &format!("{p}/users/{{name}}/display-name"),
            post(set_display_name),
        )
        .route(&format!("{p}/users/{{name}}/password"), post(set_password))
        .route(
            &format!("{p}/users/{{name}}/identities/{{id}}/unbind"),
            post(unbind_identity),
        )
        .route(
            &format!("{p}/users/{{name}}/delete"),
            get(delete_page).post(delete_user),
        )
        .route(
            &format!("{p}/users/{{name}}/app-passwords"),
            post(create_app_password),
        )
        .route(
            &format!("{p}/users/{{name}}/app-passwords/{{id}}/delete"),
            post(revoke_app_password),
        )
        .route(&format!("{p}/created"), get(created_page))
        .route(
            &format!("{p}/users/{{name}}/devices/{{id}}/revoke"),
            get(revoke_device_page).post(revoke_device),
        )
        .route(
            &format!("{p}/users/{{name}}/two-factor/reset"),
            post(reset_two_factor),
        )
        .route(
            &format!("{p}/users/{{name}}/s3/keys/{{id}}/delete"),
            post(s3::revoke_key),
        )
        .route(
            &format!("{p}/users/{{name}}/s3/buckets/{{id}}/private"),
            post(s3::make_bucket_private),
        )
        .route(
            &format!("{p}/users/{{name}}/s3/buckets/{{id}}/delete"),
            post(s3::remove_bucket),
        )
}

// ---------------------------------------------------------------------------------------------
// Sessions, CSRF and responses
// ---------------------------------------------------------------------------------------------

/// A signed-in admin.
struct Session {
    user: SessionUser,
    token: String,
    csrf: String,
    /// The frame of the admin's pages.
    chrome: Chrome,
}

/// The response a guard sends instead of the page (boxed: a `Response` is large).
type Halt = Box<Response>;

fn admin(state: &AppState) -> Result<Arc<Admin>, Halt> {
    state
        .admin
        .clone()
        .ok_or_else(|| Box::new(StatusCode::NOT_FOUND.into_response()))
}

/// `303 See Other` to `location`, with the page headers.
fn see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    web::secure_headers(response.headers_mut());
    response
}

/// The signed-in admin of the request, or the response to send instead: the sign-in page
/// for anonymous requests, a refusal for accounts without the admin flag.
async fn session(state: &AppState, admin: &Admin, headers: &HeaderMap) -> Result<Session, Halt> {
    let Some((user, token)) = state.web.session(headers).await else {
        return Err(Box::new(see_other(&admin.url("/login"))));
    };
    let csrf = state.web.session_csrf(&token);
    let mut chrome = admin.chrome(state, headers).signed_in(&user, &csrf);
    if !user.is_admin {
        let page = NotAdminPage {
            chrome,
            prefix: admin.prefix(),
            csrf: &csrf,
            username: user.username.as_str(),
        };
        return Err(Box::new(web::render(StatusCode::FORBIDDEN, &page)));
    }
    chrome.admin = Some(admin.prefix().to_owned());
    Ok(Session {
        user,
        token,
        csrf,
        chrome,
    })
}

/// Like [`session`], for form submissions: also checks the origin and the CSRF token.
async fn form_session(
    state: &AppState,
    admin: &Admin,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<Session, Halt> {
    if !state.web.same_origin(headers) {
        return Err(Box::new(site::blocked(headers, |t| t.from_other_site)));
    }
    let session = session(state, admin, headers).await?;
    if !state.web.check_session_csrf(&session.token, csrf) {
        return Err(Box::new(site::blocked(headers, |t| t.form_expired)));
    }
    Ok(session)
}

/// The error page of a request that failed on the server's side (logged).
fn internal_error(chrome: &Chrome, err: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %err, "admin request failed");
    let t = chrome.t;
    web::Message::new(chrome.clone(), t.error, t.error, t.error_lead)
        .respond(StatusCode::INTERNAL_SERVER_ERROR)
}

/// What an admin reads about a failed account change.
pub(crate) fn core_message(t: &Text, err: &CoreError) -> String {
    match err {
        CoreError::InvalidUsername { .. } => t.err_username.to_owned(),
        CoreError::InvalidDisplayName(_) => t.err_display_name.to_owned(),
        CoreError::InvalidPassword(reason) if reason.contains("at least") => {
            t.err_password_short.to_owned()
        }
        CoreError::InvalidPassword(_) => t.err_password_policy.to_owned(),
        CoreError::UserExists(name) => fill(t.err_user_exists, &[name.as_str()]),
        CoreError::UsernameRetired(name) => fill(t.err_username_retired, &[name.as_str()]),
        CoreError::LastAdmin(name) => fill(t.err_last_admin, &[name.as_str()]),
        CoreError::InvalidLabel(_) => t.err_label_invalid.to_owned(),
        CoreError::InvalidScopes(detail) => fill(t.err_scopes, &[detail]),
        CoreError::InvalidPath { path, .. } => fill(t.err_invalid_path, &[path]),
        other => other.to_string(),
    }
}

/// The account named in the URL, or a "not found" page.
async fn find_user(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    name: &str,
) -> Result<User, Halt> {
    let found = match Username::new(name) {
        Ok(username) => users::find(&state.db, &username)
            .await
            .map_err(|err| Box::new(internal_error(&session.chrome, &err)))?,
        Err(_) => None,
    };
    found.ok_or_else(|| {
        let page = MessagePage {
            chrome: session.chrome.clone(),
            frame: admin.frame(session, false, true),
            heading: session.chrome.t.a_no_such_user.to_owned(),
            lead: fill(session.chrome.t.a_no_such_user_lead, &[name]),
            link_href: admin.url("/users"),
            link_label: session.chrome.t.a_all_users.to_owned(),
        };
        Box::new(web::render(StatusCode::NOT_FOUND, &page))
    })
}

/// The form field every POST carries.
#[derive(Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `?done=<what>` after a redirect.
#[derive(Deserialize)]
struct Done {
    done: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------------------------

async fn to_root(State(state): State<AppState>) -> Response {
    match admin(&state) {
        Ok(admin) => see_other(&admin.url("/")),
        Err(halt) => *halt,
    }
}

fn login_form(
    state: &AppState,
    admin: &Admin,
    headers: &HeaderMap,
    status: StatusCode,
    user: &str,
    error: Option<&str>,
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let page = LoginPage {
        chrome: admin.chrome(state, headers),
        prefix: admin.prefix(),
        csrf: &csrf,
        user,
        error,
    };
    let mut response = web::render(status, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    if let Some((user, _)) = state.web.session(&headers).await
        && user.is_admin
    {
        return see_other(&admin.url("/"));
    }
    login_form(&state, &admin, &headers, StatusCode::OK, "", None)
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    let t = admin.chrome(&state, &headers).t;
    let user = form.user.trim().to_owned();
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        let error = t.form_expired_sign_in;
        return login_form(
            &state,
            &admin,
            &headers,
            StatusCode::FORBIDDEN,
            &user,
            Some(error),
        );
    }
    let client: IpAddr = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let password = SecretString::from(form.password);
    match state.web.verify_password(client, &user, password).await {
        Verified::Ok(account) if account.is_admin => {
            match state
                .web
                .start_session(client, &account, &admin.url("/"))
                .await
            {
                web::Started::Session(token) => {
                    let mut response = see_other(&admin.url("/"));
                    let headers = response.headers_mut();
                    headers.append(header::SET_COOKIE, state.web.session_cookie(&token));
                    headers.append(header::SET_COOKIE, state.web.removal_cookie(CSRF_COOKIE));
                    response
                }
                web::Started::SecondStep(cookie) => web::see_other(web::TWO_STEP_PATH, &[cookie]),
                web::Started::Unavailable => web::unavailable(admin.chrome(&state, &headers)),
            }
        }
        Verified::Ok(account) => {
            tracing::info!(%client, user = %account.username, "admin sign-in refused: not an admin");
            let error = t.a_not_admin_error;
            login_form(
                &state,
                &admin,
                &headers,
                StatusCode::FORBIDDEN,
                &user,
                Some(error),
            )
        }
        Verified::Invalid => {
            let error = t.wrong_password;
            login_form(
                &state,
                &admin,
                &headers,
                StatusCode::FORBIDDEN,
                &user,
                Some(error),
            )
        }
        Verified::RateLimited(wait) => web::too_many_attempts(admin.chrome(&state, &headers), wait),
        Verified::Unavailable => web::unavailable(admin.chrome(&state, &headers)),
    }
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    // Non-admin sessions may sign out here as well (see `NotAdminPage`).
    if let Some((_, token)) = state.web.session(&headers).await {
        if !state.web.check_session_csrf(&token, &form.csrf) {
            return site::blocked(&headers, |t| t.form_expired);
        }
        state.web.sign_out(&token).await;
    }
    let mut response = see_other(&admin.url("/login"));
    response
        .headers_mut()
        .append(header::SET_COOKIE, state.web.removal_cookie(SESSION_COOKIE));
    response
}

// ---------------------------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------------------------

/// The audit records the relay page lists, newest first, at most.
const RELAY_PAGE_RECORDS: i64 = 100;

/// `GET /relay`: the relay's settings and counters, the devices connected to it, the sessions
/// devices reported and the revoked devices that tried it (plan 3.2; protocol 11, 12).
async fn relay_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let mut frame = admin.frame(&session, false, false);
    frame.on_relay = true;
    let relay = match &admin.info.relay {
        None => None,
        Some(relay) => match relay_view(&state, session.chrome.t, relay).await {
            Ok(view) => Some(view),
            Err(err) => return internal_error(&session.chrome, &err),
        },
    };
    web::render(
        StatusCode::OK,
        &RelayPage {
            chrome: session.chrome,
            frame,
            relay,
        },
    )
}

async fn relay_view(
    state: &AppState,
    t: &'static Text,
    relay: &RelayStatus,
) -> gono_server_core::Result<RelayView> {
    let now = relay.snapshot();
    let records = audit::list_kinds(
        &state.db,
        &["session.started", "session.ended", "relay.refused_revoked"],
        RELAY_PAGE_RECORDS,
    )
    .await?;
    let usernames: HashMap<i64, String> = users::list(&state.db)
        .await?
        .into_iter()
        .map(|user| (user.id, user.username.to_string()))
        .collect();

    // The directory entries of every key the page names, read once each.
    let connected = relay.connected_devices();
    let mut entries: HashMap<EndpointId, Option<Device>> = HashMap::new();
    let mut keys: Vec<EndpointId> = connected
        .iter()
        .map(|(device, _)| EndpointId(*device.as_bytes()))
        .collect();
    for record in &records {
        keys.extend(record.device);
        keys.extend(record.peer);
    }
    for key in keys {
        if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(key) {
            slot.insert(devices::find(&state.db, key).await?);
        }
    }
    let name_of = |key: Option<EndpointId>| match key {
        None => String::new(),
        Some(key) => match entries.get(&key).and_then(Option::as_ref) {
            Some(device) => format!("{} ({})", device.name, key.short()),
            None => key.short(),
        },
    };
    let account_of = |user_id: Option<i64>| {
        user_id
            .and_then(|id| usernames.get(&id).cloned())
            .unwrap_or_default()
    };

    let devices = connected
        .iter()
        .map(|(device, connections)| {
            let key = EndpointId(*device.as_bytes());
            let entry = entries.get(&key).and_then(Option::as_ref);
            let registered = entry.filter(|entry| entry.is_active());
            RelayDeviceRow {
                name: entry.map_or_else(
                    || t.a_relay_not_registered.to_owned(),
                    |entry| entry.name.clone(),
                ),
                short: key.short(),
                what: entry.map_or_else(String::new, |entry| {
                    format!(
                        "{} · {}",
                        crate::login_flow::product_name(&entry.product),
                        crate::login_flow::platform_name(&entry.platform)
                    )
                }),
                account: entry.and_then(|entry| usernames.get(&entry.user_id).cloned()),
                control: entry.map(|entry| {
                    state
                        .connect
                        .as_ref()
                        .is_some_and(|connect| connect.is_online(entry.user_id, key))
                }),
                connections: *connections,
                // Admitted by the directory, or else by relay.allowed_endpoints.
                source: if registered.is_some() {
                    t.a_relay_source_registered
                } else {
                    t.a_relay_source_listed
                },
            }
        })
        .collect();

    let detail = |record: &audit::Entry, field: &str| -> Option<serde_json::Value> {
        serde_json::from_str::<serde_json::Value>(&record.details)
            .ok()
            .and_then(|details| details.get(field).cloned())
    };
    let text = |record: &audit::Entry, field: &str| {
        detail(record, field)
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    let bytes = |record: &audit::Entry, field: &str| {
        detail(record, field)
            .and_then(|value| value.as_u64())
            .map_or_else(|| "–".to_owned(), format_bytes)
    };
    let mut sessions = Vec::new();
    let mut refusals = Vec::new();
    for record in &records {
        match record.kind.as_str() {
            "relay.refused_revoked" => refusals.push(RefusalRow {
                when: pages::time(record.at),
                account: account_of(record.user_id),
                device: name_of(record.device),
            }),
            kind => {
                let ended = kind == "session.ended";
                let path = text(record, "path");
                sessions.push(SessionRow {
                    when: pages::time(record.at),
                    account: account_of(record.user_id),
                    device: name_of(record.device),
                    peer: name_of(record.peer),
                    service: text(record, "service"),
                    relayed: path != "direct",
                    path: match path.as_str() {
                        "direct" => t.a_relay_path_direct.to_owned(),
                        "relayed" => t.a_relay_path_relayed.to_owned(),
                        "mixed" => t.a_relay_path_mixed.to_owned(),
                        _ => path.clone(),
                    },
                    event: if ended {
                        t.a_relay_ended
                    } else {
                        t.a_relay_started
                    },
                    bytes: if ended {
                        format!(
                            "{} / {}",
                            bytes(record, "bytes_direct"),
                            bytes(record, "bytes_relayed")
                        )
                    } else {
                        String::new()
                    },
                });
            }
        }
    }

    let fact = |label: &'static str, value: String, mono: bool| Fact { label, value, mono };
    let listed = relay.listed_devices().to_string();
    let mut settings = vec![
        fact(
            t.a_relay_public_url,
            relay.public_url().as_str().to_owned(),
            true,
        ),
        fact(t.a_relay_listening, relay.http_addr().to_string(), true),
        fact(
            t.a_relay_qad,
            relay.qad_addr().map_or_else(
                || t.a_relay_qad_off.to_owned(),
                |addr| {
                    fill(
                        t.a_relay_qad_on,
                        &[&addr.to_string(), &now.qad_connections.to_string()],
                    )
                },
            ),
            false,
        ),
    ];
    if let Some(cert) = relay.tls_cert() {
        settings.push(fact(
            t.a_relay_certificate,
            fill(
                t.a_relay_cert_reload,
                &[
                    &cert.display().to_string(),
                    &duration(
                        t,
                        i64::try_from(relay.tls_reload_interval_secs()).unwrap_or(i64::MAX),
                    ),
                ],
            ),
            false,
        ));
    }
    settings.push(fact(
        t.a_relay_admission,
        if let Some(connect) = &state.connect {
            if connect.requires_two_factor() {
                fill(t.a_relay_admits_registered, &[&listed])
            } else {
                fill(t.a_relay_admits_registered_optional, &[&listed])
            }
        } else {
            fill(t.a_relay_admits_listed, &[&listed])
        },
        false,
    ));
    settings.push(fact(
        t.a_relay_rate_limit,
        relay.client_rate_limit().map_or_else(
            || t.a_relay_unlimited.to_owned(),
            |limit| fill(t.a_relay_per_second, &[&format_bytes(u64::from(limit))]),
        ),
        false,
    ));

    Ok(RelayView {
        host: relay.public_url().host_str().unwrap_or_default().to_owned(),
        running: relay.is_running(),
        settings,
        connections: now.connections,
        connections_note: fill(t.a_relay_connections_note, &[&now.devices.to_string()]),
        traffic: format_bytes(now.bytes_sent),
        traffic_note: fill(
            t.a_relay_traffic_note,
            &[
                &format_bytes(now.bytes_received),
                &format_bytes(now.bytes_sent),
            ],
        ),
        refused: now.denied,
        dropped: now.packets_dropped,
        dropped_note: fill(
            t.a_relay_dropped_note,
            &[&format_bytes(now.bytes_rate_limited)],
        ),
        devices,
        sessions,
        refusals,
    })
}

/// The relay's line among the features: its host name, the allowed devices connected now, what
/// it has carried and refused.
fn relay_feature(t: &'static Text, relay: Option<&RelayStatus>) -> Feature {
    let detail = match relay {
        None => t.a_relay_off.to_owned(),
        Some(relay) if !relay.is_running() => t.a_relay_stopped.to_owned(),
        Some(relay) => {
            let now = relay.snapshot();
            let mut detail = fill(
                t.a_relay_detail,
                &[
                    relay.public_url().host_str().unwrap_or_default(),
                    &now.devices.to_string(),
                    &relay.allowed_devices().to_string(),
                    &format_bytes(now.bytes_sent),
                    &now.denied.to_string(),
                ],
            );
            if relay.qad_addr().is_none() {
                detail.push_str(t.a_relay_no_qad);
            }
            detail
        }
    };
    Feature {
        name: t.a_relay,
        detail,
        on: relay.is_some_and(RelayStatus::is_running),
    }
}

async fn overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let t = session.chrome.t;
    let now = pages::now();
    let stats = match stats::overview(&state.db, now).await {
        Ok(stats) => stats,
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let info = &admin.info;

    let data_dir = info.data_dir.clone();
    let db_path = info.db_path.clone();
    let (disk, file_bytes) = tokio::task::spawn_blocking(move || {
        let disk = gono_server_dav::fs::disk_space(&data_dir);
        let file_size = |path: PathBuf| std::fs::metadata(path).map_or(0, |meta| meta.len());
        let db_bytes = db_path.map(|db_path| {
            let mut wal = db_path.clone().into_os_string();
            wal.push("-wal");
            file_size(db_path) + file_size(PathBuf::from(wal))
        });
        (disk, db_bytes)
    })
    .await
    .unwrap_or((None, None));
    // MySQL keeps its files to itself; it reports the size of the tables and indexes.
    let db_bytes = match file_bytes {
        Some(bytes) => bytes,
        None => db::size_on_server(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(0),
    };

    let (storage_number, storage_unit) = pages::split_bytes(stats.storage_used);
    let free_of_total = disk.map_or_else(
        || t.a_unknown.to_owned(),
        |(free, total)| fill(t.a_free_of, &[&format_bytes(free), &format_bytes(total)]),
    );
    let disk_note = disk.map_or_else(
        || t.a_free_unknown.to_owned(),
        |(free, total)| fill(t.a_free_note, &[&format_bytes(free), &format_bytes(total)]),
    );
    let push_live = state.push.as_ref().map(|hub| hub.connection_stats());
    let endpoints = state.push.as_ref().map(|_| Endpoints::new(&state.base_url));
    let origin = state.base_url.as_str().trim_end_matches('/').to_owned();
    let uptime = fill(t.a_up, &[&duration(t, now - info.started_at)]);
    let proxies = if info.trusted_proxies.is_empty() {
        t.a_none.to_owned()
    } else {
        info.trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let fact = |label: &'static str, value: String, mono: bool| Fact { label, value, mono };
    let server_facts = vec![
        fact(t.a_fact_version, env!("CARGO_PKG_VERSION").to_owned(), true),
        fact(t.a_fact_protocol, status::version_string(), true),
        fact(t.a_fact_instance, info.instance_id.clone(), true),
        fact(t.a_fact_started, pages::time(info.started_at), false),
        fact(t.a_fact_public_url, origin.clone(), true),
        fact(t.a_fact_listening, info.bind.to_string(), true),
        fact(t.a_fact_proxies, proxies, true),
        fact(
            t.a_fact_config,
            info.config_path.display().to_string(),
            true,
        ),
        fact(t.a_fact_log, info.log.clone(), true),
    ];
    let mut features = Vec::new();
    match &info.push {
        Some(push) => features.push(Feature {
            name: "notify_push",
            detail: fill(
                t.a_push_detail,
                &[
                    &push.ping_interval.as_secs().to_string(),
                    &push.debounce.as_secs().to_string(),
                    &push.max_connections_per_user.to_string(),
                ],
            ),
            on: true,
        }),
        None => features.push(Feature {
            name: "notify_push",
            detail: t.a_push_off_detail.to_owned(),
            on: false,
        }),
    }
    features.push(relay_feature(t, info.relay.as_ref()));
    features.push(Feature {
        name: "Login Flow v2",
        detail: count(
            t.a_flow_waiting_one,
            t.a_flows_waiting,
            stats.pending_login_flows,
            &[],
        ),
        on: true,
    });
    features.push(Feature {
        name: t.a_chunked,
        detail: fill(
            t.a_chunked_detail,
            &[&(gono_server_core::uploads::SESSION_TTL_SECS / 3600).to_string()],
        ),
        on: true,
    });
    features.push(Feature {
        name: t.a_locks,
        detail: fill(
            t.a_locks_detail,
            &[
                &duration(t, i64::try_from(info.lock_timeout_secs).unwrap_or(i64::MAX)),
                &stats.locks.to_string(),
            ],
        ),
        on: true,
    });
    features.push(Feature {
        name: t.a_web_files,
        detail: if state.files.is_some() {
            t.a_web_files_detail.to_owned()
        } else {
            t.a_web_files_off.to_owned()
        },
        on: state.files.is_some(),
    });
    features.push(Feature {
        name: t.a_web_admin,
        detail: count(t.a_session_one, t.a_sessions, stats.web_sessions, &[]),
        on: true,
    });
    let mut warnings = info.warnings.clone();
    if info.case_insensitive == Some(true) {
        warnings.push(t.a_case_warning.to_owned());
    }

    let page = OverviewPage {
        chrome: session.chrome.clone(),
        frame: admin.frame(&session, true, false),
        host: state.base_url.host_str().unwrap_or("Gono Cloud").to_owned(),
        uptime,
        warnings,
        users_note: count(
            t.a_admins_disabled_one,
            t.a_admins_disabled,
            stats.admins,
            &[&stats.disabled.to_string()],
        ),
        used_today: fill(
            t.a_used_today,
            &[&stats.app_passwords_used_today.to_string()],
        ),
        push_note: push_live.map_or_else(String::new, |(_, users)| {
            count(t.a_user_connected, t.a_users_connected, users, &[])
        }),
        storage_number,
        storage_unit: storage_unit.to_owned(),
        // The files' share of the file system they live on.
        disk: disk.map(|(_, total)| (stats.storage_used.min(total), total)),
        disk_note,
        push_live,
        server_facts,
        server_address: origin.clone(),
        webdav_url: format!("{origin}/remote.php/dav/files/<username>/"),
        websocket: endpoints.map(|endpoints| endpoints.websocket),
        data_dir: info.data_dir.display().to_string(),
        case_insensitive: info.case_insensitive,
        storage_used: format_bytes(stats.storage_used),
        free_of_total,
        database: info.database.clone(),
        db_size: format_bytes(db_bytes),
        features,
        stats,
    };
    web::render(StatusCode::OK, &page)
}

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

async fn users_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(done): Query<Done>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let (accounts, counts) =
        match tokio::try_join!(users::list(&state.db), stats::per_user(&state.db)) {
            Ok(result) => result,
            Err(err) => return internal_error(&session.chrome, &err),
        };
    let admins = accounts
        .iter()
        .filter(|user| user.is_admin && user.enabled)
        .count();
    let disabled = accounts.iter().filter(|user| !user.enabled).count();
    let t = session.chrome.t;
    let admins_text = count(t.a_admin_one, t.a_admins, admins, &[]);
    let summary = count(
        t.a_accounts_summary_one,
        t.a_accounts_summary,
        accounts.len(),
        &[&admins_text, &disabled.to_string()],
    );
    let rows = accounts
        .into_iter()
        .map(|user| {
            let counts = counts.get(&user.id).copied().unwrap_or_default();
            UserRow {
                username: user.username.to_string(),
                display_name: user.display_name,
                is_admin: user.is_admin,
                enabled: user.enabled,
                app_passwords: counts.app_passwords,
                storage: format_bytes(counts.storage_used),
                created: pages::date(user.created_at),
                services: service_view::summary(t, user.services),
            }
        })
        .collect();
    let notice = match done.done.as_deref() {
        Some("deleted") => Some(t.a_deleted_notice.to_owned()),
        _ => None,
    };
    let page = UsersPage {
        chrome: session.chrome.clone(),
        frame: admin.frame(&session, false, true),
        notice,
        summary,
        users: rows,
    };
    web::render(StatusCode::OK, &page)
}

async fn new_user_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let page = NewUserPage {
        chrome: session.chrome.clone(),
        frame: admin.frame(&session, false, true),
        error: None,
        username: String::new(),
        display_name: String::new(),
        admin: false,
    };
    web::render(StatusCode::OK, &page)
}

#[derive(Deserialize)]
struct NewUserForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
    #[serde(default)]
    admin: Option<String>,
}

/// Checks a new web login password and its repetition, then hashes it off the runtime.
async fn new_password_hash(t: &Text, password: String, repeat: &str) -> Result<String, String> {
    if password != repeat {
        return Err(t.a_passwords_differ.to_owned());
    }
    let password = SecretString::from(password);
    password::check_policy(&password).map_err(|err| core_message(t, &err))?;
    tokio::task::spawn_blocking(move || password::hash(&password))
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.to_string())
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NewUserForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let is_admin = form.admin.is_some();
    let show_error = |error: String| {
        let page = NewUserPage {
            chrome: session.chrome.clone(),
            frame: admin.frame(&session, false, true),
            error: Some(error),
            username: form.username.trim().to_owned(),
            display_name: form.display_name.trim().to_owned(),
            admin: is_admin,
        };
        web::render(StatusCode::UNPROCESSABLE_ENTITY, &page)
    };
    let username = match Username::new(form.username.trim()) {
        Ok(username) => username,
        Err(err) => return show_error(core_message(session.chrome.t, &err)),
    };
    let display_name = match users::display_name_or_default(
        Some(form.display_name.trim()).filter(|name| !name.is_empty()),
        &username,
    ) {
        Ok(name) => name,
        Err(err) => return show_error(core_message(session.chrome.t, &err)),
    };
    match users::find(&state.db, &username).await {
        Ok(Some(_)) => {
            return show_error(fill(session.chrome.t.err_user_exists, &[username.as_str()]));
        }
        Ok(None) => {}
        Err(err) => return internal_error(&session.chrome, &err),
    }
    let hash = match new_password_hash(
        session.chrome.t,
        form.password.clone(),
        &form.password_repeat,
    )
    .await
    {
        Ok(hash) => hash,
        Err(error) => return show_error(error),
    };
    let layout = state.dav.fs().layout().clone();
    let created = users::create(
        &state.db,
        &NewUser {
            username: &username,
            display_name: &display_name,
            password_hash: &hash,
            is_admin,
            services: Services::NONE,
        },
        |id| layout.create_user(id),
    )
    .await;
    match created {
        Ok(id) => {
            tracing::info!(by = %session.user.username, user = %username, id, is_admin, "admin created a user");
            see_other(&format!(
                "{}?done=created",
                admin.user_url(username.as_str())
            ))
        }
        Err(
            err @ (CoreError::UserExists(_)
            | CoreError::UsernameRetired(_)
            | CoreError::UserDirNotEmpty { .. }),
        ) => show_error(core_message(session.chrome.t, &err)),
        Err(err) => internal_error(&session.chrome, &err),
    }
}

/// What the user detail page shows besides the account itself.
struct UserPageOptions {
    notice: Option<String>,
    error: Option<String>,
    form: AppPasswordForm,
    status: StatusCode,
}

impl Default for UserPageOptions {
    fn default() -> Self {
        Self {
            notice: None,
            error: None,
            form: AppPasswordForm::default(),
            status: StatusCode::OK,
        }
    }
}

/// The user detail page.
async fn user_page_response(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    user: &User,
    options: UserPageOptions,
) -> Response {
    let UserPageOptions {
        notice,
        error,
        form,
        status,
    } = options;
    let passwords = match app_passwords::list(&state.db, user.id).await {
        Ok(passwords) => passwords,
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let storage = match stats::per_user(&state.db).await {
        Ok(counts) => {
            counts
                .get(&user.id)
                .copied()
                .unwrap_or_default()
                .storage_used
        }
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let two_factor_status = match gono_server_core::two_factor::status(&state.db, user.id).await {
        Ok(status) => status,
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let email = match gono_server_core::email::address(&state.db, user.id).await {
        Ok(email) => email,
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let identities = match gono_server_core::identities::list(&state.db, user.id).await {
        Ok(identities) => identities,
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let t = session.chrome.t;
    let now = pages::now();
    let app_passwords = passwords
        .into_iter()
        .map(|password| AppPasswordRow {
            id: password.id,
            label: password.label,
            created: fill(t.created, &[&pages::date(password.created_at)]),
            scopes: password.scopes.iter().map(ScopeChip::new).collect(),
            last_used: password.last_used_at.map_or_else(
                || t.never_used.to_owned(),
                |at| ago(t, now, at, pages::date),
            ),
            expiry: pages::expiry(t, password.expires_at, now),
        })
        .collect();
    let s3 = match &state.s3 {
        Some(ui) => match s3::user_view(state, t, ui, user.id, now).await {
            Ok(view) => Some(view),
            Err(err) => return internal_error(&session.chrome, &err),
        },
        None => None,
    };
    let remote = match &state.connect {
        Some(connect) => match connect.devices_with_presence(user.id).await {
            Ok(listed) => Some(
                listed
                    .iter()
                    .map(|(device, online)| remote_row(t, device, *online, now))
                    .collect(),
            ),
            Err(err) => return internal_error(&session.chrome, &err),
        },
        None => None,
    };
    let page = UserPage {
        chrome: session.chrome.clone(),
        frame: admin.frame(session, false, true),
        base: admin.user_url(user.username.as_str()),
        notice,
        error,
        user: UserView {
            id: user.id,
            username: user.username.to_string(),
            display_name: user.display_name.clone(),
            is_admin: user.is_admin,
            enabled: user.enabled,
            created: pages::time(user.created_at),
            updated: pages::time(user.updated_at),
            storage: format_bytes(storage),
            two_factor: match two_factor_status {
                Some(status) => fill(t.a_tf_on, &[&pages::date(status.enabled_at)]),
                None => t.a_tf_off.to_owned(),
            },
            two_factor_on: two_factor_status.is_some(),
            email: email.unwrap_or_else(|| t.a_email_none.to_owned()),
            has_password: user.has_password,
            // Every identity of the account, also of a WeChat mini program configured before:
            // an admin sees what a change of `wechat.app_id` left behind.
            identities: identities
                .iter()
                .map(|identity| IdentityRow {
                    id: identity.id,
                    provider: crate::files::account::methods::provider_name(t, identity.provider),
                    label: if identity.provider == gono_server_core::identities::Provider::WeChat {
                        identity.realm.clone()
                    } else {
                        identity.label.clone()
                    },
                    since: fill(
                        t.a_identity_since,
                        &[
                            &pages::date(identity.created_at),
                            &ago(t, now, identity.last_seen_at, pages::date),
                        ],
                    ),
                })
                .collect(),
            services: service_view::rows(t, state, user.services),
        },
        is_self: user.id == session.user.user_id,
        delete_label: fill(t.a_delete_named, &[user.username.as_str()]),
        app_passwords,
        form,
        remote,
        s3,
    };
    web::render(status, &page)
}

/// After an admin disabled or deleted account `user_id`, set its password or reset its
/// two-step verification: its sign-ins waiting for their second step end, and remote access
/// looks at the account again at once.
fn account_changed(state: &AppState, user_id: i64) {
    state.web.end_pending_sign_ins(user_id);
    if let Some(connect) = &state.connect {
        connect.poke();
    }
}

/// `POST <admin>/users/<name>/two-factor/reset`.
async fn reset_two_factor(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match gono_server_core::two_factor::disable(
        &state.db,
        user.id,
        gono_server_core::two_factor::TurnedOff::Admin,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(_) => {
            tracing::info!(by = %session.user.username, user = %user.username, "admin reset two-step verification");
            account_changed(&state, user.id);
            see_other(&format!(
                "{}?done=two-factor-reset",
                admin.user_url(user.username.as_str())
            ))
        }
        Err(err) => internal_error(&session.chrome, &err),
    }
}

/// A device registered for remote access, as the admin UI lists it.
fn remote_row(t: &Text, device: &Device, online: bool, now: i64) -> RemoteDeviceRow {
    let status = match (
        device.revoked_at,
        device.left_at,
        online,
        device.last_seen_at,
    ) {
        (Some(at), _, _, _) => fill(t.revoked_on, &[&pages::date(at)]),
        (None, Some(at), _, _) => fill(t.signed_out_on, &[&pages::date(at)]),
        (None, None, true, _) => t.online.to_owned(),
        (None, None, false, Some(at)) => fill(t.last_seen, &[&ago(t, now, at, pages::date)]),
        (None, None, false, None) => t.never_connected.to_owned(),
    };
    RemoteDeviceRow {
        hex: device.endpoint_id.to_hex(),
        name: device.name.clone(),
        what: format!(
            "{} · {}",
            crate::login_flow::product_name(&device.product),
            crate::login_flow::platform_name(&device.platform)
        ),
        short: device.endpoint_id.short(),
        status,
        revoked: device.is_revoked(),
    }
}

/// The unrevoked remote device `hex` of `user`, or the page that says there is none.
async fn user_device(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    user: &User,
    hex: &str,
) -> Result<Device, Box<Response>> {
    let missing = || {
        let page = MessagePage {
            chrome: session.chrome.clone(),
            frame: admin.frame(session, false, true),
            heading: session.chrome.t.not_found.to_owned(),
            lead: session.chrome.t.not_found_lead.to_owned(),
            link_href: admin.user_url(user.username.as_str()),
            link_label: user.username.to_string(),
        };
        Box::new(web::render(StatusCode::NOT_FOUND, &page))
    };
    if state.connect.is_none() {
        return Err(missing());
    }
    let key = EndpointId::parse(hex).ok_or_else(missing)?;
    match devices::find(&state.db, key).await {
        Ok(Some(device)) if device.user_id == user.id && !device.is_revoked() => Ok(device),
        Ok(_) => Err(missing()),
        Err(err) => Err(Box::new(internal_error(&session.chrome, &err))),
    }
}

/// `GET <admin>/users/<name>/devices/<endpoint id>/revoke`: the second confirmation.
async fn revoke_device_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, hex)): Path<(String, String)>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let device = match user_device(&state, &admin, &session, &user, &hex).await {
        Ok(device) => device,
        Err(halt) => return *halt,
    };
    let introduced = match devices::introduced_by(&state.db, device.id).await {
        Ok(introduced) => introduced,
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let online = state
        .connect
        .as_ref()
        .is_some_and(|connect| connect.is_online(user.id, device.endpoint_id));
    let page = RevokeDevicePage {
        chrome: session.chrome.clone(),
        frame: admin.frame(&session, false, true),
        base: admin.user_url(user.username.as_str()),
        username: user.username.to_string(),
        device: remote_row(session.chrome.t, &device, online, pages::now()),
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

/// `POST <admin>/users/<name>/devices/<endpoint id>/revoke`: the device, and every introduced
/// device ticked as `also_<endpoint id>`.
async fn revoke_device(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((name, hex)): Path<(String, String)>,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let csrf = fields.get("csrf").cloned().unwrap_or_default();
    let session = match form_session(&state, &admin, &headers, &csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let device = match user_device(&state, &admin, &session, &user, &hex).await {
        Ok(device) => device,
        Err(halt) => return *halt,
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
        user.id,
        &keys,
        RevokedBy::Admin,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(revoked) => {
            for device in &revoked {
                tracing::info!(
                    by = %session.user.username,
                    user = %user.username,
                    device = %device.endpoint_id.short(),
                    "admin revoked a device"
                );
            }
            if let Some(connect) = &state.connect {
                connect.poke();
            }
            see_other(&format!(
                "{}?done=device-revoked",
                admin.user_url(user.username.as_str())
            ))
        }
        Err(err) => internal_error(&session.chrome, &err),
    }
}

async fn user_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(done): Query<Done>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let t = session.chrome.t;
    let name = user.username.as_str();
    let notice = match done.done.as_deref() {
        Some("created") => Some(fill(t.a_notice_created, &[name])),
        Some("enabled") => Some(t.a_notice_enabled.to_owned()),
        Some("services") => Some(t.a_notice_services.to_owned()),
        Some("disabled") => Some(t.a_notice_disabled.to_owned()),
        Some("promoted") => Some(fill(t.a_notice_promoted, &[name])),
        Some("demoted") => Some(fill(t.a_notice_demoted, &[name])),
        Some("renamed") => Some(t.a_notice_renamed.to_owned()),
        Some("password") => Some(t.a_notice_password.to_owned()),
        Some("unbound") => Some(t.a_notice_unbound.to_owned()),
        Some("device-revoked") => Some(t.notice_device_revoked.to_owned()),
        Some("two-factor-reset") if state.remote_access_needs_two_factor() => {
            Some(t.a_notice_tf_reset.to_owned())
        }
        Some("two-factor-reset") => Some(t.a_notice_tf_reset_optional.to_owned()),
        Some("revoked") => Some(t.notice_revoked.to_owned()),
        Some("s3-key-revoked") => Some(t.s3_notice_key_revoked.to_owned()),
        Some("s3-bucket-private") => Some(t.a_s3_notice_private.to_owned()),
        Some("s3-bucket-removed") => Some(t.s3_notice_bucket_removed.to_owned()),
        _ => None,
    };
    let options = UserPageOptions {
        notice,
        ..UserPageOptions::default()
    };
    user_page_response(&state, &admin, &session, &user, options).await
}

/// Shows the user page again with an error, without changing anything.
async fn user_error(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    user: &User,
    status: StatusCode,
    error: String,
) -> Response {
    let options = UserPageOptions {
        error: Some(error),
        status,
        ..UserPageOptions::default()
    };
    user_page_response(state, admin, session, user, options).await
}

async fn enable(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_enabled(state, headers, name, form, true).await
}

async fn disable(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_enabled(state, headers, name, form, false).await
}

/// The form of `POST <admin>/users/<name>/services`: a checkbox per service, present when on.
#[derive(Deserialize)]
struct ServicesForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    files: Option<String>,
    #[serde(default)]
    webdav: Option<String>,
    #[serde(default)]
    s3: Option<String>,
    #[serde(default)]
    direct: Option<String>,
    #[serde(default)]
    relay: Option<String>,
}

/// `POST <admin>/users/<name>/services`: sets the services of an account. Admins may change
/// their own too, which is how the first admin gets any. The relay brings direct connections
/// along. Every switch takes effect at the account's next request; the control channel and the
/// relay hear of it at once (`account_changed`).
async fn set_services(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<ServicesForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let services = Services {
        files: form.files.is_some(),
        webdav: form.webdav.is_some(),
        s3: form.s3.is_some(),
        direct: form.direct.is_some(),
        relay: form.relay.is_some(),
    };
    let stored = match users::set_services(&state.db, &user.username, services).await {
        Ok(stored) => stored,
        Err(err) => return internal_error(&session.chrome, &err),
    };
    account_changed(&state, user.id);
    tracing::info!(
        by = %session.user.username,
        user = %user.username,
        services = %stored,
        "admin changed the services of an account"
    );
    see_other(&format!(
        "{}?done=services",
        admin.user_url(user.username.as_str())
    ))
}

async fn set_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
    enabled: bool,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    if !enabled && user.id == session.user.user_id {
        let error = session.chrome.t.a_cannot_disable_self.to_owned();
        return user_error(&state, &admin, &session, &user, StatusCode::CONFLICT, error).await;
    }
    match users::set_enabled(&state.db, &user.username, enabled).await {
        Ok(()) => {}
        Err(err @ CoreError::LastAdmin(_)) => {
            return user_error(
                &state,
                &admin,
                &session,
                &user,
                StatusCode::CONFLICT,
                core_message(session.chrome.t, &err),
            )
            .await;
        }
        Err(err) => return internal_error(&session.chrome, &err),
    }
    if !enabled {
        if let Err(err) = web_sessions::delete_for_user(&state.db, user.id, None).await {
            tracing::warn!(error = %err, "cannot end the browser sessions of a disabled account");
        }
        account_changed(&state, user.id);
    }
    tracing::info!(by = %session.user.username, user = %user.username, enabled, "admin changed an account");
    let done = if enabled { "enabled" } else { "disabled" };
    see_other(&format!(
        "{}?done={done}",
        admin.user_url(user.username.as_str())
    ))
}

async fn promote(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_admin(state, headers, name, form, true).await
}

async fn demote(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_admin(state, headers, name, form, false).await
}

async fn set_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
    is_admin: bool,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    // Another admin has to do it, so that nobody locks themself out by accident.
    if !is_admin && user.id == session.user.user_id {
        let error = session.chrome.t.a_cannot_demote_self.to_owned();
        return user_error(&state, &admin, &session, &user, StatusCode::CONFLICT, error).await;
    }
    match users::set_admin(&state.db, &user.username, is_admin).await {
        Ok(()) => {}
        Err(err @ CoreError::LastAdmin(_)) => {
            return user_error(
                &state,
                &admin,
                &session,
                &user,
                StatusCode::CONFLICT,
                core_message(session.chrome.t, &err),
            )
            .await;
        }
        Err(err) => return internal_error(&session.chrome, &err),
    }
    tracing::info!(by = %session.user.username, user = %user.username, is_admin, "admin changed an account's role");
    let done = if is_admin { "promoted" } else { "demoted" };
    see_other(&format!(
        "{}?done={done}",
        admin.user_url(user.username.as_str())
    ))
}

#[derive(Deserialize)]
struct DisplayNameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    display_name: String,
}

async fn set_display_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<DisplayNameForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    match users::set_display_name(&state.db, &user.username, &form.display_name).await {
        Ok(_) => {}
        Err(err @ CoreError::InvalidDisplayName(_)) => {
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            let error = core_message(session.chrome.t, &err);
            return user_error(&state, &admin, &session, &user, status, error).await;
        }
        Err(err) => return internal_error(&session.chrome, &err),
    }
    tracing::info!(by = %session.user.username, user = %user.username, "admin changed a display name");
    see_other(&format!(
        "{}?done=renamed",
        admin.user_url(user.username.as_str())
    ))
}

#[derive(Deserialize)]
struct PasswordForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
}

async fn set_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<PasswordForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let hash = match new_password_hash(session.chrome.t, form.password, &form.password_repeat).await
    {
        Ok(hash) => hash,
        Err(error) => {
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            return user_error(&state, &admin, &session, &user, status, error).await;
        }
    };
    if let Err(err) =
        users::set_password_hash(&state.db, &user.username, &hash, audit::Actor::Admin).await
    {
        return internal_error(&session.chrome, &err);
    }
    // Sign the user out everywhere else; an admin changing their own password stays in.
    let keep = (user.id == session.user.user_id).then_some(session.user.session_id);
    if let Err(err) = web_sessions::delete_for_user(&state.db, user.id, keep).await {
        tracing::warn!(error = %err, "cannot end the browser sessions after a password change");
    }
    account_changed(&state, user.id);
    tracing::info!(by = %session.user.username, user = %user.username, "admin set a web login password");
    see_other(&format!(
        "{}?done=password",
        admin.user_url(user.username.as_str())
    ))
}

/// `POST <admin>/users/<name>/identities/<id>/unbind`: unbinds a third-party identity of the
/// account, and with a WeChat identity its mini program sessions. The last way in of an account
/// without a web password stays: the admin sets a password first.
async fn unbind_identity(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    use gono_server_core::identities::{self, How, Unbound, Which};
    match identities::unbind(
        &state.db,
        user.id,
        Which::Id(id),
        How::Admin,
        audit::Actor::Admin,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(Unbound::Done(identity)) => {
            tracing::info!(
                by = %session.user.username,
                user = %user.username,
                provider = identity.provider.as_str(),
                "admin unbound an identity"
            );
            see_other(&format!(
                "{}?done=unbound",
                admin.user_url(user.username.as_str())
            ))
        }
        Ok(Unbound::NotBound) => see_other(&admin.user_url(user.username.as_str())),
        Ok(Unbound::LastSignIn) => {
            let error = session.chrome.t.a_err_last_sign_in.to_owned();
            user_error(&state, &admin, &session, &user, StatusCode::CONFLICT, error).await
        }
        Err(err) => internal_error(&session.chrome, &err),
    }
}

async fn delete_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    delete_confirmation(&state, &admin, &session, &user, None, StatusCode::OK).await
}

async fn delete_confirmation(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    user: &User,
    error: Option<String>,
    status: StatusCode,
) -> Response {
    let app_passwords = match stats::per_user(&state.db).await {
        Ok(counts) => {
            counts
                .get(&user.id)
                .copied()
                .unwrap_or_default()
                .app_passwords
        }
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let t = session.chrome.t;
    let error = error
        .or_else(|| (user.id == session.user.user_id).then(|| t.a_cannot_delete_self.to_owned()));
    let page = DeletePage {
        chrome: session.chrome.clone(),
        frame: admin.frame(session, false, true),
        base: admin.user_url(user.username.as_str()),
        username: user.username.to_string(),
        title: fill(t.a_delete_question, &[user.username.as_str()]),
        effect: count(t.a_delete_effect_one, t.a_delete_effect, app_passwords, &[]),
        error,
    };
    web::render(status, &page)
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    if user.id == session.user.user_id {
        return delete_confirmation(&state, &admin, &session, &user, None, StatusCode::CONFLICT)
            .await;
    }
    let deleted = match users::delete(&state.db, &user.username).await {
        Ok(deleted) => deleted,
        Err(err @ CoreError::LastAdmin(_)) => {
            let error = Some(core_message(session.chrome.t, &err));
            return delete_confirmation(
                &state,
                &admin,
                &session,
                &user,
                error,
                StatusCode::CONFLICT,
            )
            .await;
        }
        Err(err) => return internal_error(&session.chrome, &err),
    };
    account_changed(&state, deleted.id);
    let layout = state.dav.fs().layout().clone();
    let retired = tokio::task::spawn_blocking(move || {
        layout.retire_user(deleted.id, deleted.username.as_str(), db::unix_now())
    })
    .await;
    match retired {
        Ok(Ok(target)) => tracing::info!(
            by = %session.user.username,
            user = %user.username,
            files = ?target,
            "admin deleted a user"
        ),
        Ok(Err(err)) => tracing::warn!(
            user = %user.username,
            error = %err,
            "user deleted, but their files could not be moved to deleted/"
        ),
        Err(err) => tracing::warn!(error = %err, "user deleted, moving their files failed"),
    }
    see_other(&format!("{}?done=deleted", admin.url("/users")))
}

// ---------------------------------------------------------------------------------------------
// App passwords
// ---------------------------------------------------------------------------------------------

/// The new app password form. Mount rows are numbered fields (`mount_1`, `storage_1`,
/// `perm_1`, ...), collected by [`AppPasswordFields::form`].
pub(crate) struct AppPasswordFields {
    pub(crate) fields: HashMap<String, String>,
}

impl AppPasswordFields {
    pub(crate) fn field(&self, name: &str) -> String {
        self.fields
            .get(name)
            .map_or_else(String::new, |value| value.trim().to_owned())
    }

    pub(crate) fn form(&self) -> AppPasswordForm {
        AppPasswordForm {
            label: self.field("label"),
            expires_in_days: self.field("expires_in_days"),
            access: match self.field("access").as_str() {
                access @ ("view" | "custom") => access.to_owned(),
                _ => "full".to_owned(),
            },
            mounts: (1..=MOUNT_ROWS)
                .map(|row| MountInput {
                    mount: self.field(&format!("mount_{row}")),
                    storage: self.field(&format!("storage_{row}")),
                    permission: self.field(&format!("perm_{row}")),
                })
                .collect(),
        }
    }
}

/// The expiry of a new app password or S3 access key from a number of days (1 to 3650) after
/// `now`; empty means it never expires.
pub(crate) fn parse_expiry(t: &Text, days: &str, now: i64) -> Result<Option<i64>, String> {
    if days.is_empty() {
        return Ok(None);
    }
    let days: i64 = days
        .parse()
        .ok()
        .filter(|days| (1..=3650).contains(days))
        .ok_or_else(|| t.err_expiry.to_owned())?;
    Ok(Some(now + days * 86_400))
}

/// Validates the form: label, expiry and scopes.
pub(crate) fn parse_app_password(
    t: &Text,
    form: &AppPasswordForm,
    now: i64,
) -> Result<(String, Vec<Scope>, Option<i64>), String> {
    let label = app_passwords::check_label(&form.label).map_err(|err| core_message(t, &err))?;
    let expires_at = parse_expiry(t, &form.expires_in_days, now)?;
    let path = |value: &str| RelPath::parse(value).map_err(|_| fill(t.err_invalid_path, &[value]));
    let scopes = match form.access.as_str() {
        "view" => vec![Scope {
            permission: Permission::View,
            ..Scope::full_access()
        }],
        "custom" => {
            let mut scopes = Vec::new();
            for mount in &form.mounts {
                if mount.mount.is_empty() && mount.storage.is_empty() {
                    continue;
                }
                if mount.mount.is_empty() || mount.storage.is_empty() {
                    return Err(t.err_mount_paths.to_owned());
                }
                scopes.push(Scope {
                    mount_path: path(&mount.mount)?,
                    storage_path: path(&mount.storage)?,
                    permission: if mount.permission == "full" {
                        Permission::Full
                    } else {
                        Permission::View
                    },
                });
            }
            if scopes.is_empty() {
                return Err(t.err_no_mounts.to_owned());
            }
            app_passwords::check_scopes(scopes).map_err(|err| core_message(t, &err))?
        }
        _ => vec![Scope::full_access()],
    };
    Ok((label, scopes, expires_at))
}

async fn create_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let fields = AppPasswordFields { fields };
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &fields.field("csrf")).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let form = fields.form();
    let now = pages::now();
    let (label, scopes, expires_at) = match parse_app_password(session.chrome.t, &form, now) {
        Ok(parsed) => parsed,
        Err(error) => {
            let options = UserPageOptions {
                error: Some(error),
                form,
                status: StatusCode::UNPROCESSABLE_ENTITY,
                ..UserPageOptions::default()
            };
            return user_page_response(&state, &admin, &session, &user, options).await;
        }
    };
    let (id, token) =
        match app_passwords::create(&state.db, user.id, &label, scopes.clone(), expires_at).await {
            Ok(created) => created,
            Err(err) => return internal_error(&session.chrome, &err),
        };
    tracing::info!(by = %session.user.username, user = %user.username, app_password = id, "admin created an app password");
    admin.remember(
        session.user.session_id,
        Created {
            by: session.user.user_id,
            username: user.username.to_string(),
            label,
            token,
            scopes,
            expires_at,
            until: Instant::now() + CREATED_TTL,
        },
    );
    see_other(&admin.url("/created"))
}

/// The one-time display of the app password this session just created.
async fn created_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let Some(created) = admin.take(&session.user) else {
        let page = MessagePage {
            chrome: session.chrome.clone(),
            frame: admin.frame(&session, false, true),
            heading: session.chrome.t.a_nothing_to_show.to_owned(),
            lead: session.chrome.t.a_nothing_to_show_lead.to_owned(),
            link_href: admin.url("/users"),
            link_label: session.chrome.t.a_all_users.to_owned(),
        };
        return web::render(StatusCode::GONE, &page);
    };
    let page = CreatedPage {
        chrome: session.chrome.clone(),
        frame: admin.frame(&session, false, true),
        username: created.username,
        label: created.label,
        token: created.token.expose_secret().to_owned(),
        scopes: created.scopes.iter().map(ScopeChip::new).collect(),
        expiry: created
            .expires_at
            .map_or_else(|| session.chrome.t.no_expiry.to_owned(), pages::time),
        server: state.base_url.as_str().trim_end_matches('/').to_owned(),
    };
    let mut response = web::render(StatusCode::OK, &page);
    // `web::render` already sends `no-store`; say it in every dialect for older proxies.
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn revoke_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    match app_passwords::delete(&state.db, user.id, id).await {
        Ok(true) => {
            tracing::info!(by = %session.user.username, user = %user.username, app_password = id, "admin revoked an app password");
            see_other(&format!(
                "{}?done=revoked",
                admin.user_url(user.username.as_str())
            ))
        }
        // Already revoked (for example in another tab): nothing to report.
        Ok(false) => see_other(&admin.user_url(user.username.as_str())),
        Err(err) => internal_error(&session.chrome, &err),
    }
}

#[cfg(test)]
mod tests;
