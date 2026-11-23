//! Login Flow v2 endpoints and pages (see [`gono_server_nextcloud::login_flow`] for the protocol).
//!
//! | Request | Answer |
//! |---|---|
//! | `POST /index.php/login/v2` (or `/login/v2`) | Starts a flow. Anonymous; limited per client address and by [`login_flows::MAX_PENDING_FLOWS`]. |
//! | `POST .../login/v2/poll` with `token` (form body or query) | `404` until the user approved the device, then the new app password, once. |
//! | `GET .../login/v2/flow/<login token>` | The sign-in page, the consent page (when signed in), or the result. |
//! | `POST .../login/v2/flow/<login token>` | The forms of those pages: `action` = `login`, `grant`, `deny` or `logout`. |
//!
//! The pages need no JavaScript. Signing in uses the web login password, never an app
//! password, and only creates a browser session ([`crate::web`]); the device gets nothing
//! until the user presses "Grant access" on the consent page, which names the client. The
//! app password is minted when the client polls next. Login tokens appear in page URLs, and
//! Nextcloud iOS puts the poll token into the poll URL's query; the request log redacts both,
//! and the pages never leak them as a referrer.

use std::net::SocketAddr;

use askama::Template;
use axum::{
    Form,
    extract::{
        ConnectInfo, Path, Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use gono_server_core::{db, devices, login_flows, services::Service, two_factor};
use gono_server_nextcloud::login_flow;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::{
    app::AppState,
    client_ip::client_ip,
    i18n::{Lang, Text, fill},
    web::{self, CSRF_COOKIE, Chrome, Message, SESSION_COOKIE, SignIn, page},
};

fn json(status: StatusCode, value: &serde_json::Value) -> Response {
    let mut response = (status, serde_json::to_vec(value).unwrap_or_default()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn retry_after(response: &mut Response, seconds: u64) {
    if let Ok(value) = HeaderValue::from_str(&seconds.max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
}

/// `POST /index.php/login/v2` and `POST /login/v2`.
pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Some(wait) = state.flow_starts.check(client) {
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        retry_after(&mut response, wait.as_secs());
        return response;
    }
    // Every start costs one token of this client's (separate) bucket.
    state.flow_starts.record_failure(client);

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let client_name = login_flow::client_name(user_agent);
    match login_flows::create(&state.db, &client_name, db::unix_now()).await {
        Ok(Some(flow)) => {
            tracing::info!(%client, client_name, "Login Flow v2 started");
            let prefix = if uri.path().starts_with("/index.php/") {
                "/index.php"
            } else {
                ""
            };
            json(
                StatusCode::OK,
                &login_flow::init_document(
                    &state.base_url,
                    prefix,
                    flow.poll_token.expose_secret(),
                    flow.login_token.expose_secret(),
                ),
            )
        }
        Ok(None) => {
            tracing::warn!("too many pending Login Flow v2 sign-ins");
            let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
            retry_after(&mut response, 60);
            response
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot start a Login Flow v2 sign-in");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The `token` parameter of a poll request.
#[derive(Deserialize)]
pub struct PollForm {
    #[serde(default)]
    token: String,
}

/// `POST /index.php/login/v2/poll` and `POST /login/v2/poll`.
///
/// The token comes as a form body (Android, the desktop client) or as a query parameter of
/// the `POST` without any body (Nextcloud iOS). Nextcloud reads either, so neither a content
/// type nor a body is required here; a token in the body wins.
pub async fn poll(
    State(state): State<AppState>,
    query: Result<Query<PollForm>, QueryRejection>,
    body: Result<Form<PollForm>, FormRejection>,
) -> Response {
    let token = match (body, query) {
        (Ok(Form(form)), _) if !form.token.is_empty() => form.token,
        (_, Ok(Query(query))) => query.token,
        _ => String::new(),
    };
    if token.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match login_flows::complete(&state.db, &token, db::unix_now()).await {
        Ok(Some(credentials)) => {
            tracing::info!(
                user = %credentials.username,
                app_password = credentials.app_password_id,
                label = credentials.label,
                "Login Flow v2 completed: app password minted"
            );
            json(
                StatusCode::OK,
                &login_flow::poll_document(
                    &state.base_url,
                    credentials.username.as_str(),
                    credentials.app_password.expose_secret(),
                ),
            )
        }
        // Pending, unknown, expired or already used: Nextcloud answers 404 for all of them.
        Ok(None) => json(StatusCode::NOT_FOUND, &serde_json::json!([])),
        Err(err) => {
            tracing::error!(error = %err, "Login Flow v2 poll failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The form fields of the flow pages.
#[derive(Deserialize)]
pub struct PageForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
}

/// The sign-in form (`templates/login_flow/sign_in.html`).
#[derive(Template)]
#[template(path = "login_flow/sign_in.html")]
struct SignInPage<'a> {
    chrome: Chrome,
    client: &'a str,
    csrf: &'a str,
    error: Option<&'a str>,
    /// The buttons of the third-party providers, which come back to this page.
    providers: Vec<crate::oauth::Button>,
    next: String,
}

/// The consent page (`templates/login_flow/consent.html`).
#[derive(Template)]
#[template(path = "login_flow/consent.html")]
struct ConsentPage<'a> {
    chrome: Chrome,
    client: &'a str,
    account: String,
    /// "Not `<account>`?"
    not_you: String,
    csrf: &'a str,
    /// For a device registering for remote access.
    device: Option<DeviceFacts>,
}

/// What the consent page shows about a registering device (`docs/connect-protocol.md`, 4.2).
struct DeviceFacts {
    product: String,
    platform: String,
    short_id: String,
}

impl DeviceFacts {
    fn of(flow: &login_flows::Flow) -> Option<Self> {
        let device = flow.device.as_ref()?;
        Some(Self {
            product: product_name(&device.product),
            platform: platform_name(&device.platform),
            short_id: device.endpoint_id.short(),
        })
    }
}

/// A readable name of a product slug.
pub(crate) fn product_name(slug: &str) -> String {
    match slug {
        "input-show" => "Input Show".to_owned(),
        "gono-md" => "gono.md".to_owned(),
        other => other.to_owned(),
    }
}

/// A readable name of a platform slug.
pub(crate) fn platform_name(slug: &str) -> String {
    match slug {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        "harmonyos" => "HarmonyOS",
        "ios" => "iOS",
        "android" => "Android",
        other => other,
    }
    .to_owned()
}

page!(SignInPage<'_>, ConsentPage<'_>);

fn expired_page(headers: &HeaderMap) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    Message::new(
        chrome,
        t.link_expired,
        t.link_expired_heading,
        t.link_expired_lead,
    )
    .respond(StatusCode::NOT_FOUND)
}

fn done_page(headers: &HeaderMap, client: &str) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let mut page = Message::new(
        chrome,
        t.access_granted,
        t.access_granted,
        t.access_granted_lead,
    );
    page.client = Some(client.to_owned());
    page.note = Some(t.close_and_return.to_owned());
    page.respond(StatusCode::OK)
}

/// The refusal of a form; `lead` picks the text.
fn blocked_page(headers: &HeaderMap, lead: fn(&Text) -> &'static str) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    Message::new(chrome, t.request_blocked, t.request_blocked, lead(t))
        .respond(StatusCode::FORBIDDEN)
}

fn login_page(
    state: &AppState,
    headers: &HeaderMap,
    page_path: &str,
    status: StatusCode,
    client: &str,
    message: Option<&str>,
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let mut chrome = Chrome::for_request(headers);
    chrome.form_action = crate::oauth::form_origins(state);
    let page = SignInPage {
        providers: crate::oauth::sign_in_buttons(state, chrome.t, page_path),
        chrome,
        client,
        csrf: &csrf,
        error: message,
        next: page_path.to_owned(),
    };
    let mut response = web::render(status, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn consent_page(
    state: &AppState,
    headers: &HeaderMap,
    flow: &login_flows::Flow,
    session: &(gono_server_core::web_sessions::SessionUser, String),
) -> Response {
    let client = flow.client_name.as_str();
    let (user, token) = session;
    let account = if user.display_name == user.username.as_str() {
        user.display_name.clone()
    } else {
        format!("{} ({})", user.display_name, user.username)
    };
    let csrf = state.web.session_csrf(token);
    let chrome = Chrome::for_request(headers);
    let not_you = fill(chrome.t.not_you, &[&account]);
    web::render(
        StatusCode::OK,
        &ConsentPage {
            chrome,
            client,
            account,
            not_you,
            csrf: &csrf,
            device: DeviceFacts::of(flow),
        },
    )
}

/// The page that refuses to grant an app password to an account without WebDAV: the app could
/// not use it (`gono_server_core::services`).
fn webdav_refusal(headers: &HeaderMap) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    Message::new(
        chrome,
        t.service_off,
        t.service_off,
        t.service_off_webdav_lead,
    )
    .respond(StatusCode::FORBIDDEN)
}

/// The page that refuses a device registration to an account without direct connections. The
/// flow ends here, so that the device's next poll answers `service_not_enabled` instead of
/// waiting until the flow expires (`docs/connect-protocol.md`, 4.3).
async fn direct_refusal(state: &AppState, headers: &HeaderMap, flow_id: i64) -> Response {
    if let Err(err) = login_flows::refuse_device(&state.db, flow_id, "service_not_enabled").await {
        tracing::error!(error = %err, "cannot end a refused device registration");
    }
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    Message::new(
        chrome,
        t.service_off,
        t.service_off,
        t.service_off_direct_lead,
    )
    .respond(StatusCode::FORBIDDEN)
}

/// Why a device registration cannot be granted to `user_id` (`docs/connect-protocol.md`,
/// 4.2): the account has no two-step verification while the server requires it
/// (`connect.require_two_factor`), or holds the most devices already.
async fn device_refusal(
    state: &AppState,
    headers: &HeaderMap,
    user_id: i64,
    page: &str,
) -> Option<Response> {
    let checked = async {
        let two_factor_ok = !state.remote_access_needs_two_factor()
            || two_factor::is_enrolled(&state.db, user_id).await?;
        let devices = devices::count_active(&state.db, user_id).await?;
        Ok::<_, gono_server_core::Error>((two_factor_ok, devices))
    }
    .await;
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    match checked {
        Ok((false, _)) => {
            let mut message = Message::new(
                chrome,
                t.two_factor_needed,
                t.two_factor_needed,
                t.two_factor_needed_lead,
            );
            // The account page leads through enrolment and comes back to this page.
            if state.files.is_some() && state.web.two_factor_key().is_some() {
                let next: String = url::form_urlencoded::byte_serialize(page.as_bytes()).collect();
                message.link = Some((
                    format!("{}?next={next}#two-factor", crate::files::account::OVERVIEW),
                    t.tf_turn_on.to_owned(),
                ));
            }
            Some(message.respond(StatusCode::FORBIDDEN))
        }
        Ok((true, count)) if count >= devices::MAX_DEVICES_PER_ACCOUNT => Some(
            Message::new(
                chrome,
                t.too_many_devices,
                t.too_many_devices,
                t.too_many_devices_lead,
            )
            .respond(StatusCode::FORBIDDEN),
        ),
        Ok(_) => None,
        Err(err) => {
            tracing::error!(error = %err, "cannot check a device registration");
            Some(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Redirects to the page itself (Post/Redirect/Get), with extra `Set-Cookie` values.
fn back_to(uri: &Uri, cookies: &[HeaderValue]) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(location) = HeaderValue::from_str(uri.path()) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    for cookie in cookies {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    web::secure_headers(response.headers_mut());
    response
}

/// `GET .../login/v2/flow/<login token>`.
pub async fn page(
    State(state): State<AppState>,
    Path(token): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let flow = match login_flows::find(&state.db, &token, db::unix_now()).await {
        Ok(Some(flow)) => flow,
        Ok(None) => return expired_page(&headers),
        Err(err) => {
            tracing::error!(error = %err, "Login Flow v2 lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if flow.granted_user_id.is_some() {
        return done_page(&headers, &flow.client_name);
    }
    match state.web.session(&headers).await {
        // Say so before the user grants anything the app could not use.
        Some((user, _)) if flow.device.is_none() && !user.services.has(Service::Webdav) => {
            webdav_refusal(&headers)
        }
        Some((user, _)) if flow.device.is_some() && !user.services.has(Service::Direct) => {
            direct_refusal(&state, &headers, flow.id).await
        }
        Some(session) => consent_page(&state, &headers, &flow, &session),
        None => login_page(
            &state,
            &headers,
            uri.path(),
            StatusCode::OK,
            &flow.client_name,
            None,
        ),
    }
}

/// `POST .../login/v2/flow/<login token>`.
pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    Form(form): Form<PageForm>,
) -> Response {
    if !state.web.same_origin(&headers) {
        return blocked_page(&headers, |t| t.from_other_site);
    }
    let flow = match login_flows::find(&state.db, &token, db::unix_now()).await {
        Ok(Some(flow)) => flow,
        Ok(None) => return expired_page(&headers),
        Err(err) => {
            tracing::error!(error = %err, "Login Flow v2 lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let t = Lang::from_headers(&headers).t();

    if form.action == "login" {
        if !state.web.check_login_csrf(&headers, &form.csrf) {
            return login_page(
                &state,
                &headers,
                uri.path(),
                StatusCode::FORBIDDEN,
                &flow.client_name,
                Some(t.form_expired_sign_in),
            );
        }
        let password = SecretString::from(form.password);
        return match state
            .web
            .sign_in(client, &form.user, password, uri.path())
            .await
        {
            SignIn::SecondStep(cookie) => web::see_other(web::TWO_STEP_PATH, &[cookie]),
            SignIn::Ok(token) => {
                let cookies = [
                    state.web.session_cookie(&token),
                    state.web.removal_cookie(CSRF_COOKIE),
                ];
                let next = crate::oauth::after_password(&state, &headers, uri.path());
                if next == uri.path() {
                    back_to(&uri, &cookies)
                } else {
                    web::see_other(&next, &cookies)
                }
            }
            SignIn::Invalid => login_page(
                &state,
                &headers,
                uri.path(),
                StatusCode::FORBIDDEN,
                &flow.client_name,
                Some(t.wrong_password),
            ),
            SignIn::RateLimited(wait) => {
                web::too_many_attempts(Chrome::for_request(&headers), wait)
            }
            SignIn::Unavailable => web::unavailable(Chrome::for_request(&headers)),
        };
    }

    let Some(session) = state.web.session(&headers).await else {
        return login_page(
            &state,
            &headers,
            uri.path(),
            StatusCode::FORBIDDEN,
            &flow.client_name,
            Some(t.session_ended),
        );
    };
    if !state.web.check_session_csrf(&session.1, &form.csrf) {
        return blocked_page(&headers, |t| t.form_expired);
    }
    if flow.granted_user_id.is_some() {
        return done_page(&headers, &flow.client_name);
    }
    let user = &session.0;
    if form.action == "grant" && flow.device.is_none() && !user.services.has(Service::Webdav) {
        return webdav_refusal(&headers);
    }
    if form.action == "grant" && flow.device.is_some() && !user.services.has(Service::Direct) {
        return direct_refusal(&state, &headers, flow.id).await;
    }
    if form.action == "grant"
        && flow.device.is_some()
        && let Some(refusal) = device_refusal(&state, &headers, user.user_id, uri.path()).await
    {
        return refusal;
    }
    match form.action.as_str() {
        "grant" => match login_flows::grant(
            &state.db,
            flow.id,
            user.user_id,
            Some(client),
            db::unix_now(),
        )
        .await
        {
            Ok(_) => {
                tracing::info!(
                    %client,
                    user = %user.username,
                    client_name = flow.client_name,
                    "Login Flow v2 access granted"
                );
                back_to(&uri, &[])
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot grant a Login Flow v2 sign-in");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        "deny" => {
            if let Err(err) = login_flows::deny(&state.db, flow.id).await {
                tracing::error!(error = %err, "cannot cancel a Login Flow v2 sign-in");
            }
            tracing::info!(%client, user = %user.username, "Login Flow v2 access denied");
            let chrome = Chrome::for_request(&headers);
            let mut page = Message::new(
                chrome,
                t.access_denied,
                t.access_denied,
                t.access_denied_lead,
            );
            page.client = Some(flow.client_name.clone());
            page.note = Some(t.close_window.to_owned());
            page.respond(StatusCode::OK)
        }
        "logout" => {
            state.web.sign_out(&session.1).await;
            back_to(&uri, &[state.web.removal_cookie(SESSION_COOKIE)])
        }
        _ => Message::new(
            Chrome::for_request(&headers),
            t.bad_request,
            t.bad_request,
            t.unknown_action,
        )
        .respond(StatusCode::BAD_REQUEST),
    }
}
