//! Sign-in with Google and GitHub (`[oauth.google]`, `[oauth.github]`;
//! `plan/third-party-sign-in-design.md`, 5.1).
//!
//! | Request | Answer |
//! |---|---|
//! | `POST /login/oauth/<provider>` | Starts a sign-in (`purpose=sign_in`, from a sign-in page, with `next`) or a confirmation of the signed-in account (`purpose=reauth`, from the account page): `303` to the provider. |
//! | `GET /login/oauth/<provider>/callback` | Where the provider sends the browser back, with `code` and `state` (or `error`). |
//! | `GET /login/unbound` | An identity bound to no account: bind it after a password sign-in, or cancel. |
//! | `POST /login/unbound/cancel` | Forget that identity. |
//! | `GET /login/link`, `POST /login/link` | After a password sign-in: bind the identity that waits in this browser to the account, or not. |
//!
//! Binding from the account page (`purpose=bind`) starts in [`crate::files::account::methods`],
//! after confirming it is you, with [`OAuth::begin`].
//!
//! # A sign-in
//!
//! - **The state** is random, single use, lives [`STATE_TTL_SECS`] in memory (at most
//!   [`MAX_STATES`]; a restart forgets them, and the user starts again), and is bound to the
//!   browser that started by the [`OAUTH_COOKIE`] (`HttpOnly`, `SameSite=Lax` so that the
//!   provider's redirect carries it, `__Host-` on HTTPS). A callback in another browser does
//!   nothing. PKCE (`S256`) ties the code to the server's verifier, and Google's `nonce` ties
//!   the ID token to the state. `next` and the purpose never leave the server.
//! - **What it does** with the identity the provider reports:
//!   - bound to an enabled account: a web session, without two-step verification (decided),
//!     confirmed for [`crate::web::CONFIRM_TTL_SECS`] as a fresh sign-in;
//!   - bound to no account, but the provider verified an address that an enabled account proved
//!     itself: bound to that account automatically (`how: "email"`), signed in, and a notice is
//!     mailed to the address;
//!   - otherwise a pending identity in the [`PENDING_COOKIE`]: the unbound page offers to sign
//!     in with the password, after which [`after_password`] leads to the page that binds it.
//! - **The admin UI** takes the same sign-in; only admin accounts get a session there.
//! - **Failures** (an unknown, used or foreign state, a refused code, a token that does not
//!   check out) count as failed sign-ins of the client address and say only that the sign-in
//!   was not completed. A provider that cannot be reached says so, and logs why.
//! - **Secrets.** Client secrets are read from their files when `serve` starts. Codes, states,
//!   verifiers, tokens, subjects and the provider's addresses are never logged; log lines name
//!   the account. The provider's tokens are revoked at once and never stored.

pub mod github;
pub mod google;
#[cfg(test)]
pub mod mock;

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::Context as _;
use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, Path as UrlPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use gono_server_core::{
    Config,
    config::oauth_redirect_uri,
    db,
    identities::{self, BoundPending, Claims, Holder, Provider, SignedIn},
    users::User,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    app::AppState,
    client_ip::client_ip,
    i18n::{Text, fill},
    mail,
    site::{self, FILES_HOME},
    web::{self, CSRF_COOKIE, Chrome, Message, OAUTH_COOKIE, PENDING_COOKIE, page},
};

/// Where sign-ins start: `POST /login/oauth/<provider>`.
pub const START_PATH: &str = "/login/oauth";

/// The page of an identity bound to no account.
pub const UNBOUND_PATH: &str = "/login/unbound";

/// The page that binds it after a password sign-in.
pub const LINK_PATH: &str = "/login/link";

/// How long a state waits for its callback, in seconds.
pub const STATE_TTL_SECS: i64 = 10 * 60;

/// States kept at most; a new one ends the oldest.
pub const MAX_STATES: usize = 1000;

/// Characters of states, PKCE verifiers and the browser's cookie: 43 of `[A-Za-z0-9]`, 256 bits.
const TOKEN_CHARS: usize = 43;

/// The largest answer of a provider read, in bytes.
const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// What a provider reported, with the addresses it verified (for automatic binding).
#[derive(Debug, Clone)]
pub struct Exchanged {
    /// The identity.
    pub claims: Claims,
    /// The addresses the provider verified, lower-cased, the primary first.
    pub verified_emails: Vec<String>,
}

/// Why talking to a provider failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The provider refused, or answered something that does not check out: the sign-in is
    /// not completed, and counts as a failure.
    Refused(&'static str),
    /// The provider could not be reached or failed: say so, and log why (no secret in it).
    Unavailable(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(why) => f.write_str(why),
            Self::Unavailable(why) => f.write_str(why),
        }
    }
}

/// The HTTPS client of one provider ([`crate::http_client`]).
#[derive(Debug, Clone)]
pub struct Http {
    client: reqwest::Client,
    name: &'static str,
}

impl Http {
    /// A client for the provider called `name` in log lines.
    pub fn new(name: &'static str) -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::http_client::client()?,
            name,
        })
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>, ProviderError> {
        let response = request
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| {
                ProviderError::Unavailable(crate::http_client::describe(self.name, err))
            })?;
        let status = response.status();
        let body = crate::http_client::read_body(self.name, response, MAX_ANSWER_BYTES)
            .await
            .map_err(ProviderError::Unavailable)?;
        if status.is_server_error() {
            return Err(ProviderError::Unavailable(format!(
                "{} answered HTTP {status}",
                self.name
            )));
        }
        if !status.is_success() {
            return Err(ProviderError::Refused("the provider refused the request"));
        }
        Ok(body)
    }

    /// `GET url`, with a bearer token.
    pub async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Vec<u8>, ProviderError> {
        let mut request = self.client.get(url.clone());
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        self.send(request).await
    }

    /// `POST url` with a form, and Basic credentials.
    pub async fn post_form(
        &self,
        url: &Url,
        fields: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<Vec<u8>, ProviderError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request = self
            .client
            .post(url.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body);
        if let Some((user, password)) = basic {
            request = request.basic_auth(user, Some(password));
        }
        self.send(request).await
    }

    /// `DELETE url` with a JSON body and Basic credentials.
    pub async fn delete_json(
        &self,
        url: &Url,
        basic: (&str, &str),
        body: &serde_json::Value,
    ) -> Result<Vec<u8>, ProviderError> {
        let request = self
            .client
            .delete(url.clone())
            .basic_auth(basic.0, Some(basic.1))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        self.send(request).await
    }
}

/// The client of one provider.
#[derive(Debug)]
pub enum ProviderClient {
    /// Google.
    Google(google::Client),
    /// GitHub.
    GitHub(github::Client),
}

impl ProviderClient {
    /// The origin forms post to on the way to the provider (the pages' `form-action`).
    fn form_origin(&self) -> String {
        match self {
            Self::Google(client) => client.form_origin(),
            Self::GitHub(client) => client.form_origin(),
        }
    }

    async fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        challenge: &str,
        nonce: &str,
    ) -> Result<Url, ProviderError> {
        match self {
            Self::Google(client) => {
                client
                    .authorize_url(redirect_uri, state, challenge, nonce)
                    .await
            }
            Self::GitHub(client) => Ok(client.authorize_url(redirect_uri, state, challenge)),
        }
    }

    async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        nonce: &str,
        now: i64,
    ) -> Result<Exchanged, ProviderError> {
        match self {
            Self::Google(client) => {
                client
                    .exchange(code, verifier, redirect_uri, nonce, now)
                    .await
            }
            Self::GitHub(client) => client.exchange(code, verifier, redirect_uri).await,
        }
    }
}

/// One configured provider.
#[derive(Debug)]
pub struct OAuthProvider {
    client: ProviderClient,
    /// `allow_signup`: an identity bound to no account may create one ([`crate::signup`]).
    pub allow_signup: bool,
}

impl OAuthProvider {
    /// The provider `client`.
    pub fn new(client: ProviderClient) -> Self {
        Self {
            client,
            allow_signup: false,
        }
    }

    /// The same, letting identities bound to no account sign up when `allow`.
    #[must_use]
    pub fn with_signup(mut self, allow: bool) -> Self {
        self.allow_signup = allow;
        self
    }
}

/// What a sign-in is for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Purpose {
    /// Sign in, then go on to `next` (a local path); only admins get a session when `admin`.
    SignIn { next: String, admin: bool },
    /// Bind the identity to the account of a browser session.
    Bind { session_id: i64, user_id: i64 },
    /// Confirm it is the account's user of a browser session, then go on to `next`.
    Reauth {
        session_id: i64,
        user_id: i64,
        next: String,
    },
}

/// A sign-in waiting for its callback.
#[derive(Debug, Clone)]
struct Started {
    provider: Provider,
    purpose: Purpose,
    /// The digest of the [`OAUTH_COOKIE`] of the browser that started it.
    binding: [u8; 32],
    verifier: String,
    nonce: String,
    until: i64,
    seq: u64,
}

/// The sign-ins waiting for their callbacks, by the digest of their state.
#[derive(Debug, Default)]
struct States {
    entries: HashMap<[u8; 32], Started>,
    next_seq: u64,
}

/// Google and GitHub sign-in, while one of them is configured.
#[derive(Debug)]
pub struct OAuth {
    base_url: Url,
    google: Option<OAuthProvider>,
    github: Option<OAuthProvider>,
    states: Mutex<States>,
}

/// Reads a client secret: the first line of `path`, without the line break.
fn read_secret(path: &Path, key: &str) -> anyhow::Result<SecretString> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("read {key} {}", path.display()))?;
    let secret = content.lines().next().unwrap_or_default().trim().to_owned();
    anyhow::ensure!(
        !secret.is_empty(),
        "{key} {} is empty; put the client secret on its first line",
        path.display()
    );
    Ok(SecretString::from(secret))
}

/// A random token of [`TOKEN_CHARS`].
fn random() -> String {
    gono_server_core::secret::random_token(TOKEN_CHARS)
        .expose_secret()
        .to_owned()
}

/// Whether `value` has the shape of a state or cookie of this module.
fn is_token(value: &str) -> bool {
    value.len() == TOKEN_CHARS && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The PKCE challenge of `verifier` (`S256`).
fn challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

impl OAuth {
    /// Sign-in for the server at `base_url` with these providers; `None` without any.
    pub fn new(
        base_url: &Url,
        google: Option<OAuthProvider>,
        github: Option<OAuthProvider>,
    ) -> Option<Self> {
        (google.is_some() || github.is_some()).then(|| Self {
            base_url: base_url.clone(),
            google,
            github,
            states: Mutex::new(States::default()),
        })
    }

    /// The providers of `config` (validated). Reads the client secrets now, so that a missing
    /// one stops the start.
    pub fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        let mut google = None;
        let mut github = None;
        for (key, provider) in config.oauth_providers() {
            let client_id = provider
                .client_id
                .as_deref()
                .with_context(|| format!("oauth.{key}.client_id is not set"))?;
            let secret_key = format!("oauth.{key}.client_secret_file");
            let file = provider
                .client_secret_file
                .as_deref()
                .with_context(|| format!("{secret_key} is not set"))?;
            let secret = read_secret(file, &secret_key)?;
            match key {
                "google" => {
                    let client = google::Client::new(
                        Http::new("Google")?,
                        Url::parse(google::DISCOVERY).context("Google's discovery URL")?,
                        client_id,
                        secret,
                    );
                    google = Some(
                        OAuthProvider::new(ProviderClient::Google(client))
                            .with_signup(provider.allow_signup),
                    );
                }
                _ => {
                    let client = github::Client::new(
                        Http::new("GitHub")?,
                        github::Endpoints::github(),
                        client_id,
                        secret,
                    );
                    github = Some(
                        OAuthProvider::new(ProviderClient::GitHub(client))
                            .with_signup(provider.allow_signup),
                    );
                }
            }
        }
        Ok(Self::new(&config.server.base_url, google, github))
    }

    /// The configured provider `provider`.
    pub fn provider(&self, provider: Provider) -> Option<&OAuthProvider> {
        match provider {
            Provider::Google => self.google.as_ref(),
            Provider::GitHub => self.github.as_ref(),
            Provider::WeChat => None,
        }
    }

    /// The configured providers, in the order pages list them.
    pub fn providers(&self) -> Vec<Provider> {
        [Provider::Google, Provider::GitHub]
            .into_iter()
            .filter(|provider| self.provider(*provider).is_some())
            .collect()
    }

    /// The origins forms post to on the way to the providers, for the pages' `form-action`.
    pub fn form_origins(&self) -> String {
        [&self.google, &self.github]
            .into_iter()
            .flatten()
            .map(|provider| provider.client.form_origin())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn redirect_uri(&self, provider: Provider) -> String {
        oauth_redirect_uri(&self.base_url, provider.as_str())
    }

    /// Keeps `started` under the digest of `state`, after the expired ones and past the cap.
    fn keep(&self, state: &str, mut started: Started, now: i64) {
        let mut states = self.states.lock().unwrap_or_else(PoisonError::into_inner);
        states.entries.retain(|_, entry| entry.until > now);
        if states.entries.len() >= MAX_STATES {
            let oldest = states
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.seq)
                .map(|(digest, _)| *digest);
            if let Some(oldest) = oldest {
                states.entries.remove(&oldest);
            }
        }
        started.seq = states.next_seq;
        states.next_seq += 1;
        states
            .entries
            .insert(gono_server_core::secret::digest(state), started);
    }

    /// Takes the live sign-in of `state`: used once.
    fn take(&self, state: &str, now: i64) -> Option<Started> {
        let mut states = self.states.lock().unwrap_or_else(PoisonError::into_inner);
        states
            .entries
            .remove(&gono_server_core::secret::digest(state))
            .filter(|entry| entry.until > now)
    }

    /// The number of sign-ins waiting, for tests.
    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        self.states
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }

    /// Starts a sign-in with `provider` for `purpose` in the browser of `headers`: `303` to the
    /// provider, with the [`OAUTH_COOKIE`].
    async fn start(
        &self,
        state: &AppState,
        headers: &HeaderMap,
        provider: Provider,
        purpose: Purpose,
    ) -> Response {
        let Some(configured) = self.provider(provider) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let cookie = web::cookie(headers, &state.web.cookie_name(OAUTH_COOKIE))
            .filter(|value| is_token(value))
            .unwrap_or_else(random);
        let state_token = random();
        let verifier = random();
        let nonce = random();
        let url = match configured
            .client
            .authorize_url(
                &self.redirect_uri(provider),
                &state_token,
                &challenge(&verifier),
                &nonce,
            )
            .await
        {
            Ok(url) => url,
            Err(err) => {
                tracing::warn!(provider = provider.as_str(), error = %err, "cannot start a sign-in with a provider");
                return provider_unavailable(headers, provider);
            }
        };
        let now = db::unix_now();
        self.keep(
            &state_token,
            Started {
                provider,
                purpose,
                binding: gono_server_core::secret::digest(&cookie),
                verifier,
                nonce,
                until: now + STATE_TTL_SECS,
                seq: 0,
            },
            now,
        );
        web::see_other(url.as_str(), &[state.web.oauth_cookie(&cookie)])
    }

    /// Starts binding `provider` to the account of `session` (from the account page, which
    /// confirmed it is the account's user).
    pub async fn begin_bind(
        &self,
        state: &AppState,
        headers: &HeaderMap,
        provider: Provider,
        session: &gono_server_core::web_sessions::SessionUser,
    ) -> Response {
        let purpose = Purpose::Bind {
            session_id: session.session_id,
            user_id: session.user_id,
        };
        self.start(state, headers, provider, purpose).await
    }
}

/// The provider of a path that this server offers, with the sign-in state.
fn offered(state: &AppState, key: &str) -> Option<(Arc<OAuth>, Provider)> {
    let oauth = state.oauth.clone()?;
    let provider = Provider::parse(key)?;
    oauth.provider(provider)?;
    Some((oauth, provider))
}

/// The page that says the provider cannot be used now.
fn provider_unavailable(headers: &HeaderMap, provider: Provider) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let lead = fill(t.oauth_unavailable, &[provider.name()]);
    let mut response = Message::new(chrome, t.oauth_failed_title, t.oauth_failed_title, &lead)
        .respond(StatusCode::SERVICE_UNAVAILABLE);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

/// The page of a sign-in that was not completed, with a link back to where it started.
fn not_completed(headers: &HeaderMap, back: &str) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let mut page = Message::new(
        chrome,
        t.oauth_failed_title,
        t.oauth_failed_title,
        t.oauth_failed,
    );
    page.link = Some((back.to_owned(), t.oauth_try_again.to_owned()));
    page.respond(StatusCode::FORBIDDEN)
}

/// Where the sign-in page of `next` is: the Login Flow v2 page itself, the admin UI's, or
/// `/login` going on to `next`.
pub fn sign_in_page(state: &AppState, next: &str) -> String {
    if next.starts_with("/login/v2/flow/") || next.starts_with("/index.php/login/v2/flow/") {
        return next.to_owned();
    }
    if let Some(admin) = &state.admin
        && is_admin_path(admin.prefix(), next)
    {
        return format!("{}/login", admin.prefix());
    }
    format!("/login?next={}", encode(next))
}

/// Whether `next` is a page of the admin UI under `prefix`.
fn is_admin_path(prefix: &str, next: &str) -> bool {
    next == prefix || next.starts_with(&format!("{prefix}/"))
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Where a password sign-in goes on to: the page that binds the identity waiting in this
/// browser (`plan/third-party-sign-in-design.md`, 3.4), if one waits, then `next`.
pub fn after_password(state: &AppState, headers: &HeaderMap, next: &str) -> String {
    let waiting = web::cookie(headers, &state.web.cookie_name(PENDING_COOKIE))
        .is_some_and(|value| identities::is_token(&value));
    if waiting {
        format!("{LINK_PATH}?next={}", encode(next))
    } else {
        next.to_owned()
    }
}

#[derive(Deserialize)]
pub struct StartForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    next: String,
}

/// `POST /login/oauth/<provider>`.
pub async fn start(
    State(state): State<AppState>,
    UrlPath(key): UrlPath<String>,
    headers: HeaderMap,
    Form(form): Form<StartForm>,
) -> Response {
    let Some((oauth, provider)) = offered(&state, &key) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    match form.purpose.as_str() {
        "" | "sign_in" => {
            if state.files.is_none() && state.admin.is_none() {
                return StatusCode::NOT_FOUND.into_response();
            }
            if !state.web.check_login_csrf(&headers, &form.csrf) {
                return site::blocked(&headers, |t| t.form_expired_sign_in);
            }
            let next = site::local_path(&form.next)
                .filter(|next| *next != "/login")
                .unwrap_or(FILES_HOME)
                .to_owned();
            let admin = state
                .admin
                .as_ref()
                .is_some_and(|admin| is_admin_path(admin.prefix(), &next));
            let purpose = Purpose::SignIn { next, admin };
            oauth.start(&state, &headers, provider, purpose).await
        }
        "reauth" => {
            let Some((user, token)) = state.web.session(&headers).await else {
                return web::see_other("/login?next=%2Faccount%2F", &[]);
            };
            if !state.web.check_session_csrf(&token, &form.csrf) {
                return site::blocked(&headers, |t| t.form_expired);
            }
            let next = site::local_path(&form.next)
                .filter(|next| next.starts_with(crate::files::account::OVERVIEW))
                .unwrap_or(crate::files::account::OVERVIEW)
                .to_owned();
            let purpose = Purpose::Reauth {
                session_id: user.session_id,
                user_id: user.user_id,
                next,
            };
            oauth.start(&state, &headers, provider, purpose).await
        }
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Where a sign-in for `purpose` returns to when it ends without signing in.
fn back_of(state: &AppState, purpose: &Purpose) -> String {
    match purpose {
        Purpose::SignIn { next, .. } => sign_in_page(state, next),
        Purpose::Bind { .. } | Purpose::Reauth { .. } => crate::files::account::OVERVIEW.to_owned(),
    }
}

/// `GET /login/oauth/<provider>/callback`.
pub async fn callback(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    UrlPath(key): UrlPath<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some((oauth, provider)) = offered(&state, &key) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Some(wait) = state.web.rate_limited(client) {
        return web::too_many_attempts(Chrome::for_request(&headers), wait);
    }
    let now = db::unix_now();
    let fail = |why: &str| {
        state.web.record_failure(client);
        tracing::info!(%client, provider = provider.as_str(), why, "third-party sign-in not completed");
        not_completed(&headers, "/login")
    };
    let Some(state_token) = query.state.as_deref().filter(|value| is_token(value)) else {
        return fail("no state");
    };
    let Some(started) = oauth.take(state_token, now) else {
        return fail("unknown, used or expired state");
    };
    let binding = web::cookie(&headers, &state.web.cookie_name(OAUTH_COOKIE))
        .map(|value| gono_server_core::secret::digest(&value));
    if binding != Some(started.binding) || started.provider != provider {
        return fail("the state belongs to another browser");
    }
    if let Some(error) = &query.error {
        if error == "access_denied" {
            return cancelled(&state, &headers, &started.purpose);
        }
        state.web.record_failure(client);
        return not_completed(&headers, &back_of(&state, &started.purpose));
    }
    let Some(code) = query
        .code
        .as_deref()
        .filter(|code| !code.is_empty() && code.len() <= 2048)
    else {
        return fail("no code");
    };
    let Some(configured) = oauth.provider(provider) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let exchanged = match configured
        .client
        .exchange(
            code,
            &started.verifier,
            &oauth.redirect_uri(provider),
            &started.nonce,
            now,
        )
        .await
    {
        Ok(exchanged) => exchanged,
        Err(ProviderError::Refused(why)) => {
            state.web.record_failure(client);
            tracing::info!(%client, provider = provider.as_str(), why, "third-party sign-in not completed");
            return not_completed(&headers, &back_of(&state, &started.purpose));
        }
        Err(ProviderError::Unavailable(why)) => {
            tracing::warn!(%client, provider = provider.as_str(), error = %why, "a provider failed a sign-in");
            return provider_unavailable(&headers, provider);
        }
    };
    match started.purpose {
        Purpose::SignIn { next, admin } => {
            signed_in(&state, &headers, client, provider, exchanged, &next, admin).await
        }
        Purpose::Bind {
            session_id,
            user_id,
        } => {
            bound(
                &state, &headers, client, provider, exchanged, session_id, user_id,
            )
            .await
        }
        Purpose::Reauth {
            session_id,
            user_id,
            next,
        } => {
            reauthenticated(
                &state, &headers, client, provider, exchanged, session_id, user_id, &next,
            )
            .await
        }
    }
}

/// The user cancelled at the provider.
fn cancelled(state: &AppState, headers: &HeaderMap, purpose: &Purpose) -> Response {
    match purpose {
        Purpose::SignIn { .. } => {
            let chrome = Chrome::for_request(headers);
            let t = chrome.t;
            let mut page = Message::new(
                chrome,
                t.oauth_cancelled,
                t.oauth_cancelled,
                t.oauth_cancelled_lead,
            );
            page.link = Some((back_of(state, purpose), t.oauth_back.to_owned()));
            page.respond(StatusCode::OK)
        }
        Purpose::Bind { .. } | Purpose::Reauth { .. } => web::see_other(
            &format!("{}?done=cancelled", crate::files::account::OVERVIEW),
            &[],
        ),
    }
}

/// The page that refuses a sign-in to an account that cannot sign in.
fn cannot_sign_in(headers: &HeaderMap) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    Message::new(
        chrome,
        t.account_cannot_sign_in,
        t.account_cannot_sign_in,
        t.account_cannot_sign_in_lead,
    )
    .respond(StatusCode::FORBIDDEN)
}

/// A sign-in with `provider` reported `exchanged`: sign in, bind by address, or keep the
/// identity waiting for this browser.
async fn signed_in(
    state: &AppState,
    headers: &HeaderMap,
    client: IpAddr,
    provider: Provider,
    exchanged: Exchanged,
    next: &str,
    admin: bool,
) -> Response {
    let now = db::unix_now();
    let claims = &exchanged.claims;
    match identities::sign_in(&state.db, claims, now).await {
        Ok(SignedIn::Account(user)) => {
            return open_session(state, headers, client, provider, &user, next, admin, None).await;
        }
        Ok(SignedIn::DeletionPending { user_id, until }) => {
            tracing::info!(%client, provider = provider.as_str(), "third-party sign-in of an account waiting for its deletion");
            return crate::signup::deletion_pending(state, headers, user_id, until);
        }
        Ok(SignedIn::Disabled) => {
            tracing::info!(%client, provider = provider.as_str(), "third-party sign-in of an account that cannot sign in");
            return cannot_sign_in(headers);
        }
        Ok(SignedIn::Unbound) => {}
        Err(err) => {
            tracing::error!(error = %err, "cannot sign in with a third-party identity");
            return web::unavailable(Chrome::for_request(headers));
        }
    }
    match identities::bind_by_email(
        &state.db,
        claims,
        &exchanged.verified_emails,
        Some(client),
        now,
    )
    .await
    {
        Ok(Some(bound)) => {
            tracing::info!(%client, user = %bound.user.username, provider = provider.as_str(), "identity bound by its verified address");
            let lang = Chrome::for_request(headers).lang;
            if let Some(mailer) = &state.mailer {
                let message = mail::identity_bound(
                    lang,
                    &state.base_url,
                    bound.user.username.as_str(),
                    provider.name(),
                    &bound.identity.label,
                );
                mail::send_later(mailer, bound.email.clone(), message, "an automatic binding");
            }
            let t = lang.t();
            let notice = fill(
                t.notice_bound_auto,
                &[provider.name(), &bound.identity.label],
            );
            return open_session(
                state,
                headers,
                client,
                provider,
                &bound.user,
                next,
                admin,
                Some(notice),
            )
            .await;
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "cannot bind a third-party identity by its address");
            return web::unavailable(Chrome::for_request(headers));
        }
    }
    match identities::create_pending(&state.db, Holder::Web, claims, now).await {
        Ok((token, _)) => {
            tracing::info!(%client, provider = provider.as_str(), "third-party identity bound to no account");
            web::see_other(
                &format!("{UNBOUND_PATH}?next={}", encode(next)),
                &[state.web.pending_cookie(&token)],
            )
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot keep a third-party identity");
            web::unavailable(Chrome::for_request(headers))
        }
    }
}

/// Opens a session of `user` after a sign-in with `provider`, and goes on to `next` (with
/// `notice` on a page of its own first).
#[allow(clippy::too_many_arguments)]
async fn open_session(
    state: &AppState,
    headers: &HeaderMap,
    client: IpAddr,
    provider: Provider,
    user: &User,
    next: &str,
    admin: bool,
    notice: Option<String>,
) -> Response {
    if admin && !user.is_admin {
        tracing::info!(%client, user = %user.username, "admin sign-in refused: not an admin");
        let chrome = Chrome::for_request(headers);
        let t = chrome.t;
        let mut page = Message::new(
            chrome,
            t.request_blocked,
            t.request_blocked,
            t.a_not_admin_error,
        );
        page.link = Some((sign_in_page(state, next), t.oauth_back.to_owned()));
        return page.respond(StatusCode::FORBIDDEN);
    }
    let Some(token) = state.web.open_session_with(client, user, provider).await else {
        return web::unavailable(Chrome::for_request(headers));
    };
    let next = if admin {
        next.to_owned()
    } else {
        site::landing(Some(next), user.services)
    };
    let cookies = [
        state.web.session_cookie(&token),
        state.web.removal_cookie(CSRF_COOKIE),
        state.web.removal_cookie(PENDING_COOKIE),
    ];
    let Some(notice) = notice else {
        return web::see_other(&next, &cookies);
    };
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let mut page = Message::new(
        chrome,
        t.notice_bound_auto_title,
        t.notice_bound_auto_title,
        &notice,
    );
    page.link = Some((next, t.continue_on.to_owned()));
    let mut response = page.respond(StatusCode::OK);
    for cookie in cookies {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// The browser session of `headers`, if it is the one of `session_id` and `user_id`.
async fn same_session(
    state: &AppState,
    headers: &HeaderMap,
    session_id: i64,
    user_id: i64,
) -> Option<gono_server_core::web_sessions::SessionUser> {
    state
        .web
        .session(headers)
        .await
        .map(|(user, _)| user)
        .filter(|user| user.session_id == session_id && user.user_id == user_id)
}

/// A binding from the account page reported `exchanged`.
async fn bound(
    state: &AppState,
    headers: &HeaderMap,
    client: IpAddr,
    provider: Provider,
    exchanged: Exchanged,
    session_id: i64,
    user_id: i64,
) -> Response {
    let Some(user) = same_session(state, headers, session_id, user_id).await else {
        state.web.record_failure(client);
        return not_completed(headers, crate::files::account::OVERVIEW);
    };
    let overview = crate::files::account::OVERVIEW;
    match identities::bind(
        &state.db,
        user.user_id,
        &exchanged.claims,
        identities::How::AccountPage,
        gono_server_core::audit::Actor::User,
        Some(client),
        db::unix_now(),
    )
    .await
    {
        Ok(identities::Bound::Bound(_) | identities::Bound::Already(_)) => {
            tracing::info!(%client, user = %user.username, provider = provider.as_str(), "identity bound on the account page");
            web::see_other(&format!("{overview}?done=bound-{}", provider.as_str()), &[])
        }
        Ok(identities::Bound::OtherAccount) => web::see_other(
            &format!("{overview}?failed=taken-{}", provider.as_str()),
            &[],
        ),
        Ok(identities::Bound::AccountHasOne | identities::Bound::NoAccount) => {
            web::see_other(&format!("{overview}?failed=has-{}", provider.as_str()), &[])
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot bind a third-party identity");
            web::unavailable(Chrome::for_request(headers))
        }
    }
}

/// A confirmation from the account page reported `exchanged`: it must be the identity of
/// `provider` bound to the account.
#[allow(clippy::too_many_arguments)]
async fn reauthenticated(
    state: &AppState,
    headers: &HeaderMap,
    client: IpAddr,
    provider: Provider,
    exchanged: Exchanged,
    session_id: i64,
    user_id: i64,
    next: &str,
) -> Response {
    let Some(user) = same_session(state, headers, session_id, user_id).await else {
        state.web.record_failure(client);
        return not_completed(headers, crate::files::account::OVERVIEW);
    };
    let claims = &exchanged.claims;
    let found = match identities::find(&state.db, provider, &claims.realm, &claims.subject).await {
        Ok(found) => found,
        Err(err) => {
            tracing::error!(error = %err, "cannot look a third-party identity up");
            return web::unavailable(Chrome::for_request(headers));
        }
    };
    if found.is_some_and(|identity| identity.user_id == user.user_id) {
        state.web.confirm(&user);
        tracing::info!(%client, user = %user.username, provider = provider.as_str(), "confirmed with a third-party identity");
        return web::see_other(next, &[]);
    }
    state.web.record_failure(client);
    tracing::info!(%client, user = %user.username, provider = provider.as_str(), "confirmation with another identity refused");
    web::see_other(
        &format!(
            "{}?failed=other-{}",
            crate::files::account::OVERVIEW,
            provider.as_str()
        ),
        &[],
    )
}

/// The identity waiting in the browser of `headers`, and its token.
async fn waiting(state: &AppState, headers: &HeaderMap) -> Option<(identities::Pending, String)> {
    let token = web::cookie(headers, &state.web.cookie_name(PENDING_COOKIE))
        .filter(|value| identities::is_token(value))?;
    match identities::pending(&state.db, Holder::Web, &token, db::unix_now()).await {
        Ok(pending) => pending.map(|pending| (pending, token)),
        Err(err) => {
            tracing::error!(error = %err, "cannot read a pending identity");
            None
        }
    }
}

/// What pages show of an identity: the label, or nothing (WeChat).
fn shown_label(claims: &Claims) -> String {
    if claims.label.is_empty() {
        String::new()
    } else {
        claims.label.clone()
    }
}

/// `templates/unbound.html`.
#[derive(Template)]
#[template(path = "unbound.html")]
struct UnboundPage {
    chrome: Chrome,
    csrf: String,
    title: String,
    label: String,
    next: String,
    /// The sign-in page that binds it after the password.
    sign_in: String,
    /// The sign-up page, while the provider lets identities sign up.
    signup: Option<String>,
}

/// `templates/link.html`.
#[derive(Template)]
#[template(path = "link.html")]
struct LinkPage {
    chrome: Chrome,
    csrf: String,
    title: String,
    next: String,
}

page!(UnboundPage, LinkPage);

#[derive(Deserialize)]
pub struct NextQuery {
    #[serde(default)]
    next: String,
}

/// The local page `next` names, the file UI otherwise.
fn local_next(next: &str) -> String {
    site::local_path(next)
        .filter(|next| *next != "/login")
        .unwrap_or(FILES_HOME)
        .to_owned()
}

/// The page that says the identity waiting is gone.
fn expired(headers: &HeaderMap, back: String) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    let mut page = Message::new(
        chrome,
        t.unbound_expired,
        t.unbound_expired,
        t.unbound_expired_lead,
    );
    page.link = Some((back, t.oauth_back.to_owned()));
    page.respond(StatusCode::NOT_FOUND)
}

/// `GET /login/unbound`.
pub async fn unbound_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = local_next(&query.next);
    let Some((pending, _)) = waiting(&state, &headers).await else {
        return expired(&headers, sign_in_page(&state, &next));
    };
    let (csrf, cookie) = state.web.login_csrf(&headers);
    let chrome = Chrome::for_request(&headers);
    let t = chrome.t;
    let provider = pending.claims.provider;
    let page = UnboundPage {
        title: fill(t.unbound_title, &[provider.name()]),
        label: shown_label(&pending.claims),
        sign_in: sign_in_page(&state, &next),
        signup: crate::signup::offered(&state, provider)
            .then(|| format!("{}?next={}", crate::signup::SIGNUP_PATH, encode(&next))),
        next,
        csrf,
        chrome,
    };
    let mut response = web::render(StatusCode::OK, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

#[derive(Deserialize)]
pub struct CsrfNextForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    next: String,
    #[serde(default)]
    action: String,
}

/// `POST /login/unbound/cancel`.
pub async fn cancel_unbound(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfNextForm>,
) -> Response {
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        return site::blocked(&headers, |t| t.form_expired_sign_in);
    }
    if let Some((_, token)) = waiting(&state, &headers).await
        && let Err(err) = identities::end_pending(&state.db, Holder::Web, &token).await
    {
        tracing::warn!(error = %err, "cannot forget a pending identity");
    }
    let next = local_next(&form.next);
    web::see_other(
        &sign_in_page(&state, &next),
        &[state.web.removal_cookie(PENDING_COOKIE)],
    )
}

/// `GET /login/link`.
pub async fn link_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = local_next(&query.next);
    let Some((user, token)) = state.web.session(&headers).await else {
        return web::see_other(&sign_in_page(&state, &next), &[]);
    };
    let Some((pending, _)) = waiting(&state, &headers).await else {
        return web::see_other(&next, &[state.web.removal_cookie(PENDING_COOKIE)]);
    };
    let csrf = state.web.session_csrf(&token);
    let chrome = Chrome::for_request(&headers).signed_in(&user, &csrf);
    let t = chrome.t;
    let label = shown_label(&pending.claims);
    let page = LinkPage {
        title: fill(
            t.link_title,
            &[
                pending.claims.provider.name(),
                &label,
                user.username.as_str(),
            ],
        ),
        next,
        csrf,
        chrome,
    };
    web::render(StatusCode::OK, &page)
}

/// `POST /login/link`: `action=bind` binds the identity waiting in this browser to the
/// signed-in account, anything else forgets it.
pub async fn link(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<CsrfNextForm>,
) -> Response {
    if !state.web.same_origin(&headers) {
        return site::blocked(&headers, |t| t.from_other_site);
    }
    let next = local_next(&form.next);
    let Some((user, session)) = state.web.session(&headers).await else {
        return web::see_other(&sign_in_page(&state, &next), &[]);
    };
    if !state.web.check_session_csrf(&session, &form.csrf) {
        return site::blocked(&headers, |t| t.form_expired);
    }
    let removal = state.web.removal_cookie(PENDING_COOKIE);
    let Some((pending, token)) = waiting(&state, &headers).await else {
        return web::see_other(&next, &[removal]);
    };
    if form.action != "bind" {
        if let Err(err) = identities::end_pending(&state.db, Holder::Web, &token).await {
            tracing::warn!(error = %err, "cannot forget a pending identity");
        }
        return web::see_other(&next, &[removal]);
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let provider = pending.claims.provider;
    let outcome = identities::bind_pending(
        &state.db,
        Holder::Web,
        &token,
        user.user_id,
        Some(client),
        db::unix_now(),
    )
    .await;
    let chrome = Chrome::for_request(&headers);
    let t = chrome.t;
    let (heading, lead, status) = match outcome {
        Ok(BoundPending::Bound(identity)) => {
            tracing::info!(%client, user = %user.username, provider = provider.as_str(), "identity bound after a password sign-in");
            let label = if identity.label.is_empty() {
                provider.name().to_owned()
            } else {
                format!("{} {}", provider.name(), identity.label)
            };
            (
                t.link_done,
                fill(t.link_done_lead, &[&label]),
                StatusCode::OK,
            )
        }
        Ok(BoundPending::Expired) => return web::see_other(&next, &[removal]),
        Ok(BoundPending::OtherAccount) => (
            t.link_failed,
            fill(t.err_identity_taken, &[provider.name()]),
            StatusCode::CONFLICT,
        ),
        Ok(BoundPending::AccountHasOne) => (
            t.link_failed,
            fill(t.err_identity_has_one, &[provider.name()]),
            StatusCode::CONFLICT,
        ),
        Err(err) => {
            tracing::error!(error = %err, "cannot bind a pending identity");
            return web::unavailable(chrome);
        }
    };
    let mut page = Message::new(chrome, heading, heading, &lead);
    page.link = Some((next, t.continue_on.to_owned()));
    let mut response = page.respond(status);
    response.headers_mut().append(header::SET_COOKIE, removal);
    response
}

/// A sign-in button of a provider on a sign-in page.
#[derive(Debug, Clone)]
pub struct Button {
    /// Where its form posts (or, for WeChat, where it links).
    pub action: String,
    /// Its text.
    pub label: String,
    /// A link instead of a form.
    pub link: bool,
}

/// The buttons of the providers this server offers on a sign-in page (WeChat, Google, GitHub),
/// which go on to `next`.
pub fn sign_in_buttons(state: &AppState, t: &Text, next: &str) -> Vec<Button> {
    let mut buttons: Vec<Button> = crate::wechat::sign_in::sign_in_button(state, t, next)
        .into_iter()
        .collect();
    if let Some(oauth) = &state.oauth {
        for provider in oauth.providers() {
            buttons.push(Button {
                action: format!("{START_PATH}/{}", provider.as_str()),
                label: fill(t.sign_in_with, &[provider.name()]),
                link: false,
            });
        }
    }
    buttons
}

/// The origins the forms of a page with provider buttons post to on the way out (its
/// `form-action`).
pub fn form_origins(state: &AppState) -> String {
    state
        .oauth
        .as_ref()
        .map(|oauth| oauth.form_origins())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenges_are_s256() {
        // RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(is_token(&random()) && !is_token("short"));
    }

    #[test]
    fn admin_paths_are_told_apart() {
        assert!(is_admin_path("/manage", "/manage/"));
        assert!(is_admin_path("/manage", "/manage"));
        assert!(is_admin_path("/manage", "/manage/users/alice"));
        assert!(!is_admin_path("/manage", "/manager/"));
        assert!(!is_admin_path("/manage", "/apps/files/"));
    }
}
