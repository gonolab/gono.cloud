//! A local stand-in for Google and GitHub, for tests: an HTTP server on 127.0.0.1 with the
//! endpoints the server calls (Google's discovery document, token and revocation endpoints;
//! GitHub's token endpoint, `/user`, `/user/emails` and the revocation of tokens). It checks what
//! the providers check: the client secret, the redirect URI, the PKCE verifier against the
//! challenge of the authorization request, and that a code is used once. Tests play the user
//! at the provider with [`Mock::approve`] and [`Mock::deny`].

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Form, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::Engine as _;
use secrecy::SecretString;
use url::Url;

use super::{Http, OAuthProvider, ProviderClient, challenge, github, google};

/// The client ID of the mock's apps.
pub const CLIENT_ID: &str = "client-1";

/// Their client secret.
pub const CLIENT_SECRET: &str = "the client secret";

/// A user at the provider.
#[derive(Debug, Clone)]
pub struct Person {
    /// Google's `sub`, GitHub's numeric id.
    pub subject: String,
    /// GitHub's login.
    pub login: String,
    /// The address.
    pub email: Option<String>,
    /// Whether the provider verified it.
    pub verified: bool,
    /// The name.
    pub name: Option<String>,
}

impl Person {
    /// A user with a verified address.
    pub fn new(subject: &str, email: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            login: format!("user{subject}"),
            email: Some(email.to_owned()),
            verified: true,
            name: Some("Alice Example".to_owned()),
        }
    }
}

/// A code the user got at the provider.
#[derive(Debug, Clone)]
struct Grant {
    person: Person,
    challenge: String,
    nonce: Option<String>,
    redirect_uri: String,
}

#[derive(Debug, Default)]
struct Inner {
    codes: HashMap<String, Grant>,
    tokens: HashMap<String, Person>,
    revoked: Vec<String>,
    next: u64,
    /// Every endpoint answers 503.
    down: bool,
    /// The token endpoints refuse every code.
    refuse: bool,
    /// The ID tokens carry this nonce instead of the request's.
    wrong_nonce: bool,
}

type Shared = Arc<Mutex<Inner>>;

/// The mock provider.
pub struct Mock {
    /// `http://127.0.0.1:<port>`.
    pub origin: Url,
    inner: Shared,
}

impl Mock {
    /// Starts the mock on a free port of 127.0.0.1.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let origin = Url::parse(&format!("http://{addr}")).unwrap();
        let inner: Shared = Arc::default();
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/token", post(google_token))
            .route("/revoke", post(google_revoke))
            .route("/login/oauth/access_token", post(github_token))
            .route("/user", get(github_user))
            .route("/user/emails", get(github_emails))
            .route("/applications/{client}/token", delete(github_revoke))
            .with_state((inner.clone(), origin.clone()));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { origin, inner }
    }

    /// Google, as this mock plays it.
    pub fn google(&self) -> OAuthProvider {
        let discovery = self
            .origin
            .join("/.well-known/openid-configuration")
            .unwrap();
        OAuthProvider::new(ProviderClient::Google(google::Client::new(
            Http::new("Google").unwrap(),
            discovery,
            CLIENT_ID,
            SecretString::from(CLIENT_SECRET.to_owned()),
        )))
    }

    /// GitHub, as this mock plays it.
    pub fn github(&self) -> OAuthProvider {
        let endpoints = github::Endpoints {
            authorize: self.origin.join("/login/oauth/authorize").unwrap(),
            token: self.origin.join("/login/oauth/access_token").unwrap(),
            api: self.origin.join("/").unwrap(),
        };
        OAuthProvider::new(ProviderClient::GitHub(github::Client::new(
            Http::new("GitHub").unwrap(),
            endpoints,
            CLIENT_ID,
            SecretString::from(CLIENT_SECRET.to_owned()),
        )))
    }

    /// `person` signs in at the provider's page of `authorize` (the `Location` the server sent
    /// the browser to) and agrees: the path and query of the callback the provider sends the
    /// browser back to.
    pub fn approve(&self, authorize: &str, person: &Person) -> String {
        let url = Url::parse(authorize).unwrap();
        assert_eq!(url.origin(), self.origin.origin(), "{authorize}");
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["code_challenge_method"], "S256");
        let redirect = Url::parse(&query["redirect_uri"]).unwrap();
        let code = {
            let mut inner = self.inner.lock().unwrap();
            inner.next += 1;
            let code = format!("code-{}", inner.next);
            inner.codes.insert(
                code.clone(),
                Grant {
                    person: person.clone(),
                    challenge: query["code_challenge"].clone(),
                    nonce: query.get("nonce").cloned(),
                    redirect_uri: query["redirect_uri"].clone(),
                },
            );
            code
        };
        format!("{}?code={code}&state={}", redirect.path(), query["state"])
    }

    /// The user cancels at the provider's page of `authorize`.
    pub fn deny(&self, authorize: &str) -> String {
        let url = Url::parse(authorize).unwrap();
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let redirect = Url::parse(&query["redirect_uri"]).unwrap();
        format!(
            "{}?error=access_denied&state={}",
            redirect.path(),
            query["state"]
        )
    }

    /// Makes every endpoint answer 503 (or stop doing so).
    pub fn set_down(&self, down: bool) {
        self.inner.lock().unwrap().down = down;
    }

    /// Makes the token endpoints refuse every code (or stop doing so).
    pub fn set_refuse(&self, refuse: bool) {
        self.inner.lock().unwrap().refuse = refuse;
    }

    /// Makes the ID tokens carry another nonce (or stop doing so).
    pub fn set_wrong_nonce(&self, wrong: bool) {
        self.inner.lock().unwrap().wrong_nonce = wrong;
    }

    /// The access tokens revoked so far.
    pub async fn revoked(&self, count: usize) -> Vec<String> {
        for _ in 0..200 {
            let revoked = self.inner.lock().unwrap().revoked.clone();
            if revoked.len() >= count {
                return revoked;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.inner.lock().unwrap().revoked.clone()
    }
}

type MockState = State<(Shared, Url)>;

fn unavailable() -> Response {
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

async fn discovery(State((inner, origin)): MockState) -> Response {
    if inner.lock().unwrap().down {
        return unavailable();
    }
    let at = |path: &str| origin.join(path).unwrap().to_string();
    Json(serde_json::json!({
        "issuer": origin.as_str().trim_end_matches('/'),
        "authorization_endpoint": at("/authorize"),
        "token_endpoint": at("/token"),
        "revocation_endpoint": at("/revoke"),
    }))
    .into_response()
}

/// Takes the grant of a token request, checking what a provider checks.
fn take_grant(inner: &mut Inner, form: &HashMap<String, String>) -> Option<Grant> {
    if inner.refuse
        || form.get("client_id").map(String::as_str) != Some(CLIENT_ID)
        || form.get("client_secret").map(String::as_str) != Some(CLIENT_SECRET)
    {
        return None;
    }
    let grant = inner.codes.remove(form.get("code")?)?;
    let verifier = form.get("code_verifier")?;
    (challenge(verifier) == grant.challenge
        && form.get("redirect_uri") == Some(&grant.redirect_uri))
    .then_some(grant)
}

async fn google_token(
    State((inner, origin)): MockState,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut inner = inner.lock().unwrap();
    if inner.down {
        return unavailable();
    }
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(grant) = take_grant(&mut inner, &form) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant" })),
        )
            .into_response();
    };
    let nonce = if inner.wrong_nonce {
        Some("another".to_owned())
    } else {
        grant.nonce.clone()
    };
    let claims = serde_json::json!({
        "iss": origin.as_str().trim_end_matches('/'),
        "aud": CLIENT_ID,
        "exp": gono_server_core::db::unix_now() + 3600,
        "nonce": nonce,
        "sub": grant.person.subject,
        "email": grant.person.email,
        "email_verified": grant.person.verified,
        "name": grant.person.name,
    });
    let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    let id_token = format!(
        "{}.{}.{}",
        encode(br#"{"alg":"RS256","kid":"k1"}"#),
        encode(claims.to_string().as_bytes()),
        encode(b"not checked: the token comes over TLS")
    );
    inner.next += 1;
    let access_token = format!("ya29.token-{}", inner.next);
    Json(serde_json::json!({
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3599,
    }))
    .into_response()
}

async fn google_revoke(
    State((inner, _)): MockState,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut inner = inner.lock().unwrap();
    if let Some(token) = form.get("token") {
        inner.revoked.push(token.clone());
    }
    StatusCode::OK.into_response()
}

async fn github_token(
    State((inner, _)): MockState,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut inner = inner.lock().unwrap();
    if inner.down {
        return unavailable();
    }
    assert_eq!(
        headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "the token request asks for JSON"
    );
    let Some(grant) = take_grant(&mut inner, &form) else {
        // GitHub answers a refused code with 200 and an error.
        return Json(serde_json::json!({ "error": "bad_verification_code" })).into_response();
    };
    inner.next += 1;
    let token = format!("gho_token{}", inner.next);
    inner.tokens.insert(token.clone(), grant.person);
    Json(
        serde_json::json!({ "access_token": token, "token_type": "bearer", "scope": "user:email" }),
    )
    .into_response()
}

/// The person of the request's bearer token.
fn bearer(inner: &Inner, headers: &HeaderMap) -> Option<Person> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    inner.tokens.get(token).cloned()
}

async fn github_user(State((inner, _)): MockState, headers: HeaderMap) -> Response {
    let inner = inner.lock().unwrap();
    let Some(person) = bearer(&inner, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    Json(serde_json::json!({
        "id": person.subject.parse::<u64>().unwrap(),
        "login": person.login,
        "name": person.name,
    }))
    .into_response()
}

async fn github_emails(State((inner, _)): MockState, headers: HeaderMap) -> Response {
    let inner = inner.lock().unwrap();
    let Some(person) = bearer(&inner, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let mut emails = vec![serde_json::json!({
        "email": format!("{}@users.noreply.github.com", person.login),
        "primary": false,
        "verified": true,
        "visibility": null,
    })];
    if let Some(email) = &person.email {
        emails.insert(
            0,
            serde_json::json!({
                "email": email,
                "primary": true,
                "verified": person.verified,
                "visibility": "private",
            }),
        );
    }
    Json(emails).into_response()
}

async fn github_revoke(
    State((inner, _)): MockState,
    Path(client): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"));
    if client != CLIENT_ID
        || headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            != Some(format!("Basic {basic}").as_str())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut inner = inner.lock().unwrap();
    if let Some(token) = body["access_token"].as_str() {
        inner.tokens.remove(token);
        inner.revoked.push(token.to_owned());
    }
    StatusCode::NO_CONTENT.into_response()
}
