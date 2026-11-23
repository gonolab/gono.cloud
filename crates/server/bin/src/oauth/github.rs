//! GitHub sign-in: an OAuth app, the authorization code flow with `state` and PKCE (`S256`,
//! which GitHub accepts since July 2025 without requiring it).
//!
//! - The authorization request asks for `user:email`: the public profile needs no scope, the
//!   verified addresses do.
//! - The token request asks for JSON. `GET /user` gives the numeric `id` (the subject; logins
//!   can be renamed and reused), `login` (the label, `@login`) and `name`; `GET /user/emails`
//!   gives the addresses, of which the verified ones count, the primary first.
//! - The access token is revoked at once (`DELETE /applications/{client_id}/token`) and nothing
//!   of the answers is kept.

use gono_server_core::identities::{Claims, GITHUB_REALM, Provider};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use url::Url;

use super::{Exchanged, Http, ProviderError};

/// The scopes asked for: the verified addresses.
pub const SCOPES: &str = "user:email";

/// Where GitHub's endpoints are.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The authorization endpoint, `https://github.com/login/oauth/authorize`.
    pub authorize: Url,
    /// The token endpoint, `https://github.com/login/oauth/access_token`.
    pub token: Url,
    /// The REST API, `https://api.github.com/`.
    pub api: Url,
}

impl Endpoints {
    /// GitHub's own.
    pub fn github() -> Self {
        Self {
            authorize: Url::parse("https://github.com/login/oauth/authorize").expect("a URL"),
            token: Url::parse("https://github.com/login/oauth/access_token").expect("a URL"),
            api: Url::parse("https://api.github.com/").expect("a URL"),
        }
    }
}

/// GitHub, for one OAuth app.
#[derive(Debug)]
pub struct Client {
    http: Http,
    endpoints: Endpoints,
    client_id: String,
    secret: SecretString,
}

/// The token endpoint's answer.
#[derive(Deserialize)]
struct Token {
    #[serde(default)]
    access_token: Option<String>,
}

/// `GET /user`.
#[derive(Deserialize)]
struct User {
    id: u64,
    login: String,
    #[serde(default)]
    name: Option<String>,
}

/// One address of `GET /user/emails`.
#[derive(Deserialize)]
struct Email {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

impl Client {
    /// GitHub at `endpoints` for the app `client_id` with its secret.
    pub fn new(http: Http, endpoints: Endpoints, client_id: &str, secret: SecretString) -> Self {
        Self {
            http,
            endpoints,
            client_id: client_id.to_owned(),
            secret,
        }
    }

    /// The origin of GitHub's pages, which forms post to on the way there.
    pub fn form_origin(&self) -> String {
        self.endpoints.authorize.origin().ascii_serialization()
    }

    /// The URL that sends the browser to GitHub.
    pub fn authorize_url(&self, redirect_uri: &str, state: &str, challenge: &str) -> Url {
        let mut url = self.endpoints.authorize.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        url
    }

    fn api(&self, path: &str) -> Result<Url, ProviderError> {
        self.endpoints
            .api
            .join(path)
            .map_err(|_| ProviderError::Unavailable("GitHub's API URL is not valid".into()))
    }

    /// Exchanges `code` for the user it names, and revokes the access token.
    pub async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<Exchanged, ProviderError> {
        let body = self
            .http
            .post_form(
                &self.endpoints.token,
                &[
                    ("client_id", &self.client_id),
                    ("client_secret", self.secret.expose_secret()),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                    ("code_verifier", verifier),
                ],
                None,
            )
            .await?;
        // A refused code is `200 {"error": "bad_verification_code", ...}`.
        let token: Token = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::Refused("GitHub's token answer is not the expected JSON")
        })?;
        let Some(token) = token.access_token.map(SecretString::from) else {
            return Err(ProviderError::Refused("GitHub refused the code"));
        };
        let read = self.read_user(&token).await;
        self.revoke(token);
        read
    }

    /// The user and the verified addresses of `token`.
    async fn read_user(&self, token: &SecretString) -> Result<Exchanged, ProviderError> {
        let body = self
            .http
            .get(&self.api("user")?, Some(token.expose_secret()))
            .await?;
        let user: User = serde_json::from_slice(&body)
            .map_err(|_| ProviderError::Refused("GitHub's user is not the expected JSON"))?;
        let body = self
            .http
            .get(&self.api("user/emails")?, Some(token.expose_secret()))
            .await?;
        let mut emails: Vec<Email> = serde_json::from_slice(&body)
            .map_err(|_| ProviderError::Refused("GitHub's addresses are not the expected JSON"))?;
        // The primary address first.
        emails.sort_by_key(|email| !email.primary);
        let verified_emails: Vec<String> = emails
            .iter()
            .filter(|email| email.verified)
            .filter_map(|email| gono_server_core::email::normalize_address(&email.email))
            .collect();
        let primary = emails.first();
        let name = user
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| user.login.clone());
        Ok(Exchanged {
            claims: Claims {
                provider: Provider::GitHub,
                realm: GITHUB_REALM.to_owned(),
                subject: user.id.to_string(),
                unionid: None,
                label: format!("@{}", user.login),
                email: primary
                    .and_then(|email| gono_server_core::email::normalize_address(&email.email)),
                email_verified: primary.is_some_and(|email| email.verified),
                name: Some(name),
            },
            verified_emails,
        })
    }

    /// Revokes `token` in the background; a failure is only logged (without the token).
    fn revoke(&self, token: SecretString) {
        let Ok(url) = self.api(&format!("applications/{}/token", self.client_id)) else {
            return;
        };
        let http = self.http.clone();
        let basic = (self.client_id.clone(), self.secret.clone());
        tokio::spawn(async move {
            let body = serde_json::json!({ "access_token": token.expose_secret() });
            if let Err(err) = http
                .delete_json(&url, (&basic.0, basic.1.expose_secret()), &body)
                .await
            {
                tracing::warn!(error = %err, "cannot revoke a GitHub access token");
            }
        });
    }
}
