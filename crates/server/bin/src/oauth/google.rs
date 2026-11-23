//! Google sign-in: OpenID Connect, the authorization code flow with PKCE and a nonce.
//!
//! - The endpoints come from Google's discovery document, fetched when the first sign-in needs
//!   them and kept for [`DISCOVERY_TTL`]; a server that cannot reach Google starts all the same.
//! - The authorization request asks for `openid email profile` with `prompt=select_account`.
//! - The ID token comes from the token endpoint over TLS, so its issuer is trusted from TLS
//!   (OpenID Connect Core 3.1.3.7): its signature is not checked, but `iss`, `aud` (the client
//!   ID), `exp` and `nonce` are. It gives `sub` (the subject), `email`, `email_verified` and
//!   `name`.
//! - The access token is revoked at once ([`Client::revoke`]) and nothing of the answer is kept.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::Engine as _;
use gono_server_core::identities::{Claims, GOOGLE_REALM, Provider};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use url::Url;

use super::{Exchanged, Http, ProviderError};

/// Google's discovery document.
pub const DISCOVERY: &str = "https://accounts.google.com/.well-known/openid-configuration";

/// How long the discovery document is kept.
const DISCOVERY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The scopes asked for: the identity, the address and the name.
pub const SCOPES: &str = "openid email profile";

/// What the discovery document says.
#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    #[serde(default)]
    revocation_endpoint: Option<Url>,
}

/// Google, for one OAuth client.
#[derive(Debug)]
pub struct Client {
    http: Http,
    discovery_url: Url,
    client_id: String,
    secret: SecretString,
    discovery: Mutex<Option<(Instant, Discovery)>>,
}

impl Client {
    /// Google for the client `client_id` with its secret, finding its endpoints at
    /// `discovery_url` (Google's, [`DISCOVERY`], except in tests).
    pub fn new(http: Http, discovery_url: Url, client_id: &str, secret: SecretString) -> Self {
        Self {
            http,
            discovery_url,
            client_id: client_id.to_owned(),
            secret,
            discovery: Mutex::new(None),
        }
    }

    /// The origin of Google's pages, which forms post to on the way there: the discovery
    /// document's (Google serves both from `https://accounts.google.com`).
    pub fn form_origin(&self) -> String {
        self.discovery_url.origin().ascii_serialization()
    }

    /// The discovery document, fetched again once it is older than [`DISCOVERY_TTL`].
    async fn discovery(&self) -> Result<Discovery, ProviderError> {
        {
            let cached = self.discovery.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, discovery)) = cached.as_ref()
                && at.elapsed() < DISCOVERY_TTL
            {
                return Ok(discovery.clone());
            }
        }
        let body = self.http.get(&self.discovery_url, None).await?;
        let discovery: Discovery = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::Unavailable(
                "Google's discovery document is not the expected JSON".into(),
            )
        })?;
        *self.discovery.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((Instant::now(), discovery.clone()));
        Ok(discovery)
    }

    /// The URL that sends the browser to Google.
    pub async fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        challenge: &str,
        nonce: &str,
    ) -> Result<Url, ProviderError> {
        let mut url = self.discovery().await?.authorization_endpoint;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", nonce)
            .append_pair("prompt", "select_account");
        Ok(url)
    }

    /// Exchanges `code` for the user it names, checks the ID token and revokes the access
    /// token.
    pub async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        nonce: &str,
        now: i64,
    ) -> Result<Exchanged, ProviderError> {
        let discovery = self.discovery().await?;
        let body = self
            .http
            .post_form(
                &discovery.token_endpoint,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                    ("client_id", &self.client_id),
                    ("client_secret", self.secret.expose_secret()),
                    ("code_verifier", verifier),
                ],
                None,
            )
            .await?;
        let tokens: Tokens = serde_json::from_slice(&body).map_err(|_| {
            ProviderError::Refused("Google's token answer is not the expected JSON")
        })?;
        let Some(id_token) = tokens.id_token else {
            return Err(ProviderError::Refused("Google answered no ID token"));
        };
        let checked = check_id_token(&id_token, &discovery.issuer, &self.client_id, nonce, now);
        if let Some(access_token) = tokens.access_token {
            self.revoke(discovery.revocation_endpoint, access_token);
        }
        checked
    }

    /// Revokes `token` in the background; a failure is only logged (without the token).
    fn revoke(&self, endpoint: Option<Url>, token: String) {
        let Some(endpoint) = endpoint else {
            return;
        };
        let http = self.http.clone();
        tokio::spawn(async move {
            let token = SecretString::from(token);
            if let Err(err) = http
                .post_form(&endpoint, &[("token", token.expose_secret())], None)
                .await
            {
                tracing::warn!(error = %err, "cannot revoke a Google access token");
            }
        });
    }
}

/// The token endpoint's answer.
#[derive(Deserialize)]
struct Tokens {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

/// An audience: one client ID or several.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, client_id: &str) -> bool {
        match self {
            Self::One(one) => one == client_id,
            Self::Many(many) => many.iter().any(|one| one == client_id),
        }
    }
}

/// `email_verified`: Google sends a boolean, some issuers the string `"true"`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Verified {
    Bool(bool),
    Text(String),
}

/// The claims of an ID token that are read.
#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    aud: Audience,
    exp: i64,
    #[serde(default)]
    nonce: Option<String>,
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<Verified>,
    #[serde(default)]
    name: Option<String>,
}

/// Reads the claims of `id_token` and checks them: issued by `issuer` (Google's also as
/// `accounts.google.com`), for `client_id`, not expired at `now`, with `nonce`.
fn check_id_token(
    id_token: &str,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<Exchanged, ProviderError> {
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or(ProviderError::Refused("the ID token is not a JWT"))?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| ProviderError::Refused("the ID token is not a JWT"))?;
    let claims: IdClaims = serde_json::from_slice(&payload)
        .map_err(|_| ProviderError::Refused("the ID token lacks claims"))?;
    let issuer_ok = claims.iss == issuer
        || (issuer == "https://accounts.google.com" && claims.iss == "accounts.google.com");
    if !issuer_ok {
        return Err(ProviderError::Refused("the ID token has another issuer"));
    }
    if !claims.aud.contains(client_id) {
        return Err(ProviderError::Refused("the ID token is for another client"));
    }
    if claims.exp <= now {
        return Err(ProviderError::Refused("the ID token has expired"));
    }
    if claims.nonce.as_deref() != Some(nonce) {
        return Err(ProviderError::Refused("the ID token has another nonce"));
    }
    let verified = match claims.email_verified {
        Some(Verified::Bool(verified)) => verified,
        Some(Verified::Text(text)) => text == "true",
        None => false,
    };
    let email = claims
        .email
        .as_deref()
        .and_then(gono_server_core::email::normalize_address);
    let claims = Claims {
        provider: Provider::Google,
        realm: GOOGLE_REALM.to_owned(),
        label: email.clone().unwrap_or_default(),
        subject: claims.sub,
        unionid: None,
        email_verified: verified && email.is_some(),
        email,
        name: claims.name,
    };
    let verified_emails = claims
        .email
        .iter()
        .filter(|_| claims.email_verified)
        .cloned()
        .collect();
    Ok(Exchanged {
        claims,
        verified_emails,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(claims: &serde_json::Value) -> String {
        let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
        format!(
            "{}.{}.{}",
            encode(br#"{"alg":"RS256"}"#),
            encode(claims.to_string().as_bytes()),
            encode(b"signature")
        )
    }

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "client-1",
            "exp": 2_000,
            "nonce": "n1",
            "sub": "1080",
            "email": "Alice@Gmail.com",
            "email_verified": true,
            "name": "Alice Example",
        })
    }

    #[test]
    fn id_tokens_are_checked() {
        let check = |claims: &serde_json::Value| {
            check_id_token(
                &token(claims),
                "https://accounts.google.com",
                "client-1",
                "n1",
                1_000,
            )
        };
        let exchanged = check(&claims()).unwrap();
        assert_eq!(exchanged.claims.subject, "1080");
        assert_eq!(exchanged.claims.label, "alice@gmail.com");
        assert_eq!(exchanged.verified_emails, ["alice@gmail.com"]);
        assert_eq!(exchanged.claims.name.as_deref(), Some("Alice Example"));

        let mut other = claims();
        other["iss"] = "accounts.google.com".into();
        other["aud"] = serde_json::json!(["x", "client-1"]);
        other["email_verified"] = "false".into();
        let exchanged = check(&other).unwrap();
        assert!(exchanged.verified_emails.is_empty());
        assert!(!exchanged.claims.email_verified);

        for (key, value) in [
            ("iss", serde_json::json!("https://evil.example")),
            ("aud", serde_json::json!("client-2")),
            ("exp", serde_json::json!(1_000)),
            ("nonce", serde_json::json!("n2")),
            ("sub", serde_json::Value::Null),
        ] {
            let mut bad = claims();
            bad[key] = value;
            assert!(
                matches!(check(&bad), Err(ProviderError::Refused(_))),
                "{key}"
            );
        }
        let mut no_nonce = claims();
        no_nonce.as_object_mut().unwrap().remove("nonce");
        assert!(check(&no_nonce).is_err());
        assert!(check_id_token("x", "i", "c", "n", 0).is_err());
    }
}
