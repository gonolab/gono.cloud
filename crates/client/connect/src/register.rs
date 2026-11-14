//! Discovery and device registration (protocol 3 and 4).
//!
//! ```text
//! let server = Server::new("https://cloud.example.com")?;
//! let discovery = server.discover().await?;
//! let pending = server.start_registration(&discovery, &key, &device).await?;
//! // Show pending.short_id() on the device, open pending.login_url() in a browser (or show it
//! // as a QR code), then:
//! let credentials = pending.wait().await?;
//! ```
//!
//! The credential is a secret: the product keeps it in the platform's protected storage, next
//! to the device key (threat model C13).

use std::time::Duration;

use gono_protocol::connect::{
    DeviceEntry, DeviceId, Discovery, LoginStart, LoginStarted, PollRequest, Registered, Signed,
    Statement, paths, statement::Login,
};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Result, tls};

/// How often a pending registration is polled (protocol 4.3: every 2–5 seconds).
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// How long one HTTP request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What a device reports about itself (protocol 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// `[a-z0-9-]{1,32}`: `input-show`, ...
    pub product: String,
    /// `[a-z0-9-]{1,32}`: `macos`, `windows`, `linux`, `harmonyos`, ...
    pub platform: String,
    /// The name shown to people.
    pub name: String,
    /// Product version.
    pub version: String,
}

/// A device's credential and what the server told about it at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// The server origin, as statements name it.
    pub server: String,
    /// The account's username.
    pub username: String,
    /// The device's app password. Secret.
    pub app_password: String,
    /// The device's directory entry at registration.
    pub device: DeviceEntry,
    /// The device may send pairing requests until then.
    pub pairing_open_until: Option<i64>,
}

/// A Gono Cloud server, by its origin.
#[derive(Debug, Clone)]
pub struct Server {
    origin: Url,
    http: reqwest::Client,
}

impl Server {
    /// The server at `origin`, for example `https://cloud.example.com`.
    pub fn new(origin: &str) -> Result<Self> {
        let origin = Url::parse(origin).map_err(|err| Error::Url(err.to_string()))?;
        if !matches!(origin.scheme(), "https" | "http") || origin.host_str().is_none() {
            return Err(Error::Url(format!("{origin} is not an http(s) origin")));
        }
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls::client_config(&[b"h2", b"http/1.1"]))
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("gono-connect/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| Error::Http(err.to_string()))?;
        Ok(Self { origin, http })
    }

    fn url(&self, path: &str) -> Url {
        let mut url = self.origin.clone();
        url.set_path(path);
        url.set_query(None);
        url
    }

    /// The discovery document (protocol 3).
    pub async fn discover(&self) -> Result<Discovery> {
        let response = self
            .http
            .get(self.url(paths::DISCOVERY))
            .send()
            .await
            .map_err(|err| Error::Http(err.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::NotOffered);
        }
        json_body(response).await
    }

    /// Starts registering the device of `key` (protocol 4.1).
    pub async fn start_registration(
        &self,
        discovery: &Discovery,
        key: &SecretKey,
        device: &DeviceInfo,
    ) -> Result<PendingRegistration> {
        let login = Url::parse(&discovery.login).map_err(|err| Error::Url(err.to_string()))?;
        let start = LoginStart {
            endpoint_id: key.public().into(),
            product: device.product.clone(),
            platform: device.platform.clone(),
            name: device.name.clone(),
            version: device.version.clone(),
        };
        let response = self
            .http
            .post(login)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&start).unwrap_or_default())
            .send()
            .await
            .map_err(|err| Error::Http(err.to_string()))?;
        let started: LoginStarted = json_body(response).await?;
        Ok(PendingRegistration {
            http: self.http.clone(),
            server: discovery.server.clone(),
            key: key.clone(),
            started,
        })
    }
}

/// The body of a successful answer, or the error it names.
async fn json_body<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(|err| Error::Http(err.to_string()))?;
    if (200..300).contains(&status) {
        return serde_json::from_slice(&body).map_err(|err| Error::Http(err.to_string()));
    }
    let code = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value["error"].as_str().map(str::to_owned))
        .unwrap_or_default();
    Err(Error::Server { status, code })
}

/// A registration waiting for the user to grant it in the browser.
#[derive(Debug, Clone)]
pub struct PendingRegistration {
    http: reqwest::Client,
    server: String,
    key: SecretKey,
    started: LoginStarted,
}

impl PendingRegistration {
    /// The URL to open in a browser, or to show as a QR code.
    pub fn login_url(&self) -> &str {
        &self.started.login_url
    }

    /// The device's short ID, which the consent page shows as well: show it on the device.
    pub fn short_id(&self) -> String {
        DeviceId::from(self.key.public()).short()
    }

    /// When the registration expires, UNIX seconds.
    pub fn expires_at(&self) -> i64 {
        self.started.expires_at
    }

    /// Polls once: `None` while the user has not decided.
    pub async fn poll(&self) -> Result<Option<Credentials>> {
        let proof = Signed::sign(
            &Statement::Login(Login {
                server: self.server.clone(),
                endpoint_id: self.key.public().into(),
                challenge: self.started.challenge.clone(),
            }),
            &self.key,
        );
        let request = PollRequest {
            token: self.started.poll.token.clone(),
            proof: Some(proof),
        };
        let poll =
            Url::parse(&self.started.poll.endpoint).map_err(|err| Error::Url(err.to_string()))?;
        let response = self
            .http
            .post(poll)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&request).unwrap_or_default())
            .send()
            .await
            .map_err(|err| Error::Http(err.to_string()))?;
        match response.status().as_u16() {
            202 => Ok(None),
            404 => Err(Error::RegistrationGone),
            _ => {
                let registered: Registered = json_body(response).await?;
                Ok(Some(Credentials {
                    server: registered.server,
                    username: registered.username,
                    app_password: registered.app_password,
                    device: registered.device,
                    pairing_open_until: registered.pairing_open_until,
                }))
            }
        }
    }

    /// Polls until the user granted or denied the registration, or it expired.
    pub async fn wait(&self) -> Result<Credentials> {
        loop {
            match self.poll().await {
                Ok(Some(credentials)) => return Ok(credentials),
                Ok(None) => {}
                // A network hiccup is not the end of the sign-in.
                Err(Error::Http(err)) => tracing::debug!(error = %err, "registration poll failed"),
                Err(err) => return Err(err),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_must_be_http() {
        assert!(Server::new("https://cloud.example.com").is_ok());
        assert!(Server::new("ftp://cloud.example.com").is_err());
        assert!(Server::new("not a url").is_err());
    }
}
