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
//! Everything is bound to the origin given to [`Server::new`] (see `origin.rs`): it must be
//! `https` (plain `http` only on a loopback host), the URLs the server names must be on it,
//! redirects are not followed, and the `login` statement names it, never the `server` value of
//! an answer.
//!
//! The credential is a secret: the product keeps it in the platform's protected storage, next
//! to the device key (threat model C13).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gono_protocol::connect::{
    DeviceEntry, DeviceId, Discovery, LoginStart, LoginStarted, PollRequest, Registered, Signed,
    Statement, paths, statement::Login,
};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Result, origin::Origin, tls};

/// How often a pending registration is polled (protocol 4.3: every 2–5 seconds).
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// How long one HTTP request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest HTTP body read from the server. The protocol's bodies are at most 64 KiB.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The longest a registration is polled for, whatever its `expires_at` says (protocol 15:
/// 20 minutes).
const MAX_FLOW_SECS: i64 = 60 * 60;

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

/// A device's credential and what the server told about it at registration. `Debug` leaves
/// the app password out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// The server origin, as statements name it: the origin the device registered with.
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

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("app_password", &"<redacted>")
            .field("device", &self.device)
            .field("pairing_open_until", &self.pairing_open_until)
            .finish()
    }
}

/// A Gono Cloud server, by its origin.
#[derive(Debug, Clone)]
pub struct Server {
    origin: Origin,
    http: reqwest::Client,
}

impl Server {
    /// The server at `origin`, for example `https://cloud.example.com`. It must be `https`;
    /// plain `http` is allowed only on a loopback host (`localhost`, 127.0.0.0/8, `::1`), for
    /// tests. A path is ignored.
    pub fn new(origin: &str) -> Result<Self> {
        let origin = Origin::parse(origin)?;
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls::client_config(&[b"h2", b"http/1.1"]))
            .timeout(REQUEST_TIMEOUT)
            // A redirect could leave the origin, or TLS (`https` to `http`).
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("gono-connect/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| Error::Http(err.to_string()))?;
        Ok(Self { origin, http })
    }

    /// The server origin, normalized as statements name it: `https://cloud.example.com`.
    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }

    /// The discovery document (protocol 3), checked: its version is the one this crate
    /// speaks ([`Error::UnsupportedVersion`]), it names this origin ([`Error::WrongServer`]),
    /// and its login and WebSocket URLs are on it ([`Error::Url`]).
    pub async fn discover(&self) -> Result<Discovery> {
        let response = self
            .http
            .get(self.origin.join(paths::DISCOVERY))
            .send()
            .await
            .map_err(|err| Error::Http(err.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::NotOffered);
        }
        let discovery: Discovery = json_body(response).await?;
        self.origin.check_discovery(&discovery)?;
        Ok(discovery)
    }

    /// Starts registering the device of `key` (protocol 4.1). `discovery` is checked as
    /// [`Server::discover`] checks it.
    pub async fn start_registration(
        &self,
        discovery: &Discovery,
        key: &SecretKey,
        device: &DeviceInfo,
    ) -> Result<PendingRegistration> {
        self.origin.check_discovery(discovery)?;
        let login = self.origin.check_url("login", &discovery.login, false)?;
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
        let server_now = server_time(response.headers());
        let started: LoginStarted = json_body(response).await?;
        let poll = self
            .origin
            .check_url("poll", &started.poll.endpoint, false)?;
        Ok(PendingRegistration {
            http: self.http.clone(),
            origin: self.origin.clone(),
            poll,
            key: key.clone(),
            deadline: Instant::now() + flow_lifetime(started.expires_at, server_now),
            started,
        })
    }
}

/// UNIX seconds now, by the local clock.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The server's clock, from the `Date` header of its answer.
fn server_time(headers: &reqwest::header::HeaderMap) -> Option<i64> {
    let date = headers.get(reqwest::header::DATE)?.to_str().ok()?;
    let at = httpdate::parse_http_date(date).ok()?;
    let since = at.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since.as_secs()).ok()
}

/// How long a flow that expires at `expires_at` (server time) is polled. Measured against the
/// server's clock when its answer carried one, so that a device whose clock is off neither
/// stops early nor polls forever; at most [`MAX_FLOW_SECS`].
fn flow_lifetime(expires_at: i64, server_now: Option<i64>) -> Duration {
    let now = server_now.unwrap_or_else(unix_now);
    let left = expires_at.saturating_sub(now).clamp(0, MAX_FLOW_SECS);
    Duration::from_secs(left.unsigned_abs())
}

/// Reads the body of `response`, at most [`MAX_BODY_BYTES`].
async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let too_large = || Error::Http(format!("the answer is larger than {MAX_BODY_BYTES} bytes"));
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| Error::Http(err.to_string()))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The body of a successful answer, or the error it names.
async fn json_body<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status().as_u16();
    let body = read_body(response).await?;
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
    origin: Origin,
    poll: Url,
    key: SecretKey,
    started: LoginStarted,
    /// When [`PendingRegistration::wait`] gives up: `expires_at`, by the server's clock.
    deadline: Instant,
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

    /// When the registration expires, UNIX seconds by the server's clock.
    pub fn expires_at(&self) -> i64 {
        self.started.expires_at
    }

    /// Polls once: `None` while the user has not decided.
    ///
    /// The credential's `server` is the origin given to [`Server::new`]; an answer naming
    /// another is refused with [`Error::WrongServer`].
    pub async fn poll(&self) -> Result<Option<Credentials>> {
        let proof = Signed::sign(
            &Statement::Login(Login {
                server: self.origin.as_str().to_owned(),
                endpoint_id: self.key.public().into(),
                challenge: self.started.challenge.clone(),
            }),
            &self.key,
        );
        let request = PollRequest {
            token: self.started.poll.token.clone(),
            proof: Some(proof),
        };
        let response = self
            .http
            .post(self.poll.clone())
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
                self.origin.check_server(&registered.server)?;
                Ok(Some(Credentials {
                    server: self.origin.as_str().to_owned(),
                    username: registered.username,
                    app_password: registered.app_password,
                    device: registered.device,
                    pairing_open_until: registered.pairing_open_until,
                }))
            }
        }
    }

    /// Polls until the user granted or denied the registration, or it expired: after
    /// `expires_at` it stops with [`Error::RegistrationGone`], even while the server cannot be
    /// reached.
    pub async fn wait(&self) -> Result<Credentials> {
        loop {
            match self.poll().await {
                Ok(Some(credentials)) => return Ok(credentials),
                Ok(None) => {}
                // A network hiccup or a server problem is not the end of the sign-in.
                Err(Error::Http(err)) => tracing::debug!(error = %err, "registration poll failed"),
                Err(Error::Server { status, code }) if status == 429 || status >= 500 => {
                    tracing::debug!(status, code, "registration poll refused for now");
                }
                Err(err) => return Err(err),
            }
            let now = Instant::now();
            if now >= self.deadline {
                return Err(Error::RegistrationGone);
            }
            tokio::time::sleep(POLL_INTERVAL.min(self.deadline - now)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_must_be_https_or_loopback() {
        assert!(Server::new("https://cloud.example.com").is_ok());
        assert!(Server::new("http://127.0.0.1:8080").is_ok());
        assert!(Server::new("http://cloud.example.com").is_err());
        assert!(Server::new("ftp://cloud.example.com").is_err());
        assert!(Server::new("not a url").is_err());
        assert_eq!(
            Server::new("https://Cloud.Example.com/").unwrap().origin(),
            "https://cloud.example.com"
        );
    }

    #[tokio::test]
    async fn bodies_are_capped() {
        let response = |body: Vec<u8>| reqwest::Response::from(http::Response::new(body));
        let small: serde_json::Value = json_body(response(b"{\"a\":1}".to_vec())).await.unwrap();
        assert_eq!(small["a"], 1);
        let large = format!("\"{}\"", "x".repeat(MAX_BODY_BYTES));
        assert!(matches!(
            json_body::<String>(response(large.into_bytes())).await,
            Err(Error::Http(_))
        ));
        let refused = http::Response::builder()
            .status(409)
            .body(b"{\"error\":\"endpoint_taken\"}".to_vec())
            .unwrap();
        assert!(matches!(
            json_body::<serde_json::Value>(reqwest::Response::from(refused)).await,
            Err(Error::Server { status: 409, code }) if code == "endpoint_taken"
        ));
    }

    #[test]
    fn flows_are_polled_until_they_expire_by_the_server_clock() {
        assert_eq!(
            flow_lifetime(1_000 + 1_200, Some(1_000)),
            Duration::from_secs(1_200)
        );
        // Expired already, or a server that names a far future.
        assert_eq!(flow_lifetime(900, Some(1_000)), Duration::ZERO);
        assert_eq!(
            flow_lifetime(i64::MAX, Some(1_000)),
            Duration::from_secs(MAX_FLOW_SECS.unsigned_abs())
        );
        // Without a `Date` header the local clock decides.
        let left = flow_lifetime(unix_now() + 600, None);
        assert!(left <= Duration::from_secs(600) && left >= Duration::from_secs(590));
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::DATE,
            "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap(),
        );
        assert_eq!(server_time(&headers), Some(784_111_777));
    }

    #[test]
    fn debug_leaves_the_app_password_out() {
        let credentials = crate::tests::credentials("https://cloud.example.com", 1);
        let text = format!("{credentials:?}");
        assert!(!text.contains("secret") && text.contains("kim"), "{text}");
    }
}
