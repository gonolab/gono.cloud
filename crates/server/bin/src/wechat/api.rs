//! WeChat's server API, of which the server uses one call: `jscode2session`, which exchanges
//! the sign-in code of a mini program (`wx.login()`) for the openid of its user.
//!
//! - [`WeChatApi`] is what the endpoints use. [`HttpApi`] asks
//!   `https://api.weixin.qq.com/sns/jscode2session` with the client of [`crate::http_client`]
//!   (rustls on ring with the webpki roots, HTTP/1.1, no proxy, no redirects, timeouts), so
//!   that a slow WeChat cannot hold a request for long. Tests use [`FakeApi`], which answers
//!   what it was told.
//! - The request carries the AppSecret and the code in its query string, as WeChat wants it.
//!   Neither ever reaches a log or an error: errors are built without the URL, and WeChat's own
//!   messages are not repeated, only its error codes.
//! - The answer's `session_key` is never read: nothing here decrypts the mini program's data,
//!   and it is neither stored nor sent anywhere.

use std::{fmt, future::Future, pin::Pin};

use anyhow::Context as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use url::Url;

/// WeChat's `jscode2session`.
pub const ENDPOINT: &str = "https://api.weixin.qq.com/sns/jscode2session";

/// The largest answer read, in bytes; WeChat's have a few hundred.
const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// What `jscode2session` says about the user of a code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// The user's openid for this AppID.
    pub openid: String,
    /// The user's unionid, if WeChat reported one.
    pub unionid: Option<String>,
}

/// Why an exchange failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The code is invalid, expired or used (WeChat's 40029 and 40163).
    InvalidCode,
    /// WeChat considers the user risky and refuses it (40226).
    RiskyUser,
    /// WeChat's rate limit (45011).
    RateLimited,
    /// Anything else: WeChat could not be reached, failed, refused the AppID or the AppSecret,
    /// or answered something unexpected. The text is for the log and holds no secret.
    Failed(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCode => f.write_str("the code is invalid or used"),
            Self::RiskyUser => f.write_str("WeChat refuses this user as risky"),
            Self::RateLimited => f.write_str("WeChat's rate limit"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

/// What [`WeChatApi::code_to_session`] returns.
pub type Exchange<'a> = Pin<Box<dyn Future<Output = Result<Login, ApiError>> + Send + 'a>>;

/// WeChat's server API.
pub trait WeChatApi: Send + Sync + fmt::Debug {
    /// Exchanges the sign-in code `code` of the mini program for its user.
    fn code_to_session<'a>(&'a self, code: &'a str) -> Exchange<'a>;
}

/// [`WeChatApi`] over HTTPS.
pub struct HttpApi {
    http: reqwest::Client,
    endpoint: Url,
    app_id: String,
    secret: SecretString,
}

impl fmt::Debug for HttpApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpApi")
            .field("endpoint", &self.endpoint.as_str())
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

impl HttpApi {
    /// The API for the mini program `app_id` with its AppSecret.
    pub fn new(app_id: &str, secret: SecretString) -> anyhow::Result<Self> {
        Self::with_endpoint(
            Url::parse(ENDPOINT).context("WeChat's endpoint")?,
            app_id,
            secret,
        )
    }

    /// The API at `endpoint` instead of WeChat's, for tests.
    fn with_endpoint(endpoint: Url, app_id: &str, secret: SecretString) -> anyhow::Result<Self> {
        // The URL carries the AppSecret: the client follows no redirect, so it goes to WeChat
        // and nowhere else.
        let http =
            crate::http_client::client().context("set up the HTTPS client of WeChat's API")?;
        Ok(Self {
            http,
            endpoint,
            app_id: app_id.to_owned(),
            secret,
        })
    }

    async fn exchange(&self, code: &str) -> Result<Login, ApiError> {
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .append_pair("appid", &self.app_id)
            .append_pair("secret", self.secret.expose_secret())
            .append_pair("js_code", code)
            .append_pair("grant_type", "authorization_code");
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|err| ApiError::Failed(describe(err)))?;
        let status = response.status();
        let body = read_answer(response).await?;
        if !status.is_success() {
            return Err(ApiError::Failed(format!("WeChat answered HTTP {status}")));
        }
        parse_answer(&body)
    }
}

impl WeChatApi for HttpApi {
    fn code_to_session<'a>(&'a self, code: &'a str) -> Exchange<'a> {
        Box::pin(self.exchange(code))
    }
}

/// A reqwest error for the log: without the URL (which holds the AppSecret and the code), with
/// its causes.
fn describe(err: reqwest::Error) -> String {
    crate::http_client::describe("WeChat", err)
}

/// The body of `response`, at most [`MAX_ANSWER_BYTES`].
async fn read_answer(response: reqwest::Response) -> Result<Vec<u8>, ApiError> {
    crate::http_client::read_body("WeChat", response, MAX_ANSWER_BYTES)
        .await
        .map_err(ApiError::Failed)
}

/// The fields of an answer that are read. `session_key` is not among them, so it is never
/// decoded.
#[derive(Deserialize)]
struct Answer {
    #[serde(default)]
    openid: Option<String>,
    #[serde(default)]
    unionid: Option<String>,
    #[serde(default)]
    errcode: i64,
}

/// What an answer of `jscode2session` (JSON, whatever its content type) says.
fn parse_answer(body: &[u8]) -> Result<Login, ApiError> {
    let answer: Answer = serde_json::from_slice(body)
        .map_err(|_| ApiError::Failed("WeChat's answer is not the expected JSON".to_owned()))?;
    match answer.errcode {
        0 => {}
        40029 | 40163 => return Err(ApiError::InvalidCode),
        40226 => return Err(ApiError::RiskyUser),
        45011 => return Err(ApiError::RateLimited),
        // 40013 (invalid AppID), 40125 (invalid AppSecret), -1 (busy), ...: errmsg is not
        // repeated, the code says enough.
        code => return Err(ApiError::Failed(format!("WeChat answered errcode {code}"))),
    }
    let openid = answer
        .openid
        .filter(|openid| gono_server_core::wechat::is_wechat_id(openid))
        .ok_or_else(|| ApiError::Failed("WeChat's answer has no valid openid".to_owned()))?;
    let unionid = match answer.unionid.filter(|unionid| !unionid.is_empty()) {
        Some(unionid) if !gono_server_core::wechat::is_wechat_id(&unionid) => {
            return Err(ApiError::Failed(
                "WeChat's answer has an invalid unionid".to_owned(),
            ));
        }
        unionid => unionid,
    };
    Ok(Login { openid, unionid })
}

/// A [`WeChatApi`] that answers what it is told, for tests. A code works once, as WeChat's
/// do; an unknown code is [`ApiError::InvalidCode`].
#[cfg(test)]
#[derive(Debug, Default)]
pub struct FakeApi {
    answers: std::sync::Mutex<std::collections::HashMap<String, Result<Login, ApiError>>>,
    /// The codes exchanged, in order.
    asked: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl FakeApi {
    /// Makes `code` the code of the user `openid`.
    pub fn accept(&self, code: &str, openid: &str) {
        self.answer(
            code,
            Ok(Login {
                openid: openid.to_owned(),
                unionid: None,
            }),
        );
    }

    /// Makes `code` answer `answer`.
    pub fn answer(&self, code: &str, answer: Result<Login, ApiError>) {
        self.answers.lock().unwrap().insert(code.to_owned(), answer);
    }

    /// The codes exchanged so far.
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl WeChatApi for FakeApi {
    fn code_to_session<'a>(&'a self, code: &'a str) -> Exchange<'a> {
        Box::pin(async move {
            self.asked.lock().unwrap().push(code.to_owned());
            self.answers
                .lock()
                .unwrap()
                .remove(code)
                .unwrap_or(Err(ApiError::InvalidCode))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    /// An HTTP server on 127.0.0.1 that answers one request with `status` and `body`, and keeps
    /// the request line.
    async fn answering(
        status: &'static str,
        body: &'static str,
    ) -> (Url, Arc<Mutex<String>>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/sns/jscode2session",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        let kept = seen.clone();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let text = String::from_utf8_lossy(&request).into_owned();
            *kept.lock().unwrap() = text.lines().next().unwrap_or_default().to_owned();
            let answer = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(answer.as_bytes()).await.unwrap();
        });
        (url, seen, task)
    }

    fn api(endpoint: Url) -> HttpApi {
        HttpApi::with_endpoint(
            endpoint,
            "wxd930ea5d5a258f4f",
            SecretString::from(SECRET.to_owned()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn codes_are_exchanged_for_the_openid() {
        let (url, seen, server) = answering(
            "200 OK",
            r#"{"openid":"oGZUI0egBJY1zhBYw2KhdUfwVJJE","session_key":"tiihtNczf5v6AKRyjwEUhQ==","unionid":"oU1"}"#,
        )
        .await;
        let api = api(url);
        assert!(!format!("{api:?}").contains(SECRET));
        let login = api.code_to_session("0a3Kq0Ga1+/=").await.unwrap();
        server.await.unwrap();
        assert_eq!(
            login,
            Login {
                openid: "oGZUI0egBJY1zhBYw2KhdUfwVJJE".to_owned(),
                unionid: Some("oU1".to_owned()),
            }
        );
        let line = seen.lock().unwrap().clone();
        assert_eq!(
            line,
            format!(
                "GET /sns/jscode2session?appid=wxd930ea5d5a258f4f&secret={SECRET}\
                 &js_code=0a3Kq0Ga1%2B%2F%3D&grant_type=authorization_code HTTP/1.1"
            )
        );
    }

    #[tokio::test]
    async fn errors_of_wechat_are_told_apart() {
        for (body, expected) in [
            (
                r#"{"errcode":40029,"errmsg":"invalid code"}"#,
                ApiError::InvalidCode,
            ),
            (
                r#"{"errcode":40163,"errmsg":"code been used"}"#,
                ApiError::InvalidCode,
            ),
            (
                r#"{"errcode":40226,"errmsg":"high risk user"}"#,
                ApiError::RiskyUser,
            ),
            (
                r#"{"errcode":45011,"errmsg":"api minute-quota reach limit"}"#,
                ApiError::RateLimited,
            ),
            (
                r#"{"errcode":40125,"errmsg":"invalid appsecret 0123456789abcdef"}"#,
                ApiError::Failed("WeChat answered errcode 40125".to_owned()),
            ),
            (
                r#"{"errcode":0,"session_key":"x"}"#,
                ApiError::Failed("WeChat's answer has no valid openid".to_owned()),
            ),
            (
                r#"{"openid":"a b"}"#,
                ApiError::Failed("WeChat's answer has no valid openid".to_owned()),
            ),
            (
                r#"{"openid":"o1","unionid":"u/1"}"#,
                ApiError::Failed("WeChat's answer has an invalid unionid".to_owned()),
            ),
            (
                "<html>busy</html>",
                ApiError::Failed("WeChat's answer is not the expected JSON".to_owned()),
            ),
        ] {
            assert_eq!(parse_answer(body.as_bytes()), Err(expected), "{body}");
        }
        assert_eq!(
            parse_answer(br#"{"openid":"o1","unionid":""}"#),
            Ok(Login {
                openid: "o1".to_owned(),
                unionid: None,
            })
        );

        let (url, _, server) = answering("502 Bad Gateway", "{}").await;
        let err = api(url).code_to_session("code").await.unwrap_err();
        server.await.unwrap();
        assert_eq!(
            err,
            ApiError::Failed("WeChat answered HTTP 502 Bad Gateway".to_owned())
        );
    }

    #[tokio::test]
    async fn failures_never_show_the_secret_or_the_code() {
        // A port nobody listens on: the connection is refused at once.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!(
            "http://{}/sns/jscode2session",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        drop(listener);
        let err = api(url).code_to_session("the-code-1234").await.unwrap_err();
        let ApiError::Failed(text) = &err else {
            panic!("{err:?}");
        };
        assert!(text.starts_with("cannot reach WeChat"), "{text}");
        assert!(
            !text.contains(SECRET) && !text.contains("the-code-1234") && !text.contains("appid"),
            "{text}"
        );
    }
}
