//! Outgoing mail: the one-time codes that bind an email address to an account and reset a
//! forgotten web login password, and the notices that follow such changes (`[smtp]`).
//!
//! - [`Mailer`] is what the pages use: one plain-text message to one address. [`SmtpMailer`]
//!   sends it through the configured mail server with lettre (rustls with ring, the webpki roots,
//!   the security `smtp.security` asks for, and timeouts, so a slow server cannot hold a request
//!   or a task for long); tests use [`MemoryMailer`], which keeps the messages.
//! - [`AppState::mailer`](crate::app::AppState) exists only while `smtp.enabled`; without it the
//!   pages offer nothing that needs mail.
//! - Messages are plain text in the language of the request that triggered them ([`Lang`]),
//!   composed here from the strings of [`crate::i18n`]. A message carries no secret but the
//!   one-time code it exists for, and neither codes nor message texts are ever logged.

use std::{fmt, future::Future, pin::Pin, time::Duration};

use anyhow::Context as _;
use gono_server_core::{config::SmtpConfig, config::SmtpSecurity, secret};
use lettre::{
    AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
        extension::ClientId,
    },
};
use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use crate::i18n::{Lang, fill};

/// How long one SMTP command (the connection included) may take.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// How long sending one message may take in all.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a message was not sent. The text is for the log: it never holds the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailError(pub String);

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What [`Mailer::send`] returns.
pub type Sending<'a> = Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + 'a>>;

/// Sends plain-text mail.
pub trait Mailer: Send + Sync + fmt::Debug {
    /// Sends `text` with `subject` to the address `to` (normalized, see
    /// `gono_server_core::email::normalize_address`).
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, text: &'a str) -> Sending<'a>;
}

/// [`Mailer`] through the SMTP server of `[smtp]`.
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    /// The domain of the `Message-ID`s: the sender's, as mail servers expect.
    domain: String,
    /// For the log.
    server: String,
}

impl fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The transport holds the password; only say where mail goes.
        f.debug_struct("SmtpMailer")
            .field("server", &self.server)
            .field("from", &self.from.email.to_string())
            .finish_non_exhaustive()
    }
}

/// Reads the password of `smtp.password_file`: its first line, without the line break.
fn read_password(path: &std::path::Path) -> anyhow::Result<SecretString> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read smtp.password_file {}", path.display()))?;
    Ok(SecretString::from(
        content.lines().next().unwrap_or_default().to_owned(),
    ))
}

impl SmtpMailer {
    /// The mailer of `config` (validated, enabled). Reads the password file now, so that a
    /// missing one stops the start. The EHLO greeting names the host of `base_url`, this
    /// server's public name.
    pub fn new(config: &SmtpConfig, base_url: &Url) -> anyhow::Result<Self> {
        let host = config.host.as_deref().context("smtp.host is not set")?;
        let from = config.from.as_deref().context("smtp.from is not set")?;
        let parsed = gono_server_core::email::parse_mailbox(from)
            .map_err(|message| anyhow::anyhow!("smtp.from {from:?} {message}"))?;
        let address = parsed
            .address
            .parse()
            .with_context(|| format!("smtp.from {from:?} is not an address lettre accepts"))?;
        let from = Mailbox::new(parsed.name, address);
        let tls = |host: &str| {
            TlsParameters::new(host.to_owned())
                .with_context(|| format!("set up TLS for smtp.host {host}"))
        };
        let tls = match config.security {
            SmtpSecurity::Tls => Tls::Wrapper(tls(host)?),
            // Required, not opportunistic: a server that does not offer STARTTLS is refused
            // before anything is sent.
            SmtpSecurity::Starttls => Tls::Required(tls(host)?),
            // Validation allows this for a loopback host only.
            SmtpSecurity::None => Tls::None,
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(config.port)
            .tls(tls)
            .timeout(Some(COMMAND_TIMEOUT));
        if let Some(name) = base_url.host_str().filter(|name| name.contains('.')) {
            builder = builder.hello_name(ClientId::Domain(name.to_owned()));
        }
        if let (Some(username), Some(file)) = (&config.username, &config.password_file) {
            let password = read_password(file)?;
            builder = builder.credentials(Credentials::new(
                username.clone(),
                password.expose_secret().to_owned(),
            ));
        }
        Ok(Self {
            transport: builder.build(),
            domain: from.email.domain().to_owned(),
            from,
            server: format!("{host}:{} ({})", config.port, config.security.as_str()),
        })
    }

    /// Where mail goes, for the log: `host:port (security)`.
    pub fn server(&self) -> &str {
        &self.server
    }

    async fn deliver(&self, to: &str, subject: &str, text: &str) -> Result<(), MailError> {
        let to: lettre::Address = to
            .parse()
            .map_err(|err| MailError(format!("not an address: {err}")))?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(Mailbox::new(None, to))
            .subject(subject)
            .message_id(Some(format!(
                "<{}@{}>",
                secret::random_token(32).expose_secret(),
                self.domain
            )))
            .header(ContentType::TEXT_PLAIN)
            .body(text.to_owned())
            .map_err(|err| MailError(format!("cannot build the message: {err}")))?;
        match tokio::time::timeout(SEND_TIMEOUT, self.transport.send(message)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(MailError(format!(
                "{} refused or failed: {err}",
                self.server
            ))),
            Err(_) => Err(MailError(format!(
                "{} did not answer within {} seconds",
                self.server,
                SEND_TIMEOUT.as_secs()
            ))),
        }
    }
}

impl Mailer for SmtpMailer {
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, text: &'a str) -> Sending<'a> {
        Box::pin(self.deliver(to, subject, text))
    }
}

/// A message as composed: subject and text.
#[derive(Clone, PartialEq, Eq)]
pub struct Composed {
    /// The subject line.
    pub subject: String,
    /// The plain text.
    pub text: String,
}

impl fmt::Debug for Composed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The text may hold a code.
        f.debug_struct("Composed")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// `scheme://host[:port]` of `base_url`, how the messages name this server.
fn origin(base_url: &Url) -> String {
    base_url.origin().ascii_serialization()
}

/// The code that binds the address it is sent to. It does not name the account: the address is
/// not proven yet, and a typo must not tell a stranger who has an account here.
pub fn bind_code(lang: Lang, base_url: &Url, code: &str) -> Composed {
    let t = lang.t();
    Composed {
        subject: t.mail_bind_subject.to_owned(),
        text: fill(t.mail_bind_text, &[&origin(base_url), code]),
    }
}

/// The code that resets the password of `username`, sent to its address.
pub fn reset_code(lang: Lang, base_url: &Url, username: &str, code: &str) -> Composed {
    let t = lang.t();
    let origin = origin(base_url);
    Composed {
        subject: t.mail_reset_subject.to_owned(),
        text: fill(t.mail_reset_text, &[username, &origin, code, &origin]),
    }
}

/// The notice that the password of `username` was reset.
pub fn password_reset(lang: Lang, base_url: &Url, username: &str) -> Composed {
    let t = lang.t();
    Composed {
        subject: t.mail_reset_done_subject.to_owned(),
        text: fill(t.mail_reset_done_text, &[username, &origin(base_url)]),
    }
}

/// The notice to an address that `username` replaced with another one. The new address is not
/// named: whoever reads the old one need not learn it.
pub fn address_replaced(lang: Lang, base_url: &Url, username: &str) -> Composed {
    let t = lang.t();
    Composed {
        subject: t.mail_replaced_subject.to_owned(),
        text: fill(t.mail_replaced_text, &[username, &origin(base_url)]),
    }
}

/// The notice to an address that was removed from `username`.
pub fn address_removed(lang: Lang, base_url: &Url, username: &str) -> Composed {
    let t = lang.t();
    Composed {
        subject: t.mail_removed_subject.to_owned(),
        text: fill(t.mail_removed_text, &[username, &origin(base_url)]),
    }
}

/// Sends `message` to `to` on a task of its own, so that the request does not wait for the mail
/// server (and its time does not depend on whether a message was sent at all). Failures are
/// logged with `what`.
pub fn send_later(
    mailer: &std::sync::Arc<dyn Mailer>,
    to: String,
    message: Composed,
    what: &'static str,
) {
    let mailer = mailer.clone();
    tokio::spawn(async move {
        if let Err(err) = mailer.send(&to, &message.subject, &message.text).await {
            tracing::warn!(error = %err, "cannot send the mail of {what}");
        }
    });
}

/// A [`Mailer`] that keeps what it is given, for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MemoryMailer {
    sent: std::sync::Mutex<Vec<Sent>>,
    /// Refuse every message.
    failing: std::sync::atomic::AtomicBool,
}

/// A message [`MemoryMailer`] was given.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub to: String,
    pub subject: String,
    pub text: String,
}

#[cfg(test)]
impl Sent {
    /// The first run of six digits in the text: the code of a code mail.
    pub fn code(&self) -> String {
        let bytes = self.text.as_bytes();
        (0..bytes.len().saturating_sub(5))
            .find(|&start| {
                bytes[start..start + 6].iter().all(u8::is_ascii_digit)
                    && !bytes.get(start + 6).is_some_and(u8::is_ascii_digit)
                    && (start == 0 || !bytes[start - 1].is_ascii_digit())
            })
            .map(|start| self.text[start..start + 6].to_owned())
            .unwrap_or_else(|| panic!("no code in {:?}", self.text))
    }
}

#[cfg(test)]
impl MemoryMailer {
    /// Every message so far.
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }

    /// Waits until `count` messages were given (mail sent on tasks of its own arrives a little
    /// later), and returns them all.
    pub async fn wait_for(&self, count: usize) -> Vec<Sent> {
        for _ in 0..500 {
            let sent = self.sent();
            if sent.len() >= count {
                return sent;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{count} messages expected, got {:?}", self.sent());
    }

    /// Makes every message fail (`true`) or succeed again.
    pub fn fail(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Mailer for MemoryMailer {
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, text: &'a str) -> Sending<'a> {
        Box::pin(async move {
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(MailError("refused by the test".to_owned()));
            }
            self.sent.lock().unwrap().push(Sent {
                to: to.to_owned(),
                subject: subject.to_owned(),
                text: text.to_owned(),
            });
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::{
        io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
        net::TcpListener,
    };

    use super::*;

    /// A minimal SMTP server on 127.0.0.1 that accepts one message and keeps the commands and
    /// the data it was sent.
    async fn smtp_sink() -> (u16, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = lines.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            write.write_all(b"220 sink ESMTP\r\n").await.unwrap();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if read.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let line = line.trim_end_matches(['\r', '\n']).to_owned();
                seen.lock().unwrap().push(line.clone());
                if in_data {
                    if line == "." {
                        in_data = false;
                        write.write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let verb = line
                    .split(' ')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                let reply: &[u8] = match verb.as_str() {
                    "EHLO" => b"250-sink\r\n250 8BITMIME\r\n",
                    "MAIL" | "RCPT" | "RSET" | "NOOP" => b"250 ok\r\n",
                    "DATA" => {
                        in_data = true;
                        b"354 go on\r\n"
                    }
                    "QUIT" => {
                        write.write_all(b"221 bye\r\n").await.unwrap();
                        break;
                    }
                    _ => b"502 not here\r\n",
                };
                write.write_all(reply).await.unwrap();
            }
        });
        (port, lines, task)
    }

    #[tokio::test]
    async fn messages_go_through_the_smtp_server() {
        let (port, lines, sink) = smtp_sink().await;
        let config = SmtpConfig {
            enabled: true,
            host: Some("127.0.0.1".to_owned()),
            port,
            security: SmtpSecurity::None,
            username: None,
            password_file: None,
            from: Some("Gono Cloud <cloud@example.com>".to_owned()),
        };
        let base_url = Url::parse("https://cloud.example.com").unwrap();
        let mailer = SmtpMailer::new(&config, &base_url).unwrap();
        assert_eq!(mailer.server(), format!("127.0.0.1:{port} (none)"));
        assert!(!format!("{mailer:?}").contains("Credentials"));
        let message = reset_code(Lang::En, &base_url, "alice", "123456");
        mailer
            .send("alice@example.org", &message.subject, &message.text)
            .await
            .unwrap();
        sink.await.unwrap();

        let lines = lines.lock().unwrap().clone();
        let text = lines.join("\n");
        assert!(
            lines
                .first()
                .is_some_and(|line| line == "EHLO cloud.example.com"),
            "{text}"
        );
        assert!(
            lines.contains(&"MAIL FROM:<cloud@example.com>".to_owned()),
            "{text}"
        );
        assert!(
            lines.contains(&"RCPT TO:<alice@example.org>".to_owned()),
            "{text}"
        );
        assert!(
            text.contains("From: \"Gono Cloud\" <cloud@example.com>")
                || text.contains("From: Gono Cloud <cloud@example.com>"),
            "{text}"
        );
        assert!(text.contains("To: alice@example.org"), "{text}");
        assert!(
            text.contains(&format!("Subject: {}", message.subject)),
            "{text}"
        );
        assert!(
            text.contains("Content-Type: text/plain; charset=utf-8"),
            "{text}"
        );
        assert!(
            text.contains("Message-ID: <") && text.contains("@example.com>"),
            "{text}"
        );
        assert!(text.contains("123456"), "{text}");
        assert!(
            text.contains("https://cloud.example.com/login/reset"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_server_that_does_not_answer_is_an_error() {
        // A port nobody listens on: the connection is refused at once.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = SmtpConfig {
            enabled: true,
            host: Some("127.0.0.1".to_owned()),
            port,
            security: SmtpSecurity::None,
            username: None,
            password_file: None,
            from: Some("cloud@example.com".to_owned()),
        };
        let mailer =
            SmtpMailer::new(&config, &Url::parse("http://localhost:8080").unwrap()).unwrap();
        let err = mailer
            .send("alice@example.org", "s", "secret 123456")
            .await
            .unwrap_err();
        assert!(!err.0.contains("123456"), "{err}");
    }

    #[test]
    fn a_missing_password_file_stops_the_start() {
        let config = SmtpConfig {
            enabled: true,
            host: Some("smtp.example.com".to_owned()),
            port: 465,
            security: SmtpSecurity::Tls,
            username: Some("cloud".to_owned()),
            password_file: Some("/nonexistent/gono-cloud/smtp-password".into()),
            from: Some("cloud@example.com".to_owned()),
        };
        let err = SmtpMailer::new(&config, &Url::parse("https://cloud.example.com").unwrap())
            .unwrap_err();
        assert!(format!("{err:#}").contains("smtp.password_file"), "{err:#}");
    }

    #[test]
    fn messages_name_the_server_and_carry_only_their_code() {
        let base_url = Url::parse("https://cloud.example.com/").unwrap();
        for lang in [Lang::En, Lang::Zh] {
            let bind = bind_code(lang, &base_url, "024680");
            assert!(
                bind.text.contains("024680") && bind.text.contains("https://cloud.example.com")
            );
            assert!(!format!("{bind:?}").contains("024680"));
            let reset = reset_code(lang, &base_url, "alice", "135791");
            assert!(reset.text.contains("alice") && reset.text.contains("135791"));
            assert!(
                reset.text.contains("https://cloud.example.com/login/reset"),
                "{}",
                reset.text
            );
            for notice in [
                password_reset(lang, &base_url, "alice"),
                address_replaced(lang, &base_url, "alice"),
                address_removed(lang, &base_url, "alice"),
            ] {
                assert!(notice.text.contains("alice") && notice.text.contains("cloud.example.com"));
                assert!(
                    !notice.text.bytes().any(|b| b.is_ascii_digit()),
                    "{}",
                    notice.text
                );
            }
        }
    }
}
