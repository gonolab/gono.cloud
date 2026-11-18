//! Building blocks of the server's HTML pages: the web file UI, the sign-in and account pages,
//! the Login Flow v2 pages and the web admin UI.
//!
//! - **Pages** are askama templates (`crates/server/bin/templates/`) with a [`Chrome`] (the
//!   masthead, the language of [`crate::i18n`] and the theme), rendered with [`render`]. Every
//!   value is HTML-escaped by the template engine. Every page loads the same stylesheet
//!   (`assets/web.css`) and script (`assets/app.js`) from [`ASSETS_PATH`] under
//!   content-hashed names. The script only enhances: every page works without it.
//! - **Theme**: system, light or dark, kept in the [`THEME_COOKIE`] and switched by a form, so
//!   that it needs no script either.
//! - **Sign-in** ([`Web::sign_in`]) with the web login password (Argon2), behind a per-client
//!   [`RateLimiter`] of its own: checked before anything is verified, one token per failure.
//!   It is not shared with device authentication, so failing devices behind the same address
//!   do not keep a user from signing a new device in. Unknown accounts cost the same Argon2
//!   work as known ones, so response times do not reveal which accounts exist.
//! - **Second step** ([`Web::second_step`]): an account with two-step verification gets a
//!   pending sign-in instead of a session, bound to the account (by id) and capped per account,
//!   per client and in all; a new one ends the oldest rather than being refused. Codes of one
//!   account are checked one at a time ([`Web::check_code`]): the lock after failures, the
//!   verification and the record of a failure cannot interleave. The attempt of the pending
//!   sign-in and the client's limiter token are taken before a code is verified, and a failure
//!   that cannot be recorded makes the answer "unavailable". A pending sign-in ends when the
//!   account's password changes, it is disabled or deleted, or its verification is turned off.
//! - **Sessions**: a successful sign-in creates a `web_sessions` row
//!   ([`gono_server_core::web_sessions`]) and sets the [`SESSION_COOKIE`] (`HttpOnly`,
//!   `SameSite=Lax`, `Secure` when the public origin is HTTPS). App passwords never create a
//!   session, and sessions never authenticate WebDAV requests.
//! - **Cookie names**: on an HTTPS origin the cookies of sessions, sign-ins and CSRF tokens are
//!   named with the [`HOST_PREFIX`], which browsers accept only from this host itself. Other
//!   hosts of the same site (the S3 API's serves pages its users uploaded) can set cookies for
//!   the whole site, but none of these; a request that carries a cookie more than once is taken
//!   to carry it not at all ([`cookie`]).
//! - **CSRF**: every form carries a token. Before sign-in it is a double-submit token: a random
//!   value in the [`CSRF_COOKIE`] (`SameSite=Strict`) repeated in the form. After sign-in it
//!   is derived from the session token, which the page cannot read; the script sends it in a
//!   header. POSTs with an `Origin` or `Sec-Fetch-Site` header that names another site are
//!   refused as well.
//! - **Headers** ([`render`]): a strict Content Security Policy (the one script only, by a
//!   nonce of this response; stylesheets, images and media from this origin; no inline styles;
//!   requests and forms only to this origin; no framing), `X-Frame-Options: DENY`,
//!   `Referrer-Policy: same-origin` (page URLs can carry tokens, so no other site ever sees
//!   them; `no-referrer` would also make browsers send `Origin: null` with our own forms),
//!   `Cache-Control: no-store`.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError, Weak},
    time::Duration,
};

use askama::Template;
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use gono_server_core::{
    Username, db, password, secret,
    two_factor::{self, Key, Verification},
    users::{self, User},
    web_sessions::{self, SessionUser},
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use url::Url;

use crate::{
    i18n::{Lang, Text, fill},
    ratelimit::RateLimiter,
};

/// Cookie holding the session token.
pub const SESSION_COOKIE: &str = "gono_session";

/// Prefix of the names of [`SESSION_COOKIE`], [`CSRF_COOKIE`] and [`TWO_STEP_COOKIE`] on an
/// HTTPS origin. Browsers accept a cookie named so only from the host itself, with `Secure`,
/// `Path=/` and no `Domain`, so no other host of the site can plant one.
pub const HOST_PREFIX: &str = "__Host-";

/// Cookie holding the double-submit CSRF token of forms shown before sign-in.
pub const CSRF_COOKIE: &str = "gono_csrf";

/// Cookie holding the token of a sign-in waiting for its second step.
pub const TWO_STEP_COOKIE: &str = "gono_two_step";

/// Where the second step of a sign-in is entered.
pub const TWO_STEP_PATH: &str = "/login/two-step";

/// How long a sign-in waits for its second step, in seconds.
const TWO_STEP_TTL_SECS: i64 = 5 * 60;

/// Wrong codes one pending sign-in may take before the password has to be entered again.
const TWO_STEP_ATTEMPTS: u32 = 5;

/// Sign-ins waiting for their second step per account, at most: a new one ends the
/// account's oldest.
const MAX_PENDING_PER_ACCOUNT: usize = 5;

/// Sign-ins waiting for their second step per client (see [`client_key`]), at most: a new one
/// ends the client's oldest.
const MAX_PENDING_PER_CLIENT: usize = 20;

/// Sign-ins waiting for their second step in all, at most: a new one ends the oldest. Also the
/// most enrolments and recovery code displays kept.
const MAX_PENDING: usize = 1000;

/// How long an enrolment waits for its first code, in seconds.
const ENROLMENT_TTL_SECS: i64 = 10 * 60;

/// A sign-in whose password was right, waiting for its second step.
#[derive(Debug, Clone)]
struct Pending {
    user_id: i64,
    username: String,
    /// The account's `updated_at` when its password was checked: a change since (a new
    /// password, also one set with the CLI) ends the sign-in.
    updated_at: i64,
    /// The client that entered the password, as [`client_key`] counts it.
    client: IpAddr,
    /// Where to go once signed in: a local path.
    next: String,
    until: i64,
    /// Codes checked so far, each counted before it is verified.
    attempts: u32,
    /// Creation order, so that the oldest ends first.
    seq: u64,
}

/// The sign-ins waiting for their second step, by the digest of their cookie token.
#[derive(Debug, Default)]
struct PendingSignIns {
    entries: HashMap<[u8; 32], Pending>,
    next_seq: u64,
}

impl PendingSignIns {
    /// Adds `entry` under `digest`. Expired sign-ins go first, then the oldest past the caps
    /// per account, per client and in all: a new sign-in is never refused, so that nobody can
    /// keep the table full and block the sign-ins of others.
    fn insert(&mut self, digest: [u8; 32], mut entry: Pending, now: i64) {
        self.entries.retain(|_, pending| pending.until > now);
        let (user_id, client) = (entry.user_id, entry.client);
        self.trim(
            |pending| pending.user_id == user_id,
            MAX_PENDING_PER_ACCOUNT - 1,
        );
        self.trim(
            |pending| pending.client == client,
            MAX_PENDING_PER_CLIENT - 1,
        );
        self.trim(|_| true, MAX_PENDING - 1);
        entry.seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(digest, entry);
    }

    /// Ends the oldest of the sign-ins that `select` picks until at most `keep` of them remain.
    fn trim(&mut self, select: impl Fn(&Pending) -> bool, keep: usize) {
        let mut picked: Vec<([u8; 32], u64)> = self
            .entries
            .iter()
            .filter(|(_, pending)| select(pending))
            .map(|(digest, pending)| (*digest, pending.seq))
            .collect();
        if picked.len() <= keep {
            return;
        }
        picked.sort_unstable_by_key(|(_, seq)| *seq);
        for (digest, _) in &picked[..picked.len() - keep] {
            self.entries.remove(digest);
        }
    }

    /// The live sign-in of `digest`.
    fn get(&self, digest: &[u8; 32], now: i64) -> Option<&Pending> {
        self.entries.get(digest).filter(|entry| entry.until > now)
    }
}

/// A client as the caps of pending sign-ins count it: IPv4 addresses one by one, IPv6
/// addresses per `/64`, the block a single host usually controls (as the failed-attempt
/// limiter does).
fn client_key(client: IpAddr) -> IpAddr {
    match client {
        IpAddr::V4(_) => client,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = v6.segments();
                segments[4..].fill(0);
                IpAddr::V6(segments.into())
            }
        },
    }
}

/// A secret being enrolled, by the session that started it.
#[derive(Clone)]
pub struct Enrolment {
    /// The account of that session: should a session of another account ever get the same
    /// row id, it sees nothing.
    user_id: i64,
    /// The TOTP secret.
    pub secret: [u8; two_factor::SECRET_BYTES],
    /// Where to go once it is on: a local path.
    pub next: Option<String>,
    until: i64,
}

impl std::fmt::Debug for Enrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrolment")
            .field("user_id", &self.user_id)
            .field("secret", &"[redacted]")
            .field("next", &self.next)
            .field("until", &self.until)
            .finish()
    }
}

/// Recovery codes waiting to be shown once, by session.
#[derive(Clone)]
pub struct Shown {
    /// The account of that session (see [`Enrolment`]).
    user_id: i64,
    /// The codes.
    pub codes: Vec<String>,
    /// Where to go after reading them.
    pub next: Option<String>,
    until: i64,
}

impl std::fmt::Debug for Shown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shown")
            .field("user_id", &self.user_id)
            .field(
                "codes",
                &format_args!("[{} codes, redacted]", self.codes.len()),
            )
            .field("next", &self.next)
            .field("until", &self.until)
            .finish()
    }
}

/// Outcome of [`Web::check_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeCheck {
    /// The code is right and used up: a TOTP code, or a recovery code with how many are left.
    Right {
        /// Recovery codes left, when the code was one.
        recovery_left: Option<i64>,
    },
    /// The code is wrong; the failure is recorded.
    Wrong,
    /// The account has no two-step verification (any more).
    NotEnrolled,
    /// Too many wrong codes for this account; nothing was checked.
    Locked,
    /// Too many failures from this client; nothing was checked.
    RateLimited(Duration),
    /// The database failed, the key file is missing or does not open the secret, or a
    /// failure could not be recorded (then the code counts as not checked: it never passes).
    Unavailable,
}

/// Length of the pre-sign-in CSRF token.
const CSRF_CHARS: usize = 43;

/// Outcome of [`Web::verify_password`].
#[derive(Debug)]
pub enum Verified {
    /// The password is right and the account is enabled.
    Ok(User),
    /// Unknown account, wrong password or disabled account.
    Invalid,
    /// Too many failures from this client; retry after the given time.
    RateLimited(Duration),
    /// The password could not be checked because the database failed.
    Unavailable,
}

/// Outcome of [`Web::start_session`].
#[derive(Debug)]
pub enum Started {
    /// A session: its cookie token.
    Session(SecretString),
    /// The account has two-step verification: the `Set-Cookie` value of the pending sign-in.
    /// Send the browser to [`TWO_STEP_PATH`].
    SecondStep(HeaderValue),
    /// The database failed.
    Unavailable,
}

/// Outcome of [`Web::second_step`].
#[derive(Debug)]
pub enum SecondStep {
    /// Signed in: the session's cookie token, where to go, and how many recovery codes are
    /// left if one was used.
    Ok {
        /// The session's cookie token.
        token: SecretString,
        /// A local path.
        next: String,
        /// Recovery codes left, when the code was one.
        recovery_left: Option<i64>,
    },
    /// The code is wrong; the user may try again.
    Wrong,
    /// No sign-in waits: it expired, was used, or took too many wrong codes.
    Expired,
    /// Too many wrong codes for this account; the second step is locked for a while.
    Locked,
    /// Too many failures from this client.
    RateLimited(Duration),
    /// The code could not be checked (database, or the key file changed).
    Unavailable,
}

/// Outcome of [`Web::sign_in`].
#[derive(Debug)]
pub enum SignIn {
    /// The password is right: the cookie token of a new session.
    Ok(SecretString),
    /// The password is right and the account has two-step verification: the `Set-Cookie`
    /// value of the pending sign-in.
    SecondStep(HeaderValue),
    /// Unknown account, wrong password or disabled account.
    Invalid,
    /// Too many failures from this client; retry after the given time.
    RateLimited(Duration),
    /// The password could not be checked or the session not stored: the database failed.
    Unavailable,
}

/// Sessions, sign-in and CSRF checks of the HTML pages. Shared by all handlers.
#[derive(Debug)]
pub struct Web {
    pool: db::Pool,
    limiter: Arc<RateLimiter>,
    /// `scheme://host[:port]` of the public origin.
    origin: String,
    /// Mark cookies `Secure` (the public origin is HTTPS).
    secure: bool,
    /// The key of the TOTP secrets; `None` while two-step verification is unavailable.
    two_factor_key: Option<Key>,
    /// Sign-ins waiting for their second step.
    pending: Mutex<PendingSignIns>,
    /// The locks of the accounts whose codes are being checked ([`Web::lock_account`]). An
    /// entry lives only while a request holds or waits for its lock.
    checking: Mutex<HashMap<i64, Weak<AsyncMutex<()>>>>,
    /// Enrolments waiting for their first code, by session id.
    enrolments: Mutex<HashMap<i64, Enrolment>>,
    /// Recovery codes waiting to be shown once, by session id.
    shown: Mutex<HashMap<i64, Shown>>,
}

/// A PHC string to verify against when the account does not exist.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        password::hash(&SecretString::from(
            "gono-cloud-timing-equalizer".to_owned(),
        ))
        .unwrap_or_default()
    })
}

/// The value of cookie `name` in the request, or `None` when the request carries it more than
/// once: then another host of the site, or a path below the pages, has set one of them, and
/// which one is ours cannot be told.
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then(|| value.trim_matches('"').to_owned())
        });
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

/// The CSRF token of forms shown to the holder of session `token`.
fn session_csrf(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gono-csrf-v1\0");
    hasher.update(token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

impl Web {
    /// Creates the page support for the public origin `base_url`, recording failed sign-ins
    /// in `limiter`.
    pub fn new(pool: db::Pool, limiter: Arc<RateLimiter>, base_url: &Url) -> Self {
        Self {
            pool,
            limiter,
            origin: base_url.origin().ascii_serialization(),
            secure: base_url.scheme() == "https",
            two_factor_key: None,
            pending: Mutex::new(PendingSignIns::default()),
            checking: Mutex::new(HashMap::new()),
            enrolments: Mutex::new(HashMap::new()),
            shown: Mutex::new(HashMap::new()),
        }
    }

    /// Makes two-step verification available with `key`.
    pub fn with_two_factor_key(mut self, key: Key) -> Self {
        self.two_factor_key = Some(key);
        self
    }

    /// The key of the TOTP secrets, when two-step verification is available.
    pub fn two_factor_key(&self) -> Option<&Key> {
        self.two_factor_key.as_ref()
    }

    /// Opens a session for `user`, whose password was just verified, unless the account has
    /// two-step verification: then the sign-in waits for its code at [`TWO_STEP_PATH`] and
    /// continues to `next` (a local path).
    pub async fn start_session(&self, client: IpAddr, user: &User, next: &str) -> Started {
        match two_factor::is_enrolled(&self.pool, user.id).await {
            Ok(true) => {}
            Ok(false) => {
                let Some(token) = self.open_session(client, user).await else {
                    return Started::Unavailable;
                };
                // An enrolment that committed between the check above and the new session
                // ended the account's other sessions before this one existed. Look again, and
                // keep the token to ourselves if it did: the password alone is not enough now.
                match two_factor::is_enrolled(&self.pool, user.id).await {
                    Ok(false) => return Started::Session(token),
                    Ok(true) => self.sign_out(token.expose_secret()).await,
                    Err(err) => {
                        tracing::error!(error = %err, "cannot check two-step verification");
                        self.sign_out(token.expose_secret()).await;
                        return Started::Unavailable;
                    }
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot check two-step verification");
                return Started::Unavailable;
            }
        }
        let token = secret::random_token(43);
        let now = db::unix_now();
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                secret::digest(token.expose_secret()),
                Pending {
                    user_id: user.id,
                    username: user.username.to_string(),
                    updated_at: user.updated_at,
                    client: client_key(client),
                    next: next.to_owned(),
                    until: now + TWO_STEP_TTL_SECS,
                    attempts: 0,
                    seq: 0,
                },
                now,
            );
        tracing::info!(%client, user = %user.username, "web sign-in waits for its second step");
        Started::SecondStep(self.cookie_header(
            TWO_STEP_COOKIE,
            token.expose_secret(),
            "Strict",
            Some(u32::try_from(TWO_STEP_TTL_SECS).unwrap_or(300)),
        ))
    }

    /// The username of the sign-in waiting for its second step in this request, if any.
    pub fn pending_user(&self, headers: &HeaderMap) -> Option<String> {
        let token = cookie(headers, &self.cookie_name(TWO_STEP_COOKIE))?;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&secret::digest(&token), db::unix_now())
            .map(|entry| entry.username.clone())
    }

    /// Ends every sign-in of `user_id` waiting for its second step: its password changed, the
    /// account was disabled or deleted, or two-step verification was turned off or reset.
    pub fn end_pending_sign_ins(&self, user_id: i64) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .retain(|_, entry| entry.user_id != user_id);
    }

    /// The sign-ins of `user_id` waiting for their second step, for tests.
    #[cfg(test)]
    pub fn pending_sign_ins(&self, user_id: i64) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .values()
            .filter(|entry| entry.user_id == user_id)
            .count()
    }

    /// Waits until no other code of `user_id` is being checked, and keeps others waiting until
    /// the guard drops. The lock check, the verification and the record of a failure so happen
    /// one request at a time per account: concurrent wrong codes cannot all pass the lock check
    /// before the first failure is recorded.
    async fn lock_account(&self, user_id: i64) -> OwnedMutexGuard<()> {
        let lock = {
            let mut checking = self.checking.lock().unwrap_or_else(PoisonError::into_inner);
            // Entries nobody holds or waits for any more go, so the map stays as small as
            // the number of requests in flight.
            checking.retain(|_, lock| lock.strong_count() > 0);
            match checking.get(&user_id).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    checking.insert(user_id, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }

    /// What is checked before a code of `user_id` from `client`, under the account's lock: the
    /// client's failed-attempt limiter, the account's lock after failures, and the key.
    async fn before_code(&self, client: IpAddr, user_id: i64, now: i64) -> Result<Key, CodeCheck> {
        if let Some(wait) = self.limiter.check(client) {
            return Err(CodeCheck::RateLimited(wait));
        }
        match two_factor::locked(&self.pool, user_id, now).await {
            Ok(false) => {}
            Ok(true) => return Err(CodeCheck::Locked),
            Err(err) => {
                tracing::error!(error = %err, "cannot check two-step failures");
                return Err(CodeCheck::Unavailable);
            }
        }
        self.two_factor_key.clone().ok_or_else(|| {
            tracing::error!("two-step verification is enrolled but the key file is missing");
            CodeCheck::Unavailable
        })
    }

    /// Verifies `code` of `user_id` from `client` while `guard` holds the account's lock, and
    /// records a failure. The client's limiter token is taken before verifying, so a right
    /// code costs one too.
    ///
    /// It runs on a task of its own: a client that goes away while its code is checked cannot
    /// keep the failure from being recorded, and the lock is held until it is.
    async fn verify_code(
        &self,
        guard: OwnedMutexGuard<()>,
        key: Key,
        client: IpAddr,
        user_id: i64,
        code: &str,
        now: i64,
    ) -> CodeCheck {
        let pool = self.pool.clone();
        let limiter = self.limiter.clone();
        let code = code.to_owned();
        let task = tokio::spawn(async move {
            let _guard = guard;
            limiter.record_failure(client);
            let verified =
                match two_factor::verify(&pool, &key, user_id, &code, Some(client), now).await {
                    Ok(verified) => verified,
                    Err(err) => {
                        tracing::error!(error = %err, "cannot check a second step");
                        return CodeCheck::Unavailable;
                    }
                };
            match verified {
                Verification::Code => CodeCheck::Right {
                    recovery_left: None,
                },
                Verification::RecoveryCode { left } => CodeCheck::Right {
                    recovery_left: Some(left),
                },
                Verification::NotEnrolled => CodeCheck::NotEnrolled,
                Verification::WrongKey => {
                    tracing::error!(
                        user_id,
                        "the TOTP secret does not open with the key file: was two_factor.key_file replaced?"
                    );
                    CodeCheck::Unavailable
                }
                Verification::Wrong => {
                    match two_factor::record_failure(&pool, user_id, Some(client), now).await {
                        Ok(()) => CodeCheck::Wrong,
                        Err(err) => {
                            // Unrecorded, the failure would not count towards the lock.
                            tracing::error!(error = %err, "cannot record a failed second step");
                            CodeCheck::Unavailable
                        }
                    }
                }
            }
        });
        task.await.unwrap_or_else(|err| {
            tracing::error!(error = %err, "a second-step check failed");
            CodeCheck::Unavailable
        })
    }

    /// Checks a code (TOTP or recovery) of `user_id` from `client`, as the forms of the account
    /// page that need one do: under the account's lock, behind the same limits as the second
    /// step of a sign-in, and used up when right.
    pub async fn check_code(&self, client: IpAddr, user_id: i64, code: &str) -> CodeCheck {
        let now = db::unix_now();
        let guard = self.lock_account(user_id).await;
        match self.before_code(client, user_id, now).await {
            Ok(key) => {
                self.verify_code(guard, key, client, user_id, code, now)
                    .await
            }
            Err(outcome) => outcome,
        }
    }

    /// Checks the second step of the sign-in of this request: a TOTP code or a recovery code
    /// (`docs/connect-protocol.md`, 13.3).
    pub async fn second_step(&self, client: IpAddr, headers: &HeaderMap, code: &str) -> SecondStep {
        let Some(token) = cookie(headers, &self.cookie_name(TWO_STEP_COOKIE)) else {
            return SecondStep::Expired;
        };
        let digest = secret::digest(&token);
        let now = db::unix_now();
        let Some(user_id) = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&digest, now)
            .map(|entry| entry.user_id)
        else {
            return SecondStep::Expired;
        };
        let guard = self.lock_account(user_id).await;
        let key = match self.before_code(client, user_id, now).await {
            Ok(key) => key,
            Err(CodeCheck::Locked) => return SecondStep::Locked,
            Err(CodeCheck::RateLimited(wait)) => return SecondStep::RateLimited(wait),
            Err(_) => return SecondStep::Unavailable,
        };
        // The attempt counts before the code is verified.
        let entry = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(entry) = pending
                .entries
                .get_mut(&digest)
                .filter(|entry| entry.until > now && entry.attempts < TWO_STEP_ATTEMPTS)
            else {
                pending.entries.remove(&digest);
                return SecondStep::Expired;
            };
            entry.attempts += 1;
            entry.clone()
        };
        let recovery_left = match self
            .verify_code(guard, key, client, user_id, code, now)
            .await
        {
            CodeCheck::Right { recovery_left } => recovery_left,
            CodeCheck::Wrong => {
                tracing::info!(%client, user = %entry.username, "wrong second step of a web sign-in");
                if entry.attempts >= TWO_STEP_ATTEMPTS {
                    self.end_pending(&digest);
                    return SecondStep::Expired;
                }
                return SecondStep::Wrong;
            }
            // Turned off since the password was checked: it has to be entered again.
            CodeCheck::NotEnrolled => {
                self.end_pending(&digest);
                return SecondStep::Expired;
            }
            CodeCheck::Locked => return SecondStep::Locked,
            CodeCheck::RateLimited(wait) => return SecondStep::RateLimited(wait),
            CodeCheck::Unavailable => return SecondStep::Unavailable,
        };
        // Used once.
        if !self.end_pending(&digest) {
            return SecondStep::Expired;
        }
        // By id: the account must still be the one whose password was checked.
        let user = match two_factor::sign_in_account(&self.pool, user_id).await {
            Ok(Some(user)) if user.enabled && user.updated_at == entry.updated_at => user,
            Ok(_) => {
                tracing::info!(
                    %client,
                    user = %entry.username,
                    "a sign-in ended at its second step: the account was changed, disabled or deleted"
                );
                return SecondStep::Expired;
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot read the account of a sign-in");
                return SecondStep::Unavailable;
            }
        };
        match self.open_session(client, &user).await {
            Some(token) => SecondStep::Ok {
                token,
                next: entry.next,
                recovery_left,
            },
            None => SecondStep::Unavailable,
        }
    }

    /// Ends the sign-in of `digest`; `false` if there was none.
    fn end_pending(&self, digest: &[u8; 32]) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .remove(digest)
            .is_some()
    }

    /// The `Set-Cookie` value that ends a pending sign-in.
    pub fn two_step_removal(&self) -> HeaderValue {
        self.cookie_header(TWO_STEP_COOKIE, "", "Strict", Some(0))
    }

    /// Starts enrolling a new secret for `session`.
    pub fn start_enrolment(&self, session: &SessionUser, next: Option<String>) -> Enrolment {
        let now = db::unix_now();
        let enrolment = Enrolment {
            user_id: session.user_id,
            secret: two_factor::new_secret(),
            next,
            until: now + ENROLMENT_TTL_SECS,
        };
        let mut enrolments = self
            .enrolments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        enrolments.retain(|_, entry| entry.until > now);
        if enrolments.len() >= MAX_PENDING {
            enrolments.clear();
        }
        enrolments.insert(session.session_id, enrolment.clone());
        enrolment
    }

    /// The enrolment of `session`, if it has not expired.
    pub fn enrolment(&self, session: &SessionUser) -> Option<Enrolment> {
        let now = db::unix_now();
        self.enrolments
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&session.session_id)
            .filter(|entry| entry.user_id == session.user_id && entry.until > now)
            .cloned()
    }

    /// Ends the enrolment of `session`.
    pub fn end_enrolment(&self, session: &SessionUser) {
        let mut enrolments = self
            .enrolments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if enrolments
            .get(&session.session_id)
            .is_some_and(|entry| entry.user_id == session.user_id)
        {
            enrolments.remove(&session.session_id);
        }
    }

    /// Keeps `codes` to be shown once to `session`.
    pub fn show_once(&self, session: &SessionUser, codes: Vec<String>, next: Option<String>) {
        let now = db::unix_now();
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        shown.retain(|_, entry| entry.until > now);
        if shown.len() >= MAX_PENDING {
            shown.clear();
        }
        shown.insert(
            session.session_id,
            Shown {
                user_id: session.user_id,
                codes,
                next,
                until: now + ENROLMENT_TTL_SECS,
            },
        );
    }

    /// The recovery codes waiting for `session`, once.
    pub fn take_shown(&self, session: &SessionUser) -> Option<Shown> {
        let now = db::unix_now();
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        if !shown
            .get(&session.session_id)
            .is_some_and(|entry| entry.user_id == session.user_id)
        {
            return None;
        }
        shown
            .remove(&session.session_id)
            .filter(|entry| entry.until > now)
    }

    /// The name of cookie `base` on this origin: with the [`HOST_PREFIX`] for the cookies of
    /// sessions, sign-ins and CSRF tokens on an HTTPS origin (whose `Set-Cookie` values carry
    /// `Secure` and `Path=/` and no `Domain`, as the prefix asks), as it is otherwise.
    pub fn cookie_name(&self, base: &str) -> String {
        if self.secure && [SESSION_COOKIE, CSRF_COOKIE, TWO_STEP_COOKIE].contains(&base) {
            format!("{HOST_PREFIX}{base}")
        } else {
            base.to_owned()
        }
    }

    fn cookie_header(
        &self,
        name: &str,
        value: &str,
        same_site: &str,
        max_age: Option<u32>,
    ) -> HeaderValue {
        let name = self.cookie_name(name);
        let mut cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite={same_site}");
        if self.secure {
            cookie.push_str("; Secure");
        }
        if let Some(max_age) = max_age {
            cookie.push_str(&format!("; Max-Age={max_age}"));
        }
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    /// The `Set-Cookie` value that stores a session token.
    pub fn session_cookie(&self, token: &SecretString) -> HeaderValue {
        self.cookie_header(SESSION_COOKIE, token.expose_secret(), "Lax", None)
    }

    /// The `Set-Cookie` value that deletes cookie `name`.
    pub fn removal_cookie(&self, name: &str) -> HeaderValue {
        self.cookie_header(
            name,
            "",
            if name == CSRF_COOKIE { "Strict" } else { "Lax" },
            Some(0),
        )
    }

    /// The `Set-Cookie` value that stores `theme` for a year (or forgets the choice).
    pub fn theme_cookie(&self, theme: Theme) -> HeaderValue {
        match theme.attr() {
            Some(name) => self.cookie_header(THEME_COOKIE, name, "Lax", Some(365 * 86_400)),
            None => self.cookie_header(THEME_COOKIE, "", "Lax", Some(0)),
        }
    }

    /// The signed-in account of the request and its session token, if it has a live session.
    pub async fn session(&self, headers: &HeaderMap) -> Option<(SessionUser, String)> {
        let token = cookie(headers, &self.cookie_name(SESSION_COOKIE))?;
        match web_sessions::lookup(&self.pool, &token, db::unix_now()).await {
            Ok(user) => user.map(|user| (user, token)),
            Err(err) => {
                tracing::error!(error = %err, "session lookup failed");
                None
            }
        }
    }

    /// Ends the session with `token`.
    pub async fn sign_out(&self, token: &str) {
        if let Err(err) = web_sessions::delete(&self.pool, token).await {
            tracing::error!(error = %err, "cannot end a session");
        }
    }

    /// Checks a web login password (see the module documentation) without opening a session.
    pub async fn verify_password(
        &self,
        client: IpAddr,
        username: &str,
        password: SecretString,
    ) -> Verified {
        if let Some(wait) = self.limiter.check(client) {
            return Verified::RateLimited(wait);
        }
        let account = match Username::new(username.trim()) {
            Ok(name) => match users::credentials(&self.pool, &name).await {
                Ok(account) => account,
                Err(err) => {
                    tracing::error!(error = %err, "sign-in lookup failed");
                    return Verified::Unavailable;
                }
            },
            Err(_) => None,
        };
        let phc = account
            .as_ref()
            .map_or_else(|| dummy_hash().to_owned(), |(_, hash)| hash.clone());
        let verified = tokio::task::spawn_blocking(move || password::verify(&password, &phc))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        match account {
            Some((user, _)) if verified && user.enabled => Verified::Ok(user),
            _ => {
                self.limiter.record_failure(client);
                tracing::info!(%client, user = %username.trim(), "rejected web sign-in");
                Verified::Invalid
            }
        }
    }

    /// Opens a session for an account whose password was verified; returns the cookie token.
    pub async fn open_session(&self, client: IpAddr, user: &User) -> Option<SecretString> {
        match web_sessions::create(&self.pool, user.id, db::unix_now()).await {
            Ok(token) => {
                tracing::info!(%client, user = %user.username, "web sign-in");
                Some(token)
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot create a session");
                None
            }
        }
    }

    /// Checks a web login password and opens a session, or starts the second step that
    /// continues to `next` (see the module documentation).
    pub async fn sign_in(
        &self,
        client: IpAddr,
        username: &str,
        password: SecretString,
        next: &str,
    ) -> SignIn {
        match self.verify_password(client, username, password).await {
            Verified::Ok(user) => match self.start_session(client, &user, next).await {
                Started::Session(token) => SignIn::Ok(token),
                Started::SecondStep(cookie) => SignIn::SecondStep(cookie),
                Started::Unavailable => SignIn::Unavailable,
            },
            Verified::Invalid => SignIn::Invalid,
            Verified::RateLimited(wait) => SignIn::RateLimited(wait),
            Verified::Unavailable => SignIn::Unavailable,
        }
    }

    /// The CSRF token for a form shown before sign-in, and the `Set-Cookie` value to send
    /// with the page. An existing token is kept, so that several open pages stay valid.
    pub fn login_csrf(&self, headers: &HeaderMap) -> (String, HeaderValue) {
        let token = cookie(headers, &self.cookie_name(CSRF_COOKIE))
            .filter(|token| {
                token.len() == CSRF_CHARS && token.bytes().all(|b| b.is_ascii_alphanumeric())
            })
            .unwrap_or_else(|| secret::random_token(CSRF_CHARS).expose_secret().to_owned());
        let cookie = self.cookie_header(CSRF_COOKIE, &token, "Strict", None);
        (token, cookie)
    }

    /// Whether a form submitted before sign-in carries the token of its CSRF cookie.
    pub fn check_login_csrf(&self, headers: &HeaderMap, submitted: &str) -> bool {
        cookie(headers, &self.cookie_name(CSRF_COOKIE)).is_some_and(|expected| {
            !expected.is_empty()
                && secret::constant_time_eq(expected.as_bytes(), submitted.as_bytes())
        })
    }

    /// The CSRF token for forms shown to the holder of session `token`.
    pub fn session_csrf(&self, token: &str) -> String {
        session_csrf(token)
    }

    /// Whether a form submitted with session `token` carries that session's CSRF token.
    pub fn check_session_csrf(&self, token: &str, submitted: &str) -> bool {
        secret::constant_time_eq(session_csrf(token).as_bytes(), submitted.as_bytes())
    }

    /// Whether a form submission comes from this origin as far as the browser says: an
    /// `Origin` header must name the public origin, and `Sec-Fetch-Site` must not be
    /// `cross-site` or `same-site`. Requests without these headers (non-browser clients)
    /// rely on the CSRF token alone.
    pub fn same_origin(&self, headers: &HeaderMap) -> bool {
        same_origin(&self.origin, headers)
    }
}

/// See [`Web::same_origin`]; `origin` is `scheme://host[:port]`.
///
/// Browsers send `Origin: null` instead of the origin when the page's referrer policy or a
/// privacy setting hides it; that is accepted only together with `Sec-Fetch-Site:
/// same-origin`, which pages cannot forge.
fn same_origin(origin: &str, headers: &HeaderMap) -> bool {
    let fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok());
    let origin_ok = match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        None => true,
        Some("null") => fetch_site == Some("same-origin"),
        Some(value) => value == origin,
    };
    let fetch_ok = fetch_site.is_none_or(|site| matches!(site, "same-origin" | "none"));
    origin_ok && fetch_ok
}

/// The stylesheet of every page.
pub const STYLE: &str = include_str!("../assets/web.css");

/// The script of every page. It only enhances them (theme switch without a reload, drag and
/// drop, resumable uploads): every page works without it.
pub const SCRIPT: &str = include_str!("../assets/app.js");

/// The icon of every page (SVG).
pub const ICON: &str = include_str!("../assets/icon.svg");

/// Path prefix of the static assets. Their names carry a hash of their content, so they can
/// be cached forever.
pub const ASSETS_PATH: &str = "/apps/assets/";

/// The cookie holding the chosen theme (`light` or `dark`; absent: follow the system).
pub const THEME_COOKIE: &str = "gono_theme";

/// Where the theme switch posts to.
pub const THEME_PATH: &str = "/apps/theme";

/// The URLs of the stylesheet and the script.
struct AssetUrls {
    style: String,
    script: String,
    icon: String,
}

fn asset_urls() -> &'static AssetUrls {
    static URLS: OnceLock<AssetUrls> = OnceLock::new();
    URLS.get_or_init(|| {
        let short = |text: &str| {
            let digest = Sha256::digest(text.as_bytes());
            digest[..6]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        AssetUrls {
            style: format!("{ASSETS_PATH}web.{}.css", short(STYLE)),
            script: format!("{ASSETS_PATH}app.{}.js", short(SCRIPT)),
            icon: format!("{ASSETS_PATH}icon.{}.svg", short(ICON)),
        }
    })
}

/// The URL of the stylesheet.
pub fn style_url() -> &'static str {
    &asset_urls().style
}

/// The URL of the script.
pub fn script_url() -> &'static str {
    &asset_urls().script
}

/// The URL of the page icon.
pub fn icon_url() -> &'static str {
    &asset_urls().icon
}

/// The asset at `path` with its content type, if there is one.
pub fn asset(path: &str) -> Option<(&'static str, &'static str)> {
    let urls = asset_urls();
    if path == urls.style {
        Some(("text/css; charset=utf-8", STYLE))
    } else if path == urls.script {
        Some(("text/javascript; charset=utf-8", SCRIPT))
    } else if path == urls.icon || path == format!("{ASSETS_PATH}icon.svg") {
        Some(("image/svg+xml", ICON))
    } else {
        None
    }
}

/// The colour theme a page is shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    /// Follow the system setting (`prefers-color-scheme`).
    #[default]
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl Theme {
    /// The theme chosen in this browser ([`THEME_COOKIE`]).
    pub fn from_headers(headers: &HeaderMap) -> Self {
        match cookie(headers, THEME_COOKIE).as_deref() {
            Some("light") => Self::Light,
            Some("dark") => Self::Dark,
            _ => Self::System,
        }
    }

    /// The `data-theme` attribute of the page; none follows the system.
    pub fn attr(self) -> Option<&'static str> {
        match self {
            Self::System => None,
            Self::Light => Some("light"),
            Self::Dark => Some("dark"),
        }
    }

    /// The theme after this one in the switch's cycle: system, light, dark.
    pub fn next(self) -> Self {
        match self {
            Self::System => Self::Light,
            Self::Light => Self::Dark,
            Self::Dark => Self::System,
        }
    }

    /// The name stored in the cookie and reported to the script.
    pub fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

/// The signed-in account as the masthead shows it.
#[derive(Debug, Clone)]
pub struct ChromeUser {
    /// Login name.
    pub username: String,
    /// Display name.
    pub display_name: String,
    /// One or two letters for the avatar.
    pub initials: String,
}

impl ChromeUser {
    /// The masthead's view of a session.
    pub fn new(user: &SessionUser) -> Self {
        let initials: String = user
            .display_name
            .split_whitespace()
            .filter_map(|word| word.chars().next())
            .take(2)
            .collect();
        Self {
            username: user.username.to_string(),
            display_name: user.display_name.clone(),
            initials: if initials.is_empty() {
                user.username.as_str().chars().take(1).collect()
            } else {
                initials
            },
        }
    }
}

/// The masthead entry of the current page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nav {
    /// None of them.
    #[default]
    None,
    /// The file browser.
    Files,
    /// The favorites.
    Favorites,
    /// The account page.
    Account,
    /// The admin UI.
    Admin,
}

/// What every page shows around its content (the masthead), and what it needs for the
/// response: the language, the theme and the CSP nonce of the response.
#[derive(Debug, Clone)]
pub struct Chrome {
    /// Language of the page.
    pub lang: Lang,
    /// The strings in that language.
    pub t: &'static Text,
    /// The `data-theme` attribute, if the browser chose a theme.
    pub theme: Option<&'static str>,
    /// The theme switch's label for the current theme.
    pub theme_label: &'static str,
    /// Nonce of this response's `script-src`.
    pub nonce: String,
    /// URL of the stylesheet.
    pub style: &'static str,
    /// URL of the script.
    pub script: &'static str,
    /// URL of the page icon.
    pub icon: &'static str,
    /// The signed-in account, if any.
    pub user: Option<ChromeUser>,
    /// CSRF token of the session (empty without one), for the forms in the masthead and for
    /// the script's requests.
    pub csrf: String,
    /// The current masthead entry.
    pub nav: Nav,
    /// The web file UI is enabled.
    pub files: bool,
    /// The admin UI's path, when it is enabled and the user is an admin.
    pub admin: Option<String>,
    /// Where the sign-out form posts.
    pub logout: String,
    /// Path and query of the page, where the theme switch returns to.
    pub here: String,
    /// The text in the search box.
    pub query: String,
    /// Strings for the script (JSON, safe inside a `<script type="application/json">`).
    pub script_text: String,
}

impl Chrome {
    /// The frame of a page for an anonymous visitor in `lang`, with the theme of `headers`.
    pub fn new(headers: &HeaderMap, lang: Lang) -> Self {
        let theme = Theme::from_headers(headers);
        let t = lang.t();
        Self {
            lang,
            t,
            theme: theme.attr(),
            theme_label: match theme {
                Theme::System => t.theme_system,
                Theme::Light => t.theme_light,
                Theme::Dark => t.theme_dark,
            },
            nonce: secret::random_token(22).expose_secret().to_owned(),
            style: style_url(),
            script: script_url(),
            icon: icon_url(),
            user: None,
            csrf: String::new(),
            nav: Nav::None,
            files: false,
            admin: None,
            logout: String::new(),
            here: "/".to_owned(),
            query: String::new(),
            script_text: script_text(t),
        }
    }

    /// The frame of a page for an anonymous visitor, in the browser's language.
    pub fn for_request(headers: &HeaderMap) -> Self {
        Self::new(headers, Lang::from_headers(headers))
    }

    /// The same frame for the signed-in `user`, whose session has the CSRF token `csrf`.
    #[must_use]
    pub fn signed_in(mut self, user: &SessionUser, csrf: &str) -> Self {
        self.user = Some(ChromeUser::new(user));
        self.csrf = csrf.to_owned();
        self
    }

    /// Whether masthead entry `index` is the current one (for the templates, which cannot
    /// name [`Nav`]): 1 files, 2 favorites, 3 account, 4 admin.
    pub fn on(&self, index: u8) -> bool {
        let nav = match index {
            1 => Nav::Files,
            2 => Nav::Favorites,
            3 => Nav::Account,
            4 => Nav::Admin,
            _ => return false,
        };
        self.nav == nav
    }

    /// Where the brand links to.
    pub fn home(&self) -> &str {
        if self.files {
            "/apps/files/"
        } else if let Some(admin) = &self.admin {
            admin
        } else {
            "/"
        }
    }
}

/// The strings the script shows, as JSON that can be embedded in a page.
fn script_text(t: &Text) -> String {
    let value = serde_json::json!({
        "uploads": t.js_uploads,
        "waiting": t.js_waiting,
        "uploading": t.js_uploading,
        "finishing": t.js_finishing,
        "done": t.js_done,
        "replaced": t.js_replaced,
        "skipped": t.js_skipped,
        "failed": t.js_failed,
        "retrying": t.js_retrying,
        "cancelled": t.js_cancelled,
        "retry": t.js_retry,
        "cancelAll": t.js_cancel_all,
        "close": t.js_close,
        "conflict": t.js_conflict,
        "leave": t.js_leave,
        "left": t.js_left,
        "dropHere": t.drop_here,
        "selected": t.selected,
        "today": t.today,
        "yesterday": t.yesterday,
        "themeSystem": t.theme_system,
        "themeLight": t.theme_light,
        "themeDark": t.theme_dark,
        "linkCopied": t.js_link_copied,
    });
    embed_json(&value)
}

/// `value` as JSON text that cannot end a `<script>` element or open a comment.
pub fn embed_json(value: &serde_json::Value) -> String {
    value
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// A page template with its frame.
pub trait Page: Template {
    /// The frame of the page.
    fn chrome(&self) -> &Chrome;
}

/// Implements [`Page`] for templates with a `chrome` field.
macro_rules! page {
    ($($ty:ty),+ $(,)?) => {
        $(impl $crate::web::Page for $ty {
            fn chrome(&self) -> &$crate::web::Chrome {
                &self.chrome
            }
        })+
    };
}
pub(crate) use page;

/// The `Content-Security-Policy` of a page whose script carries `nonce`: the page's own
/// stylesheet and script, images and media from this origin (previews), requests and forms
/// to this origin only, and no framing.
fn page_policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'self'; img-src 'self'; \
         media-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; \
         base-uri 'none'; object-src 'none'"
    )
}

/// The `Content-Security-Policy` of responses without a page (redirects).
const BARE_POLICY: &str =
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Adds the security headers of a response without a page body (see the module
/// documentation).
pub fn secure_headers(headers: &mut HeaderMap) {
    add_security_headers(headers, BARE_POLICY);
}

fn add_security_headers(headers: &mut HeaderMap, policy: &str) {
    let set = |headers: &mut HeaderMap, name: &'static str, value: &str| {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    };
    set(headers, "content-security-policy", policy);
    set(headers, "x-frame-options", "DENY");
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "referrer-policy", "same-origin");
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cache-control", "no-store");
}

/// Renders a page with the security headers and its nonce in the CSP.
pub fn render(status: StatusCode, page: &impl Page) -> Response {
    let html = match page.render() {
        Ok(html) => html,
        Err(err) => {
            tracing::error!(error = %err, "cannot render a page");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut response = (status, html).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    add_security_headers(response.headers_mut(), &page_policy(&page.chrome().nonce));
    response
}

/// `303 See Other` to `location` (a path on this server), with the security headers and
/// extra `Set-Cookie` values.
pub fn see_other(location: &str, cookies: &[HeaderValue]) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    for cookie in cookies {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    secure_headers(response.headers_mut());
    response
}

/// The page shown while a client is blocked by the failed-attempt limiter, with
/// `Retry-After`.
pub fn too_many_attempts(chrome: Chrome, wait: Duration) -> Response {
    let t = chrome.t;
    let seconds = wait.as_secs().max(1).to_string();
    let mut response = Message::new(
        chrome,
        t.too_many_attempts,
        t.too_many_attempts,
        &fill(t.too_many_attempts_lead, &[&seconds]),
    )
    .respond(StatusCode::TOO_MANY_REQUESTS);
    if let Ok(value) = HeaderValue::from_str(&seconds) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The page shown when a password could not be checked because the database failed: `503`
/// with `Retry-After`, so that it does not read as a wrong password.
pub fn unavailable(chrome: Chrome) -> Response {
    let t = chrome.t;
    let mut response = Message::new(chrome, t.unavailable, t.unavailable, t.unavailable_lead)
        .respond(StatusCode::SERVICE_UNAVAILABLE);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

/// A page with a heading and a short text (`templates/message.html`).
#[derive(Debug, Clone, Template)]
#[template(path = "message.html")]
pub struct Message {
    /// The frame.
    pub chrome: Chrome,
    /// Window title.
    pub title: String,
    /// Heading.
    pub heading: String,
    /// A client (device) name shown before `lead`.
    pub client: Option<String>,
    /// The text.
    pub lead: String,
    /// A second, smaller text.
    pub note: Option<String>,
    /// A button: link target and label.
    pub link: Option<(String, String)>,
}

page!(Message);

impl Message {
    /// A message page with a heading and a text.
    pub fn new(chrome: Chrome, title: &str, heading: &str, lead: &str) -> Self {
        Self {
            chrome,
            title: title.to_owned(),
            heading: heading.to_owned(),
            client: None,
            lead: lead.to_owned(),
            note: None,
            link: None,
        }
    }

    /// Renders the page with `status`.
    pub fn respond(&self, status: StatusCode) -> Response {
        render(status, self)
    }
}

/// The ids of every `id="..."` attribute in `html`, for tests that check uniqueness.
#[cfg(test)]
pub fn element_ids(html: &str) -> Vec<String> {
    html.match_indices(" id=\"")
        .filter_map(|(index, needle)| {
            let rest = &html[index + needle.len()..];
            rest.find('"').map(|end| rest[..end].to_owned())
        })
        .collect()
}

/// Whether `html` holds `word` with no ASCII letter or digit on either side. Pages carry random
/// alphanumeric tokens (the CSP nonce, the CSRF token), so a plain `contains` of a short word
/// such as "S3" now and then finds it inside one of them.
#[cfg(test)]
pub fn mentions(html: &str, word: &str) -> bool {
    html.match_indices(word).any(|(index, _)| {
        let before = html[..index].chars().next_back();
        let after = html[index + word.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric())
            && !after.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_inside_random_tokens_are_not_mentions() {
        assert!(mentions("S3", "S3"));
        assert!(mentions("<h2>S3 buckets</h2>", "S3"));
        assert!(!mentions(r#"nonce="aS3b" value="S3x" csrf="yS3""#, "S3"));
    }

    #[test]
    fn cookies_are_parsed_by_name() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, "a=1; gono_session=abc".parse().unwrap());
        headers.append(header::COOKIE, "gono_csrf=\"xyz\"".parse().unwrap());
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("abc"));
        assert_eq!(cookie(&headers, CSRF_COOKIE).as_deref(), Some("xyz"));
        assert_eq!(cookie(&headers, "b"), None);
        // A cookie named twice (one set by another host of the site, say) counts as absent.
        headers.append(header::COOKIE, "gono_session=planted".parse().unwrap());
        assert_eq!(cookie(&headers, SESSION_COOKIE), None);
        assert_eq!(cookie(&headers, CSRF_COOKIE).as_deref(), Some("xyz"));
    }

    #[tokio::test]
    async fn cookies_of_https_origins_are_host_only() {
        let dir = tempfile::tempdir().unwrap();
        let config = gono_server_core::config::DbConfig {
            path: dir.path().join("db.sqlite"),
            max_connections: 2,
            busy_timeout_secs: 5,
        };
        let pool = db::connect(&config, db::OpenMode::CreateIfMissing)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let limiter = Arc::new(RateLimiter::new());
        let https = Web::new(
            pool.clone(),
            limiter.clone(),
            &Url::parse("https://cloud.example.com").unwrap(),
        );
        let http = Web::new(pool, limiter, &Url::parse("http://localhost:8080").unwrap());
        let token = SecretString::from("t".repeat(43));
        let set = https.session_cookie(&token);
        let set = set.to_str().unwrap();
        assert!(set.starts_with(&format!("__Host-gono_session={}; Path=/;", "t".repeat(43))));
        assert!(set.contains("; Secure") && !set.contains("Domain"), "{set}");
        let removal = https.removal_cookie(CSRF_COOKIE);
        assert!(removal.to_str().unwrap().starts_with("__Host-gono_csrf=;"));
        assert!(
            https
                .two_step_removal()
                .to_str()
                .unwrap()
                .starts_with("__Host-gono_two_step=;")
        );
        // The theme is no secret and keeps its name.
        assert_eq!(https.cookie_name(THEME_COOKIE), THEME_COOKIE);
        // A plain HTTP origin (a test installation) cannot use the prefix.
        assert!(
            http.session_cookie(&token)
                .to_str()
                .unwrap()
                .starts_with("gono_session=")
        );

        // The pages read only the prefixed cookie: one set by another host of the site under
        // the plain name is not taken up.
        let csrf = |cookies: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, cookies.parse().unwrap());
            https.login_csrf(&headers).0
        };
        let kept = "a".repeat(CSRF_CHARS);
        assert_eq!(csrf(&format!("__Host-gono_csrf={kept}")), kept);
        assert_ne!(csrf(&format!("gono_csrf={kept}")), kept);
    }

    fn pending(user_id: i64, client: IpAddr) -> Pending {
        Pending {
            user_id,
            username: String::new(),
            updated_at: 0,
            client: client_key(client),
            next: "/".into(),
            until: 1_300,
            attempts: 0,
            seq: 0,
        }
    }

    fn digest(index: usize) -> [u8; 32] {
        let mut digest = [0; 32];
        digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
        digest
    }

    #[test]
    fn pending_sign_ins_are_capped_by_ending_the_oldest() {
        let now = 1_000;
        let client: IpAddr = "192.0.2.1".parse().unwrap();

        // Per account: a new sign-in ends the account's oldest, never another account's.
        let mut table = PendingSignIns::default();
        table.insert(digest(100), pending(2, "192.0.2.2".parse().unwrap()), now);
        for index in 0..7 {
            table.insert(digest(index), pending(1, client), now);
        }
        assert_eq!(table.entries.len(), MAX_PENDING_PER_ACCOUNT + 1);
        assert!(table.get(&digest(0), now).is_none() && table.get(&digest(1), now).is_none());
        assert!(table.get(&digest(2), now).is_some() && table.get(&digest(6), now).is_some());
        assert!(
            table.get(&digest(100), now).is_some(),
            "the other account's"
        );

        // Per client, over many accounts; IPv6 counts per /64.
        let mut table = PendingSignIns::default();
        for index in 0..30 {
            let client: IpAddr = format!("2001:db8::{index:x}").parse().unwrap();
            table.insert(digest(index), pending(index as i64, client), now);
        }
        assert_eq!(table.entries.len(), MAX_PENDING_PER_CLIENT);
        assert!(table.get(&digest(9), now).is_none());
        assert!(table.get(&digest(10), now).is_some() && table.get(&digest(29), now).is_some());

        // In all: a full table ends its oldest rather than refusing the new one.
        let mut table = PendingSignIns::default();
        for index in 0..MAX_PENDING + 10 {
            let client = IpAddr::from((index as u32 + 1).to_be_bytes());
            table.insert(digest(index), pending(index as i64, client), now);
        }
        assert_eq!(table.entries.len(), MAX_PENDING);
        assert!(table.get(&digest(9), now).is_none());
        assert!(table.get(&digest(MAX_PENDING + 9), now).is_some());

        // Expired ones go first, and are never found.
        assert!(table.get(&digest(MAX_PENDING + 9), 1_300).is_none());
        table.insert(digest(0), pending(1, client), 1_300);
        assert_eq!(table.entries.len(), 1);
    }

    #[test]
    fn secrets_are_left_out_of_debug_output() {
        let enrolment = Enrolment {
            user_id: 1,
            secret: [0xab; two_factor::SECRET_BYTES],
            next: None,
            until: 0,
        };
        let text = format!("{enrolment:?}");
        assert!(text.contains("redacted") && !text.contains("171"), "{text}");
        let shown = Shown {
            user_id: 1,
            codes: vec!["ABCD-EFGH-JKMN-PQRS".into()],
            next: None,
            until: 0,
        };
        let text = format!("{shown:?}");
        assert!(
            text.contains("redacted") && !text.contains("ABCD"),
            "{text}"
        );
    }

    #[test]
    fn session_csrf_tokens_are_bound_to_the_session() {
        assert_eq!(session_csrf("a"), session_csrf("a"));
        assert_ne!(session_csrf("a"), session_csrf("b"));
        assert_eq!(
            session_csrf("a").len(),
            43,
            "SHA-256, base64url without padding"
        );
    }

    fn plain() -> Chrome {
        Chrome::new(&HeaderMap::new(), Lang::En)
    }

    #[test]
    fn pages_carry_the_security_headers() {
        let message = Message::new(plain(), "T<", "<b>", "x");
        let nonce = message.chrome.nonce.clone();
        let response = message.respond(StatusCode::OK);
        let headers = response.headers();
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(
            csp.contains(&format!("script-src 'nonce-{nonce}'")),
            "{csp}"
        );
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "same-origin");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(
            headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        // Every response gets a nonce of its own.
        assert_ne!(plain().nonce, plain().nonce);
    }

    #[tokio::test]
    async fn templates_escape_values_and_link_the_hashed_assets() {
        let mut message = Message::new(plain(), "T", "<script>alert(1)</script>", "a & b");
        message.client = Some("\"evil\" <img>".into());
        let html = message.render().unwrap();
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(html.contains("&#60;script&#62;"), "{html}");
        assert!(!html.contains("\"evil\""), "{html}");
        assert!(!html.contains("<img>"), "{html}");
        assert!(
            html.contains(&format!("href=\"{}\"", style_url())),
            "{html}"
        );
        assert!(
            html.contains(&format!(
                "src=\"{}\" nonce=\"{}\"",
                script_url(),
                message.chrome.nonce
            )),
            "{html}"
        );
        assert!(
            !html.contains(" style=\""),
            "no inline styles: the CSP refuses them"
        );
        assert_eq!(asset(style_url()), Some(("text/css; charset=utf-8", STYLE)));
        assert!(asset(script_url()).is_some());
        assert!(
            asset("/apps/assets/web.css").is_none(),
            "only the hashed names"
        );
    }

    #[test]
    fn the_script_text_cannot_end_its_element() {
        let json = embed_json(&serde_json::json!({ "x": "</script><!--&" }));
        assert!(
            !json.contains('<') && !json.contains('>') && !json.contains('&'),
            "{json}"
        );
        assert!(
            !SCRIPT.contains("innerHTML"),
            "the script builds DOM nodes only"
        );
        assert!(!SCRIPT.contains("eval("), "the script never evaluates text");
    }

    #[test]
    fn themes_cycle_through_system_light_and_dark() {
        let mut headers = HeaderMap::new();
        assert_eq!(Theme::from_headers(&headers), Theme::System);
        headers.insert(header::COOKIE, HeaderValue::from_static("gono_theme=dark"));
        assert_eq!(Theme::from_headers(&headers), Theme::Dark);
        assert_eq!(Theme::Dark.next(), Theme::System);
        assert_eq!(Theme::System.next().next(), Theme::Dark);
        headers.insert(header::COOKIE, HeaderValue::from_static("gono_theme=\"><x"));
        assert_eq!(
            Theme::from_headers(&headers),
            Theme::System,
            "unknown values: system"
        );
    }

    #[test]
    fn origin_checks() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.insert(*name, HeaderValue::from_static(value));
            }
            map
        };
        let origin = "https://cloud.example.com";
        assert!(same_origin(origin, &headers(&[])));
        assert!(same_origin(
            origin,
            &headers(&[("origin", origin), ("sec-fetch-site", "same-origin")])
        ));
        assert!(!same_origin(
            origin,
            &headers(&[("origin", "https://evil.example")])
        ));
        assert!(!same_origin(
            origin,
            &headers(&[("sec-fetch-site", "cross-site")])
        ));
        assert!(!same_origin(
            origin,
            &headers(&[("sec-fetch-site", "same-site")])
        ));
        // A hidden origin counts only with the browser's own same-origin statement.
        assert!(same_origin(
            origin,
            &headers(&[("origin", "null"), ("sec-fetch-site", "same-origin")])
        ));
        assert!(!same_origin(origin, &headers(&[("origin", "null")])));
        assert!(!same_origin(
            origin,
            &headers(&[("origin", "null"), ("sec-fetch-site", "cross-site")])
        ));
    }
}
