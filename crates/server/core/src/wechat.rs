//! The WeChat mini program: its users' identities, the tickets that bind them to accounts, and
//! the mini program's sessions (`external_identities` of provider `wechat`,
//! `wechat_bind_tickets`, `pending_identities` held by the mini program and `mp_sessions`).
//!
//! A mini program knows its users by the openid WeChat gives each of them for its AppID: the
//! identity `(wechat, <AppID>, <openid>)` of [`crate::identities`]. The server learns that
//! openid only by exchanging a sign-in code of the mini program with WeChat (`jscode2session`,
//! in the binary); this module starts where that exchange ends:
//!
//! - **Binding.** On the account page a user makes a bind ticket ([`create_ticket`], once the
//!   caller confirmed it is the account's user), which the page shows as a QR code. The mini
//!   program that scans it first signs in ([`sign_in`]); as its openid is bound to no account
//!   yet, it gets a signup token for that openid (a pending identity held by the mini program),
//!   and then binds it with the ticket ([`bind`]). Binding gives that WeChat user the account's
//!   mini program sessions; unbinding ([`crate::identities::unbind`]) takes them away again.
//! - **Tickets** are 128 random bits ([`TICKET_CHARS`]), valid for [`TICKET_TTL_SECS`] and used
//!   up by the binding they make. A new ticket ends the account's earlier ones.
//! - **Signup tokens** are 256 random bits, valid for [`SIGNUP_TTL_SECS`], bound to the openid
//!   that [`sign_in`] found unbound. A new one for the same openid ends the earlier ones, and
//!   binding uses it up.
//! - **Sessions** are bearer tokens of 256 random bits. A session ends [`SESSION_TTL_SECS`]
//!   after its last use (each use extends it, at most once per [`SEEN_GRANULARITY_SECS`]), when
//!   its identity is unbound (the cascade of `mp_sessions`), and when the account is disabled
//!   or deleted. An identity has at most [`MAX_SESSIONS`]: a new one ends the oldest. A session
//!   reads the account's name and services ([`Account`]) and nothing else.
//!
//! Tickets and tokens are stored only as SHA-256 digests ([`secret::digest`]): they are random,
//! so a fast hash is enough. Every write is one write transaction, so the unique keys, the
//! single use of tickets and the end of sessions hold under concurrent requests. The audit log
//! records `identity.bound` (`how: "mini_program"`) with the AppID, never the openid.

use std::net::IpAddr;

use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;

use crate::{
    audit::Actor,
    db::{self, Flag, Pool, Text},
    error::Result,
    identities::{self, Bound, Claims, Holder, How, Provider},
    secret,
    services::Services,
    types::Username,
};

/// How long a bind ticket is valid, in seconds.
pub const TICKET_TTL_SECS: i64 = 10 * 60;

/// How long a signup token is valid, in seconds.
pub const SIGNUP_TTL_SECS: i64 = identities::PENDING_TTL_SECS;

/// A session ends this long after its last use, in seconds (30 days).
pub const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// `last_seen_at` and the expiry of a session are written at most this often.
pub const SEEN_GRANULARITY_SECS: i64 = 60;

/// Sessions per identity at most; a new one ends the oldest.
pub const MAX_SESSIONS: i64 = 5;

/// Characters of a bind ticket: 22 of `[A-Za-z0-9]` are 131 random bits. Short, so that the QR
/// code that carries it stays easy to scan.
pub const TICKET_CHARS: usize = 22;

/// Characters of signup tokens and session tokens: 43 of `[A-Za-z0-9]` are 256 random bits.
pub const TOKEN_CHARS: usize = identities::TOKEN_CHARS;

/// The longest openid or unionid accepted, in bytes. WeChat's have 28 characters today.
pub const MAX_ID_BYTES: usize = 128;

/// Whether `app_id` looks like the AppID of a mini program: `wx` and 16 letters or digits.
pub fn is_app_id(app_id: &str) -> bool {
    app_id.len() == 18
        && app_id.starts_with("wx")
        && app_id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether `id` can be an openid or a unionid: 1 to [`MAX_ID_BYTES`] letters, digits, `-` and
/// `_` (WeChat's are URL-safe base64).
pub fn is_wechat_id(id: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `value` has the shape of a token of `chars` characters from `[A-Za-z0-9]`.
fn is_random(value: &str, chars: usize) -> bool {
    value.len() == chars && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether `ticket` has the shape of a bind ticket.
pub fn is_ticket(ticket: &str) -> bool {
    is_random(ticket, TICKET_CHARS)
}

/// Whether `token` has the shape of a signup or session token.
pub fn is_token(token: &str) -> bool {
    is_random(token, TOKEN_CHARS)
}

/// What a mini program session reads of its account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The account's id.
    pub user_id: i64,
    /// Its login name.
    pub username: Username,
    /// Its display name.
    pub display_name: String,
    /// The services it may use.
    pub services: Services,
    /// When the WeChat identity that reads it was bound to it, UNIX seconds: for an account
    /// made by a sign-up in the mini program, when it was made.
    pub bound_at: i64,
}

/// A new session: the bearer token, returned once (only its digest is stored), and when it
/// ends unless it is used.
#[derive(Debug)]
pub struct NewSession {
    /// The bearer token.
    pub token: SecretString,
    /// When it ends, UNIX seconds.
    pub expires_at: i64,
}

/// A new bind ticket, returned once.
#[derive(Debug)]
pub struct Ticket {
    /// The ticket.
    pub ticket: SecretString,
    /// When it ends, UNIX seconds.
    pub expires_at: i64,
}

/// Outcome of [`create_ticket`].
#[derive(Debug)]
pub enum NewTicket {
    /// A new ticket to show.
    Ticket(Ticket),
    /// The account has an identity of this AppID already; nothing was made.
    Bound,
}

/// Makes a bind ticket for account `user_id` and AppID `app_id`, and ends the account's earlier
/// tickets. The caller has confirmed that the account's user asks for it.
pub async fn create_ticket(pool: &Pool, user_id: i64, app_id: &str, now: i64) -> Result<NewTicket> {
    let mut tx = db::begin_immediate(pool).await?;
    let bound: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM external_identities WHERE user_id = ? AND provider = 'wechat' \
         AND realm = ?",
    )
    .bind(user_id)
    .bind(app_id)
    .fetch_optional(&mut *tx)
    .await?;
    if bound.is_some() {
        return Ok(NewTicket::Bound);
    }
    sqlx::query("DELETE FROM wechat_bind_tickets WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let ticket = secret::random_token(TICKET_CHARS);
    let expires_at = now.saturating_add(TICKET_TTL_SECS);
    let id = db::next_id(&mut tx, "wechat_bind_tickets").await?;
    sqlx::query(
        "INSERT INTO wechat_bind_tickets (id, ticket_hash, user_id, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&secret::digest(ticket.expose_secret())[..])
    .bind(user_id)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(NewTicket::Ticket(Ticket { ticket, expires_at }))
}

/// Whether `ticket` is a live ticket of account `user_id`: neither used, replaced nor expired.
pub async fn ticket_is_live(pool: &Pool, user_id: i64, ticket: &str, now: i64) -> Result<bool> {
    let live: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM wechat_bind_tickets WHERE ticket_hash = ? AND user_id = ? \
         AND expires_at > ?",
    )
    .bind(&secret::digest(ticket)[..])
    .bind(user_id)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(live.is_some())
}

#[derive(FromRow)]
struct AccountRow {
    id: i64,
    #[sqlx(try_from = "Text")]
    username: String,
    display_name: String,
    #[sqlx(try_from = "Flag")]
    enabled: bool,
    #[sqlx(flatten)]
    services: Services,
}

impl AccountRow {
    /// What a session of a WeChat identity bound at `bound_at` reads of the account.
    fn into_account(self, bound_at: i64) -> Result<Account> {
        Ok(Account {
            user_id: self.id,
            username: Username::new(self.username)?,
            display_name: self.display_name,
            services: self.services,
            bound_at,
        })
    }
}

/// The account `user_id` with its `enabled` flag, inside `tx`.
async fn account_in(tx: &mut db::Tx, user_id: i64) -> Result<Option<AccountRow>> {
    let sql = format!(
        "SELECT id, username, display_name, enabled, {} FROM users WHERE id = ?",
        crate::services::COLUMNS
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?)
}

/// Opens a session with WeChat identity `identity_id` inside `tx`, after ending the identity's
/// oldest sessions beyond [`MAX_SESSIONS`].
async fn open_session(tx: &mut db::Tx, identity_id: i64, now: i64) -> Result<NewSession> {
    // The newest session that stays besides the new one, the (MAX_SESSIONS - 1)th: every older
    // one ends. Ids grow with time (`id_sequences`).
    let oldest_kept: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM mp_sessions WHERE identity_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?",
    )
    .bind(identity_id)
    .bind(MAX_SESSIONS - 2)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(oldest_kept) = oldest_kept {
        sqlx::query("DELETE FROM mp_sessions WHERE identity_id = ? AND id < ?")
            .bind(identity_id)
            .bind(oldest_kept)
            .execute(&mut **tx)
            .await?;
    }
    let token = secret::random_token(TOKEN_CHARS);
    let expires_at = now.saturating_add(SESSION_TTL_SECS);
    let id = db::next_id(tx, "mp_sessions").await?;
    sqlx::query(
        "INSERT INTO mp_sessions (id, token_hash, identity_id, created_at, last_seen_at, \
         expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&secret::digest(token.expose_secret())[..])
    .bind(identity_id)
    .bind(now)
    .bind(now)
    .bind(expires_at)
    .execute(&mut **tx)
    .await?;
    Ok(NewSession { token, expires_at })
}

/// Outcome of [`sign_in`].
#[derive(Debug)]
pub enum SignIn {
    /// The openid is bound to an enabled account: a new session of it.
    Session {
        /// The session.
        session: NewSession,
        /// What it reads of the account.
        account: Account,
    },
    /// The openid is bound to no account: a signup token for it, which [`bind`] takes.
    Unbound {
        /// The token, returned once.
        token: SecretString,
        /// When it ends, UNIX seconds.
        expires_at: i64,
    },
    /// The openid is bound to a disabled account; nothing was made.
    Disabled,
    /// The openid is bound to an account that waits for its deletion, until then; nothing was
    /// made.
    DeletionPending(i64),
}

/// Signs in the WeChat user `openid` of AppID `app_id`, as WeChat's `jscode2session` reported
/// it (with `unionid`, if it reported one): a session if the openid is bound to an account,
/// otherwise a signup token for it. The identity's `last_seen_at` (and its unionid, once WeChat
/// reports one) is updated.
pub async fn sign_in(
    pool: &Pool,
    app_id: &str,
    openid: &str,
    unionid: Option<&str>,
    now: i64,
) -> Result<SignIn> {
    let mut tx = db::begin_immediate(pool).await?;
    if let Some(identity) = identities::find_in(&mut tx, Provider::WeChat, app_id, openid).await? {
        let Some(row) = account_in(&mut tx, identity.user_id).await? else {
            // The cascade removes the identity with its account.
            return Ok(SignIn::Disabled);
        };
        let deleting: Option<i64> =
            sqlx::query_scalar("SELECT deleting_at FROM users WHERE id = ?")
                .bind(identity.user_id)
                .fetch_one(&mut *tx)
                .await?;
        if let Some(until) = deleting {
            return Ok(SignIn::DeletionPending(until));
        }
        if !row.enabled {
            return Ok(SignIn::Disabled);
        }
        identities::touch_in(&mut tx, identity.id, None, unionid, now).await?;
        let session = open_session(&mut tx, identity.id, now).await?;
        let account = row.into_account(identity.created_at)?;
        tx.commit().await?;
        return Ok(SignIn::Session { session, account });
    }
    let claims = Claims::wechat(app_id, openid, unionid);
    let (token, expires_at) =
        identities::create_pending_in(&mut tx, Holder::MiniProgram, &claims, now).await?;
    tx.commit().await?;
    Ok(SignIn::Unbound { token, expires_at })
}

/// Opens a mini program session with WeChat identity `identity_id` (after a sign-up or an
/// undone deletion), with what it reads of the identity's account.
pub async fn open_session_of(
    pool: &Pool,
    identity_id: i64,
    now: i64,
) -> Result<Option<(NewSession, Account)>> {
    let mut tx = db::begin_immediate(pool).await?;
    let identity: Option<(i64, i64)> =
        sqlx::query_as("SELECT user_id, created_at FROM external_identities WHERE id = ?")
            .bind(identity_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((user_id, bound_at)) = identity else {
        return Ok(None);
    };
    let Some(row) = account_in(&mut tx, user_id)
        .await?
        .filter(|row| row.enabled)
    else {
        return Ok(None);
    };
    let session = open_session(&mut tx, identity_id, now).await?;
    let account = row.into_account(bound_at)?;
    tx.commit().await?;
    Ok(Some((session, account)))
}

/// Outcome of [`bind`].
#[derive(Debug)]
pub enum Bind {
    /// The openid is the account's now (or was already): a new session of it.
    Bound {
        /// The session.
        session: NewSession,
        /// What it reads of the account.
        account: Account,
    },
    /// The signup token is unknown, expired, used, of another AppID, or replaced by a newer
    /// one.
    SessionExpired,
    /// The ticket is unknown, expired, used or replaced by a newer one.
    TicketExpired,
    /// The ticket's account is disabled.
    Disabled,
    /// The openid is bound to another account. The ticket stays valid for another WeChat
    /// user; the signup token has ended.
    AccountExists,
    /// The ticket's account has another openid of this AppID. The ticket has ended.
    BindFailed,
}

/// Binds the openid of the live signup token `signup_token` of AppID `app_id` to the account
/// of the live bind ticket `ticket`, uses both up, opens a session and records
/// `identity.bound` (`how: "mini_program"`). See [`Bind`] for the refusals; every check and the
/// binding are one write transaction.
pub async fn bind(
    pool: &Pool,
    app_id: &str,
    signup_token: &str,
    ticket: &str,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Bind> {
    let mut tx = db::begin_immediate(pool).await?;
    let signup = identities::pending_in(&mut tx, Holder::MiniProgram, signup_token, now)
        .await?
        .filter(|pending| {
            pending.claims.provider == Provider::WeChat && pending.claims.realm == app_id
        });
    let Some(signup) = signup else {
        return Ok(Bind::SessionExpired);
    };
    let ticket_row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT id, user_id FROM wechat_bind_tickets WHERE ticket_hash = ? AND expires_at > ?",
    )
    .bind(&secret::digest(ticket)[..])
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((ticket_id, user_id)) = ticket_row else {
        return Ok(Bind::TicketExpired);
    };
    let Some(row) = account_in(&mut tx, user_id).await? else {
        return Ok(Bind::TicketExpired);
    };
    if !row.enabled {
        return Ok(Bind::Disabled);
    }
    let bound = identities::bind_in(
        &mut tx,
        user_id,
        &signup.claims,
        How::MiniProgram,
        Actor::User,
        client_ip,
        now,
    )
    .await?;
    let identity = match bound {
        // Bound to this account already: there is nothing to bind, and the ticket and the
        // token are used up all the same.
        Bound::Bound(identity) | Bound::Already(identity) => identity,
        // The ticket stays valid for another WeChat user; the signup token ends.
        Bound::OtherAccount => {
            identities::end_pending_in(&mut tx, signup.id).await?;
            tx.commit().await?;
            return Ok(Bind::AccountExists);
        }
        Bound::AccountHasOne => {
            end_ticket(&mut tx, ticket_id).await?;
            tx.commit().await?;
            return Ok(Bind::BindFailed);
        }
        Bound::NoAccount => return Ok(Bind::TicketExpired),
    };
    end_ticket(&mut tx, ticket_id).await?;
    identities::end_pending_in(&mut tx, signup.id).await?;
    let session = open_session(&mut tx, identity.id, now).await?;
    let account = row.into_account(identity.created_at)?;
    tx.commit().await?;
    Ok(Bind::Bound { session, account })
}

/// Ends bind ticket `id` inside `tx`.
async fn end_ticket(tx: &mut db::Tx, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM wechat_bind_tickets WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// What [`lookup`] found for a bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// A live session of this account, now extended.
    Live(Account),
    /// A session that ended: it was not used for [`SESSION_TTL_SECS`].
    Expired,
    /// A session of a disabled account.
    Disabled,
    /// No session: never made, logged out, ended with its identity, or of another AppID.
    Unknown,
}

#[derive(FromRow)]
struct SessionRow {
    session_id: i64,
    last_seen_at: i64,
    expires_at: i64,
    /// When the session's identity was bound.
    bound_at: i64,
    #[sqlx(flatten)]
    account: AccountRow,
}

/// The session of bearer token `token` of AppID `app_id`, extending it. A session lives only
/// as long as its identity: unbinding removes it.
pub async fn lookup(pool: &Pool, app_id: &str, token: &str, now: i64) -> Result<Lookup> {
    let sql = format!(
        "SELECT s.id AS session_id, s.last_seen_at, s.expires_at, i.created_at AS bound_at, \
         u.id, u.username, u.display_name, u.enabled, {} \
         FROM mp_sessions s JOIN external_identities i ON i.id = s.identity_id \
         JOIN users u ON u.id = i.user_id \
         WHERE s.token_hash = ? AND i.provider = 'wechat' AND i.realm = ?",
        crate::services::USER_COLUMNS
    );
    let row: Option<SessionRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&secret::digest(token)[..])
        .bind(app_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(Lookup::Unknown);
    };
    if row.expires_at <= now {
        return Ok(Lookup::Expired);
    }
    if !row.account.enabled {
        return Ok(Lookup::Disabled);
    }
    if now - row.last_seen_at >= SEEN_GRANULARITY_SECS {
        let mut tx = db::begin_immediate(pool).await?;
        sqlx::query("UPDATE mp_sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?")
            .bind(now)
            .bind(now.saturating_add(SESSION_TTL_SECS))
            .bind(row.session_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(Lookup::Live(row.account.into_account(row.bound_at)?))
}

/// Ends the session of bearer token `token` of AppID `app_id`, expired or not. Returns `false`
/// if there was none.
pub async fn logout(pool: &Pool, app_id: &str, token: &str) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let deleted = sqlx::query(
        "DELETE FROM mp_sessions WHERE token_hash = ? AND identity_id IN \
         (SELECT id FROM external_identities WHERE provider = 'wechat' AND realm = ?)",
    )
    .bind(&secret::digest(token)[..])
    .bind(app_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(deleted)
}

/// Removes the bind and sign-in tickets and the sessions that expired at `now`. Returns how many
/// there were. The signup tokens are pending identities, which
/// [`crate::identities::purge_expired`] removes.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let mut purged = 0;
    for sql in [
        "DELETE FROM wechat_bind_tickets WHERE expires_at <= ?",
        "DELETE FROM wechat_sign_in_tickets WHERE expires_at <= ?",
        "DELETE FROM mp_sessions WHERE expires_at <= ?",
    ] {
        purged += sqlx::query(sql)
            .bind(now)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    }
    tx.commit().await?;
    Ok(purged)
}

// ---------------------------------------------------------------------------------------------
// Signing in on the web (`wechat_sign_in_tickets`)
// ---------------------------------------------------------------------------------------------

/// How long a sign-in ticket waits for its scan, and each later stage for the next, in seconds.
pub const SIGN_IN_TTL_SECS: i64 = 2 * 60;

/// How long the 6 digits of a sign-in are valid, in seconds.
pub const CODE_TTL_SECS: i64 = 2 * 60;

/// Tries the 6 digits of a sign-in take; the last wrong one ends the sign-in.
pub const CODE_TRIES: i64 = 3;

/// Digits the phone shows.
pub const CODE_DIGITS: usize = 6;

/// What a sign-in ticket is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Signing in on a sign-in page.
    SignIn,
    /// Signing in to the admin UI: admin accounts only.
    Admin,
    /// Confirming it is the user of an account, on its account page.
    Reauth,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::Admin => "admin",
            Self::Reauth => "reauth",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "admin" => Self::Admin,
            "reauth" => Self::Reauth,
            _ => Self::SignIn,
        }
    }
}

/// Where a sign-in is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Waiting for a scan.
    Waiting,
    /// Scanned: locked to a WeChat identity, waiting for its confirmation on the phone.
    Scanned,
    /// Confirmed: the phone shows the digits, which the browser is to enter.
    Code,
    /// The browser signed in.
    Done,
    /// The phone cancelled it.
    Denied,
    /// The digits were entered wrong too often.
    Tries,
    /// Its time ran out.
    Expired,
}

impl Stage {
    /// How the mini program's `flow` and the page's status name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Scanned => "scanned",
            Self::Code => "code",
            Self::Done => "done",
            Self::Denied => "denied",
            Self::Tries => "tries",
            Self::Expired => "expired",
        }
    }

    /// Whether the sign-in ended without signing in.
    pub fn ended(self) -> bool {
        matches!(self, Self::Denied | Self::Tries | Self::Expired)
    }
}

/// A sign-in ticket as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInTicket {
    /// Row id.
    pub id: i64,
    /// What it is for.
    pub purpose: Purpose,
    /// The account of a confirmation ([`Purpose::Reauth`]).
    pub user_id: Option<i64>,
    /// The browser's name.
    pub browser_name: String,
    /// The browser's network.
    pub browser_net: String,
    /// Where it is; [`Stage::Expired`] once its time ran out.
    pub stage: Stage,
    /// The identity it is locked to.
    pub identity_id: Option<i64>,
    /// When the digits end.
    pub code_expires_at: Option<i64>,
    /// Tries left for the digits.
    pub tries_left: i64,
    /// When it ends.
    pub expires_at: i64,
}

#[derive(FromRow)]
struct SignInRow {
    id: i64,
    purpose: String,
    user_id: Option<i64>,
    browser_name: String,
    browser_net: String,
    stage: String,
    ended: Option<String>,
    identity_id: Option<i64>,
    code_expires_at: Option<i64>,
    tries_left: i64,
    expires_at: i64,
}

impl SignInRow {
    fn into_ticket(self, now: i64) -> SignInTicket {
        let stage = match (self.stage.as_str(), self.ended.as_deref()) {
            ("done", _) => Stage::Done,
            (_, Some("denied")) => Stage::Denied,
            (_, Some(_)) => Stage::Tries,
            _ if self.expires_at <= now => Stage::Expired,
            ("scanned", _) => Stage::Scanned,
            ("code", _) => Stage::Code,
            _ => Stage::Waiting,
        };
        SignInTicket {
            id: self.id,
            purpose: Purpose::parse(&self.purpose),
            user_id: self.user_id,
            browser_name: self.browser_name,
            browser_net: self.browser_net,
            stage,
            identity_id: self.identity_id,
            code_expires_at: self.code_expires_at,
            tries_left: self.tries_left,
            expires_at: self.expires_at,
        }
    }
}

const SIGN_IN_COLUMNS: &str = "id, purpose, user_id, browser_name, browser_net, stage, ended, \
                               identity_id, code_expires_at, tries_left, expires_at";

/// The digest of the digits `code` of `ticket`: only the holder of the ticket (the server, in
/// memory, for the browser that shows it) can compute it, so a copy of the database does not
/// give the digits away.
fn code_digest(ticket: &str, code: &str) -> [u8; 32] {
    secret::digest(&format!("gono-wechat-code\0{ticket}\0{code}"))
}

/// Six random digits.
fn new_code() -> String {
    use rand::RngExt as _;
    format!("{:06}", rand::rng().random_range(0..1_000_000u32))
}

/// Makes a sign-in ticket for the browser whose cookie is `browser`, and ends its earlier ones.
/// `user_id` is the account of a [`Purpose::Reauth`]. Returns the ticket (once) and when it
/// ends.
pub async fn create_sign_in(
    pool: &Pool,
    browser: &str,
    purpose: Purpose,
    user_id: Option<i64>,
    browser_name: &str,
    browser_net: &str,
    now: i64,
) -> Result<Ticket> {
    let mut tx = db::begin_immediate(pool).await?;
    let browser_hash = secret::digest(browser);
    sqlx::query("DELETE FROM wechat_sign_in_tickets WHERE browser_hash = ?")
        .bind(&browser_hash[..])
        .execute(&mut *tx)
        .await?;
    let ticket = secret::random_token(TICKET_CHARS);
    let expires_at = now.saturating_add(SIGN_IN_TTL_SECS);
    let id = db::next_id(&mut tx, "wechat_sign_in_tickets").await?;
    let name: String = browser_name.chars().take(64).collect();
    sqlx::query(
        "INSERT INTO wechat_sign_in_tickets (id, ticket_hash, browser_hash, purpose, user_id, \
         browser_name, browser_net, stage, tries_left, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?)",
    )
    .bind(id)
    .bind(&secret::digest(ticket.expose_secret())[..])
    .bind(&browser_hash[..])
    .bind(purpose.as_str())
    .bind(user_id.filter(|_| purpose == Purpose::Reauth))
    .bind(name)
    .bind(browser_net)
    .bind(CODE_TRIES)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Ticket { ticket, expires_at })
}

/// The sign-in ticket `ticket`, if one was made, whatever its stage.
pub async fn sign_in_ticket(pool: &Pool, ticket: &str, now: i64) -> Result<Option<SignInTicket>> {
    let sql = format!("SELECT {SIGN_IN_COLUMNS} FROM wechat_sign_in_tickets WHERE ticket_hash = ?");
    let row: Option<SignInRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&secret::digest(ticket)[..])
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| row.into_ticket(now)))
}

/// The sign-in ticket `ticket` of the browser whose cookie is `browser`.
pub async fn browser_sign_in(
    pool: &Pool,
    ticket: &str,
    browser: &str,
    now: i64,
) -> Result<Option<SignInTicket>> {
    let sql = format!(
        "SELECT {SIGN_IN_COLUMNS} FROM wechat_sign_in_tickets \
         WHERE ticket_hash = ? AND browser_hash = ?"
    );
    let row: Option<SignInRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&secret::digest(ticket)[..])
        .bind(&secret::digest(browser)[..])
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| row.into_ticket(now)))
}

/// Outcome of [`lock_sign_in`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locked {
    /// Locked to the identity (or already to it); it has [`SIGN_IN_TTL_SECS`] from now.
    Locked(SignInTicket),
    /// Another identity scanned it first.
    Taken,
    /// Unknown, ended, done or expired.
    Expired,
}

/// Locks the live sign-in ticket `ticket` to WeChat identity `identity_id`, which scanned it.
pub async fn lock_sign_in(pool: &Pool, ticket: &str, identity_id: i64, now: i64) -> Result<Locked> {
    let mut tx = db::begin_immediate(pool).await?;
    let sql = format!("SELECT {SIGN_IN_COLUMNS} FROM wechat_sign_in_tickets WHERE ticket_hash = ?");
    let row: Option<SignInRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&secret::digest(ticket)[..])
        .fetch_optional(&mut *tx)
        .await?;
    let Some(found) = row.map(|row| row.into_ticket(now)) else {
        return Ok(Locked::Expired);
    };
    match found.stage {
        Stage::Waiting => {}
        Stage::Scanned | Stage::Code if found.identity_id == Some(identity_id) => {
            return Ok(Locked::Locked(found));
        }
        Stage::Scanned | Stage::Code => return Ok(Locked::Taken),
        _ => return Ok(Locked::Expired),
    }
    let expires_at = now.saturating_add(SIGN_IN_TTL_SECS);
    sqlx::query(
        "UPDATE wechat_sign_in_tickets SET stage = 'scanned', identity_id = ?, expires_at = ? \
         WHERE id = ?",
    )
    .bind(identity_id)
    .bind(expires_at)
    .bind(found.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Locked::Locked(SignInTicket {
        stage: Stage::Scanned,
        identity_id: Some(identity_id),
        expires_at,
        ..found
    }))
}

/// Shows the digits of the sign-in ticket `ticket`, locked to `identity_id`, on its phone: new
/// ones, valid for [`CODE_TTL_SECS`] and [`CODE_TRIES`] tries. `None` if the ticket is not
/// locked to that identity or has ended.
pub async fn issue_code(
    pool: &Pool,
    ticket: &str,
    identity_id: i64,
    now: i64,
) -> Result<Option<(String, i64)>> {
    let mut tx = db::begin_immediate(pool).await?;
    let code = new_code();
    let expires_at = now.saturating_add(CODE_TTL_SECS);
    let issued = sqlx::query(
        "UPDATE wechat_sign_in_tickets SET stage = 'code', code_hash = ?, code_expires_at = ?, \
         tries_left = ?, expires_at = ? WHERE ticket_hash = ? AND identity_id = ? \
         AND stage IN ('scanned', 'code') AND expires_at > ?",
    )
    .bind(&code_digest(ticket, &code)[..])
    .bind(expires_at)
    .bind(CODE_TRIES)
    .bind(expires_at)
    .bind(&secret::digest(ticket)[..])
    .bind(identity_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(issued.then_some((code, expires_at)))
}

/// Ends the sign-in ticket `ticket` as the phone of `identity_id` cancelled it. Returns `false`
/// if it is not locked to that identity or has ended.
pub async fn deny_sign_in(pool: &Pool, ticket: &str, identity_id: i64, now: i64) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let denied = sqlx::query(
        "UPDATE wechat_sign_in_tickets SET stage = 'ended', ended = 'denied', code_hash = NULL, \
         code_expires_at = NULL WHERE ticket_hash = ? AND identity_id = ? \
         AND stage IN ('scanned', 'code') AND expires_at > ?",
    )
    .bind(&secret::digest(ticket)[..])
    .bind(identity_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(denied)
}

/// Outcome of [`enter_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entered {
    /// The digits are right: the sign-in is done, by this identity.
    Right(SignInTicket),
    /// Wrong, with tries left.
    Wrong(i64),
    /// Wrong for the last time: the sign-in ended.
    Ended,
    /// No digits wait for this browser: not confirmed yet, ended or expired.
    NoCode,
}

/// Checks the digits `code` that the browser whose cookie is `browser` entered for its sign-in
/// ticket `ticket`. Each try counts before the comparison; the right digits finish the sign-in
/// (once).
pub async fn enter_code(
    pool: &Pool,
    ticket: &str,
    browser: &str,
    code: &str,
    now: i64,
) -> Result<Entered> {
    let mut tx = db::begin_immediate(pool).await?;
    let sql = format!(
        "SELECT {SIGN_IN_COLUMNS}, code_hash FROM wechat_sign_in_tickets \
         WHERE ticket_hash = ? AND browser_hash = ?"
    );
    #[derive(FromRow)]
    struct Row {
        #[sqlx(flatten)]
        ticket: SignInRow,
        code_hash: Option<Vec<u8>>,
    }
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&secret::digest(ticket)[..])
        .bind(&secret::digest(browser)[..])
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Ok(Entered::NoCode);
    };
    let stored = row.code_hash;
    let found = row.ticket.into_ticket(now);
    let live = found.stage == Stage::Code
        && found.tries_left > 0
        && found.code_expires_at.is_some_and(|until| until > now);
    let Some(stored) = stored.filter(|_| live) else {
        return Ok(Entered::NoCode);
    };
    let right = code.len() == CODE_DIGITS
        && code.bytes().all(|b| b.is_ascii_digit())
        && secret::constant_time_eq(&stored, &code_digest(ticket, code));
    if right {
        sqlx::query(
            "UPDATE wechat_sign_in_tickets SET stage = 'done', code_hash = NULL, \
             code_expires_at = NULL WHERE id = ?",
        )
        .bind(found.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(Entered::Right(SignInTicket {
            stage: Stage::Done,
            ..found
        }));
    }
    let left = found.tries_left - 1;
    if left > 0 {
        sqlx::query("UPDATE wechat_sign_in_tickets SET tries_left = ? WHERE id = ?")
            .bind(left)
            .bind(found.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(Entered::Wrong(left));
    }
    sqlx::query(
        "UPDATE wechat_sign_in_tickets SET tries_left = 0, stage = 'ended', ended = 'tries', \
         code_hash = NULL, code_expires_at = NULL WHERE id = ?",
    )
    .bind(found.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Entered::Ended)
}

/// Ends the sign-in tickets of the browser whose cookie is `browser`.
pub async fn end_browser_sign_ins(pool: &Pool, browser: &str) -> Result<()> {
    let mut tx = db::begin_immediate(pool).await?;
    sqlx::query("DELETE FROM wechat_sign_in_tickets WHERE browser_hash = ?")
        .bind(&secret::digest(browser)[..])
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// The WeChat identity `identity_id` with its account, as a sign-in finds it: its openid must
/// be `openid` (the WeChat user that asks now).
pub async fn identity_of(
    pool: &Pool,
    identity_id: i64,
    app_id: &str,
    openid: &str,
) -> Result<bool> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM external_identities WHERE id = ? AND provider = 'wechat' AND realm = ? \
         AND subject = ?",
    )
    .bind(identity_id)
    .bind(app_id)
    .bind(openid)
    .fetch_optional(pool)
    .await?;
    Ok(found.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids_are_wx_and_sixteen_characters() {
        assert!(is_app_id("wxd930ea5d5a258f4f"));
        assert!(is_app_id("wx0123456789ABCDEF"));
        for invalid in [
            "",
            "wx",
            "wxd930ea5d5a258f4",
            "wxd930ea5d5a258f4f0",
            "xwd930ea5d5a258f4f",
            "wxd930ea5d5a258f-f",
            " wxd930ea5d5a258f4",
        ] {
            assert!(!is_app_id(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn wechat_ids_are_url_safe() {
        assert!(is_wechat_id("oGZUI0egBJY1zhBYw2KhdUfwVJJE"));
        assert!(is_wechat_id("o6_bmasdasdsad6_2sgVt7hMZOPfL"));
        assert!(is_wechat_id(&"a".repeat(MAX_ID_BYTES)));
        for invalid in ["", "a b", "a/b", "a+b", "a=", &"a".repeat(MAX_ID_BYTES + 1)] {
            assert!(!is_wechat_id(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn tickets_and_tokens_have_their_lengths() {
        let ticket = secret::random_token(TICKET_CHARS);
        let token = secret::random_token(TOKEN_CHARS);
        assert!(is_ticket(ticket.expose_secret()) && !is_token(ticket.expose_secret()));
        assert!(is_token(token.expose_secret()) && !is_ticket(token.expose_secret()));
        assert!(!is_ticket(&"a-".repeat(11)));
        assert!(!is_token(&format!("{}é", "a".repeat(41))));
    }
}
