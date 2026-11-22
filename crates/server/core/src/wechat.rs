//! WeChat mini program identities, the tickets that bind them to accounts, and the sessions of
//! the mini program (`wechat_identities`, `wechat_bind_tickets`, `wechat_signup_tokens` and
//! `mp_sessions`).
//!
//! A mini program knows its users by the openid WeChat gives each of them for its AppID. The
//! server learns that openid only by exchanging a sign-in code of the mini program with WeChat
//! (`jscode2session`, in the binary); this module starts where that exchange ends:
//!
//! - **Binding.** On the account page a user makes a bind ticket ([`create_ticket`], with the
//!   web login password, checked by the caller), which the page shows as a QR code. The mini
//!   program that scans it first signs in ([`sign_in`]); as its openid is bound to no account
//!   yet, it gets a signup token for that openid, and then binds it with the ticket ([`bind`]).
//!   An account has at most one identity per AppID, and an openid of an AppID belongs to one
//!   account at most (two unique keys). Binding gives that WeChat user the account's mini
//!   program sessions; [`unbind`] takes them away again.
//! - **Tickets** are 128 random bits ([`TICKET_CHARS`]), valid for [`TICKET_TTL_SECS`] and used
//!   up by the binding they make. A new ticket ends the account's earlier ones.
//! - **Signup tokens** are 256 random bits, valid for [`SIGNUP_TTL_SECS`], bound to the openid
//!   that [`sign_in`] found unbound. A new one for the same openid ends the earlier ones, and
//!   binding uses it up.
//! - **Sessions** are bearer tokens of 256 random bits. A session ends [`SESSION_TTL_SECS`]
//!   after its last use (each use extends it, at most once per [`SEEN_GRANULARITY_SECS`]), when
//!   its identity is unbound, and when the account is disabled or deleted. An identity has at
//!   most [`MAX_SESSIONS`]: a new one ends the oldest. A session reads the account's name and
//!   services ([`Account`]) and nothing else.
//!
//! Tickets and tokens are stored only as SHA-256 digests ([`secret::digest`]): they are random,
//! so a fast hash is enough. Every write is one write transaction, so the unique keys, the
//! single use of tickets and the end of sessions hold under concurrent requests. The audit log
//! records `wechat.bound` and `wechat.unbound` with the AppID, never the openid.

use std::net::IpAddr;

use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;

use crate::{
    audit::{self, Actor, Record},
    db::{self, Flag, Pool, Text},
    error::{Error, Result},
    secret,
    services::Services,
    types::Username,
};

/// How long a bind ticket is valid, in seconds.
pub const TICKET_TTL_SECS: i64 = 10 * 60;

/// How long a signup token is valid, in seconds.
pub const SIGNUP_TTL_SECS: i64 = 10 * 60;

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
pub const TOKEN_CHARS: usize = 43;

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

/// A WeChat identity bound to an account. The openid is not part of it: nothing shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The AppID of the mini program.
    pub app_id: String,
    /// When it was bound, UNIX seconds.
    pub created_at: i64,
    /// When the mini program last signed in with it.
    pub last_seen_at: i64,
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

#[derive(FromRow)]
struct IdentityRow {
    app_id: Text,
    created_at: i64,
    last_seen_at: i64,
}

impl From<IdentityRow> for Identity {
    fn from(row: IdentityRow) -> Self {
        Self {
            app_id: row.app_id.0,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
        }
    }
}

/// The identities bound to account `user_id`, one per AppID, oldest first.
pub async fn identities(pool: &Pool, user_id: i64) -> Result<Vec<Identity>> {
    let rows: Vec<IdentityRow> = sqlx::query_as(
        "SELECT app_id, created_at, last_seen_at FROM wechat_identities WHERE user_id = ? \
         ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Identity::from).collect())
}

/// The identity of AppID `app_id` bound to account `user_id`, if there is one.
pub async fn identity(pool: &Pool, user_id: i64, app_id: &str) -> Result<Option<Identity>> {
    let row: Option<IdentityRow> = sqlx::query_as(
        "SELECT app_id, created_at, last_seen_at FROM wechat_identities \
         WHERE user_id = ? AND app_id = ?",
    )
    .bind(user_id)
    .bind(app_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Identity::from))
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
/// tickets. The caller has checked the web login password.
pub async fn create_ticket(pool: &Pool, user_id: i64, app_id: &str, now: i64) -> Result<NewTicket> {
    let mut tx = db::begin_immediate(pool).await?;
    let bound: Option<i64> =
        sqlx::query_scalar("SELECT id FROM wechat_identities WHERE user_id = ? AND app_id = ?")
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
    fn into_account(self) -> Result<Account> {
        Ok(Account {
            user_id: self.id,
            username: Username::new(self.username)?,
            display_name: self.display_name,
            services: self.services,
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

/// Opens a session of `user_id` with the identity (`app_id`, `openid`) inside `tx`, after
/// ending the identity's oldest sessions beyond [`MAX_SESSIONS`].
async fn open_session(
    tx: &mut db::Tx,
    user_id: i64,
    app_id: &str,
    openid: &str,
    now: i64,
) -> Result<NewSession> {
    // The newest session that stays besides the new one, the (MAX_SESSIONS - 1)th: every older
    // one ends. Ids grow with time (`id_sequences`).
    let oldest_kept: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM mp_sessions WHERE user_id = ? AND app_id = ? AND openid = ? \
         ORDER BY id DESC LIMIT 1 OFFSET ?",
    )
    .bind(user_id)
    .bind(app_id)
    .bind(openid)
    .bind(MAX_SESSIONS - 2)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(oldest_kept) = oldest_kept {
        sqlx::query(
            "DELETE FROM mp_sessions WHERE user_id = ? AND app_id = ? AND openid = ? AND id < ?",
        )
        .bind(user_id)
        .bind(app_id)
        .bind(openid)
        .bind(oldest_kept)
        .execute(&mut **tx)
        .await?;
    }
    let token = secret::random_token(TOKEN_CHARS);
    let expires_at = now.saturating_add(SESSION_TTL_SECS);
    let id = db::next_id(tx, "mp_sessions").await?;
    sqlx::query(
        "INSERT INTO mp_sessions (id, token_hash, user_id, app_id, openid, created_at, \
         last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&secret::digest(token.expose_secret())[..])
    .bind(user_id)
    .bind(app_id)
    .bind(openid)
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
    let bound: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM wechat_identities WHERE app_id = ? AND openid = ?")
            .bind(app_id)
            .bind(openid)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(user_id) = bound {
        let Some(row) = account_in(&mut tx, user_id).await? else {
            // The cascade removes the identity with its account.
            return Ok(SignIn::Disabled);
        };
        if !row.enabled {
            return Ok(SignIn::Disabled);
        }
        sqlx::query(
            "UPDATE wechat_identities SET last_seen_at = ?, unionid = COALESCE(?, unionid) \
             WHERE app_id = ? AND openid = ?",
        )
        .bind(now)
        .bind(unionid)
        .bind(app_id)
        .bind(openid)
        .execute(&mut *tx)
        .await?;
        let session = open_session(&mut tx, user_id, app_id, openid, now).await?;
        let account = row.into_account()?;
        tx.commit().await?;
        return Ok(SignIn::Session { session, account });
    }
    sqlx::query("DELETE FROM wechat_signup_tokens WHERE app_id = ? AND openid = ?")
        .bind(app_id)
        .bind(openid)
        .execute(&mut *tx)
        .await?;
    let token = secret::random_token(TOKEN_CHARS);
    let expires_at = now.saturating_add(SIGNUP_TTL_SECS);
    let id = db::next_id(&mut tx, "wechat_signup_tokens").await?;
    sqlx::query(
        "INSERT INTO wechat_signup_tokens (id, token_hash, app_id, openid, unionid, created_at, \
         expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&secret::digest(token.expose_secret())[..])
    .bind(app_id)
    .bind(openid)
    .bind(unionid)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(SignIn::Unbound { token, expires_at })
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

/// Runs `sql`, a `DELETE` of one row by its id, inside `tx`.
async fn delete_row(tx: &mut db::Tx, sql: &'static str, id: i64) -> Result<()> {
    sqlx::query(sql).bind(id).execute(&mut **tx).await?;
    Ok(())
}

#[derive(FromRow)]
struct SignupRow {
    id: i64,
    openid: Text,
    unionid: Option<Text>,
}

/// Binds the openid of the live signup token `signup_token` of AppID `app_id` to the account
/// of the live bind ticket `ticket`, uses both up, opens a session and records
/// `wechat.bound`. See [`Bind`] for the refusals; every check and the binding are one write
/// transaction.
pub async fn bind(
    pool: &Pool,
    app_id: &str,
    signup_token: &str,
    ticket: &str,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Bind> {
    let mut tx = db::begin_immediate(pool).await?;
    let signup: Option<SignupRow> = sqlx::query_as(
        "SELECT id, openid, unionid FROM wechat_signup_tokens \
         WHERE token_hash = ? AND app_id = ? AND expires_at > ?",
    )
    .bind(&secret::digest(signup_token)[..])
    .bind(app_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
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
    let openid = signup.openid.0;
    let owner: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM wechat_identities WHERE app_id = ? AND openid = ?")
            .bind(app_id)
            .bind(&openid)
            .fetch_optional(&mut *tx)
            .await?;
    const END_SIGNUP: &str = "DELETE FROM wechat_signup_tokens WHERE id = ?";
    const END_TICKET: &str = "DELETE FROM wechat_bind_tickets WHERE id = ?";
    match owner {
        Some(owner) if owner != user_id => {
            delete_row(&mut tx, END_SIGNUP, signup.id).await?;
            tx.commit().await?;
            return Ok(Bind::AccountExists);
        }
        // Bound to this account already: there is nothing to bind, and the ticket and the
        // token are used up all the same.
        Some(_) => {}
        None => {
            let other: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM wechat_identities WHERE user_id = ? AND app_id = ?",
            )
            .bind(user_id)
            .bind(app_id)
            .fetch_optional(&mut *tx)
            .await?;
            if other.is_some() {
                delete_row(&mut tx, END_TICKET, ticket_id).await?;
                tx.commit().await?;
                return Ok(Bind::BindFailed);
            }
            let id = db::next_id(&mut tx, "wechat_identities").await?;
            let inserted = sqlx::query(
                "INSERT INTO wechat_identities (id, user_id, app_id, openid, unionid, \
                 created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(user_id)
            .bind(app_id)
            .bind(&openid)
            .bind(signup.unionid.as_deref())
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await;
            match inserted {
                Ok(_) => {}
                // Inside the write transaction nobody binds in between; the unique keys back
                // the checks above up.
                Err(err)
                    if err
                        .as_database_error()
                        .is_some_and(|e| e.is_unique_violation()) =>
                {
                    return Ok(Bind::BindFailed);
                }
                Err(err) => return Err(Error::Database(err)),
            }
            audit::record_in(
                &mut tx,
                &Record::new(user_id, "wechat.bound", Actor::User)
                    .client_ip(client_ip)
                    .details(serde_json::json!({ "app_id": app_id })),
                now,
            )
            .await?;
        }
    }
    delete_row(&mut tx, END_TICKET, ticket_id).await?;
    delete_row(&mut tx, END_SIGNUP, signup.id).await?;
    let session = open_session(&mut tx, user_id, app_id, &openid, now).await?;
    let account = row.into_account()?;
    tx.commit().await?;
    Ok(Bind::Bound { session, account })
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
    #[sqlx(try_from = "Flag")]
    bound: bool,
    #[sqlx(flatten)]
    account: AccountRow,
}

/// The session of bearer token `token` of AppID `app_id`, extending it. A session counts only
/// while its identity is bound to its account.
pub async fn lookup(pool: &Pool, app_id: &str, token: &str, now: i64) -> Result<Lookup> {
    let sql = format!(
        "SELECT s.id AS session_id, s.last_seen_at, s.expires_at, \
         EXISTS (SELECT 1 FROM wechat_identities i WHERE i.user_id = s.user_id \
                 AND i.app_id = s.app_id AND i.openid = s.openid) AS bound, \
         u.id, u.username, u.display_name, u.enabled, {} \
         FROM mp_sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = ? AND s.app_id = ?",
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
    if !row.bound {
        return Ok(Lookup::Unknown);
    }
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
    Ok(Lookup::Live(row.account.into_account()?))
}

/// Ends the session of bearer token `token` of AppID `app_id`, expired or not. Returns `false`
/// if there was none.
pub async fn logout(pool: &Pool, app_id: &str, token: &str) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let deleted = sqlx::query("DELETE FROM mp_sessions WHERE token_hash = ? AND app_id = ?")
        .bind(&secret::digest(token)[..])
        .bind(app_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(deleted)
}

/// Unbinds the identity of AppID `app_id` from account `user_id`, ends every session of the
/// account with that AppID and records `wechat.unbound`. Returns `false` if there was no
/// identity (then nothing changed).
pub async fn unbind(
    pool: &Pool,
    user_id: i64,
    app_id: &str,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let deleted = sqlx::query("DELETE FROM wechat_identities WHERE user_id = ? AND app_id = ?")
        .bind(user_id)
        .bind(app_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Ok(false);
    }
    sqlx::query("DELETE FROM mp_sessions WHERE user_id = ? AND app_id = ?")
        .bind(user_id)
        .bind(app_id)
        .execute(&mut *tx)
        .await?;
    audit::record_in(
        &mut tx,
        &Record::new(user_id, "wechat.unbound", Actor::User)
            .client_ip(client_ip)
            .details(serde_json::json!({ "app_id": app_id })),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Removes the tickets, signup tokens and sessions that expired at `now`. Returns how many
/// there were.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let mut purged = 0;
    for sql in [
        "DELETE FROM wechat_bind_tickets WHERE expires_at <= ?",
        "DELETE FROM wechat_signup_tokens WHERE expires_at <= ?",
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
