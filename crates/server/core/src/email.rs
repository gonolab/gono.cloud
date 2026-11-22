//! Email addresses of accounts and the one-time codes that prove them (`users.email` and the
//! `email_codes` table).
//!
//! An account may have one email address. Its user binds it on the account page by entering a
//! code sent to it; with it, a forgotten web login password can be reset with a code sent there
//! (`/login/forgot`). The address is a recovery credential: changing or removing it bumps the
//! account's `updated_at`, so sign-ins waiting for their second step end, and it ends every code
//! of the account that is still waiting.
//!
//! - **Addresses** are ASCII (`local@domain`, the dot-atom form; international domains in their
//!   `xn--` form), at most [`MAX_ADDRESS_BYTES`], and stored lower-cased ([`normalize_address`]),
//!   so `Alice@Example.com` and `alice@example.com` are one address. An address belongs to one
//!   account at most (a unique key).
//! - **Codes** are 6 random digits ([`CODE_DIGITS`]) for one [`Purpose`] and the address they
//!   were sent to, valid for [`CODE_TTL_SECS`] and for at most [`MAX_ATTEMPTS`] tries, each
//!   counted before the code is compared. A new code ends the account's earlier ones of the same
//!   purpose; a used one ends at once. Codes are never stored in plain text: a row holds the
//!   SHA-256 of the code together with the row's id. That keeps them out of sight of whoever
//!   reads the database or a backup, but 6 digits are only 20 bits: whoever can read the
//!   database while a code waits could find it by trying them all. Codes therefore live for
//!   minutes, bind only the address they were sent to, and resetting a password with one does
//!   not touch two-step verification.
//! - **Sending** is limited per account and purpose: one code per [`SEND_INTERVAL_SECS`] and
//!   [`SENDS_PER_DAY`] in a day ([`send_code`]), which also bounds the guesses at codes to
//!   `SENDS_PER_DAY * MAX_ATTEMPTS` a day. Used and expired codes stay a day to be counted;
//!   [`purge`] removes them after that.
//!
//! Every write is one write transaction, so the limits, the attempt counts and the uniqueness of
//! addresses hold under concurrent requests, also from other processes.

use std::net::IpAddr;

use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use sqlx::FromRow;

use crate::{
    audit::{self, Actor, Record},
    db::{self, Flag, Pool, Text},
    error::{Error, Result},
    secret,
    types::Username,
    users::User,
};

/// The longest address, in bytes (RFC 5321's limit of a path, less the angle brackets).
pub const MAX_ADDRESS_BYTES: usize = 254;

/// The longest local part (before the `@`), in bytes.
const MAX_LOCAL_BYTES: usize = 64;

/// Digits of a code.
pub const CODE_DIGITS: usize = 6;

/// The codes there are: 10 to the power of [`CODE_DIGITS`].
const CODE_SPACE: u32 = 1_000_000;

/// How long a code is valid, in seconds.
pub const CODE_TTL_SECS: i64 = 10 * 60;

/// Tries a code takes; the last wrong one ends it.
pub const MAX_ATTEMPTS: i64 = 5;

/// Codes per account and purpose are at least this far apart, in seconds.
pub const SEND_INTERVAL_SECS: i64 = 60;

/// Codes per account and purpose within [`DAY_SECS`].
pub const SENDS_PER_DAY: i64 = 10;

/// The window of [`SENDS_PER_DAY`], and how long the rows of codes are kept for it.
pub const DAY_SECS: i64 = 24 * 60 * 60;

/// What a code is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Binding the address it was sent to to the account (the account page).
    Bind,
    /// Resetting the web login password of the account whose address it was sent to.
    Reset,
}

impl Purpose {
    /// The stored form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Reset => "reset",
        }
    }
}

/// Whether `local` is a dot-atom: `atext` characters (RFC 5322) in dot-separated parts.
fn is_dot_atom(local: &str) -> bool {
    !local.is_empty()
        && local.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b))
        })
}

/// Whether `domain` (lower case) is a DNS name of at least two labels whose last is not
/// numeric: address literals (`[192.0.2.1]`) and single labels (`localhost`) are not accepted.
fn is_mail_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_lowercase()))
}

/// `address` if it is one this server accepts, as typed (surrounding whitespace removed).
fn check_address(address: &str) -> Option<&str> {
    let address = address.trim();
    if address.len() > MAX_ADDRESS_BYTES {
        return None;
    }
    let (local, domain) = address.split_once('@')?;
    (local.len() <= MAX_LOCAL_BYTES
        && is_dot_atom(local)
        && is_mail_domain(&domain.to_ascii_lowercase()))
    .then_some(address)
}

/// The stored form of a typed address: without surrounding whitespace, in lower case. `None`
/// if it is not an address this server accepts (see the module documentation).
pub fn normalize_address(input: &str) -> Option<String> {
    check_address(input).map(str::to_ascii_lowercase)
}

/// A sender as `smtp.from` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// The display name, if any, without quotes.
    pub name: Option<String>,
    /// The address, as written.
    pub address: String,
}

/// Parses `address` or `Name <address>` (the name may be in double quotes). The error says
/// what is wrong, for the configuration's messages.
pub fn parse_mailbox(input: &str) -> std::result::Result<Mailbox, &'static str> {
    let input = input.trim();
    if input.chars().any(char::is_control) {
        return Err("contains control characters");
    }
    let (name, address) = match input
        .strip_suffix('>')
        .and_then(|rest| rest.rsplit_once('<'))
    {
        Some((name, address)) => {
            let name = name.trim();
            let name = name
                .strip_prefix('"')
                .and_then(|name| name.strip_suffix('"'))
                .unwrap_or(name)
                .trim();
            if name.contains(['<', '>', '"', '\\']) {
                return Err("has a name with <, >, \" or \\");
            }
            ((!name.is_empty()).then(|| name.to_owned()), address)
        }
        None => (None, input),
    };
    let address = check_address(address).ok_or("is not an email address")?;
    Ok(Mailbox {
        name,
        address: address.to_owned(),
    })
}

/// The digits of a typed code (spaces allowed), or `None`.
pub fn parse_code(input: &str) -> Option<String> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    (digits.len() == CODE_DIGITS && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// The stored digest of `code` in row `id`: SHA-256 over a label, the id and the code, so that
/// equal codes of two rows have different digests.
fn code_digest(id: i64, code: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gono-email-code-v1\0");
    hasher.update(id.to_be_bytes());
    hasher.update(code.as_bytes());
    hasher.finalize().into()
}

/// A new code: the one value to put into the mail that carries it.
pub struct Code {
    /// Row id, for [`discard`].
    pub id: i64,
    /// The digits.
    pub code: String,
    /// The address it is for.
    pub email: String,
    /// When it ends, UNIX seconds.
    pub expires_at: i64,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Code")
            .field("id", &self.id)
            .field("code", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Outcome of [`send_code`].
#[derive(Debug)]
pub enum NewCode {
    /// A new code to mail.
    Code(Code),
    /// A code of this purpose was made less than [`SEND_INTERVAL_SECS`] ago; this many seconds
    /// are left.
    TooSoon(i64),
    /// [`SENDS_PER_DAY`] codes of this purpose were made within a day.
    DailyLimit,
}

/// The address of account `user_id`, if it has one.
pub async fn address(pool: &Pool, user_id: i64) -> Result<Option<String>> {
    let email: Option<Option<Text>> = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(email.flatten().map(String::from))
}

#[derive(FromRow)]
struct AccountRow {
    #[sqlx(flatten)]
    user: User,
    email: Option<Text>,
}

/// The account a sign-in form names by `login`: its username or its email address, with the
/// address. A username wins over another account's address (usernames may contain `@`).
///
/// One query whatever `login` is, so that the time it takes does not tell whether the account
/// exists.
pub async fn find_account(pool: &Pool, login: &str) -> Result<Option<(User, Option<String>)>> {
    let login = login.trim();
    // Values that match no row stand in for what `login` cannot be: no username and no address
    // is empty.
    let username = Username::new(login)
        .map(|name| name.as_str().to_owned())
        .unwrap_or_default();
    let email = normalize_address(login).unwrap_or_default();
    let sql = format!(
        "SELECT {}, email FROM users WHERE username = ? OR email = ? \
         ORDER BY CASE WHEN username = ? THEN 0 ELSE 1 END LIMIT 1",
        crate::users::USER_COLUMNS
    );
    let row: Option<AccountRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&username)
        .bind(&email)
        .bind(&username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| (row.user, row.email.map(String::from))))
}

/// The address the live code of `purpose` of `user_id` was sent to, and when it ends.
pub async fn pending(
    pool: &Pool,
    user_id: i64,
    purpose: Purpose,
    now: i64,
) -> Result<Option<(String, i64)>> {
    let row: Option<(Text, i64)> = sqlx::query_as(
        "SELECT email, expires_at FROM email_codes \
         WHERE user_id = ? AND purpose = ? AND expires_at > ? AND attempts < ? \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(purpose.as_str())
    .bind(now)
    .bind(MAX_ATTEMPTS)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(email, expires_at)| (email.0, expires_at)))
}

/// Ends every live code of `user_id` (of `purpose`, or of every purpose) inside `tx`: it
/// expires now and is kept for the daily count.
async fn end_codes(
    tx: &mut db::Tx,
    user_id: i64,
    purpose: Option<Purpose>,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE email_codes SET expires_at = ? \
         WHERE user_id = ? AND (? IS NULL OR purpose = ?) AND expires_at > ?",
    )
    .bind(now)
    .bind(user_id)
    .bind(purpose.map(Purpose::as_str))
    .bind(purpose.map(Purpose::as_str))
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Makes a new code of `purpose` for `email` (normalized, see [`normalize_address`]) of
/// account `user_id`, within the limits of the module documentation, and ends the account's
/// earlier codes of that purpose. The caller mails it, and calls [`discard`] if that fails.
///
/// A bind code is made also for an address that another account has: that is found out only
/// when the code is entered ([`bind`]), so that only the owner of an address can learn that it
/// is taken.
pub async fn send_code(
    pool: &Pool,
    user_id: i64,
    purpose: Purpose,
    email: &str,
    now: i64,
) -> Result<NewCode> {
    let mut tx = db::begin_immediate(pool).await?;
    let (count, last): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MAX(created_at), 0) FROM email_codes \
         WHERE user_id = ? AND purpose = ? AND created_at > ?",
    )
    .bind(user_id)
    .bind(purpose.as_str())
    .bind(now - DAY_SECS)
    .fetch_one(&mut *tx)
    .await?;
    if count > 0 && last > now - SEND_INTERVAL_SECS {
        // A clock that went back must not make the wait longer than the interval.
        return Ok(NewCode::TooSoon(
            (last + SEND_INTERVAL_SECS - now).clamp(1, SEND_INTERVAL_SECS),
        ));
    }
    if count >= SENDS_PER_DAY {
        return Ok(NewCode::DailyLimit);
    }
    end_codes(&mut tx, user_id, Some(purpose), now).await?;
    let id = db::next_id(&mut tx, "email_codes").await?;
    let code = format!("{:06}", rand::rng().random_range(0..CODE_SPACE));
    let expires_at = now + CODE_TTL_SECS;
    sqlx::query(
        "INSERT INTO email_codes (id, user_id, purpose, email, code_hash, created_at, \
         expires_at, attempts) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
    )
    .bind(id)
    .bind(user_id)
    .bind(purpose.as_str())
    .bind(email)
    .bind(&code_digest(id, &code)[..])
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(NewCode::Code(Code {
        id,
        code,
        email: email.to_owned(),
        expires_at,
    }))
}

/// Ends the code of row `id`, whose mail could not be sent. It still counts towards the limits:
/// a failing mail server must not turn them off.
pub async fn discard(pool: &Pool, id: i64, now: i64) -> Result<()> {
    let mut tx = db::begin_immediate(pool).await?;
    sqlx::query("UPDATE email_codes SET expires_at = ? WHERE id = ? AND expires_at > ?")
        .bind(now)
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(FromRow)]
struct CodeRow {
    id: i64,
    email: Text,
    code_hash: Vec<u8>,
    attempts: i64,
}

/// Outcome of `try_code`.
enum Tried {
    /// The code is right.
    Right(CodeRow),
    /// The code is wrong; it takes this many more tries (0: it has ended).
    Wrong(i64),
    /// No code waits.
    None,
}

/// Takes one try at the live code of `purpose` of `user_id` inside `tx`. The try is counted
/// before the code is compared, and the digests are compared in constant time.
async fn try_code(
    tx: &mut db::Tx,
    user_id: i64,
    purpose: Purpose,
    code: &str,
    now: i64,
) -> Result<Tried> {
    let row: Option<CodeRow> = sqlx::query_as(
        "SELECT id, email, code_hash, attempts FROM email_codes \
         WHERE user_id = ? AND purpose = ? AND expires_at > ? AND attempts < ? \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(purpose.as_str())
    .bind(now)
    .bind(MAX_ATTEMPTS)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(Tried::None);
    };
    sqlx::query("UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?")
        .bind(row.id)
        .execute(&mut **tx)
        .await?;
    if secret::constant_time_eq(&code_digest(row.id, code), &row.code_hash) {
        Ok(Tried::Right(row))
    } else {
        Ok(Tried::Wrong(MAX_ATTEMPTS - row.attempts - 1))
    }
}

/// Outcome of [`bind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bind {
    /// The address is the account's now; `previous` is the one it replaced.
    Bound {
        /// The new address.
        email: String,
        /// The address it had before, which should hear of the change.
        previous: Option<String>,
    },
    /// The code is wrong; it takes this many more tries (0: it has ended).
    Wrong(i64),
    /// No code waits: none was sent, it expired, was replaced or took too many tries.
    Expired,
    /// Another account has the address. The code has ended.
    Taken,
}

/// Binds the address of the live bind code of `user_id` to the account, if `code` is that
/// code (see `try_code`). Ends every live code of the account, also those for password
/// resets, which were sent to the address it had, and bumps `updated_at`.
pub async fn bind(
    pool: &Pool,
    user_id: i64,
    code: &str,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Bind> {
    let mut tx = db::begin_immediate(pool).await?;
    let row = match try_code(&mut tx, user_id, Purpose::Bind, code, now).await? {
        Tried::Right(row) => row,
        Tried::None => return Ok(Bind::Expired),
        Tried::Wrong(left) => {
            tx.commit().await?;
            return Ok(Bind::Wrong(left));
        }
    };
    let email = row.email.0;
    // Inside the write transaction nobody can take the address in between; the unique key
    // backs this up.
    let taken: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE email = ? AND id <> ?")
        .bind(&email)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    if taken.is_some() {
        end_codes(&mut tx, user_id, Some(Purpose::Bind), now).await?;
        tx.commit().await?;
        return Ok(Bind::Taken);
    }
    let previous: Option<Option<Text>> = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(previous) = previous else {
        return Ok(Bind::Expired);
    };
    let updated = sqlx::query("UPDATE users SET email = ?, updated_at = ? WHERE id = ?")
        .bind(&email)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await;
    match updated {
        Ok(_) => {}
        Err(err)
            if err
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation()) =>
        {
            return Ok(Bind::Taken);
        }
        Err(err) => return Err(Error::Database(err)),
    }
    end_codes(&mut tx, user_id, None, now).await?;
    audit::record_in(
        &mut tx,
        &Record::new(user_id, "email.bound", Actor::User).client_ip(client_ip),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Bind::Bound {
        email,
        previous: previous.map(String::from),
    })
}

/// Removes the address of `user_id`, ends the account's live codes and bumps `updated_at`.
/// Returns the address it had, `None` if it had none (then nothing changed).
pub async fn remove(
    pool: &Pool,
    user_id: i64,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Option<String>> {
    let mut tx = db::begin_immediate(pool).await?;
    let previous: Option<Option<Text>> = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(previous) = previous.flatten() else {
        return Ok(None);
    };
    sqlx::query("UPDATE users SET email = NULL, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    end_codes(&mut tx, user_id, None, now).await?;
    audit::record_in(
        &mut tx,
        &Record::new(user_id, "email.removed", Actor::User).client_ip(client_ip),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(previous.0))
}

/// Outcome of [`reset_password`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reset {
    /// The password is reset.
    Done {
        /// The account's name.
        username: String,
        /// Its address, which should hear of the reset.
        email: String,
    },
    /// Nothing changed: no such account, a disabled one, no live code, or a wrong one. The
    /// cases are not told apart, so that nothing can be learnt about an account.
    Refused,
}

/// Resets the web login password of account `user_id` to `password_hash` (an Argon2 PHC
/// string) if `code` is its live reset code, sent to the address the account still has (see
/// `try_code`). Disabled accounts cannot reset.
///
/// A reset ends every browser session of the account and every live code, bumps `updated_at`
/// (so sign-ins waiting for their second step end) and is recorded as `password.reset`, all in
/// one transaction. Two-step verification stays as it is.
///
/// `user_id` is `None` when the form named no account: the write transaction runs all the same,
/// as it does for an account without a code.
pub async fn reset_password(
    pool: &Pool,
    user_id: Option<i64>,
    code: &str,
    password_hash: &str,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Reset> {
    let mut tx = db::begin_immediate(pool).await?;
    let Some(user_id) = user_id else {
        tx.commit().await?;
        return Ok(Reset::Refused);
    };
    let account: Option<(Text, Flag, Option<Text>)> =
        sqlx::query_as("SELECT username, enabled, email FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((username, Flag(true), Some(email))) = account else {
        tx.commit().await?;
        return Ok(Reset::Refused);
    };
    let row = match try_code(&mut tx, user_id, Purpose::Reset, code, now).await? {
        // A code sent to an address the account no longer has does not count (changing the
        // address ends codes already; this keeps it so).
        Tried::Right(row) if row.email.0 == email.0 => row,
        Tried::Right(_) | Tried::Wrong(_) | Tried::None => {
            tx.commit().await?;
            return Ok(Reset::Refused);
        }
    };
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(password_hash)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM web_sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    end_codes(&mut tx, user_id, None, now).await?;
    audit::record_in(
        &mut tx,
        &Record::new(user_id, "password.reset", Actor::User).client_ip(client_ip),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Reset::Done {
        username: username.0,
        email: row.email.0,
    })
}

/// Removes the codes that ended (expired, used, replaced or tried too often) and are older than
/// a day, which the daily limit no longer counts. Returns how many there were.
pub async fn purge(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query(
        "DELETE FROM email_codes WHERE created_at <= ? AND (expires_at <= ? OR attempts >= ?)",
    )
    .bind(now - DAY_SECS)
    .bind(now)
    .bind(MAX_ATTEMPTS)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(purged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_checked_and_lower_cased() {
        for (input, stored) in [
            ("alice@example.com", "alice@example.com"),
            ("  Alice.B+cloud@Example.COM ", "alice.b+cloud@example.com"),
            ("o'neil@mail.example.org", "o'neil@mail.example.org"),
            ("a@xn--fiqs8s.cn", "a@xn--fiqs8s.cn"),
            ("x@a-b.example", "x@a-b.example"),
        ] {
            assert_eq!(normalize_address(input).as_deref(), Some(stored), "{input}");
        }
        let long_local = format!("{}@example.com", "a".repeat(65));
        let long = format!("a@{}.com", vec!["b".repeat(63); 4].join("."));
        for invalid in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "alice@localhost",
            "alice@example",
            "alice@192.0.2.1",
            "alice@[192.0.2.1]",
            "al ice@example.com",
            "alice@exa mple.com",
            "a@b@example.com",
            ".alice@example.com",
            "alice.@example.com",
            "al..ice@example.com",
            "alice@-example.com",
            "alice@example..com",
            "\"alice\"@example.com",
            "alice@example.com.",
            "álice@example.com",
            "alice@exämple.com",
            "alice\n@example.com",
            "<alice@example.com>",
            &long_local,
            &long,
        ] {
            assert_eq!(normalize_address(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn senders_have_an_address_and_an_optional_name() {
        let mailbox = |name: Option<&str>, address: &str| Mailbox {
            name: name.map(str::to_owned),
            address: address.to_owned(),
        };
        assert_eq!(
            parse_mailbox("cloud@example.com"),
            Ok(mailbox(None, "cloud@example.com"))
        );
        assert_eq!(
            parse_mailbox(" Gono Cloud <Cloud@Example.com> "),
            Ok(mailbox(Some("Gono Cloud"), "Cloud@Example.com"))
        );
        assert_eq!(
            parse_mailbox("\"Gono, Cloud\" <cloud@example.com>"),
            Ok(mailbox(Some("Gono, Cloud"), "cloud@example.com"))
        );
        assert_eq!(
            parse_mailbox("<cloud@example.com>"),
            Ok(mailbox(None, "cloud@example.com"))
        );
        for invalid in [
            "Gono Cloud",
            "a\"b <c@example.com>",
            "<c@example.com",
            "a <b>",
        ] {
            assert!(parse_mailbox(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn codes_are_six_digits() {
        assert_eq!(parse_code(" 012 345 ").as_deref(), Some("012345"));
        for invalid in ["", "12345", "1234567", "12345a", "١٢٣٤٥٦"] {
            assert_eq!(parse_code(invalid), None, "{invalid}");
        }
        assert_ne!(code_digest(1, "123456"), code_digest(2, "123456"));
        assert_ne!(code_digest(1, "123456"), code_digest(1, "123457"));
        let code = Code {
            id: 1,
            code: "987654".to_owned(),
            email: "a@example.com".to_owned(),
            expires_at: 0,
        };
        assert!(!format!("{code:?}").contains("987654"));
    }
}
