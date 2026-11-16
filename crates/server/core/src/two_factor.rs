//! Two-step verification of accounts (`two_factor` and `recovery_codes` tables),
//! `docs/connect-protocol.md` section 13.
//!
//! - **TOTP** (RFC 6238): HMAC-SHA-1, 6 digits, a 30-second step, the codes of the previous,
//!   current and next step accepted. A code of a step at or before the last accepted one is
//!   refused, so a code works once.
//! - **The secret** (20 random bytes) is sealed with the [`Key`] that lives outside the
//!   database directory, in the configuration directory ([`crate::sealing`], purpose
//!   [`Purpose::Totp`]: the user id is part of the associated data). A copy of the database
//!   alone does not give the second factor away.
//! - **Recovery codes**: 10 codes of 16 Crockford base32 characters (80 bits), shown once,
//!   stored as SHA-256 digests, each usable once.
//! - **Failures** are counted per account from the audit log (`two_factor.failed`): after
//!   [`FAILURES_PER_WINDOW`] in [`FAILURE_WINDOW_SECS`] or [`FAILURES_PER_DAY`] in a day, the
//!   second step is locked until the window passes ([`locked`]).
//!
//! Remote access is available only on accounts that have it enrolled.

use std::{net::IpAddr, path::PathBuf};

use rand::RngExt as _;
use ring::hmac;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    audit::{self, Actor, Record},
    db::{self, Pool},
    error::{Error, Result},
    sealing::Purpose,
    secret,
    users::User,
};

/// Seconds per TOTP step.
pub const STEP_SECS: i64 = 30;

/// Bytes of a TOTP secret.
pub const SECRET_BYTES: usize = 20;

/// Recovery codes per account.
pub const RECOVERY_CODES: usize = 10;

/// Failed second steps per account within [`FAILURE_WINDOW_SECS`] before it locks.
pub const FAILURES_PER_WINDOW: i64 = 5;

/// The short window of failed second steps (15 minutes).
pub const FAILURE_WINDOW_SECS: i64 = 15 * 60;

/// Failed second steps per account within a day before it locks.
pub const FAILURES_PER_DAY: i64 = 20;

/// The issuer authenticator apps show.
pub const ISSUER: &str = "Gono Cloud";

/// Crockford's base32 alphabet, for recovery codes.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// RFC 4648 base32 alphabet, for the secret authenticator apps read.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The key TOTP secrets are sealed with ([`Purpose::Totp`]).
pub use crate::sealing::Key;

/// The default name of the key file, in the configuration directory.
pub fn default_key_file() -> PathBuf {
    PathBuf::from("two-factor.key")
}

/// A new TOTP secret.
pub fn new_secret() -> [u8; SECRET_BYTES] {
    rand::rng().random()
}

/// RFC 4648 base32 without padding, as authenticator apps read secrets.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// `text` in groups of four characters separated by spaces, for reading.
pub fn grouped(text: &str) -> String {
    text.as_bytes()
        .chunks(4)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The `otpauth://` URI of the QR code (Key Uri Format).
pub fn otpauth_uri(account: &str, secret: &[u8]) -> String {
    let encode = |text: &str| -> String {
        text.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        encode(ISSUER),
        encode(account),
        base32(secret),
        encode(ISSUER)
    )
}

/// The 6-digit code of `secret` at time step `step`.
pub fn code_at(secret: &[u8], step: i64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let digest = tag.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    value % 1_000_000
}

/// The time step of `now`.
pub fn step_of(now: i64) -> i64 {
    now.div_euclid(STEP_SECS)
}

/// The six digits of a typed code (spaces allowed), or `None`.
pub fn parse_code(input: &str) -> Option<u32> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    (digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// The step among the previous, current and next one of `now` whose code `code` is, if it is
/// later than `last_step`.
pub fn matching_step(secret: &[u8], code: u32, now: i64, last_step: i64) -> Option<i64> {
    let step = step_of(now);
    let mut found = None;
    for candidate in [step - 1, step, step + 1] {
        // Compare every candidate, so that the time spent does not tell which one matched.
        let matches = secret::constant_time_eq(
            &code_at(secret, candidate).to_be_bytes(),
            &code.to_be_bytes(),
        );
        if matches && candidate > last_step && found.is_none() {
            found = Some(candidate);
        }
    }
    found
}

/// A new recovery code, as shown: `XXXX-XXXX-XXXX-XXXX`.
fn new_recovery_code() -> String {
    let mut rng = rand::rng();
    let raw: String = (0..16)
        .map(|_| char::from(CROCKFORD[rng.random_range(0..32)]))
        .collect();
    raw.as_bytes()
        .chunks(4)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .collect::<Vec<_>>()
        .join("-")
}

/// The canonical form of a typed recovery code: 16 Crockford characters, upper case, without
/// separators, with the letters Crockford reads as digits (`O`, `I`, `L`) mapped. `None` if
/// it is not one.
pub fn normalize_recovery_code(input: &str) -> Option<String> {
    let mut code = String::with_capacity(16);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) {
            return None;
        }
        code.push(c);
    }
    (code.len() == 16).then_some(code)
}

fn recovery_digest(code: &str) -> [u8; 32] {
    Sha256::digest(code.as_bytes()).into()
}

/// Whether account `user_id` has two-step verification enrolled.
pub async fn is_enrolled(pool: &Pool, user_id: i64) -> Result<bool> {
    let enrolled: Option<i64> = sqlx::query_scalar("SELECT 1 FROM two_factor WHERE user_id = ?1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(enrolled.is_some())
}

/// Whether any account has it enrolled.
pub async fn any_enrolled(pool: &Pool) -> Result<bool> {
    let any: Option<i64> = sqlx::query_scalar("SELECT 1 FROM two_factor LIMIT 1")
        .fetch_optional(pool)
        .await?;
    Ok(any.is_some())
}

/// What the account page shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// When it was turned on.
    pub enabled_at: i64,
    /// Recovery codes not used yet.
    pub recovery_codes_left: i64,
}

/// The two-step verification of `user_id`, if enrolled.
pub async fn status(pool: &Pool, user_id: i64) -> Result<Option<Status>> {
    let enabled_at: Option<i64> =
        sqlx::query_scalar("SELECT enabled_at FROM two_factor WHERE user_id = ?1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    let Some(enabled_at) = enabled_at else {
        return Ok(None);
    };
    let left: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(Some(Status {
        enabled_at,
        recovery_codes_left: left,
    }))
}

/// Replaces the recovery codes of `user_id` inside `tx` and returns the new ones.
async fn replace_recovery_codes(tx: &mut db::Tx, user_id: i64) -> Result<Vec<String>> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    for code in &codes {
        let canonical = normalize_recovery_code(code).unwrap_or_default();
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)")
            .bind(user_id)
            .bind(&recovery_digest(&canonical)[..])
            .execute(&mut **tx)
            .await?;
    }
    Ok(codes)
}

/// Turns two-step verification on for `user_id` with `secret`, whose code of `step` the user
/// just entered (so that code cannot be used again), and returns the new recovery codes.
/// Fails with [`Error::TwoFactorEnrolled`] if it is on already.
///
/// Every browser session of the account except `keep_session` (the one that enrolled) ends
/// in the same transaction: a session opened with the password alone before must not keep
/// what only a second step gives from now on.
#[allow(clippy::too_many_arguments)]
pub async fn enable(
    pool: &Pool,
    key: &Key,
    user_id: i64,
    secret: &[u8],
    step: i64,
    keep_session: Option<i64>,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Vec<String>> {
    let mut tx = db::begin_immediate(pool).await?;
    let inserted = sqlx::query(
        "INSERT INTO two_factor (user_id, secret, last_step, enabled_at) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(key.seal(Purpose::Totp, user_id, secret))
    .bind(step)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(Error::TwoFactorEnrolled);
    }
    sqlx::query("DELETE FROM web_sessions WHERE user_id = ?1 AND id IS NOT ?2")
        .bind(user_id)
        .bind(keep_session)
        .execute(&mut *tx)
        .await?;
    let codes = replace_recovery_codes(&mut tx, user_id).await?;
    audit::record(
        &mut *tx,
        &Record::new(user_id, "two_factor.enabled", Actor::User).client_ip(client_ip),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(codes)
}

/// The account a sign-in waiting for its second step continues with, looked up by its id
/// (the name may have been given to another account since): `None` if it was deleted. The
/// caller checks that it is still enabled and unchanged.
pub async fn sign_in_account(pool: &Pool, user_id: i64) -> Result<Option<User>> {
    Ok(sqlx::query_as(
        "SELECT id, username, display_name, enabled, is_admin, created_at, updated_at \
         FROM users WHERE id = ?1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

/// The recent uses of recovery codes of `user_id`, newest first: when, and from which client
/// address (`docs/connect-protocol.md`, 13.4).
pub async fn recovery_code_uses(
    pool: &Pool,
    user_id: i64,
    since: i64,
    limit: i64,
) -> Result<Vec<(i64, Option<String>)>> {
    Ok(sqlx::query_as(
        "SELECT at, client_ip FROM audit_log \
         WHERE user_id = ?1 AND kind = 'recovery_code.used' AND at > ?2 \
         ORDER BY id DESC LIMIT ?3",
    )
    .bind(user_id)
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

/// Replaces the recovery codes of `user_id` and returns the new ones.
pub async fn renew_recovery_codes(
    pool: &Pool,
    user_id: i64,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Vec<String>> {
    let mut tx = db::begin_immediate(pool).await?;
    let codes = replace_recovery_codes(&mut tx, user_id).await?;
    audit::record(
        &mut *tx,
        &Record::new(user_id, "recovery_codes.renewed", Actor::User).client_ip(client_ip),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(codes)
}

/// Who turned it off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnedOff {
    /// The user, with the password and a code.
    User,
    /// An admin, in the admin UI.
    Admin,
    /// The operator, with `gono-cloud user reset-two-factor`.
    Cli,
}

/// Turns two-step verification off for `user_id`. Returns `false` if it was not on.
pub async fn disable(
    pool: &Pool,
    user_id: i64,
    by: TurnedOff,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let removed = sqlx::query("DELETE FROM two_factor WHERE user_id = ?1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if removed {
        let (kind, actor) = match by {
            TurnedOff::User => ("two_factor.disabled", Actor::User),
            TurnedOff::Admin => ("two_factor.reset", Actor::Admin),
            TurnedOff::Cli => ("two_factor.reset", Actor::Cli),
        };
        audit::record(
            &mut *tx,
            &Record::new(user_id, kind, actor).client_ip(client_ip),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(removed)
}

/// The outcome of [`verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// A TOTP code of a step not used before.
    Code,
    /// An unused recovery code, now used; how many are left.
    RecoveryCode {
        /// Codes still unused.
        left: i64,
    },
    /// Neither.
    Wrong,
    /// The account has no two-step verification.
    NotEnrolled,
    /// The stored secret does not open with this key: the key file changed.
    WrongKey,
}

/// Checks `input`, a TOTP code or a recovery code, for account `user_id` at `now`, and uses it
/// up if it is right; the use of a recovery code is recorded with `client_ip`. A failure is
/// not recorded here; see [`record_failure`].
pub async fn verify(
    pool: &Pool,
    key: &Key,
    user_id: i64,
    input: &str,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Verification> {
    let row: Option<(Vec<u8>, i64)> =
        sqlx::query_as("SELECT secret, last_step FROM two_factor WHERE user_id = ?1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    let Some((sealed, last_step)) = row else {
        return Ok(Verification::NotEnrolled);
    };
    if let Some(code) = parse_code(input) {
        let Some(secret) = key.open(Purpose::Totp, user_id, &sealed) else {
            return Ok(Verification::WrongKey);
        };
        let Some(step) = matching_step(&secret, code, now, last_step) else {
            return Ok(Verification::Wrong);
        };
        let mut tx = db::begin_immediate(pool).await?;
        // Only one request can move the step past `step - 1`: a code works once.
        let used = sqlx::query(
            "UPDATE two_factor SET last_step = ?2 WHERE user_id = ?1 AND last_step < ?2",
        )
        .bind(user_id)
        .bind(step)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        tx.commit().await?;
        return Ok(if used {
            Verification::Code
        } else {
            Verification::Wrong
        });
    }
    if let Some(code) = normalize_recovery_code(input) {
        let mut tx = db::begin_immediate(pool).await?;
        let used = sqlx::query(
            "UPDATE recovery_codes SET used_at = ?3 \
             WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
        )
        .bind(user_id)
        .bind(&recovery_digest(&code)[..])
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if !used {
            tx.commit().await?;
            return Ok(Verification::Wrong);
        }
        audit::record(
            &mut *tx,
            &Record::new(user_id, "recovery_code.used", Actor::User).client_ip(client_ip),
            now,
        )
        .await?;
        let left: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(Verification::RecoveryCode { left });
    }
    Ok(Verification::Wrong)
}

/// Whether the second step of `user_id` is locked at `now` by too many failures.
pub async fn locked(pool: &Pool, user_id: i64, now: i64) -> Result<bool> {
    let (window, day): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(at > ?2), 0), COUNT(*) FROM audit_log \
         WHERE user_id = ?1 AND kind = 'two_factor.failed' AND at > ?3",
    )
    .bind(user_id)
    .bind(now - FAILURE_WINDOW_SECS)
    .bind(now - 24 * 60 * 60)
    .fetch_one(pool)
    .await?;
    Ok(window >= FAILURES_PER_WINDOW || day >= FAILURES_PER_DAY)
}

/// Records a failed second step of `user_id` from `client_ip`, and the lock it causes.
pub async fn record_failure(
    pool: &Pool,
    user_id: i64,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<()> {
    audit::record(
        pool,
        &Record::new(user_id, "two_factor.failed", Actor::User).client_ip(client_ip),
        now,
    )
    .await?;
    if locked(pool, user_id, now).await? {
        audit::record(
            pool,
            &Record::new(user_id, "two_factor.locked", Actor::Server)
                .client_ip(client_ip)
                .details(json!({
                    "per_window": FAILURES_PER_WINDOW,
                    "window_secs": FAILURE_WINDOW_SECS,
                    "per_day": FAILURES_PER_DAY,
                })),
            now,
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_the_rfc_6238_test_vectors() {
        // RFC 6238, appendix B: the SHA-1 secret "12345678901234567890", 8 digits there; the
        // last six digits are the 6-digit codes.
        let secret = b"12345678901234567890";
        for (time, eight) in [
            (59_i64, 94_287_082_u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
        ] {
            assert_eq!(code_at(secret, step_of(time)), eight % 1_000_000, "{time}");
        }
    }

    #[test]
    fn codes_of_neighbouring_steps_are_accepted_once() {
        let secret = new_secret();
        let now = 1_763_200_000;
        let step = step_of(now);
        let code = code_at(&secret, step - 1);
        assert_eq!(matching_step(&secret, code, now, 0), Some(step - 1));
        assert_eq!(matching_step(&secret, code, now, step - 1), None, "used");
        assert_eq!(
            matching_step(&secret, code_at(&secret, step - 2), now, 0),
            None
        );
        assert_eq!(parse_code("123 456"), Some(123_456));
        assert_eq!(parse_code("12345"), None);
        assert_eq!(parse_code("abcdef"), None);
    }

    #[test]
    fn base32_and_uris() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(&[0; 20]).len(), 32);
        assert_eq!(grouped("ABCDEFGHIJ"), "ABCD EFGH IJ");
        let uri = otpauth_uri("kim@example", &[0; 20]);
        assert!(
            uri.starts_with("otpauth://totp/Gono%20Cloud:kim%40example?secret="),
            "{uri}"
        );
        assert!(uri.ends_with("&issuer=Gono%20Cloud&algorithm=SHA1&digits=6&period=30"));
    }

    #[test]
    fn recovery_codes_are_80_bits_of_crockford_base32() {
        let code = new_recovery_code();
        assert_eq!(code.len(), 19);
        let canonical = normalize_recovery_code(&code).unwrap();
        assert_eq!(canonical.len(), 16);
        assert_eq!(
            normalize_recovery_code(&code.to_ascii_lowercase()),
            Some(canonical.clone())
        );
        assert_eq!(
            normalize_recovery_code("o1il-0000-0000-0000").as_deref(),
            Some("0111000000000000")
        );
        assert!(
            normalize_recovery_code("UUUU-0000-0000-0000").is_none(),
            "U is not Crockford"
        );
        assert!(normalize_recovery_code("0000-0000-0000").is_none());
    }
}
