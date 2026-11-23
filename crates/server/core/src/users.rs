//! User account storage.
//!
//! Every write is one `BEGIN IMMEDIATE` transaction. Creating an account also creates its
//! storage directories (see [`crate::storage`]); the directories are created before the
//! transaction commits, so a failure leaves neither a half-created account nor an orphaned
//! database row behind.
//!
//! **At least one enabled admin remains.** [`delete`], [`set_enabled`] and [`set_admin`] refuse
//! to remove, disable or demote the last enabled admin account ([`Error::LastAdmin`]). The check
//! runs inside the same `BEGIN IMMEDIATE` transaction as the change, so two admins disabling or
//! demoting each other at the same moment cannot both succeed.

use sqlx::FromRow;

use crate::{
    audit::{self, Actor, Record},
    db::{self, Flag, Pool, Text},
    error::{Error, Result},
    services::Services,
    types::Username,
};

/// Maximum length of a display name, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 255;

/// Validates a display name, defaulting to the username when none is given.
pub fn display_name_or_default(display_name: Option<&str>, username: &Username) -> Result<String> {
    match display_name {
        Some(display_name) => validate_display_name(display_name),
        None => Ok(username.as_str().to_owned()),
    }
}

/// Validates a display name and returns it without surrounding whitespace: it must not be
/// empty, must be at most [`MAX_DISPLAY_NAME_CHARS`] characters long and must not contain
/// control characters.
pub fn validate_display_name(display_name: &str) -> Result<String> {
    let display_name = display_name.trim();
    if display_name.is_empty() {
        return Err(Error::InvalidDisplayName("must not be empty"));
    }
    if display_name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(Error::InvalidDisplayName(
            "must be at most 255 characters long",
        ));
    }
    if display_name.chars().any(char::is_control) {
        return Err(Error::InvalidDisplayName(
            "must not contain control characters",
        ));
    }
    Ok(display_name.to_owned())
}

/// How an account came to be (`users.created_via`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CreatedVia {
    /// An administrator made it in the admin UI.
    Admin,
    /// The operator made it with the command line (`user add`, and `init` for the first admin).
    Cli,
    /// Its user signed up with WeChat, in the mini program.
    WeChat,
    /// Its user signed up with Google.
    Google,
    /// Its user signed up with GitHub.
    GitHub,
}

impl CreatedVia {
    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Cli => "cli",
            Self::WeChat => "wechat",
            Self::Google => "google",
            Self::GitHub => "github",
        }
    }

    /// The value of its stored form.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "admin" => Self::Admin,
            "cli" => Self::Cli,
            "wechat" => Self::WeChat,
            "google" => Self::Google,
            "github" => Self::GitHub,
            _ => return None,
        })
    }

    /// Whether its user made it, by signing up with a third-party identity.
    pub fn is_self_service(self) -> bool {
        matches!(self, Self::WeChat | Self::Google | Self::GitHub)
    }
}

impl TryFrom<Text> for CreatedVia {
    type Error = Error;

    fn try_from(value: Text) -> Result<Self> {
        Self::parse(&value.0).ok_or_else(|| {
            Error::Database(sqlx::Error::Decode(
                format!("unknown users.created_via {:?}", value.0).into(),
            ))
        })
    }
}

/// A user account as stored, without its password hash.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct User {
    /// Numeric id; also names the user's storage directories.
    pub id: i64,
    /// Login name.
    #[sqlx(try_from = "Text")]
    pub username: Username,
    /// Name shown in clients.
    pub display_name: String,
    /// Whether the account may sign in.
    #[sqlx(try_from = "Flag")]
    pub enabled: bool,
    /// Whether the account may use the web admin UI.
    #[sqlx(try_from = "Flag")]
    pub is_admin: bool,
    /// Creation time, UNIX seconds.
    pub created_at: i64,
    /// Last change, UNIX seconds.
    pub updated_at: i64,
    /// Whether it has a web login password. An account without one signs in with its
    /// third-party identities only ([`crate::identities`]).
    #[sqlx(try_from = "Flag")]
    pub has_password: bool,
    /// How it came to be.
    #[sqlx(try_from = "Text")]
    pub created_via: CreatedVia,
    /// When the server deletes it, if it asked for its deletion; it is disabled until then.
    pub deleting_at: Option<i64>,
    /// The services it may use.
    #[sqlx(flatten)]
    pub services: Services,
}

impl TryFrom<String> for Username {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<Text> for Username {
    type Error = Error;

    fn try_from(value: Text) -> Result<Self> {
        Self::new(value.0)
    }
}

/// Input of [`create`]: an account that a person makes, with a web login password. Accounts
/// that their users make by signing up with a third-party identity have none.
#[derive(Debug, Clone)]
pub struct NewUser<'a> {
    /// Login name.
    pub username: &'a Username,
    /// Validated display name (see [`display_name_or_default`]).
    pub display_name: &'a str,
    /// Argon2id PHC string of the web login password.
    pub password_hash: &'a str,
    /// Grant access to the web admin UI.
    pub is_admin: bool,
    /// The services it may use from the start. Accounts created by people (the CLI, the admin
    /// UI, `init`) start with [`Services::NONE`]; tests set what they exercise.
    pub services: Services,
}

/// The columns of [`User`]; the last ones are [`crate::services::COLUMNS`].
pub(crate) const USER_COLUMNS: &str = "id, username, display_name, enabled, is_admin, created_at, updated_at, \
                            (password_hash IS NOT NULL) AS has_password, created_via, deleting_at, \
                            service_files, service_webdav, service_s3, service_direct, service_relay";

/// Returns the number of user accounts.
pub async fn count(pool: &Pool) -> Result<i64> {
    let count = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Creates the first account of a fresh installation as an enabled admin.
///
/// `password_hash` is the PHC string from [`crate::password::hash`]. Fails with
/// [`Error::AlreadyInitialized`] if any account exists, so running `init` twice cannot create a
/// second admin behind the operator's back. The check and the insert share one
/// `BEGIN IMMEDIATE` transaction.
pub async fn create_initial_admin(
    pool: &Pool,
    username: &Username,
    display_name: &str,
    password_hash: &str,
) -> Result<i64> {
    let mut tx = db::begin_immediate(pool).await?;

    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;
    if existing > 0 {
        return Err(Error::AlreadyInitialized);
    }

    let id = insert(
        &mut tx,
        &NewUser {
            username,
            display_name,
            password_hash,
            is_admin: true,
            services: Services::NONE,
        },
        CreatedVia::Cli,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Creates an enabled account in the admin UI and returns its id (see [`create_via`]).
pub async fn create(
    pool: &Pool,
    user: &NewUser<'_>,
    prepare_storage: impl FnOnce(i64) -> Result<()>,
) -> Result<i64> {
    create_via(pool, user, CreatedVia::Admin, prepare_storage).await
}

/// Creates an enabled account made through `via` (the admin UI or the command line) and
/// returns its id.
///
/// `prepare_storage` runs with the new id after the insert but before the commit; if it fails,
/// the account is not created. Use it to create the storage directories.
pub async fn create_via(
    pool: &Pool,
    user: &NewUser<'_>,
    via: CreatedVia,
    prepare_storage: impl FnOnce(i64) -> Result<()>,
) -> Result<i64> {
    let mut tx = db::begin_immediate(pool).await?;
    let id = insert(&mut tx, user, via).await?;
    prepare_storage(id)?;
    tx.commit().await?;
    Ok(id)
}

async fn insert(tx: &mut db::Tx, user: &NewUser<'_>, via: CreatedVia) -> Result<i64> {
    insert_account(
        tx,
        user.username,
        user.display_name,
        Some(user.password_hash),
        user.is_admin,
        user.services,
        via,
    )
    .await
}

/// Inserts an enabled account inside `tx` and returns its id: [`Error::UsernameRetired`] for a
/// retired name, [`Error::UserExists`] for a name in use.
pub(crate) async fn insert_account(
    tx: &mut db::Tx,
    username: &Username,
    display_name: &str,
    password_hash: Option<&str>,
    is_admin: bool,
    services: Services,
    via: CreatedVia,
) -> Result<i64> {
    let now = db::unix_now();
    let retired: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM retired_usernames WHERE username = ?")
            .bind(username.as_str())
            .fetch_optional(&mut **tx)
            .await?;
    if retired.is_some() {
        return Err(Error::UsernameRetired(username.clone()));
    }
    let id = db::next_id(tx, "users").await?;
    let services = services.normalized();
    sqlx::query(
        "INSERT INTO users (id, username, display_name, password_hash, enabled, is_admin, \
         created_at, updated_at, created_via, service_files, service_webdav, service_s3, \
         service_direct, service_relay) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(username.as_str())
    .bind(display_name)
    .bind(password_hash)
    .bind(is_admin)
    .bind(now)
    .bind(now)
    .bind(via.as_str())
    .bind(services.files)
    .bind(services.webdav)
    .bind(services.s3)
    .bind(services.direct)
    .bind(services.relay)
    .execute(&mut **tx)
    .await
    .map_err(|err| match err.as_database_error() {
        Some(db_err) if db_err.is_unique_violation() => Error::UserExists(username.clone()),
        _ => Error::Database(err),
    })?;
    Ok(id)
}

/// Returns every account, ordered by username.
pub async fn list(pool: &Pool) -> Result<Vec<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users ORDER BY username");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await?)
}

/// Looks an account up by name.
pub async fn find(pool: &Pool, username: &Username) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(username.as_str())
        .fetch_optional(pool)
        .await?)
}

#[derive(FromRow)]
struct CredentialsRow {
    #[sqlx(flatten)]
    user: User,
    password_hash: Option<String>,
}

/// Looks an account up by name together with its web login password hash, for signing in:
/// `None` for an account without a password. Verify the password with
/// [`crate::password::verify`].
pub async fn credentials(
    pool: &Pool,
    username: &Username,
) -> Result<Option<(User, Option<String>)>> {
    let sql = format!("SELECT {USER_COLUMNS}, password_hash FROM users WHERE username = ?");
    let row: Option<CredentialsRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(username.as_str())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| (row.user, row.password_hash)))
}

/// Like [`find`], but a missing account is [`Error::UserNotFound`].
pub async fn get(pool: &Pool, username: &Username) -> Result<User> {
    find(pool, username)
        .await?
        .ok_or_else(|| Error::UserNotFound(username.clone()))
}

/// Fails with [`Error::LastAdmin`] if `username` is an enabled admin and no other enabled
/// admin exists. Runs inside the caller's write transaction.
async fn keep_an_admin(tx: &mut db::Tx, username: &Username) -> Result<()> {
    let others: Option<i64> = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM users WHERE is_admin = 1 AND enabled = 1 \
         AND username <> ?) FROM users WHERE username = ? AND is_admin = 1 AND enabled = 1",
    )
    .bind(username.as_str())
    .bind(username.as_str())
    .fetch_optional(&mut **tx)
    .await?;
    match others {
        Some(0) => Err(Error::LastAdmin(username.clone())),
        _ => Ok(()),
    }
}

/// Deletes an account. App passwords, sessions, file metadata, locks and devices go with it
/// through `ON DELETE CASCADE`; the storage directories are left to the caller. Revoked keys
/// stay in `revoked_keys`, and the name of an account that registered devices is retired: it
/// is never given to another account (protocol 9.1). The last enabled admin cannot be deleted.
pub async fn delete(pool: &Pool, username: &Username) -> Result<User> {
    let mut tx = db::begin_immediate(pool).await?;
    keep_an_admin(&mut tx, username).await?;
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?");
    let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(username.as_str())
        .fetch_optional(&mut *tx)
        .await?;
    let user = user.ok_or_else(|| Error::UserNotFound(username.clone()))?;
    sqlx::query(tx.backend().pick(
        "INSERT OR IGNORE INTO retired_usernames (username, retired_at) \
         SELECT username, ? FROM users WHERE id = ? \
         AND EXISTS (SELECT 1 FROM devices WHERE devices.user_id = users.id)",
        "INSERT INTO retired_usernames (username, retired_at) \
         SELECT username, ? FROM users WHERE id = ? \
         AND EXISTS (SELECT 1 FROM devices WHERE devices.user_id = users.id) \
         ON DUPLICATE KEY UPDATE retired_usernames.username = retired_usernames.username",
    ))
    .bind(db::unix_now())
    .bind(user.id)
    .execute(&mut *tx)
    .await?;
    // The devices go first: their credentials are app passwords that the account's deletion
    // removes as well, and InnoDB checks the devices' reference to them row by row, where
    // SQLite checks it at the end of the statement.
    sqlx::query("DELETE FROM devices WHERE user_id = ?")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(user)
}

/// Replaces the web login password hash of an account, or gives it its first one. The first
/// password of an account that had none is recorded as `password.set`, by `actor`.
pub async fn set_password_hash(
    pool: &Pool,
    username: &Username,
    password_hash: &str,
    actor: Actor,
) -> Result<()> {
    let mut tx = db::begin_immediate(pool).await?;
    let row: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE username = ?")
            .bind(username.as_str())
            .fetch_optional(&mut *tx)
            .await?;
    let Some((user_id, previous)) = row else {
        return Err(Error::UserNotFound(username.clone()));
    };
    let now = db::unix_now();
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(password_hash)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if previous.is_none() {
        audit::record_in(&mut tx, &Record::new(user_id, "password.set", actor), now).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Gives account `user_id`, which has no web login password, its first one, and records
/// `password.set` by its user. Returns `false` if the account has a password already or does
/// not exist (then nothing changed): setting the first one needs no current password, so it
/// never replaces one.
pub async fn set_first_password(
    pool: &Pool,
    user_id: i64,
    password_hash: &str,
    client_ip: Option<std::net::IpAddr>,
    now: i64,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let set = sqlx::query(
        "UPDATE users SET password_hash = ?, updated_at = ? \
         WHERE id = ? AND password_hash IS NULL",
    )
    .bind(password_hash)
    .bind(now)
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if set {
        audit::record_in(
            &mut tx,
            &Record::new(user_id, "password.set", Actor::User).client_ip(client_ip),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(set)
}

/// Enables or disables an account. A disabled account cannot sign in with any credential, and
/// disabling it ends its WeChat mini program sessions ([`crate::wechat`]), which enabling it
/// again does not bring back. The last enabled admin cannot be disabled.
pub async fn set_enabled(pool: &Pool, username: &Username, enabled: bool) -> Result<()> {
    let mut tx = db::begin_immediate(pool).await?;
    if !enabled {
        keep_an_admin(&mut tx, username).await?;
    }
    // Enabling an account also undoes a deletion it waits for: a disabled account is what
    // waiting for one means.
    let result = sqlx::query(
        "UPDATE users SET enabled = ?, updated_at = ?,          deleting_at = CASE WHEN ? = 1 THEN NULL ELSE deleting_at END WHERE username = ?",
    )
    .bind(enabled)
    .bind(db::unix_now())
    .bind(enabled)
    .bind(username.as_str())
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Err(Error::UserNotFound(username.clone()));
    }
    if !enabled {
        sqlx::query(
            "DELETE FROM mp_sessions WHERE identity_id IN (SELECT i.id FROM external_identities i \
             JOIN users u ON u.id = i.user_id WHERE u.username = ?)",
        )
        .bind(username.as_str())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The account with id `user_id`, if it exists.
pub async fn by_id(pool: &Pool, user_id: i64) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(user_id)
        .fetch_optional(pool)
        .await?)
}

/// Sets the services account `username` may use, and returns them as stored: the relay needs
/// direct connections, so [`Services::normalized`] turns those on with it.
///
/// `updated_at` stays as it is: the services are not credentials, so a sign-in waiting for its
/// second step (which ends when `updated_at` changes) is not affected.
pub async fn set_services(
    pool: &Pool,
    username: &Username,
    services: Services,
) -> Result<Services> {
    let services = services.normalized();
    let mut tx = db::begin_immediate(pool).await?;
    let result = sqlx::query(
        "UPDATE users SET service_files = ?, service_webdav = ?, service_s3 = ?, \
         service_direct = ?, service_relay = ? WHERE username = ?",
    )
    .bind(services.files)
    .bind(services.webdav)
    .bind(services.s3)
    .bind(services.direct)
    .bind(services.relay)
    .bind(username.as_str())
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Err(Error::UserNotFound(username.clone()));
    }
    tx.commit().await?;
    Ok(services)
}

/// Grants or withdraws access to the web admin UI. The last enabled admin cannot be demoted.
/// Granting the flag to an admin, or withdrawing it from an ordinary account, changes nothing
/// and succeeds.
///
/// The admin UI checks the flag on every request, so a demoted admin loses access at once; their
/// browser sessions stay valid for the Login Flow pages.
pub async fn set_admin(pool: &Pool, username: &Username, is_admin: bool) -> Result<()> {
    let mut tx = db::begin_immediate(pool).await?;
    if !is_admin {
        keep_an_admin(&mut tx, username).await?;
    }
    let result = sqlx::query("UPDATE users SET is_admin = ?, updated_at = ? WHERE username = ?")
        .bind(is_admin)
        .bind(db::unix_now())
        .bind(username.as_str())
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() == 0 {
        return Err(Error::UserNotFound(username.clone()));
    }
    tx.commit().await?;
    Ok(())
}

/// Changes the display name of an account and returns the name as stored (validated with
/// [`validate_display_name`], so without surrounding whitespace).
pub async fn set_display_name(
    pool: &Pool,
    username: &Username,
    display_name: &str,
) -> Result<String> {
    let display_name = validate_display_name(display_name)?;
    let mut tx = db::begin_immediate(pool).await?;
    let result =
        sqlx::query("UPDATE users SET display_name = ?, updated_at = ? WHERE username = ?")
            .bind(&display_name)
            .bind(db::unix_now())
            .bind(username.as_str())
            .execute(&mut *tx)
            .await?;
    if result.rows_affected() == 0 {
        return Err(Error::UserNotFound(username.clone()));
    }
    tx.commit().await?;
    Ok(display_name)
}

// ---------------------------------------------------------------------------------------------
// Self-service accounts: sign-up, renaming and deletion with a cooling-off period
// (`plan/third-party-sign-in-design.md`, 4.5 and 4.6)
// ---------------------------------------------------------------------------------------------

/// Random characters of a generated username, after its provider's prefix.
pub const GENERATED_CHARS: usize = 8;

/// How long an account waits for its deletion after asking for it, in seconds (7 days).
pub const DELETION_DELAY_SECS: i64 = 7 * 24 * 60 * 60;

/// How often an account may change its username, in seconds (once a day).
pub const RENAME_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// Accounts one client network may sign up for in a day.
pub const SIGNUPS_PER_NET_PER_DAY: usize = 5;

/// Accounts the whole server takes by sign-up in a day.
pub const SIGNUPS_PER_DAY: i64 = 200;

/// The prefix of the usernames generated for sign-ups with `via`: `wx`, `gg`, `gh`.
fn prefix(via: CreatedVia) -> &'static str {
    match via {
        CreatedVia::WeChat => "wx",
        CreatedVia::Google => "gg",
        CreatedVia::GitHub => "gh",
        CreatedVia::Admin | CreatedVia::Cli => "u",
    }
}

/// A generated username for a sign-up with `via`: its prefix and [`GENERATED_CHARS`] random
/// lower-case letters and digits.
pub fn generated_username(via: CreatedVia) -> Username {
    use rand::RngExt as _;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    let tail: String = (0..GENERATED_CHARS)
        .map(|_| char::from(CHARS[rng.random_range(0..CHARS.len())]))
        .collect();
    Username::new(format!("{}{tail}", prefix(via))).expect("a valid username")
}

/// Outcome of [`sign_up`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedUp {
    /// The account, enabled, with no service and no password, and its identity.
    Created(Box<User>, crate::identities::Identity),
    /// The username is taken or retired.
    UsernameTaken,
    /// The identity is bound to an account already.
    AlreadyBound,
    /// The daily cap of the client's network or of the server is reached.
    Limited,
}

/// Creates the account of a sign-up with the identity of `claims`: `username`, `display_name`,
/// no web login password, no service (every account starts with none), created via the
/// identity's provider. Binds the identity to it (`how: "signup"`) and records
/// `account.created` with `via`, in one transaction. `client_net` is the network of the client
/// (`crate::email::client_net`), for the daily caps; `terms` the version of the terms the user
/// accepted, if the server has terms. `prepare_storage` runs with the new id before the commit.
#[allow(clippy::too_many_arguments)]
pub async fn sign_up(
    pool: &Pool,
    claims: &crate::identities::Claims,
    username: &Username,
    display_name: &str,
    terms: Option<&str>,
    client_ip: Option<std::net::IpAddr>,
    now: i64,
    prepare_storage: impl FnOnce(i64) -> Result<()>,
) -> Result<SignedUp> {
    let display_name = validate_display_name(display_name)?;
    let via = claims.provider.created_via();
    let mut tx = db::begin_immediate(pool).await?;
    // The caps: per day for the server, and per client network.
    let since = now - 24 * 60 * 60;
    let recent: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT client_ip FROM audit_log WHERE kind = 'account.created' AND at > ? \
         ORDER BY id DESC LIMIT ?",
    )
    .bind(since)
    .bind(SIGNUPS_PER_DAY)
    .fetch_all(&mut *tx)
    .await?;
    if i64::try_from(recent.len()).unwrap_or(i64::MAX) >= SIGNUPS_PER_DAY {
        return Ok(SignedUp::Limited);
    }
    if let Some(ip) = client_ip {
        let net = crate::email::client_net(ip);
        let same = recent
            .iter()
            .flatten()
            .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
            .filter(|ip| crate::email::client_net(*ip) == net)
            .count();
        if same >= SIGNUPS_PER_NET_PER_DAY {
            return Ok(SignedUp::Limited);
        }
    }
    if crate::identities::find_in(&mut tx, claims.provider, &claims.realm, &claims.subject)
        .await?
        .is_some()
    {
        return Ok(SignedUp::AlreadyBound);
    }
    let id = match insert_account(
        &mut tx,
        username,
        &display_name,
        None,
        false,
        Services::NONE,
        via,
    )
    .await
    {
        Ok(id) => id,
        Err(Error::UserExists(_) | Error::UsernameRetired(_)) => {
            return Ok(SignedUp::UsernameTaken);
        }
        Err(err) => return Err(err),
    };
    let mut details = serde_json::json!({ "via": via.as_str() });
    if let Some(terms) = terms {
        details["terms"] = serde_json::Value::from(terms);
    }
    audit::record_in(
        &mut tx,
        &Record::new(id, "account.created", Actor::User)
            .client_ip(client_ip)
            .details(details),
        now,
    )
    .await?;
    let identity = match crate::identities::bind_in(
        &mut tx,
        id,
        claims,
        crate::identities::How::Signup,
        Actor::User,
        client_ip,
        now,
    )
    .await?
    {
        crate::identities::Bound::Bound(identity) => identity,
        _ => return Ok(SignedUp::AlreadyBound),
    };
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?");
    let user: User = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    prepare_storage(id)?;
    tx.commit().await?;
    Ok(SignedUp::Created(Box::new(user), identity))
}

/// Whether account `user_id` may still change its username: it was made by a sign-up, and
/// has no app password and never registered a device (devices' pairing statements name the
/// account by its username, protocol 8.3 and 8.4).
pub async fn can_rename(pool: &Pool, user_id: i64) -> Result<bool> {
    let row: Option<(Text, Flag)> = sqlx::query_as(
        "SELECT created_via, (EXISTS (SELECT 1 FROM app_passwords a WHERE a.user_id = users.id) \
         OR EXISTS (SELECT 1 FROM devices d WHERE d.user_id = users.id)) FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some_and(|(via, used)| {
        CreatedVia::parse(&via.0).is_some_and(CreatedVia::is_self_service) && !used.0
    }))
}

/// Outcome of [`rename`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Renamed {
    /// Renamed.
    Done,
    /// The new name is in use or retired (`username_taken`).
    Taken,
    /// The account may not change its username any more (`username_locked`): not made by a
    /// sign-up, or it has an app password or a device.
    Locked,
    /// It changed its username less than [`RENAME_INTERVAL_SECS`] ago.
    TooSoon,
}

/// Changes the username of account `user_id`, made by a sign-up and never used by a device
/// ([`can_rename`]), to `username`; at most once a day. Records `account.renamed`. The old
/// name is free again.
pub async fn rename(
    pool: &Pool,
    user_id: i64,
    username: &Username,
    actor: Actor,
    client_ip: Option<std::net::IpAddr>,
    now: i64,
) -> Result<Renamed> {
    let mut tx = db::begin_immediate(pool).await?;
    let row: Option<(Text, Text, Flag)> = sqlx::query_as(
        "SELECT username, created_via, (EXISTS (SELECT 1 FROM app_passwords a \
         WHERE a.user_id = users.id) OR EXISTS (SELECT 1 FROM devices d \
         WHERE d.user_id = users.id)) FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((old, via, used)) = row else {
        return Ok(Renamed::Locked);
    };
    if used.0 || !CreatedVia::parse(&via.0).is_some_and(CreatedVia::is_self_service) {
        return Ok(Renamed::Locked);
    }
    if old.0 == username.as_str() {
        return Ok(Renamed::Done);
    }
    let recent: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM audit_log WHERE user_id = ? AND kind = 'account.renamed' AND at > ? \
         LIMIT 1",
    )
    .bind(user_id)
    .bind(now - RENAME_INTERVAL_SECS)
    .fetch_optional(&mut *tx)
    .await?;
    if recent.is_some() {
        return Ok(Renamed::TooSoon);
    }
    let retired: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM retired_usernames WHERE username = ?")
            .bind(username.as_str())
            .fetch_optional(&mut *tx)
            .await?;
    if retired.is_some() {
        return Ok(Renamed::Taken);
    }
    let updated = sqlx::query("UPDATE users SET username = ?, updated_at = ? WHERE id = ?")
        .bind(username.as_str())
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
            return Ok(Renamed::Taken);
        }
        Err(err) => return Err(Error::Database(err)),
    }
    audit::record_in(
        &mut tx,
        &Record::new(user_id, "account.renamed", actor)
            .client_ip(client_ip)
            .details(serde_json::json!({ "from": old.0, "to": username.as_str() })),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Renamed::Done)
}

/// Asks for the deletion of account `user_id`, which has no web login password: it is
/// disabled at once (its mini program sessions end, its devices are refused; app passwords
/// stay) and deleted [`DELETION_DELAY_SECS`] from `now` unless the request is undone. Records
/// `account.deletion_requested` by `actor`. Returns when it will be deleted, or `None` if the
/// account has a password, waits already or is an admin (nothing changed).
pub async fn request_deletion(
    pool: &Pool,
    user_id: i64,
    actor: Actor,
    client_ip: Option<std::net::IpAddr>,
    now: i64,
) -> Result<Option<i64>> {
    let mut tx = db::begin_immediate(pool).await?;
    let until = now.saturating_add(DELETION_DELAY_SECS);
    let asked = sqlx::query(
        "UPDATE users SET enabled = 0, deleting_at = ?, updated_at = ? WHERE id = ? \
         AND password_hash IS NULL AND deleting_at IS NULL AND is_admin = 0",
    )
    .bind(until)
    .bind(now)
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !asked {
        return Ok(None);
    }
    sqlx::query(
        "DELETE FROM mp_sessions WHERE identity_id IN \
         (SELECT id FROM external_identities WHERE user_id = ?)",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM web_sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    audit::record_in(
        &mut tx,
        &Record::new(user_id, "account.deletion_requested", actor)
            .client_ip(client_ip)
            .details(serde_json::json!({ "at": until })),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(until))
}

/// Undoes the deletion request of account `user_id` before it is due: the account is enabled
/// again. Records `account.deletion_cancelled` by `actor`. Returns `false` if it waits for no
/// deletion, or the deletion is due (nothing changed).
pub async fn cancel_deletion(
    pool: &Pool,
    user_id: i64,
    actor: Actor,
    client_ip: Option<std::net::IpAddr>,
    now: i64,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let cancelled = sqlx::query(
        "UPDATE users SET enabled = 1, deleting_at = NULL, updated_at = ? WHERE id = ? \
         AND deleting_at IS NOT NULL AND deleting_at > ?",
    )
    .bind(now)
    .bind(user_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if cancelled {
        audit::record_in(
            &mut tx,
            &Record::new(user_id, "account.deletion_cancelled", actor).client_ip(client_ip),
            now,
        )
        .await?;
        tx.commit().await?;
    }
    Ok(cancelled)
}

/// The accounts whose deletion is due at `now`.
pub async fn due_deletions(pool: &Pool, now: i64) -> Result<Vec<User>> {
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM users WHERE deleting_at IS NOT NULL AND deleting_at <= ?"
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(now)
        .fetch_all(pool)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_defaults_to_username() {
        let username = Username::new("alice").unwrap();
        assert_eq!(display_name_or_default(None, &username).unwrap(), "alice");
        assert_eq!(
            display_name_or_default(Some("  Alice Example "), &username).unwrap(),
            "Alice Example"
        );
        assert!(display_name_or_default(Some("   "), &username).is_err());
        assert!(display_name_or_default(Some("a\u{7}b"), &username).is_err());
        assert!(display_name_or_default(Some(&"x".repeat(256)), &username).is_err());
    }

    #[test]
    fn user_columns_end_with_the_service_columns() {
        let columns: String = USER_COLUMNS.split_whitespace().collect();
        let services: String = crate::services::COLUMNS.split_whitespace().collect();
        assert!(columns.ends_with(&services), "{columns}");
    }
}
