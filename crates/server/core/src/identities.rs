//! Third-party identities of accounts (`external_identities`), and the identities that signed in
//! while bound to no account (`pending_identities`). See `plan/third-party-sign-in-design.md`.
//!
//! - **An identity** is a user of a [`Provider`] as `(provider, realm, subject)`: WeChat users
//!   by the AppID of the mini program and their openid for it, Google users by the `sub` of
//!   their ID tokens, GitHub users by their numeric id (never the login, which can be renamed
//!   and reused). It belongs to one account at most, and an account has one identity per
//!   provider and realm at most (two unique keys); changing one means unbinding it first.
//! - **Ways in.** An account signs in with its web login password, with any of its identities,
//!   or with both, and always keeps at least one of them: [`unbind`] refuses to take the last
//!   identity of an account without a password ([`Unbound::LastSignIn`]). Every identity row
//!   counts, also one of a realm the server no longer offers (a WeChat AppID changed since);
//!   an administrator can always set a password.
//! - **Pending identities** ([`create_pending`]) are what a provider reported about a user whose
//!   identity is bound to no account, kept for [`PENDING_TTL_SECS`] for the [`Holder`] of a
//!   random token of [`TOKEN_CHARS`]: the mini program (its signup token) or a browser (in a
//!   cookie). They become a binding or a new account, or expire. A new one of the same identity
//!   and holder ends the earlier ones; a token is found only by its own holder.
//! - **Audit.** Binding and unbinding record `identity.bound` and `identity.unbound` with the
//!   provider and [`How`] (and the AppID for WeChat), never the subject.
//!
//! Tokens are stored only as SHA-256 digests ([`secret::digest`]). Every write is one write
//! transaction, so the unique keys and the rule of the last way in hold under concurrent
//! requests.

use std::net::IpAddr;

use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;

use crate::{
    audit::{self, Actor, Record},
    db::{self, Flag, Pool, Text, Tx},
    error::{Error, Result},
    secret,
    users::{CreatedVia, User},
};

/// The realm of Google's identities: the issuer of its ID tokens.
pub const GOOGLE_REALM: &str = "https://accounts.google.com";

/// The realm of GitHub's identities.
pub const GITHUB_REALM: &str = "github.com";

/// How long a pending identity waits, in seconds.
pub const PENDING_TTL_SECS: i64 = 10 * 60;

/// Characters of the token of a pending identity: 43 of `[A-Za-z0-9]` are 256 random bits.
pub const TOKEN_CHARS: usize = 43;

/// The longest realm, in bytes.
pub const MAX_REALM_BYTES: usize = 64;

/// The longest subject, in bytes (OpenID Connect's limit of `sub`).
pub const MAX_SUBJECT_BYTES: usize = 255;

/// The longest label or name kept, in characters; longer ones are cut.
pub const MAX_LABEL_CHARS: usize = 255;

/// Whether `token` has the shape of the token of a pending identity.
pub fn is_token(token: &str) -> bool {
    token.len() == TOKEN_CHARS && token.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A provider of third-party sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Provider {
    /// WeChat, through the mini program of `[wechat]`.
    WeChat,
    /// Google (OpenID Connect).
    Google,
    /// GitHub (an OAuth app).
    GitHub,
}

impl Provider {
    /// Every provider, in the order pages list them.
    pub const ALL: [Self; 3] = [Self::WeChat, Self::Google, Self::GitHub];

    /// The stored form, also the provider's key in URLs and the configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeChat => "wechat",
            Self::Google => "google",
            Self::GitHub => "github",
        }
    }

    /// The provider of a stored form or key.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "wechat" => Self::WeChat,
            "google" => Self::Google,
            "github" => Self::GitHub,
            _ => return None,
        })
    }

    /// Its name as pages show it.
    pub fn name(self) -> &'static str {
        match self {
            Self::WeChat => "WeChat",
            Self::Google => "Google",
            Self::GitHub => "GitHub",
        }
    }

    /// What an account that its user signed up with it was created through.
    pub fn created_via(self) -> CreatedVia {
        match self {
            Self::WeChat => CreatedVia::WeChat,
            Self::Google => CreatedVia::Google,
            Self::GitHub => CreatedVia::GitHub,
        }
    }
}

impl TryFrom<Text> for Provider {
    type Error = Error;

    fn try_from(value: Text) -> Result<Self> {
        Self::parse(&value.0).ok_or_else(|| {
            Error::Database(sqlx::Error::Decode(
                format!("unknown provider {:?}", value.0).into(),
            ))
        })
    }
}

/// How an identity was bound or unbound, as the audit log records it (`how`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// By its user on the account page (or the sign-in page's confirmation after a password
    /// sign-in).
    AccountPage,
    /// By the WeChat mini program (a bind ticket of the account page, or unbinding there).
    MiniProgram,
    /// Automatically, because the provider's verified address is the account's.
    Email,
    /// With a new account its user signed up for.
    Signup,
    /// By an administrator in the admin UI.
    Admin,
    /// By the operator with the command line.
    Cli,
}

impl How {
    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountPage => "account_page",
            Self::MiniProgram => "mini_program",
            Self::Email => "email",
            Self::Signup => "signup",
            Self::Admin => "admin",
            Self::Cli => "cli",
        }
    }
}

/// An identity bound to an account. The subject is not part of it: nothing shows it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Identity {
    /// Row id.
    pub id: i64,
    /// The account.
    pub user_id: i64,
    /// The provider.
    #[sqlx(try_from = "Text")]
    pub provider: Provider,
    /// The realm: the AppID for WeChat.
    #[sqlx(try_from = "Text")]
    pub realm: String,
    /// What pages show of it ('' for WeChat).
    pub label: String,
    /// When it was bound, UNIX seconds.
    pub created_at: i64,
    /// When it last signed in.
    pub last_seen_at: i64,
}

/// What a provider reported about a user, from one sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// The provider.
    pub provider: Provider,
    /// The realm.
    pub realm: String,
    /// The subject: never shown, never logged.
    pub subject: String,
    /// WeChat's unionid, when WeChat reported one.
    pub unionid: Option<String>,
    /// What pages show of the identity ('' for WeChat).
    pub label: String,
    /// The address the provider reported, lower-cased.
    pub email: Option<String>,
    /// Whether the provider verified `email`.
    pub email_verified: bool,
    /// The user's name at the provider.
    pub name: Option<String>,
}

impl Claims {
    /// The claims of a WeChat user `openid` of AppID `app_id`: no label, address or name.
    pub fn wechat(app_id: &str, openid: &str, unionid: Option<&str>) -> Self {
        Self {
            provider: Provider::WeChat,
            realm: app_id.to_owned(),
            subject: openid.to_owned(),
            unionid: unionid.map(str::to_owned),
            label: String::new(),
            email: None,
            email_verified: false,
            name: None,
        }
    }

    /// Checks the lengths the schema holds, and cuts the label and the name to
    /// [`MAX_LABEL_CHARS`].
    fn checked(&self) -> Result<Self> {
        let invalid = |what: &str| {
            Error::Database(sqlx::Error::Protocol(format!(
                "a provider reported an invalid {what}"
            )))
        };
        if self.realm.is_empty() || self.realm.len() > MAX_REALM_BYTES {
            return Err(invalid("realm"));
        }
        if self.subject.is_empty() || self.subject.len() > MAX_SUBJECT_BYTES {
            return Err(invalid("subject"));
        }
        if self.provider != Provider::WeChat && self.unionid.is_some() {
            return Err(invalid("unionid"));
        }
        let cut = |text: &str| -> String {
            text.chars()
                .filter(|c| !c.is_control())
                .take(MAX_LABEL_CHARS)
                .collect()
        };
        let email = self
            .email
            .as_deref()
            .and_then(crate::email::normalize_address);
        Ok(Self {
            label: cut(&self.label),
            email_verified: self.email_verified && email.is_some(),
            email,
            name: self
                .name
                .as_deref()
                .map(cut)
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty()),
            ..self.clone()
        })
    }
}

const IDENTITY_COLUMNS: &str = "id, user_id, provider, realm, label, created_at, last_seen_at";

/// The identities bound to account `user_id`, in the order of [`Provider::ALL`] and then oldest
/// first.
pub async fn list(pool: &Pool, user_id: i64) -> Result<Vec<Identity>> {
    let sql = format!("SELECT {IDENTITY_COLUMNS} FROM external_identities WHERE user_id = ?");
    let mut identities: Vec<Identity> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    identities.sort_by_key(|identity| (identity.provider, identity.id));
    Ok(identities)
}

/// The identity of `provider` and `realm` bound to account `user_id`, if there is one.
pub async fn of_account(
    pool: &Pool,
    user_id: i64,
    provider: Provider,
    realm: &str,
) -> Result<Option<Identity>> {
    let sql = format!(
        "SELECT {IDENTITY_COLUMNS} FROM external_identities \
         WHERE user_id = ? AND provider = ? AND realm = ?"
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(user_id)
        .bind(provider.as_str())
        .bind(realm)
        .fetch_optional(pool)
        .await?)
}

/// The identity of `(provider, realm, subject)`, whichever account it is bound to, inside `tx`.
pub(crate) async fn find_in(
    tx: &mut Tx,
    provider: Provider,
    realm: &str,
    subject: &str,
) -> Result<Option<Identity>> {
    let sql = format!(
        "SELECT {IDENTITY_COLUMNS} FROM external_identities \
         WHERE provider = ? AND realm = ? AND subject = ?"
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(provider.as_str())
        .bind(realm)
        .bind(subject)
        .fetch_optional(&mut **tx)
        .await?)
}

/// The identity of `(provider, realm, subject)`, whichever account it is bound to.
pub async fn find(
    pool: &Pool,
    provider: Provider,
    realm: &str,
    subject: &str,
) -> Result<Option<Identity>> {
    let sql = format!(
        "SELECT {IDENTITY_COLUMNS} FROM external_identities \
         WHERE provider = ? AND realm = ? AND subject = ?"
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(provider.as_str())
        .bind(realm)
        .bind(subject)
        .fetch_optional(pool)
        .await?)
}

/// Records a sign-in with identity `id` inside `tx`: its `last_seen_at`, the label the
/// provider reports now (GitHub logins can be renamed), and WeChat's unionid once reported.
pub(crate) async fn touch_in(
    tx: &mut Tx,
    id: i64,
    label: Option<&str>,
    unionid: Option<&str>,
    now: i64,
) -> Result<()> {
    let label: Option<String> = label.map(|label| label.chars().take(MAX_LABEL_CHARS).collect());
    sqlx::query(
        "UPDATE external_identities SET last_seen_at = ?, label = COALESCE(?, label), \
         unionid = COALESCE(?, unionid) WHERE id = ?",
    )
    .bind(now)
    .bind(label)
    .bind(unionid)
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// What signing in with an identity found ([`sign_in`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedIn {
    /// The identity is bound to this enabled account; its sign-in is recorded.
    Account(Box<User>),
    /// It is bound to a disabled account.
    Disabled,
    /// It is bound to an account that waits for its deletion `until` then.
    DeletionPending {
        /// The account.
        user_id: i64,
        /// When it is deleted.
        until: i64,
    },
    /// It is bound to no account.
    Unbound,
}

/// The account `user_id` inside `tx`.
async fn user_in(tx: &mut Tx, user_id: i64) -> Result<Option<User>> {
    let sql = format!(
        "SELECT {} FROM users WHERE id = ?",
        crate::users::USER_COLUMNS
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?)
}

/// What [`SignedIn`] says of an account that the identity is bound to.
fn signed_in(user: User) -> SignedIn {
    match user.deleting_at {
        Some(until) => SignedIn::DeletionPending {
            user_id: user.id,
            until,
        },
        None if !user.enabled => SignedIn::Disabled,
        None => SignedIn::Account(Box::new(user)),
    }
}

/// Signs in with the identity of `claims`, as its provider just reported it: the account it is
/// bound to, if any. A sign-in of an enabled account records the identity's `last_seen_at` and
/// the label the provider reports now (GitHub logins can be renamed).
pub async fn sign_in(pool: &Pool, claims: &Claims, now: i64) -> Result<SignedIn> {
    let claims = claims.checked()?;
    let mut tx = db::begin_immediate(pool).await?;
    let Some(identity) = find_in(&mut tx, claims.provider, &claims.realm, &claims.subject).await?
    else {
        return Ok(SignedIn::Unbound);
    };
    let Some(user) = user_in(&mut tx, identity.user_id).await? else {
        return Ok(SignedIn::Unbound);
    };
    let outcome = signed_in(user);
    if matches!(outcome, SignedIn::Account(_)) {
        let label = (claims.provider != Provider::WeChat).then_some(claims.label.as_str());
        touch_in(&mut tx, identity.id, label, claims.unionid.as_deref(), now).await?;
        tx.commit().await?;
    }
    Ok(outcome)
}

/// Signs in with identity `identity_id`, which a provider just confirmed (WeChat's mini
/// program): the account it is bound to, with the identity. A sign-in of an enabled account
/// records the identity's `last_seen_at`.
pub async fn sign_in_identity(
    pool: &Pool,
    identity_id: i64,
    now: i64,
) -> Result<(SignedIn, Option<Identity>)> {
    let mut tx = db::begin_immediate(pool).await?;
    let sql = format!("SELECT {IDENTITY_COLUMNS} FROM external_identities WHERE id = ?");
    let identity: Option<Identity> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(identity_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(identity) = identity else {
        return Ok((SignedIn::Unbound, None));
    };
    let Some(user) = user_in(&mut tx, identity.user_id).await? else {
        return Ok((SignedIn::Unbound, None));
    };
    let outcome = signed_in(user);
    if matches!(outcome, SignedIn::Account(_)) {
        touch_in(&mut tx, identity.id, None, None, now).await?;
        tx.commit().await?;
    }
    Ok((outcome, Some(identity)))
}

/// An automatic binding by address ([`bind_by_email`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundByEmail {
    /// The account, enabled, which signs in now.
    pub user: Box<User>,
    /// The identity bound to it.
    pub identity: Identity,
    /// The account's address, which the provider verified: it gets the notice.
    pub email: String,
}

/// Binds the identity of `claims`, which is bound to no account, to the account whose address
/// is one of `verified` (the addresses the provider verified, lower-cased), when that account
/// proved the address itself (`users.email`), is enabled, waits for no deletion and has no
/// identity of this provider and realm yet (`plan/third-party-sign-in-design.md`, 3.3). Records
/// `identity.bound` with [`How::Email`]. `None` binds nothing.
pub async fn bind_by_email(
    pool: &Pool,
    claims: &Claims,
    verified: &[String],
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Option<BoundByEmail>> {
    let claims = claims.checked()?;
    let addresses: Vec<String> = verified
        .iter()
        .filter_map(|address| crate::email::normalize_address(address))
        .take(db::MAX_LIST)
        .collect();
    if addresses.is_empty() {
        return Ok(None);
    }
    let mut tx = db::begin_immediate(pool).await?;
    for email in addresses {
        let sql = format!(
            "SELECT {} FROM users WHERE email = ?",
            crate::users::USER_COLUMNS
        );
        let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(user) = user else {
            continue;
        };
        if !user.enabled || user.deleting_at.is_some() {
            continue;
        }
        match bind_in(
            &mut tx,
            user.id,
            &claims,
            How::Email,
            Actor::User,
            client_ip,
            now,
        )
        .await?
        {
            Bound::Bound(identity) => {
                tx.commit().await?;
                return Ok(Some(BoundByEmail {
                    user: Box::new(user),
                    identity,
                    email,
                }));
            }
            // The account has one of this provider already: nothing is bound, and the sign-in
            // goes on as for any identity bound to no account.
            Bound::AccountHasOne | Bound::NoAccount => {}
            // Bound meanwhile: the caller signs in again.
            Bound::Already(_) | Bound::OtherAccount => return Ok(None),
        }
    }
    Ok(None)
}

/// Outcome of [`bind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    /// The identity is the account's now.
    Bound(Identity),
    /// It was the account's already; nothing changed.
    Already(Identity),
    /// It belongs to another account (`account_exists`); nothing changed.
    OtherAccount,
    /// The account has another identity of this provider and realm (`bind_failed`); nothing
    /// changed.
    AccountHasOne,
    /// The account does not exist.
    NoAccount,
}

/// What [`bind_in`] would find for the identity of `claims` and account `user_id` inside `tx`,
/// without binding anything: `None` when it would bind, otherwise [`Bound::Already`] or the
/// refusal ([`Bound::NoAccount`], [`Bound::OtherAccount`], [`Bound::AccountHasOne`]), checked
/// in that order.
pub(crate) async fn check_bind_in(
    tx: &mut Tx,
    user_id: i64,
    claims: &Claims,
) -> Result<Option<Bound>> {
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
    if exists.is_none() {
        return Ok(Some(Bound::NoAccount));
    }
    if let Some(identity) = find_in(tx, claims.provider, &claims.realm, &claims.subject).await? {
        return Ok(Some(if identity.user_id == user_id {
            Bound::Already(identity)
        } else {
            Bound::OtherAccount
        }));
    }
    let other: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM external_identities WHERE user_id = ? AND provider = ? AND realm = ?",
    )
    .bind(user_id)
    .bind(claims.provider.as_str())
    .bind(&claims.realm)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(other.is_some().then_some(Bound::AccountHasOne))
}

/// Binds the identity of `claims` to account `user_id` inside `tx` and records
/// `identity.bound` by `actor`, `how`. See [`Bound`] for the refusals, which change nothing;
/// [`check_bind_in`] makes the checks.
pub(crate) async fn bind_in(
    tx: &mut Tx,
    user_id: i64,
    claims: &Claims,
    how: How,
    actor: Actor,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Bound> {
    let claims = claims.checked()?;
    if let Some(found) = check_bind_in(tx, user_id, &claims).await? {
        return Ok(found);
    }
    let id = db::next_id(tx, "external_identities").await?;
    let inserted = sqlx::query(
        "INSERT INTO external_identities (id, user_id, provider, realm, subject, unionid, label, \
         created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(claims.provider.as_str())
    .bind(&claims.realm)
    .bind(&claims.subject)
    .bind(claims.unionid.as_deref())
    .bind(&claims.label)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await;
    match inserted {
        Ok(_) => {}
        // Inside the write transaction nobody binds in between; the unique keys back the
        // checks above up.
        Err(err)
            if err
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation()) =>
        {
            return Ok(Bound::AccountHasOne);
        }
        Err(err) => return Err(Error::Database(err)),
    }
    audit::record_in(
        tx,
        &Record::new(user_id, "identity.bound", actor)
            .client_ip(client_ip)
            .details(details(claims.provider, &claims.realm, how)),
        now,
    )
    .await?;
    Ok(Bound::Bound(Identity {
        id,
        user_id,
        provider: claims.provider,
        realm: claims.realm,
        label: claims.label,
        created_at: now,
        last_seen_at: now,
    }))
}

/// Binds the identity of `claims` to account `user_id`: see [`bind_in`].
pub async fn bind(
    pool: &Pool,
    user_id: i64,
    claims: &Claims,
    how: How,
    actor: Actor,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Bound> {
    let mut tx = db::begin_immediate(pool).await?;
    let bound = bind_in(&mut tx, user_id, claims, how, actor, client_ip, now).await?;
    tx.commit().await?;
    Ok(bound)
}

/// The details of `identity.bound` and `identity.unbound`.
fn details(provider: Provider, realm: &str, how: How) -> serde_json::Value {
    let mut details = serde_json::json!({ "provider": provider.as_str(), "how": how.as_str() });
    if provider == Provider::WeChat {
        details["app_id"] = serde_json::Value::from(realm);
    }
    details
}

/// Outcome of [`unbind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unbound {
    /// The identity is unbound, and its mini program sessions ended with it.
    Done(Identity),
    /// The account has no such identity; nothing changed.
    NotBound,
    /// It is the account's last way in: the account has no web login password and no other
    /// identity (`last_sign_in`). Nothing changed.
    LastSignIn,
}

/// Which identity [`unbind`] takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which<'a> {
    /// The account's identity of a provider and realm.
    Realm(Provider, &'a str),
    /// The account's identity with this row id.
    Id(i64),
}

/// Unbinds an identity from account `user_id` and records `identity.unbound` by `actor`,
/// `how`. Unless the account keeps a way in, its web login password or another identity, it
/// refuses ([`Unbound::LastSignIn`]). The mini program's sessions of the identity end with it
/// (`mp_sessions` cascades).
pub async fn unbind(
    pool: &Pool,
    user_id: i64,
    which: Which<'_>,
    how: How,
    actor: Actor,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Unbound> {
    let mut tx = db::begin_immediate(pool).await?;
    let sql = match which {
        Which::Realm(..) => format!(
            "SELECT {IDENTITY_COLUMNS} FROM external_identities \
             WHERE user_id = ? AND provider = ? AND realm = ?"
        ),
        Which::Id(_) => {
            format!(
                "SELECT {IDENTITY_COLUMNS} FROM external_identities WHERE user_id = ? AND id = ?"
            )
        }
    };
    let query = sqlx::query_as::<_, Identity>(sqlx::AssertSqlSafe(sql)).bind(user_id);
    let query = match which {
        Which::Realm(provider, realm) => query.bind(provider.as_str()).bind(realm),
        Which::Id(id) => query.bind(id),
    };
    let Some(identity) = query.fetch_optional(&mut *tx).await? else {
        return Ok(Unbound::NotBound);
    };
    if !keeps_a_way_in(&mut tx, user_id, identity.id).await? {
        return Ok(Unbound::LastSignIn);
    }
    sqlx::query("DELETE FROM external_identities WHERE id = ?")
        .bind(identity.id)
        .execute(&mut *tx)
        .await?;
    audit::record_in(
        &mut tx,
        &Record::new(user_id, "identity.unbound", actor)
            .client_ip(client_ip)
            .details(details(identity.provider, &identity.realm, how)),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Unbound::Done(identity))
}

/// Whether account `user_id` keeps a way in without identity `without`: a web login password
/// or another identity.
async fn keeps_a_way_in(tx: &mut Tx, user_id: i64, without: i64) -> Result<bool> {
    let keeps: Option<Flag> = sqlx::query_scalar(
        "SELECT (password_hash IS NOT NULL OR EXISTS (SELECT 1 FROM external_identities i \
         WHERE i.user_id = users.id AND i.id <> ?)) FROM users WHERE id = ?",
    )
    .bind(without)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(keeps.is_some_and(|keeps| keeps.0))
}

/// Who holds the token of a pending identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// The WeChat mini program: its signup token.
    MiniProgram,
    /// A browser, in a cookie.
    Web,
}

impl Holder {
    fn as_str(self) -> &'static str {
        match self {
            Self::MiniProgram => "mini_program",
            Self::Web => "web",
        }
    }
}

/// A pending identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Row id.
    pub id: i64,
    /// What the provider reported.
    pub claims: Claims,
    /// When it ends, UNIX seconds.
    pub expires_at: i64,
}

#[derive(FromRow)]
struct PendingRow {
    id: i64,
    #[sqlx(try_from = "Text")]
    provider: Provider,
    #[sqlx(try_from = "Text")]
    realm: String,
    #[sqlx(try_from = "Text")]
    subject: String,
    unionid: Option<Text>,
    label: String,
    email: Option<Text>,
    #[sqlx(try_from = "Flag")]
    email_verified: bool,
    name: Option<String>,
    expires_at: i64,
}

impl From<PendingRow> for Pending {
    fn from(row: PendingRow) -> Self {
        Self {
            id: row.id,
            claims: Claims {
                provider: row.provider,
                realm: row.realm,
                subject: row.subject,
                unionid: row.unionid.map(String::from),
                label: row.label,
                email: row.email.map(String::from),
                email_verified: row.email_verified,
                name: row.name,
            },
            expires_at: row.expires_at,
        }
    }
}

/// Keeps the identity of `claims`, bound to no account, for `holder` inside `tx`, and ends the
/// earlier ones of the same identity and holder. Returns the token (once; only its digest is
/// stored) and when it ends.
pub(crate) async fn create_pending_in(
    tx: &mut Tx,
    holder: Holder,
    claims: &Claims,
    now: i64,
) -> Result<(SecretString, i64)> {
    let claims = claims.checked()?;
    sqlx::query(
        "DELETE FROM pending_identities WHERE provider = ? AND realm = ? AND subject = ? \
         AND holder = ?",
    )
    .bind(claims.provider.as_str())
    .bind(&claims.realm)
    .bind(&claims.subject)
    .bind(holder.as_str())
    .execute(&mut **tx)
    .await?;
    let token = secret::random_token(TOKEN_CHARS);
    let expires_at = now.saturating_add(PENDING_TTL_SECS);
    let id = db::next_id(tx, "pending_identities").await?;
    sqlx::query(
        "INSERT INTO pending_identities (id, token_hash, holder, provider, realm, subject, \
         unionid, label, email, email_verified, name, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&secret::digest(token.expose_secret())[..])
    .bind(holder.as_str())
    .bind(claims.provider.as_str())
    .bind(&claims.realm)
    .bind(&claims.subject)
    .bind(claims.unionid.as_deref())
    .bind(&claims.label)
    .bind(claims.email.as_deref())
    .bind(claims.email_verified)
    .bind(claims.name.as_deref())
    .bind(now)
    .bind(expires_at)
    .execute(&mut **tx)
    .await?;
    Ok((token, expires_at))
}

/// Keeps the identity of `claims` for `holder`: see [`create_pending_in`].
pub async fn create_pending(
    pool: &Pool,
    holder: Holder,
    claims: &Claims,
    now: i64,
) -> Result<(SecretString, i64)> {
    let mut tx = db::begin_immediate(pool).await?;
    let created = create_pending_in(&mut tx, holder, claims, now).await?;
    tx.commit().await?;
    Ok(created)
}

const PENDING_COLUMNS: &str = "id, provider, realm, subject, unionid, label, email, \
                               email_verified, name, expires_at";

/// The live pending identity of `holder` with token `token`, inside `tx`.
pub(crate) async fn pending_in(
    tx: &mut Tx,
    holder: Holder,
    token: &str,
    now: i64,
) -> Result<Option<Pending>> {
    let sql = format!(
        "SELECT {PENDING_COLUMNS} FROM pending_identities \
         WHERE token_hash = ? AND holder = ? AND expires_at > ?"
    );
    let row: Option<PendingRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&secret::digest(token)[..])
        .bind(holder.as_str())
        .bind(now)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.map(Pending::from))
}

/// The live pending identity of `holder` with token `token`.
pub async fn pending(
    pool: &Pool,
    holder: Holder,
    token: &str,
    now: i64,
) -> Result<Option<Pending>> {
    let sql = format!(
        "SELECT {PENDING_COLUMNS} FROM pending_identities \
         WHERE token_hash = ? AND holder = ? AND expires_at > ?"
    );
    let row: Option<PendingRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&secret::digest(token)[..])
        .bind(holder.as_str())
        .bind(now)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Pending::from))
}

/// Ends pending identity `id` inside `tx`.
pub(crate) async fn end_pending_in(tx: &mut Tx, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM pending_identities WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Ends the pending identity of `holder` with token `token`, if there is one.
pub async fn end_pending(pool: &Pool, holder: Holder, token: &str) -> Result<()> {
    let mut tx = db::begin_immediate(pool).await?;
    sqlx::query("DELETE FROM pending_identities WHERE token_hash = ? AND holder = ?")
        .bind(&secret::digest(token)[..])
        .bind(holder.as_str())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Outcome of [`bind_pending`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundPending {
    /// Bound (or the account's already), and the pending identity is used up.
    Bound(Identity),
    /// No such pending identity: expired, used or replaced.
    Expired,
    /// The identity belongs to another account; the pending identity is used up.
    OtherAccount,
    /// The account has another identity of this provider and realm; the pending identity
    /// stays.
    AccountHasOne,
}

/// Binds the pending identity of `holder` with token `token` to account `user_id`, as its user
/// asked after signing in with the password, and uses it up. Records `identity.bound` with
/// [`How::AccountPage`].
pub async fn bind_pending(
    pool: &Pool,
    holder: Holder,
    token: &str,
    user_id: i64,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<BoundPending> {
    let mut tx = db::begin_immediate(pool).await?;
    let Some(pending) = pending_in(&mut tx, holder, token, now).await? else {
        return Ok(BoundPending::Expired);
    };
    let bound = bind_in(
        &mut tx,
        user_id,
        &pending.claims,
        How::AccountPage,
        Actor::User,
        client_ip,
        now,
    )
    .await?;
    let outcome = match bound {
        Bound::Bound(identity) | Bound::Already(identity) => BoundPending::Bound(identity),
        Bound::OtherAccount => BoundPending::OtherAccount,
        Bound::AccountHasOne | Bound::NoAccount => return Ok(BoundPending::AccountHasOne),
    };
    end_pending_in(&mut tx, pending.id).await?;
    tx.commit().await?;
    Ok(outcome)
}

/// Removes the pending identities that expired at `now`. Returns how many there were.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query("DELETE FROM pending_identities WHERE expires_at <= ?")
        .bind(now)
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
    fn providers_round_trip() {
        for provider in Provider::ALL {
            assert_eq!(Provider::parse(provider.as_str()), Some(provider));
        }
        assert_eq!(Provider::parse("Google"), None);
        assert_eq!(Provider::parse(""), None);
        assert!(Provider::WeChat < Provider::Google && Provider::Google < Provider::GitHub);
    }

    #[test]
    fn claims_are_cut_to_what_the_schema_holds() {
        let claims = Claims {
            provider: Provider::Google,
            realm: GOOGLE_REALM.to_owned(),
            subject: "1".repeat(21),
            unionid: None,
            label: format!("{}\u{7}", "a".repeat(300)),
            email: Some(" Alice@Example.COM ".to_owned()),
            email_verified: true,
            name: Some("  ".to_owned()),
        };
        let checked = claims.checked().unwrap();
        assert_eq!(checked.label.chars().count(), MAX_LABEL_CHARS);
        assert_eq!(checked.email.as_deref(), Some("alice@example.com"));
        assert!(checked.email_verified);
        assert_eq!(checked.name, None);

        let bad = Claims {
            email: Some("not an address".to_owned()),
            ..claims.clone()
        };
        let checked = bad.checked().unwrap();
        assert_eq!(checked.email, None);
        assert!(!checked.email_verified, "no address, nothing verified");

        for invalid in [
            Claims {
                subject: String::new(),
                ..claims.clone()
            },
            Claims {
                subject: "x".repeat(MAX_SUBJECT_BYTES + 1),
                ..claims.clone()
            },
            Claims {
                realm: "r".repeat(MAX_REALM_BYTES + 1),
                ..claims.clone()
            },
            Claims {
                unionid: Some("u".to_owned()),
                ..claims.clone()
            },
        ] {
            assert!(invalid.checked().is_err(), "{invalid:?}");
        }
        assert!(
            Claims::wechat("wxd930ea5d5a258f4f", "o1", Some("u1"))
                .checked()
                .is_ok()
        );
    }

    #[test]
    fn tokens_have_their_shape() {
        assert!(is_token(secret::random_token(TOKEN_CHARS).expose_secret()));
        assert!(!is_token(&"a".repeat(TOKEN_CHARS - 1)));
        assert!(!is_token(&format!("{}-", "a".repeat(TOKEN_CHARS - 1))));
    }
}
