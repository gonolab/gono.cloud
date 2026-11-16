//! S3 buckets and access keys (`s3_buckets`, `s3_key_grants`, and `app_passwords` rows of kind
//! `s3`).
//!
//! - A **bucket** is a name bound to a folder of its owner's tree, by file id: the binding
//!   follows the folder through WebDAV moves and disappears with it. Names are unique across the
//!   server, because an anonymous request names only the bucket. A folder is bound to one bucket
//!   at most, is never the root of the tree, and is neither inside nor above another bucket's
//!   folder when it is bound (a later WebDAV move can still nest them).
//! - An **access key** is an `app_passwords` row of kind `s3`: an access key id
//!   (`GONO` and 16 characters from `[A-Z0-9]`) and a secret of 40 characters from
//!   `[A-Za-z0-9]` (about 238 bits), shown once. SigV4 signatures are HMACs keyed with the
//!   secret, so the secret is sealed with the server's key file ([`crate::sealing`]) instead of
//!   hashed. Keys share the label, expiry and `last_used_at` of app passwords, never their
//!   scopes: what a key reaches are its [`Grant`]s, either one grant for every bucket of its
//!   owner (present and future) or grants for single buckets.

use rand::RngExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;

use crate::{
    app_passwords::check_label,
    db::{self, Pool, Tx},
    error::{Error, Result},
    path::RelPath,
    sealing::{Key, Purpose},
    types::{Permission, Username},
};

/// Start of every access key id.
pub const ACCESS_KEY_PREFIX: &str = "GONO";

/// Characters after [`ACCESS_KEY_PREFIX`].
const ACCESS_KEY_CHARS: usize = 16;

/// Characters of a secret key.
const SECRET_CHARS: usize = 40;

const UPPER_ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A bucket name: 3 to 63 characters from `[a-z0-9-]`, starting and ending with a letter or a
/// digit. Dots are not allowed, so that one wildcard certificate covers virtual-hosted style.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BucketName(String);

impl BucketName {
    /// Validates `name`.
    pub fn new(name: &str) -> Result<Self> {
        let invalid = |reason| Error::InvalidBucketName {
            name: name.to_owned(),
            reason,
        };
        if !(3..=63).contains(&name.len()) {
            return Err(invalid("must be 3 to 63 characters long"));
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid(
                "must consist of lowercase letters, digits and '-' only",
            ));
        }
        let alphanumeric = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_alphanumeric());
        if !alphanumeric(name.bytes().next()) || !alphanumeric(name.bytes().last()) {
            return Err(invalid("must start and end with a letter or a digit"));
        }
        // Reserved by AWS: punycode host names and access point aliases.
        if name.starts_with("xn--") || name.ends_with("-s3alias") || name.ends_with("--ol-s3") {
            return Err(invalid("uses a prefix or suffix that S3 reserves"));
        }
        Ok(Self(name.to_owned()))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BucketName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What anonymous requests may read in a bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Anonymous {
    /// Nothing.
    #[default]
    Private,
    /// Objects with the `public-read` ACL.
    Acl,
    /// Every object.
    PublicRead,
}

impl Anonymous {
    /// The stored value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Acl => "acl",
            Self::PublicRead => "public-read",
        }
    }
}

impl std::str::FromStr for Anonymous {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "private" => Ok(Self::Private),
            "acl" => Ok(Self::Acl),
            "public-read" => Ok(Self::PublicRead),
            other => Err(Error::InvalidAnonymous(other.to_owned())),
        }
    }
}

/// A bucket and where its folder is now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// Row id.
    pub id: i64,
    /// The name.
    pub name: String,
    /// Owner.
    pub owner_id: i64,
    /// File id of the folder.
    pub root_file_id: i64,
    /// The folder's current path in the owner's tree.
    pub folder: RelPath,
    /// Anonymous reads, as stored (effective only while `s3.allow_anonymous` is on).
    pub anonymous: Anonymous,
    /// Anonymous listing, as stored.
    pub anonymous_list: bool,
    /// Creation time, UNIX seconds.
    pub created_at: i64,
}

#[derive(FromRow)]
struct BucketRow {
    id: i64,
    name: String,
    owner_id: i64,
    root_file_id: i64,
    rel_path: String,
    anonymous: String,
    anonymous_list: bool,
    created_at: i64,
}

impl TryFrom<BucketRow> for Bucket {
    type Error = Error;

    fn try_from(row: BucketRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            name: row.name,
            owner_id: row.owner_id,
            root_file_id: row.root_file_id,
            folder: RelPath::from_db(row.rel_path),
            anonymous: row.anonymous.parse()?,
            anonymous_list: row.anonymous_list,
            created_at: row.created_at,
        })
    }
}

const BUCKET_QUERY: &str = "SELECT b.id, b.name, b.owner_id, b.root_file_id, f.rel_path, \
     b.anonymous, b.anonymous_list, b.created_at \
     FROM s3_buckets b JOIN files f ON f.id = b.root_file_id";

/// The bucket called `name`, if there is one.
pub async fn bucket(pool: &Pool, name: &str) -> Result<Option<Bucket>> {
    let row: Option<BucketRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{BUCKET_QUERY} WHERE b.name = ?1"
    )))
    .bind(name)
    .fetch_optional(pool)
    .await?;
    row.map(Bucket::try_from).transpose()
}

/// The buckets of `owner`, by name.
pub async fn buckets_of(pool: &Pool, owner: i64) -> Result<Vec<Bucket>> {
    let rows: Vec<BucketRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{BUCKET_QUERY} WHERE b.owner_id = ?1 ORDER BY b.name"
    )))
    .bind(owner)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(Bucket::try_from).collect()
}

/// Binds the folder with file id `folder_id` of `owner` as bucket `name`.
///
/// Fails if the name is taken ([`Error::BucketExists`]), or if the folder is not a folder of
/// `owner`, is the root of the tree, is bound already, or lies inside or above another
/// bucket's folder ([`Error::InvalidBucketFolder`]).
pub async fn create_bucket(
    pool: &Pool,
    owner: i64,
    name: &BucketName,
    folder_id: i64,
) -> Result<Bucket> {
    let mut tx = db::begin_immediate(pool).await?;
    let taken: Option<i64> = sqlx::query_scalar("SELECT owner_id FROM s3_buckets WHERE name = ?1")
        .bind(name.as_str())
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(taken_by) = taken {
        return Err(Error::BucketExists {
            name: name.to_string(),
            yours: taken_by == owner,
        });
    }
    let folder: Option<(String, bool)> =
        sqlx::query_as("SELECT rel_path, is_dir FROM files WHERE id = ?1 AND owner_id = ?2")
            .bind(folder_id)
            .bind(owner)
            .fetch_optional(&mut *tx)
            .await?;
    let invalid = |path: &str, reason| Error::InvalidBucketFolder {
        path: if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        },
        reason,
    };
    let path = match folder {
        Some((path, true)) => RelPath::from_db(path),
        Some((path, false)) => return Err(invalid(&path, "not a folder")),
        None => return Err(invalid(&format!("#{folder_id}"), "no such folder")),
    };
    if path.is_root() {
        return Err(invalid("", "the root of the tree cannot be a bucket"));
    }
    for other in buckets_in(&mut tx, owner).await? {
        if other.root_file_id == folder_id {
            return Err(invalid(path.as_str(), "the folder is a bucket already"));
        }
        if path.starts_with(&other.folder) || other.folder.starts_with(&path) {
            return Err(invalid(
                path.as_str(),
                "the folder lies inside or above another bucket's folder",
            ));
        }
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO s3_buckets (name, owner_id, root_file_id, created_at) \
         VALUES (?1, ?2, ?3, ?4) RETURNING id",
    )
    .bind(name.as_str())
    .bind(owner)
    .bind(folder_id)
    .bind(db::unix_now())
    .fetch_one(&mut *tx)
    .await?;
    let row: BucketRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{BUCKET_QUERY} WHERE b.id = ?1"
    )))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    row.try_into()
}

async fn buckets_in(tx: &mut Tx, owner: i64) -> Result<Vec<Bucket>> {
    let rows: Vec<BucketRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{BUCKET_QUERY} WHERE b.owner_id = ?1"
    )))
    .bind(owner)
    .fetch_all(&mut **tx)
    .await?;
    rows.into_iter().map(Bucket::try_from).collect()
}

/// Removes the binding of `owner`'s bucket `id`; the folder and its files stay. Returns `false`
/// if there is no such bucket.
pub async fn delete_bucket(pool: &Pool, owner: i64, id: i64) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let removed = sqlx::query("DELETE FROM s3_buckets WHERE id = ?1 AND owner_id = ?2")
        .bind(id)
        .bind(owner)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(removed == 1)
}

/// Sets what anonymous requests may do in `owner`'s bucket `id`. Returns `false` if there is
/// no such bucket.
pub async fn set_anonymous(
    pool: &Pool,
    owner: i64,
    id: i64,
    anonymous: Anonymous,
    list: bool,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let changed = sqlx::query(
        "UPDATE s3_buckets SET anonymous = ?3, anonymous_list = ?4 WHERE id = ?1 AND owner_id = ?2",
    )
    .bind(id)
    .bind(owner)
    .bind(anonymous.as_str())
    .bind(list)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(changed == 1)
}

/// What an access key may reach: one bucket, or (`bucket_id` `None`) every bucket of its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// The bucket, or `None` for every bucket.
    pub bucket_id: Option<i64>,
    /// Read only, or read and write.
    pub permission: Permission,
}

impl Grant {
    /// Every bucket, read and write: the grant that may also create and delete buckets.
    pub const fn everything() -> Self {
        Self {
            bucket_id: None,
            permission: Permission::Full,
        }
    }
}

/// An access key, never its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Key {
    /// The `app_passwords` row id.
    pub id: i64,
    /// Owner.
    pub user_id: i64,
    /// The access key id.
    pub access_key_id: String,
    /// Human-readable name.
    pub label: String,
    /// Creation time, UNIX seconds.
    pub created_at: i64,
    /// Expiry, UNIX seconds; `None` never expires.
    pub expires_at: Option<i64>,
    /// Last successful signature, UNIX seconds (updated at most every few minutes).
    pub last_used_at: Option<i64>,
    /// What the key reaches.
    pub grants: Vec<Grant>,
}

/// An access key that may sign requests now, with its secret.
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// The `app_passwords` row id.
    pub id: i64,
    /// Owner's id.
    pub user_id: i64,
    /// Owner's name.
    pub username: Username,
    /// Owner's display name.
    pub display_name: String,
    /// The secret the signature is keyed with.
    pub secret: SecretString,
    /// What the key reaches.
    pub grants: Vec<Grant>,
    /// Last recorded use, UNIX seconds.
    pub last_used_at: Option<i64>,
}

/// A new access key id.
pub fn generate_access_key_id() -> String {
    let mut rng = rand::rng();
    let mut id = String::from(ACCESS_KEY_PREFIX);
    for _ in 0..ACCESS_KEY_CHARS {
        id.push(char::from(
            UPPER_ALPHANUMERIC[rng.random_range(0..UPPER_ALPHANUMERIC.len())],
        ));
    }
    id
}

/// Whether `id` has the shape of an access key id (cheap to check before any lookup).
pub fn is_access_key_id(id: &str) -> bool {
    id.strip_prefix(ACCESS_KEY_PREFIX).is_some_and(|rest| {
        rest.len() == ACCESS_KEY_CHARS
            && rest
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

/// Checks that grants are a single grant for every bucket, or grants for distinct buckets of
/// `owner`, and returns them ordered.
async fn check_grants(tx: &mut Tx, owner: i64, grants: Vec<Grant>) -> Result<Vec<Grant>> {
    if grants.is_empty() {
        return Err(Error::InvalidGrants(
            "a key needs at least one grant".to_owned(),
        ));
    }
    if grants.iter().any(|grant| grant.bucket_id.is_none()) && grants.len() > 1 {
        return Err(Error::InvalidGrants(
            "a grant for every bucket cannot be combined with other grants".to_owned(),
        ));
    }
    let mut grants = grants;
    grants.sort_by_key(|grant| grant.bucket_id);
    for pair in grants.windows(2) {
        if pair[0].bucket_id == pair[1].bucket_id {
            return Err(Error::InvalidGrants("a bucket is granted twice".to_owned()));
        }
    }
    for id in grants.iter().filter_map(|grant| grant.bucket_id) {
        let found: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM s3_buckets WHERE id = ?1 AND owner_id = ?2")
                .bind(id)
                .bind(owner)
                .fetch_optional(&mut **tx)
                .await?;
        if found.is_none() {
            return Err(Error::InvalidGrants(format!(
                "bucket {id} does not belong to the key's account"
            )));
        }
    }
    Ok(grants)
}

/// Creates an access key for `user_id` and returns it with its secret, which is returned
/// exactly once.
pub async fn create_key(
    pool: &Pool,
    sealing: &Key,
    user_id: i64,
    label: &str,
    grants: Vec<Grant>,
    expires_at: Option<i64>,
) -> Result<(S3Key, SecretString)> {
    let label = check_label(label)?;
    let secret = crate::secret::random_token(SECRET_CHARS);
    let mut tx = db::begin_immediate(pool).await?;
    let grants = check_grants(&mut tx, user_id, grants).await?;
    let created_at = db::unix_now();
    // 36^16 ids: a collision is not going to happen, but would only fail the insert.
    let access_key_id = generate_access_key_id();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO app_passwords (user_id, kind, access_key_id, secret_sealed, label, \
         created_at, expires_at) VALUES (?1, 's3', ?2, x'', ?3, ?4, ?5) RETURNING id",
    )
    .bind(user_id)
    .bind(&access_key_id)
    .bind(&label)
    .bind(created_at)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;
    // The row id is part of the associated data, so the secret is sealed once it is known.
    sqlx::query("UPDATE app_passwords SET secret_sealed = ?2 WHERE id = ?1")
        .bind(id)
        .bind(sealing.seal(Purpose::S3Secret, id, secret.expose_secret().as_bytes()))
        .execute(&mut *tx)
        .await?;
    for grant in &grants {
        sqlx::query(
            "INSERT INTO s3_key_grants (app_password_id, bucket_id, permission) \
             VALUES (?1, ?2, ?3)",
        )
        .bind(id)
        .bind(grant.bucket_id)
        .bind(grant.permission.as_str())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let key = S3Key {
        id,
        user_id,
        access_key_id,
        label,
        created_at,
        expires_at,
        last_used_at: None,
        grants,
    };
    Ok((key, secret))
}

#[derive(FromRow)]
struct KeyRow {
    id: i64,
    user_id: i64,
    access_key_id: String,
    label: String,
    created_at: i64,
    expires_at: Option<i64>,
    last_used_at: Option<i64>,
}

#[derive(FromRow)]
struct GrantRow {
    app_password_id: i64,
    bucket_id: Option<i64>,
    permission: String,
}

impl TryFrom<&GrantRow> for Grant {
    type Error = Error;

    fn try_from(row: &GrantRow) -> Result<Self> {
        Ok(Self {
            bucket_id: row.bucket_id,
            permission: row.permission.parse()?,
        })
    }
}

/// The access keys of `user_id`, oldest first.
pub async fn list_keys(pool: &Pool, user_id: i64) -> Result<Vec<S3Key>> {
    let rows: Vec<KeyRow> = sqlx::query_as(
        "SELECT id, user_id, access_key_id, label, created_at, expires_at, last_used_at \
         FROM app_passwords WHERE user_id = ?1 AND kind = 's3' ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let grants: Vec<GrantRow> = sqlx::query_as(
        "SELECT g.app_password_id, g.bucket_id, g.permission FROM s3_key_grants g \
         JOIN app_passwords a ON a.id = g.app_password_id WHERE a.user_id = ?1 \
         ORDER BY g.app_password_id, g.bucket_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(S3Key {
                grants: grants
                    .iter()
                    .filter(|grant| grant.app_password_id == row.id)
                    .map(Grant::try_from)
                    .collect::<Result<_>>()?,
                id: row.id,
                user_id: row.user_id,
                access_key_id: row.access_key_id,
                label: row.label,
                created_at: row.created_at,
                expires_at: row.expires_at,
                last_used_at: row.last_used_at,
            })
        })
        .collect()
}

/// Revokes `user_id`'s access key `id`. Returns `false` if there is no such key.
pub async fn delete_key(pool: &Pool, user_id: i64, id: i64) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let removed =
        sqlx::query("DELETE FROM app_passwords WHERE id = ?1 AND user_id = ?2 AND kind = 's3'")
            .bind(id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    tx.commit().await?;
    Ok(removed == 1)
}

#[derive(FromRow)]
struct SigningRow {
    id: i64,
    user_id: i64,
    secret_sealed: Vec<u8>,
    expires_at: Option<i64>,
    last_used_at: Option<i64>,
    username: String,
    display_name: String,
    enabled: bool,
}

/// The access key `access_key_id` with its secret, if it may sign requests at `now`: it exists,
/// has not expired, its account is enabled, and its secret opens with `sealing` (it does not
/// after the key file was replaced, which is logged).
pub async fn signing_key(
    pool: &Pool,
    sealing: &Key,
    access_key_id: &str,
    now: i64,
) -> Result<Option<SigningKey>> {
    if !is_access_key_id(access_key_id) {
        return Ok(None);
    }
    let row: Option<SigningRow> = sqlx::query_as(
        "SELECT a.id, a.user_id, a.secret_sealed, a.expires_at, a.last_used_at, u.username, \
         u.display_name, u.enabled FROM app_passwords a JOIN users u ON u.id = a.user_id \
         WHERE a.kind = 's3' AND a.access_key_id = ?1",
    )
    .bind(access_key_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if !row.enabled || row.expires_at.is_some_and(|at| at <= now) {
        return Ok(None);
    }
    let Some(secret) = sealing
        .open(Purpose::S3Secret, row.id, &row.secret_sealed)
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        tracing::error!(
            access_key_id,
            "the secret of an S3 access key does not open with the key file; was \
             two_factor.key_file replaced? Create a new key"
        );
        return Ok(None);
    };
    let grants: Vec<GrantRow> = sqlx::query_as(
        "SELECT app_password_id, bucket_id, permission FROM s3_key_grants \
         WHERE app_password_id = ?1 ORDER BY bucket_id",
    )
    .bind(row.id)
    .fetch_all(pool)
    .await?;
    Ok(Some(SigningKey {
        id: row.id,
        user_id: row.user_id,
        username: Username::new(row.username)?,
        display_name: row.display_name,
        secret: SecretString::from(secret),
        grants: grants.iter().map(Grant::try_from).collect::<Result<_>>()?,
        last_used_at: row.last_used_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names_follow_s3_rules() {
        for good in ["abc", "photos-2026", "0day", &"a".repeat(63)] {
            assert!(BucketName::new(good).is_ok(), "{good}");
        }
        for bad in [
            "ab",
            &"a".repeat(64),
            "Photos",
            "my.bucket",
            "my_bucket",
            "-abc",
            "abc-",
            "xn--abc",
            "abc-s3alias",
            "abc--ol-s3",
            "ünï",
        ] {
            assert!(BucketName::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn access_key_ids_have_a_fixed_shape() {
        let id = generate_access_key_id();
        assert_eq!(id.len(), 20);
        assert!(is_access_key_id(&id), "{id}");
        assert_ne!(id, generate_access_key_id());
        for bad in [
            "AKIAIOSFODNN7EXAMPLE",
            "GONOabcdefghijklmnop",
            "GONO123",
            "",
        ] {
            assert!(!is_access_key_id(bad), "{bad}");
        }
    }

    #[test]
    fn anonymous_modes_round_trip() {
        for mode in [Anonymous::Private, Anonymous::Acl, Anonymous::PublicRead] {
            assert_eq!(mode.as_str().parse::<Anonymous>().unwrap(), mode);
        }
        assert!("public".parse::<Anonymous>().is_err());
    }
}
