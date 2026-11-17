//! The device directory (`devices` and the tables around it): devices registered for remote
//! access, their event log, their approvals, and which device has applied which revocation.
//!
//! The protocol is `docs/connect-protocol.md`; section numbers below point into it.
//!
//! - **Identity.** A device is its Ed25519 public key ([`EndpointId`]). A key belongs to one
//!   account and to one row, which stays as a tombstone once the device is revoked: a revoked
//!   key is never registered again (9.1).
//! - **Credential.** Every unrevoked device has exactly one app password, without file scopes,
//!   for the control channel (4.5). It is created by [`register`] and deleted by [`revoke`] and
//!   [`leave`]; [`crate::app_passwords`] neither lists nor deletes it on its own.
//! - **Event log** (5.6). `device.added`, `device.revoked` and `pair.approved` are appended in
//!   the same transaction as the change. Their bodies are the event's fields as the protocol
//!   sends them, without `type` and `seq`.
//! - **Remote access** is available for an account that is enabled and, when the server
//!   requires it (`connect.require_two_factor`), has two-step verification enrolled
//!   ([`remote_access`]); only its active devices are admitted to the relay ([`admissible`]).

use std::{fmt, net::IpAddr, str::FromStr};

use secrecy::SecretString;
use serde_json::json;
use sqlx::FromRow;

use crate::{
    app_passwords,
    audit::{self, Actor, Record},
    db::{self, Pool, Tx},
    error::{Error, Result},
};

/// Most unrevoked devices of one account (protocol 15).
pub const MAX_DEVICES_PER_ACCOUNT: i64 = 50;

/// How long a device may send pairing requests after it registered or the user allowed it
/// (protocol 8.6).
pub const PAIRING_WINDOW_SECS: i64 = 60 * 60;

/// How long logged events are kept (protocol 5.6).
pub const EVENT_RETENTION_SECS: i64 = 45 * 24 * 60 * 60;

/// Longest device name, in characters.
pub const MAX_NAME_CHARS: usize = gono_protocol::connect::name::MAX_NAME_CHARS;

/// Most services (ALPNs) a device may list.
pub const MAX_SERVICES: usize = 16;

/// Longest service name, in bytes.
pub const MAX_SERVICE_LEN: usize = 64;

/// Longest version string, in characters.
pub const MAX_VERSION_CHARS: usize = 64;

/// A device's Ed25519 public key: its identity and its iroh `EndpointId`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointId(pub [u8; 32]);

impl EndpointId {
    /// Parses the wire form: exactly 64 lowercase hex digits (protocol 2.1).
    pub fn parse(hex: &str) -> Option<Self> {
        let bytes = hex.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        let mut key = [0u8; 32];
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            key[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
        }
        Some(Self(key))
    }

    /// The key from a 32-byte slice, as stored.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?))
    }

    /// 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
            hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        hex
    }

    /// The short ID shown to people: the first 8 bytes in upper-case hex, grouped in fours
    /// (`AB12-CD34-EF56-7890`), as Input Show shows it.
    pub fn short(&self) -> String {
        let hex = self.to_hex()[..16].to_ascii_uppercase();
        let groups: Vec<&str> = (0..4).map(|i| &hex[i * 4..i * 4 + 4]).collect();
        groups.join("-")
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EndpointId({})", self.short())
    }
}

impl FromStr for EndpointId {
    type Err = Error;

    fn from_str(hex: &str) -> Result<Self> {
        Self::parse(hex).ok_or(Error::InvalidDevice {
            field: "endpoint_id",
            reason: "must be 64 lowercase hex digits",
        })
    }
}

/// Checks a `product` or `platform` value: `[a-z0-9-]{1,32}` (gono-protocol's `is_slug`).
pub fn check_slug(field: &'static str, value: &str) -> Result<String> {
    use gono_protocol::connect::name::{MAX_SLUG_CHARS, is_slug};

    if is_slug(value) {
        return Ok(value.to_owned());
    }
    let reason = if value.is_empty() || value.len() > MAX_SLUG_CHARS {
        "must be 1 to 32 characters long"
    } else {
        "may only contain lowercase letters, digits and '-'"
    };
    Err(Error::InvalidDevice { field, reason })
}

/// Checks a device name as protocol 2.1 says: trimmed, 1 to [`MAX_NAME_CHARS`] characters, no
/// control characters, bidirectional controls or invisible characters, since other devices show
/// it in approval prompts and notices.
pub fn check_name(value: &str) -> Result<String> {
    gono_protocol::connect::name::check_name(value)
        .map(str::to_owned)
        .map_err(|err| Error::InvalidDevice {
            field: "name",
            reason: err.reason(),
        })
}

/// Checks a version string: at most [`MAX_VERSION_CHARS`] characters, no control characters.
/// Empty is allowed.
pub fn check_version(value: &str) -> Result<String> {
    let version = value.trim();
    if version.chars().count() > MAX_VERSION_CHARS || version.chars().any(char::is_control) {
        return Err(Error::InvalidDevice {
            field: "version",
            reason: "must be at most 64 printable characters",
        });
    }
    Ok(version.to_owned())
}

/// Checks a list of services (ALPNs): at most [`MAX_SERVICES`], each 1 to
/// [`MAX_SERVICE_LEN`] printable ASCII characters, no duplicates.
pub fn check_services(services: &[String]) -> Result<Vec<String>> {
    if services.len() > MAX_SERVICES {
        return Err(Error::InvalidDevice {
            field: "services",
            reason: "must list at most 16 services",
        });
    }
    let mut checked: Vec<String> = Vec::with_capacity(services.len());
    for service in services {
        if service.is_empty()
            || service.len() > MAX_SERVICE_LEN
            || !service.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::InvalidDevice {
                field: "services",
                reason: "each must be 1 to 64 printable ASCII characters",
            });
        }
        if !checked.contains(service) {
            checked.push(service.clone());
        }
    }
    Ok(checked)
}

/// A directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Row id.
    pub id: i64,
    /// The account.
    pub user_id: i64,
    /// The key.
    pub endpoint_id: EndpointId,
    /// The device's app password; `None` once revoked or signed out.
    pub app_password_id: Option<i64>,
    /// `input-show`, ...
    pub product: String,
    /// `macos`, ...
    pub platform: String,
    /// Name shown to people.
    pub name: String,
    /// Product version, possibly empty.
    pub version: String,
    /// The device accepts remote connections.
    pub accept_remote: bool,
    /// Unattended access is on.
    pub unattended: bool,
    /// ALPNs the device accepts.
    pub services: Vec<String>,
    /// The device may send pairing requests until then.
    pub pairing_open_until: Option<i64>,
    /// When it registered.
    pub registered_at: i64,
    /// When it last had a control connection.
    pub last_seen_at: Option<i64>,
    /// When it was revoked.
    pub revoked_at: Option<i64>,
    /// When it signed out (protocol 9.4), unless it registered again since.
    pub left_at: Option<i64>,
}

impl Device {
    /// Whether the device was revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Whether the device signed out and was not revoked since.
    pub fn is_signed_out(&self) -> bool {
        self.left_at.is_some() && !self.is_revoked()
    }

    /// Whether the device is registered: it has its credential, so it is neither revoked nor
    /// signed out.
    pub fn is_active(&self) -> bool {
        self.app_password_id.is_some()
    }

    /// Whether the device may send pairing requests at `now`.
    pub fn pairing_open(&self, now: i64) -> bool {
        self.is_active() && self.pairing_open_until.is_some_and(|until| now < until)
    }

    /// The directory entry of protocol 6.1, with `online` as given.
    pub fn entry(&self, online: bool) -> serde_json::Value {
        json!({
            "endpoint_id": self.endpoint_id.to_hex(),
            "name": self.name,
            "product": self.product,
            "platform": self.platform,
            "version": self.version,
            "registered_at": self.registered_at,
            "online": online,
            "last_seen_at": self.last_seen_at,
            "accept_remote": self.accept_remote,
            "unattended": self.unattended,
            "services": self.services,
            "revoked_at": self.revoked_at,
        })
    }
}

#[derive(FromRow)]
struct DeviceRow {
    id: i64,
    user_id: i64,
    endpoint_id: Vec<u8>,
    app_password_id: Option<i64>,
    product: String,
    platform: String,
    name: String,
    version: String,
    accept_remote: bool,
    unattended: bool,
    services: String,
    pairing_open_until: Option<i64>,
    registered_at: i64,
    last_seen_at: Option<i64>,
    revoked_at: Option<i64>,
    left_at: Option<i64>,
}

impl From<DeviceRow> for Device {
    fn from(row: DeviceRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            // The column has a length check, so this never falls back.
            endpoint_id: EndpointId::from_slice(&row.endpoint_id).unwrap_or(EndpointId([0; 32])),
            app_password_id: row.app_password_id,
            product: row.product,
            platform: row.platform,
            name: row.name,
            version: row.version,
            accept_remote: row.accept_remote,
            unattended: row.unattended,
            services: serde_json::from_str(&row.services).unwrap_or_default(),
            pairing_open_until: row.pairing_open_until,
            registered_at: row.registered_at,
            last_seen_at: row.last_seen_at,
            revoked_at: row.revoked_at,
            left_at: row.left_at,
        }
    }
}

const COLUMNS: &str = "id, user_id, endpoint_id, app_password_id, product, platform, name, \
     version, accept_remote, unattended, services, pairing_open_until, registered_at, \
     last_seen_at, revoked_at, left_at";

/// What a registering device reported about itself, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice {
    /// The key.
    pub endpoint_id: EndpointId,
    /// See [`check_slug`].
    pub product: String,
    /// See [`check_slug`].
    pub platform: String,
    /// See [`check_name`].
    pub name: String,
    /// See [`check_version`].
    pub version: String,
}

/// Outcome of [`register`].
#[derive(Debug)]
pub enum Registration {
    /// Registered, or registered again (protocol 4.4).
    Registered {
        /// The directory entry.
        device: Box<Device>,
        /// The new app password, returned once.
        app_password: SecretString,
        /// `false` when the key was registered to this account already.
        new: bool,
    },
    /// The key belongs to another account.
    Taken,
    /// The key was revoked.
    Revoked,
    /// The account has [`MAX_DEVICES_PER_ACCOUNT`] registered devices.
    TooMany,
}

/// The number of registered devices of `user_id`: neither revoked nor signed out.
pub async fn count_active(pool: &Pool, user_id: i64) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices WHERE user_id = ?1 AND app_password_id IS NOT NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?)
}

/// Registers `new` for `user_id` inside `tx`: creates the directory entry and its app password,
/// replaces the app password of an entry the account already has (protocol 4.3, 4.4), or brings
/// back an entry of the account that signed out (9.4). A key stays bound to the account it was
/// first registered to. Appends `device.added` when the entry (re)enters the directory and
/// records the audit record with `granted_from`, the browser that granted the registration.
pub(crate) async fn register(
    tx: &mut Tx,
    user_id: i64,
    new: &NewDevice,
    granted_from: Option<IpAddr>,
    now: i64,
) -> Result<Registration> {
    let existing: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE endpoint_id = ?1"
    )))
    .bind(&new.endpoint_id.0[..])
    .fetch_optional(&mut **tx)
    .await?;
    // A key revoked in an account that was deleted since has no entry any more, but stays
    // revoked (protocol 9.1).
    if existing.is_none() {
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM revoked_keys WHERE endpoint_id = ?1")
                .bind(&new.endpoint_id.0[..])
                .fetch_optional(&mut **tx)
                .await?;
        if revoked.is_some() {
            return Ok(Registration::Revoked);
        }
    }
    let label = new.name.clone();
    let app_password = app_passwords::generate_device_token();
    let pairing_until = now.saturating_add(PAIRING_WINDOW_SECS);

    if let Some(existing) = existing {
        if existing.user_id != user_id {
            return Ok(Registration::Taken);
        }
        if existing.revoked_at.is_some() {
            return Ok(Registration::Revoked);
        }
        let Some(old_password) = existing.app_password_id else {
            return come_back(tx, existing.id, user_id, new, granted_from, now).await;
        };
        let password_id =
            app_passwords::insert(tx, user_id, &label, &[], None, &app_password).await?;
        sqlx::query(
            "UPDATE devices SET app_password_id = ?2, product = ?3, platform = ?4, name = ?5, \
             version = ?6, pairing_open_until = ?7 WHERE id = ?1",
        )
        .bind(existing.id)
        .bind(password_id)
        .bind(&new.product)
        .bind(&new.platform)
        .bind(&new.name)
        .bind(&new.version)
        .bind(pairing_until)
        .execute(&mut **tx)
        .await?;
        sqlx::query("DELETE FROM app_passwords WHERE id = ?1")
            .bind(old_password)
            .execute(&mut **tx)
            .await?;
        let device = get_in(tx, existing.id).await?;
        audit::record(
            &mut **tx,
            &Record::new(user_id, "device.reregistered", Actor::User)
                .device(new.endpoint_id)
                .client_ip(granted_from)
                .details(json!({
                    "product": new.product,
                    "platform": new.platform,
                    "name": new.name,
                })),
            now,
        )
        .await?;
        return Ok(Registration::Registered {
            device: Box::new(device),
            app_password,
            new: false,
        });
    }

    if count_active_in(tx, user_id).await? >= MAX_DEVICES_PER_ACCOUNT {
        return Ok(Registration::TooMany);
    }
    let password_id = app_passwords::insert(tx, user_id, &label, &[], None, &app_password).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO devices (user_id, endpoint_id, app_password_id, product, platform, name, \
         version, pairing_open_until, registered_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) RETURNING id",
    )
    .bind(user_id)
    .bind(&new.endpoint_id.0[..])
    .bind(password_id)
    .bind(&new.product)
    .bind(&new.platform)
    .bind(&new.name)
    .bind(&new.version)
    .bind(pairing_until)
    .bind(now)
    .fetch_one(&mut **tx)
    .await?;
    let device = get_in(tx, id).await?;
    append_event(
        tx,
        user_id,
        "device.added",
        &json!({ "device": device.entry(false), "at": now }),
        now,
    )
    .await?;
    audit::record(
        &mut **tx,
        &Record::new(user_id, "device.registered", Actor::User)
            .device(new.endpoint_id)
            .client_ip(granted_from)
            .details(json!({
                "product": new.product,
                "platform": new.platform,
                "name": new.name,
            })),
        now,
    )
    .await?;
    Ok(Registration::Registered {
        device: Box::new(device),
        app_password,
        new: true,
    })
}

/// Registers the signed-out entry `id` of `user_id` again (protocol 9.4): it gets a new app
/// password and enters the directory again, so the account's devices get `device.added`.
async fn come_back(
    tx: &mut Tx,
    id: i64,
    user_id: i64,
    new: &NewDevice,
    granted_from: Option<IpAddr>,
    now: i64,
) -> Result<Registration> {
    if count_active_in(tx, user_id).await? >= MAX_DEVICES_PER_ACCOUNT {
        return Ok(Registration::TooMany);
    }
    let app_password = app_passwords::generate_device_token();
    let password_id =
        app_passwords::insert(tx, user_id, &new.name, &[], None, &app_password).await?;
    sqlx::query(
        "UPDATE devices SET app_password_id = ?2, left_at = NULL, product = ?3, platform = ?4, \
         name = ?5, version = ?6, pairing_open_until = ?7 WHERE id = ?1",
    )
    .bind(id)
    .bind(password_id)
    .bind(&new.product)
    .bind(&new.platform)
    .bind(&new.name)
    .bind(&new.version)
    .bind(now.saturating_add(PAIRING_WINDOW_SECS))
    .execute(&mut **tx)
    .await?;
    let device = get_in(tx, id).await?;
    append_event(
        tx,
        user_id,
        "device.added",
        &json!({ "device": device.entry(false), "at": now }),
        now,
    )
    .await?;
    audit::record(
        &mut **tx,
        &Record::new(user_id, "device.reregistered", Actor::User)
            .device(new.endpoint_id)
            .client_ip(granted_from)
            .details(json!({
                "product": new.product,
                "platform": new.platform,
                "name": new.name,
                "after_sign_out": true,
            })),
        now,
    )
    .await?;
    Ok(Registration::Registered {
        device: Box::new(device),
        app_password,
        new: true,
    })
}

async fn count_active_in(tx: &mut Tx, user_id: i64) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices WHERE user_id = ?1 AND app_password_id IS NOT NULL",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?)
}

async fn get_in(tx: &mut Tx, id: i64) -> Result<Device> {
    let row: DeviceRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE id = ?1"
    )))
    .bind(id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.into())
}

/// Every directory entry of `user_id`, revoked ones included, oldest first.
pub async fn list(pool: &Pool, user_id: i64) -> Result<Vec<Device>> {
    let rows: Vec<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE user_id = ?1 ORDER BY id"
    )))
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Device::from).collect())
}

/// The entry with row id `id`.
pub async fn get(pool: &Pool, id: i64) -> Result<Option<Device>> {
    let row: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE id = ?1"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Device::from))
}

/// The entry of key `endpoint_id`, in any account.
pub async fn find(pool: &Pool, endpoint_id: EndpointId) -> Result<Option<Device>> {
    let row: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE endpoint_id = ?1"
    )))
    .bind(&endpoint_id.0[..])
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Device::from))
}

/// The unrevoked device whose credential is app password `app_password_id`.
pub async fn find_by_app_password(pool: &Pool, app_password_id: i64) -> Result<Option<Device>> {
    let row: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE app_password_id = ?1"
    )))
    .bind(app_password_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Device::from))
}

/// Changes to a device's own entry (protocol 6.3). `None` leaves a field as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// New name; see [`check_name`].
    pub name: Option<String>,
    /// Accepts remote connections.
    pub accept_remote: Option<bool>,
    /// Unattended access is on.
    pub unattended: Option<bool>,
    /// ALPNs; see [`check_services`].
    pub services: Option<Vec<String>>,
}

impl Settings {
    /// Whether nothing would change.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.accept_remote.is_none()
            && self.unattended.is_none()
            && self.services.is_none()
    }
}

/// Applies `settings` to the unrevoked device `id`, validating them first. Returns the updated
/// entry, or `None` if the device is gone or revoked. A rename is recorded in the audit log as
/// `actor`'s.
pub async fn update_settings(
    pool: &Pool,
    id: i64,
    settings: &Settings,
    actor: Actor,
    now: i64,
) -> Result<Option<Device>> {
    let name = settings.name.as_deref().map(check_name).transpose()?;
    let services = settings
        .services
        .as_deref()
        .map(check_services)
        .transpose()?
        .map(|services| serde_json::Value::from(services).to_string());
    let mut tx = db::begin_immediate(pool).await?;
    let Some(before) = sqlx::query_as::<_, DeviceRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE id = ?1 AND app_password_id IS NOT NULL"
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .map(Device::from) else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE devices SET name = COALESCE(?2, name), \
         accept_remote = COALESCE(?3, accept_remote), unattended = COALESCE(?4, unattended), \
         services = COALESCE(?5, services) WHERE id = ?1",
    )
    .bind(id)
    .bind(&name)
    .bind(settings.accept_remote)
    .bind(settings.unattended)
    .bind(&services)
    .execute(&mut *tx)
    .await?;
    let after = get_in(&mut tx, id).await?;
    if before.name != after.name {
        audit::record(
            &mut *tx,
            &Record::new(after.user_id, "device.renamed", actor)
                .device(after.endpoint_id)
                .details(json!({ "from": before.name, "to": after.name })),
            now,
        )
        .await?;
    }
    if before.accept_remote != after.accept_remote || before.unattended != after.unattended {
        audit::record(
            &mut *tx,
            &Record::new(after.user_id, "device.settings", actor)
                .device(after.endpoint_id)
                .details(json!({
                    "accept_remote": after.accept_remote,
                    "unattended": after.unattended,
                })),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Some(after))
}

/// Records that device `id` had a control connection at `now`.
pub async fn record_seen(pool: &Pool, id: i64, now: i64) -> Result<()> {
    sqlx::query(
        "UPDATE devices SET last_seen_at = ?2 \
         WHERE id = ?1 AND (last_seen_at IS NULL OR last_seen_at < ?2)",
    )
    .bind(id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Opens the pairing window of the unrevoked device `endpoint_id` of `user_id` until `until`
/// ("Allow pairing" on the account page, protocol 8.6). Returns `false` if there is no such
/// device.
pub async fn open_pairing(
    pool: &Pool,
    user_id: i64,
    endpoint_id: EndpointId,
    until: i64,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let opened = sqlx::query(
        "UPDATE devices SET pairing_open_until = ?3 \
         WHERE user_id = ?1 AND endpoint_id = ?2 AND app_password_id IS NOT NULL",
    )
    .bind(user_id)
    .bind(&endpoint_id.0[..])
    .bind(until)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(opened)
}

/// Where a revocation came from (`by` of protocol 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedBy {
    /// The user, on the account page.
    AccountPage,
    /// An admin, in the admin UI.
    Admin,
    /// The operator, with `gono-cloud device revoke`.
    Cli,
}

impl RevokedBy {
    /// The wire and stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountPage => "account_page",
            Self::Admin => "admin",
            Self::Cli => "cli",
        }
    }

    fn actor(self) -> Actor {
        match self {
            Self::AccountPage => Actor::User,
            Self::Admin => Actor::Admin,
            Self::Cli => Actor::Cli,
        }
    }
}

/// Revokes the unrevoked devices `endpoint_ids` of `user_id` in one transaction (protocol 9.2),
/// signed-out ones included: marks them revoked, deletes their app passwords, appends
/// `device.revoked` for each, and records the audit records. Keys that are not unrevoked
/// devices of the account are skipped. Returns the revoked entries.
pub async fn revoke(
    pool: &Pool,
    user_id: i64,
    endpoint_ids: &[EndpointId],
    by: RevokedBy,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<Vec<Device>> {
    let mut tx = db::begin_immediate(pool).await?;
    let mut revoked = Vec::new();
    for endpoint_id in endpoint_ids {
        let row: Option<(i64, Option<i64>)> = sqlx::query_as(
            "SELECT id, app_password_id FROM devices \
             WHERE user_id = ?1 AND endpoint_id = ?2 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(&endpoint_id.0[..])
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id, app_password_id)) = row else {
            continue;
        };
        sqlx::query(
            "UPDATE devices SET revoked_at = ?2, app_password_id = NULL, \
             pairing_open_until = NULL WHERE id = ?1",
        )
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if let Some(app_password_id) = app_password_id {
            sqlx::query("DELETE FROM app_passwords WHERE id = ?1")
                .bind(app_password_id)
                .execute(&mut *tx)
                .await?;
        }
        // Kept after the account is deleted, which removes the entry (protocol 9.1).
        sqlx::query("INSERT OR IGNORE INTO revoked_keys (endpoint_id, revoked_at) VALUES (?1, ?2)")
            .bind(&endpoint_id.0[..])
            .bind(now)
            .execute(&mut *tx)
            .await?;
        append_event(
            &mut tx,
            user_id,
            "device.revoked",
            &json!({ "endpoint_id": endpoint_id.to_hex(), "at": now, "by": by.as_str() }),
            now,
        )
        .await?;
        revoked.push(get_in(&mut tx, id).await?);
    }
    for device in &revoked {
        let together: Vec<String> = revoked
            .iter()
            .filter(|other| other.id != device.id)
            .map(|other| other.endpoint_id.to_hex())
            .collect();
        audit::record(
            &mut *tx,
            &Record::new(user_id, "device.revoked", by.actor())
                .device(device.endpoint_id)
                .client_ip(client_ip)
                .details(json!({ "by": by.as_str(), "together_with": together })),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(revoked)
}

/// Signs device `id` out (protocol 9.4): deletes its app password and marks the entry signed
/// out. The entry stays, so that the key remains bound to the account and can still be
/// revoked; the device may register again into the same account. `actor` is the device itself,
/// or its user on the account page ("stop remote access"). Returns the entry, or `None` if it
/// was not registered.
pub async fn leave(pool: &Pool, id: i64, actor: Actor, now: i64) -> Result<Option<Device>> {
    let mut tx = db::begin_immediate(pool).await?;
    let Some(device) = sqlx::query_as::<_, DeviceRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM devices WHERE id = ?1 AND app_password_id IS NOT NULL"
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .map(Device::from) else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE devices SET app_password_id = NULL, left_at = ?2, pairing_open_until = NULL \
         WHERE id = ?1",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM app_passwords WHERE id = ?1")
        .bind(device.app_password_id)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut *tx,
        &Record::new(device.user_id, "device.removed", actor).device(device.endpoint_id),
        now,
    )
    .await?;
    let left = get_in(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Some(left))
}

/// The unrevoked devices of `user_id` that `approver` introduced through approvals (protocol
/// 9.1), oldest approval first.
pub async fn introduced_by(pool: &Pool, approver: i64) -> Result<Vec<Device>> {
    let rows: Vec<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {} FROM devices d JOIN device_approvals a ON a.subject_id = d.id \
         WHERE a.approver_id = ?1 AND d.revoked_at IS NULL ORDER BY a.approved_at, d.id",
        COLUMNS
            .split(", ")
            .map(|column| format!("d.{column}"))
            .collect::<Vec<_>>()
            .join(", ")
    )))
    .bind(approver)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Device::from).collect())
}

/// Records an approval (protocol 8.2, step 4) in one transaction: appends the `pair.approved`
/// event with `body` and remembers that `approver` introduced `subject`. Returns the event's
/// sequence number.
pub async fn record_approval(
    pool: &Pool,
    user_id: i64,
    approver: i64,
    subject: i64,
    body: &serde_json::Value,
    now: i64,
) -> Result<i64> {
    let mut tx = db::begin_immediate(pool).await?;
    let seq = append_event(&mut tx, user_id, "pair.approved", body, now).await?;
    sqlx::query(
        "INSERT INTO device_approvals (approver_id, subject_id, approved_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT (approver_id, subject_id) DO UPDATE SET approved_at = excluded.approved_at",
    )
    .bind(approver)
    .bind(subject)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(seq)
}

/// Records that device `device_id` applied the revocations of `revoked` (protocol 9.3). Keys
/// that are not revoked devices of the same account are ignored. Returns the keys recorded.
pub async fn record_applied(
    pool: &Pool,
    device_id: i64,
    revoked: &[EndpointId],
    now: i64,
) -> Result<Vec<EndpointId>> {
    let mut tx = db::begin_immediate(pool).await?;
    let mut recorded = Vec::new();
    for endpoint_id in revoked {
        let inserted = sqlx::query(
            "INSERT INTO revocations_applied (revoked_device_id, device_id, applied_at) \
             SELECT r.id, d.id, ?3 FROM devices r JOIN devices d ON d.user_id = r.user_id \
             WHERE r.endpoint_id = ?2 AND r.revoked_at IS NOT NULL AND d.id = ?1 \
             ON CONFLICT DO NOTHING",
        )
        .bind(device_id)
        .bind(&endpoint_id.0[..])
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 1 {
            recorded.push(*endpoint_id);
        }
    }
    tx.commit().await?;
    Ok(recorded)
}

/// For every revoked device of `user_id`, the devices that applied its revocation:
/// `(revoked device id, device id)` pairs.
pub async fn applied(pool: &Pool, user_id: i64) -> Result<Vec<(i64, i64)>> {
    Ok(sqlx::query_as(
        "SELECT a.revoked_device_id, a.device_id FROM revocations_applied a \
         JOIN devices r ON r.id = a.revoked_device_id WHERE r.user_id = ?1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// A logged event (protocol 5.6).
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Event {
    /// Its number on the control channel.
    pub seq: i64,
    /// The account.
    pub user_id: i64,
    /// `device.added`, `device.revoked` or `pair.approved`.
    pub kind: String,
    /// Its fields as JSON, without `type` and `seq`.
    pub body: String,
    /// When it was appended.
    pub created_at: i64,
}

/// Appends an event to the log of `user_id` inside `tx` and returns its sequence number.
pub(crate) async fn append_event(
    tx: &mut Tx,
    user_id: i64,
    kind: &'static str,
    body: &serde_json::Value,
    now: i64,
) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO device_events (user_id, kind, body, created_at) VALUES (?1, ?2, ?3, ?4) \
         RETURNING seq",
    )
    .bind(user_id)
    .bind(kind)
    .bind(body.to_string())
    .bind(now)
    .fetch_one(&mut **tx)
    .await?)
}

/// Up to `limit` events of `user_id` after `since`, oldest first, and whether events after
/// `since` are missing (so the device cannot catch up from the log alone): removed already, or
/// more than `limit`. When there are more, the newest `limit` are returned: the directory
/// snapshot covers the older additions and revocations, and the newest approvals are the ones
/// still valid.
pub async fn events_since(
    pool: &Pool,
    user_id: i64,
    since: i64,
    limit: i64,
) -> Result<(Vec<Event>, bool)> {
    let mut events: Vec<Event> = sqlx::query_as(
        "SELECT seq, user_id, kind, body, created_at FROM device_events \
         WHERE user_id = ?1 AND seq > ?2 ORDER BY seq DESC LIMIT ?3",
    )
    .bind(user_id)
    .bind(since)
    .bind(limit.saturating_add(1))
    .fetch_all(pool)
    .await?;
    let mut truncated = i64::try_from(events.len()).unwrap_or(i64::MAX) > limit;
    events.truncate(usize::try_from(limit).unwrap_or(0));
    events.reverse();
    // `since` is the last event the device processed, one of this account's. Events are purged
    // oldest first, so if that one is still there, nothing after it is missing. If it is gone,
    // events after it may have been purged too. `since == 0` is a device that never saw any
    // and needs none of the old ones.
    if since > 0 && !truncated {
        let kept: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM device_events WHERE user_id = ?1 AND seq = ?2")
                .bind(user_id)
                .bind(since)
                .fetch_optional(pool)
                .await?;
        truncated = kept.is_none();
    }
    Ok((events, truncated))
}

/// Up to `limit` events of every account after `seq`, oldest first: what the control channel
/// still has to send.
pub async fn events_after(pool: &Pool, seq: i64, limit: i64) -> Result<Vec<Event>> {
    Ok(sqlx::query_as(
        "SELECT seq, user_id, kind, body, created_at FROM device_events \
         WHERE seq > ?1 ORDER BY seq LIMIT ?2",
    )
    .bind(seq)
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

/// The highest sequence number ever handed out, 0 if none.
pub async fn last_seq(pool: &Pool) -> Result<i64> {
    // `sqlite_sequence` remembers the highest AUTOINCREMENT value even after rows are purged.
    let seq: Option<i64> =
        sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'device_events'")
            .fetch_optional(pool)
            .await?;
    Ok(seq.unwrap_or(0))
}

/// Removes every event appended before `before`. Returns how many there were.
pub async fn purge_events(pool: &Pool, before: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query("DELETE FROM device_events WHERE created_at < ?1")
        .bind(before)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(purged)
}

/// Whether remote access is available on account `user_id`: it is enabled and, if
/// `require_two_factor` (`connect.require_two_factor`), has two-step verification enrolled.
pub async fn remote_access(pool: &Pool, user_id: i64, require_two_factor: bool) -> Result<bool> {
    let available: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM users u LEFT JOIN two_factor t ON t.user_id = u.id \
         WHERE u.id = ?1 AND u.enabled = 1 AND (?2 = 0 OR t.user_id IS NOT NULL)",
    )
    .bind(user_id)
    .bind(require_two_factor)
    .fetch_optional(pool)
    .await?;
    Ok(available.is_some())
}

/// The keys the relay admits from the directory (protocol 11.1): registered devices (neither
/// revoked nor signed out) of enabled accounts, with two-step verification if
/// `require_two_factor`.
pub async fn admissible(pool: &Pool, require_two_factor: bool) -> Result<Vec<EndpointId>> {
    let keys: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT d.endpoint_id FROM devices d JOIN users u ON u.id = d.user_id \
         LEFT JOIN two_factor t ON t.user_id = u.id \
         WHERE d.app_password_id IS NOT NULL AND u.enabled = 1 \
         AND (?1 = 0 OR t.user_id IS NOT NULL)",
    )
    .bind(require_two_factor)
    .fetch_all(pool)
    .await?;
    Ok(keys
        .iter()
        .filter_map(|key| EndpointId::from_slice(key))
        .collect())
}

/// The keys of revoked devices (tombstones), with their accounts.
pub async fn revoked_keys(pool: &Pool) -> Result<Vec<(EndpointId, i64)>> {
    let rows: Vec<(Vec<u8>, i64)> =
        sqlx::query_as("SELECT endpoint_id, user_id FROM devices WHERE revoked_at IS NOT NULL")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(key, user_id)| Some((EndpointId::from_slice(&key)?, user_id)))
        .collect())
}

/// The enabled accounts.
pub async fn enabled_accounts(pool: &Pool) -> Result<Vec<i64>> {
    Ok(sqlx::query_scalar("SELECT id FROM users WHERE enabled = 1")
        .fetch_all(pool)
        .await?)
}

/// The accounts on which remote access is available: enabled, with two-step verification if
/// `require_two_factor`.
pub async fn remote_access_accounts(pool: &Pool, require_two_factor: bool) -> Result<Vec<i64>> {
    Ok(sqlx::query_scalar(
        "SELECT u.id FROM users u LEFT JOIN two_factor t ON t.user_id = u.id \
         WHERE u.enabled = 1 AND (?1 = 0 OR t.user_id IS NOT NULL)",
    )
    .bind(require_two_factor)
    .fetch_all(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_ids_are_lowercase_hex() {
        let hex = "3f6a".repeat(16);
        let id = EndpointId::parse(&hex).unwrap();
        assert_eq!(id.to_hex(), hex);
        assert_eq!(id.short(), "3F6A-3F6A-3F6A-3F6A");
        assert!(EndpointId::parse(&hex.to_ascii_uppercase()).is_none());
        assert!(EndpointId::parse(&hex[..62]).is_none());
        assert!(EndpointId::parse(&format!("{}zz", &hex[..62])).is_none());
    }

    #[test]
    fn fields_are_checked() {
        assert_eq!(check_slug("product", "input-show").unwrap(), "input-show");
        assert!(check_slug("product", "Input Show").is_err());
        assert!(check_slug("product", "").is_err());
        assert!(check_slug("platform", &"a".repeat(33)).is_err());
        assert_eq!(check_name("  Home PC ").unwrap(), "Home PC");
        assert!(check_name("a\u{7}b").is_err());
        assert!(check_name("Home \u{202E}CP").is_err());
        assert!(check_name("Home\u{200B}PC").is_err());
        assert!(check_name(&"x".repeat(65)).is_err());
        assert_eq!(check_version("").unwrap(), "");
        assert_eq!(
            check_services(&["inputshow/1".to_owned(), "inputshow/1".to_owned()]).unwrap(),
            ["inputshow/1"]
        );
        assert!(check_services(&["with space".to_owned()]).is_err());
    }
}
