//! Pending Login Flow v2 sign-ins and device registrations (`login_flows` table).
//!
//! 1. [`create`]: a client starts a flow and receives two random tokens, one to poll with and
//!    one embedded in the login URL it opens in the browser. Only their digests are stored.
//!    [`create_device`] starts the registration of a device for remote access, which also
//!    gets a random challenge to sign (`docs/connect-protocol.md`, section 4).
//! 2. [`find`] / [`grant`] / [`deny`]: the browser pages look the flow up by the login token;
//!    after the user signed in with the web login password and approved the device on the
//!    consent page, the flow is marked as granted to that user. A phone app that signs in with
//!    WeChat finds its own registration by the poll token instead ([`find_device`]).
//! 3. [`complete`]: the client's next poll consumes the granted flow and mints a new app
//!    password (full access, labeled with the client's name) in the same transaction, and
//!    returns it exactly once. The plaintext is never stored. A registering device polls with
//!    [`device_poll`], proves its key against the challenge, and [`complete_device`] then
//!    registers it ([`crate::devices`]).
//!
//! Flows expire [`FLOW_TTL_SECS`] after they were started, are single-use, and expired ones
//! are removed by a background task ([`purge_expired`]). At most [`MAX_PENDING_FLOWS`] live
//! flows exist at a time, so that anonymous clients cannot grow the table without bound. A
//! Nextcloud flow never registers a device and a device flow never mints a full-access app
//! password: each kind of poll consumes only its own kind of flow.

use std::net::IpAddr;

use rand::RngExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;

use crate::{
    app_passwords::{self, Scope},
    db::{self, Flag, Pool, Text},
    devices::{self, EndpointId, NewDevice, Registration},
    error::Result,
    secret,
    types::Username,
};

/// Lifetime of a flow, in seconds (20 minutes, like Nextcloud).
pub const FLOW_TTL_SECS: i64 = 20 * 60;

/// Most live flows at a time.
pub const MAX_PENDING_FLOWS: i64 = 1000;

/// Length of the poll and login tokens (about 380 bits; Nextcloud uses 128 characters).
const TOKEN_CHARS: usize = 64;

/// Label of an app password whose client sent no usable name.
const FALLBACK_LABEL: &str = "Login Flow v2 device";

/// The tokens of a new flow, returned once.
#[derive(Debug)]
pub struct NewFlow {
    /// Token the client polls with.
    pub poll_token: SecretString,
    /// Token in the login URL.
    pub login_token: SecretString,
    /// Expiry, UNIX seconds.
    pub expires_at: i64,
}

/// What a registering device reported, as the consent page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDevice {
    /// The device's key.
    pub endpoint_id: EndpointId,
    /// `input-show`, ...
    pub product: String,
    /// `macos`, ...
    pub platform: String,
    /// Product version, possibly empty.
    pub version: String,
}

/// A live flow, as the browser pages see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// Row id.
    pub id: i64,
    /// Name of the client that started the flow (for a device: the name it reported).
    pub client_name: String,
    /// The user who approved it, once approved.
    pub granted_user_id: Option<i64>,
    /// Expiry, UNIX seconds.
    pub expires_at: i64,
    /// For a device registration: the device.
    pub device: Option<FlowDevice>,
}

#[derive(FromRow)]
struct FlowRow {
    id: i64,
    client_name: String,
    granted_user_id: Option<i64>,
    expires_at: i64,
    device_endpoint_id: Option<Vec<u8>>,
    device_product: Option<String>,
    device_platform: Option<String>,
    device_version: Option<String>,
}

impl From<FlowRow> for Flow {
    fn from(row: FlowRow) -> Self {
        let device = row
            .device_endpoint_id
            .as_deref()
            .and_then(EndpointId::from_slice)
            .map(|endpoint_id| FlowDevice {
                endpoint_id,
                product: row.device_product.unwrap_or_default(),
                platform: row.device_platform.unwrap_or_default(),
                version: row.device_version.unwrap_or_default(),
            });
        Self {
            id: row.id,
            client_name: row.client_name,
            granted_user_id: row.granted_user_id,
            expires_at: row.expires_at,
            device,
        }
    }
}

/// What a completed flow hands to the client.
#[derive(Debug)]
pub struct Credentials {
    /// Login name of the user who approved the device.
    pub username: Username,
    /// The newly minted app password.
    pub app_password: SecretString,
    /// Its id.
    pub app_password_id: i64,
    /// Its label.
    pub label: String,
}

/// Starts a flow for a client named `client_name`. Returns `None` when
/// [`MAX_PENDING_FLOWS`] live flows exist.
pub async fn create(pool: &Pool, client_name: &str, now: i64) -> Result<Option<NewFlow>> {
    insert(pool, client_name, None, now).await
}

/// Starts the registration of `device` (protocol 4.1). Returns the tokens and the challenge
/// the device must sign, or `None` when [`MAX_PENDING_FLOWS`] live flows exist.
pub async fn create_device(
    pool: &Pool,
    device: &NewDevice,
    now: i64,
) -> Result<Option<(NewFlow, [u8; 32])>> {
    let challenge: [u8; 32] = rand::rng().random();
    let flow = insert(pool, &device.name, Some((device, challenge)), now).await?;
    Ok(flow.map(|flow| (flow, challenge)))
}

async fn insert(
    pool: &Pool,
    client_name: &str,
    device: Option<(&NewDevice, [u8; 32])>,
    now: i64,
) -> Result<Option<NewFlow>> {
    let poll_token = secret::random_token(TOKEN_CHARS);
    let login_token = secret::random_token(TOKEN_CHARS);
    let expires_at = now.saturating_add(FLOW_TTL_SECS);
    let mut tx = db::begin_immediate(pool).await?;
    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM login_flows WHERE expires_at > ?")
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
    if live >= MAX_PENDING_FLOWS {
        return Ok(None);
    }
    let id = db::next_id(&mut tx, "login_flows").await?;
    sqlx::query(
        "INSERT INTO login_flows (id, poll_token_hash, login_token_hash, client_name, \
         created_at, expires_at, device_endpoint_id, device_product, device_platform, \
         device_version, device_challenge) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&secret::digest(poll_token.expose_secret())[..])
    .bind(&secret::digest(login_token.expose_secret())[..])
    .bind(client_name)
    .bind(now)
    .bind(expires_at)
    .bind(device.map(|(device, _)| device.endpoint_id.0.to_vec()))
    .bind(device.map(|(device, _)| device.product.clone()))
    .bind(device.map(|(device, _)| device.platform.clone()))
    .bind(device.map(|(device, _)| device.version.clone()))
    .bind(device.map(|(_, challenge)| challenge.to_vec()))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(NewFlow {
        poll_token,
        login_token,
        expires_at,
    }))
}

/// The live flow whose login URL carries `login_token`.
pub async fn find(pool: &Pool, login_token: &str, now: i64) -> Result<Option<Flow>> {
    let row: Option<FlowRow> = sqlx::query_as(
        "SELECT id, client_name, granted_user_id, expires_at, device_endpoint_id, \
         device_product, device_platform, device_version FROM login_flows \
         WHERE login_token_hash = ? AND expires_at > ?",
    )
    .bind(&secret::digest(login_token)[..])
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Flow::from))
}

/// The live device registration polled with `poll_token`: what a device's own sign-in sees of
/// its flow (an app's WeChat login, `POST /gono/v1/login/wechat`), as [`find`] gives it to the
/// browser pages. Refused registrations are not live.
pub async fn find_device(pool: &Pool, poll_token: &str, now: i64) -> Result<Option<Flow>> {
    let row: Option<FlowRow> = sqlx::query_as(
        "SELECT id, client_name, granted_user_id, expires_at, device_endpoint_id, \
         device_product, device_platform, device_version FROM login_flows \
         WHERE poll_token_hash = ? AND expires_at > ? AND device_endpoint_id IS NOT NULL \
         AND refusal IS NULL",
    )
    .bind(&secret::digest(poll_token)[..])
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Flow::from))
}

/// Records that `user_id` approved the live, not yet approved flow `id`, from a browser at
/// `client_ip`. Returns `false` if there is no such flow.
pub async fn grant(
    pool: &Pool,
    id: i64,
    user_id: i64,
    client_ip: Option<IpAddr>,
    now: i64,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let granted = sqlx::query(
        "UPDATE login_flows SET granted_user_id = ?, granted_client_ip = ? \
         WHERE id = ? AND granted_user_id IS NULL AND expires_at > ?",
    )
    .bind(user_id)
    .bind(client_ip.map(|ip| ip.to_canonical().to_string()))
    .bind(id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(granted)
}

/// Ends the flow `id` without granting anything. Returns `false` if there was none.
pub async fn deny(pool: &Pool, id: i64) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let denied = sqlx::query("DELETE FROM login_flows WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(denied)
}

/// Completes the approved flow polled with `poll_token`: deletes it and mints a new app
/// password for the approving user in the same transaction. Returns `None` while the flow is
/// pending, and for unknown, expired or already completed flows, and for device
/// registrations. A flow approved by an account that was disabled since then is consumed
/// without minting anything.
pub async fn complete(pool: &Pool, poll_token: &str, now: i64) -> Result<Option<Credentials>> {
    let mut tx = db::begin_immediate(pool).await?;
    // Selected, then deleted: the write transaction keeps anyone else from consuming it in
    // between.
    let flow: Option<(i64, String, i64)> = sqlx::query_as(
        "SELECT id, client_name, granted_user_id FROM login_flows WHERE poll_token_hash = ? \
         AND granted_user_id IS NOT NULL AND expires_at > ? AND device_endpoint_id IS NULL",
    )
    .bind(&secret::digest(poll_token)[..])
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((flow_id, client_name, user_id)) = flow else {
        return Ok(None);
    };
    sqlx::query("DELETE FROM login_flows WHERE id = ?")
        .bind(flow_id)
        .execute(&mut *tx)
        .await?;
    // The account may have been disabled, or lost WebDAV, since it granted the flow: the flow
    // is used up without an app password then.
    let user: Option<(Text, Flag, Flag)> =
        sqlx::query_as("SELECT username, enabled, service_webdav FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((Text(username), Flag(true), Flag(true))) = user else {
        tx.commit().await?;
        return Ok(None);
    };
    let label =
        app_passwords::check_label(&client_name).unwrap_or_else(|_| FALLBACK_LABEL.to_owned());
    let app_password = app_passwords::generate_device_token();
    let app_password_id = app_passwords::insert(
        &mut tx,
        user_id,
        &label,
        &[Scope::full_access()],
        None,
        &app_password,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(Credentials {
        username: Username::new(username)?,
        app_password,
        app_password_id,
        label,
    }))
}

/// The state of a device registration, as its poll sees it (protocol 4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePoll {
    /// The user has not decided yet.
    Pending,
    /// The consent page refused the registration because of the account; the reason is an
    /// error code of protocol 4.3 (`service_not_enabled`). The flow is used up.
    Refused(String),
    /// Unknown, expired, used, denied, or not a device registration.
    Gone,
    /// Granted: the device must now prove that it holds `endpoint_id` by signing `challenge`.
    Granted {
        /// The key the flow registers.
        endpoint_id: EndpointId,
        /// The challenge of the flow.
        challenge: [u8; 32],
    },
}

/// Looks up the device registration polled with `poll_token` without consuming it.
pub async fn device_poll(pool: &Pool, poll_token: &str, now: i64) -> Result<DevicePoll> {
    type Row = (i64, Option<i64>, Vec<u8>, Vec<u8>, Option<Text>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, granted_user_id, device_endpoint_id, device_challenge, refusal \
         FROM login_flows \
         WHERE poll_token_hash = ? AND expires_at > ? AND device_endpoint_id IS NOT NULL",
    )
    .bind(&secret::digest(poll_token)[..])
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        None => DevicePoll::Gone,
        Some((id, _, _, _, Some(Text(reason)))) => {
            // Told once: the flow ends with this answer.
            let mut tx = db::begin_immediate(pool).await?;
            sqlx::query("DELETE FROM login_flows WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            DevicePoll::Refused(reason)
        }
        Some((_, None, _, _, None)) => DevicePoll::Pending,
        Some((_, Some(_), endpoint_id, challenge, None)) => {
            match (
                EndpointId::from_slice(&endpoint_id),
                <[u8; 32]>::try_from(challenge.as_slice()),
            ) {
                (Some(endpoint_id), Ok(challenge)) => DevicePoll::Granted {
                    endpoint_id,
                    challenge,
                },
                _ => DevicePoll::Gone,
            }
        }
    })
}

/// Refuses the pending device registration `id` because of its account, with `reason`, an
/// error code of protocol 4.3 that the device's next poll gets (`service_not_enabled`).
/// Returns `false` if there is no such pending registration.
pub async fn refuse_device(pool: &Pool, id: i64, reason: &'static str) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let refused = sqlx::query(
        "UPDATE login_flows SET refusal = ? WHERE id = ? AND granted_user_id IS NULL \
         AND device_endpoint_id IS NOT NULL",
    )
    .bind(reason)
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    tx.commit().await?;
    Ok(refused)
}

/// How [`complete_device`] ended.
#[derive(Debug)]
pub enum DeviceCompletion {
    /// The flow is not (or no longer) granted, or its account was disabled since.
    Gone,
    /// The account lost the direct connection service since it granted the flow, which is
    /// used up (`service_not_enabled`).
    ServiceNotEnabled,
    /// The registration ran.
    Done(Username, Registration),
}

impl DeviceCompletion {
    /// The account and outcome of a registration that ran.
    pub fn done(self) -> Option<(Username, Registration)> {
        match self {
            Self::Done(username, registration) => Some((username, registration)),
            Self::Gone | Self::ServiceNotEnabled => None,
        }
    }
}

/// Completes the granted device registration polled with `poll_token`, once the caller has
/// checked the device's proof (protocol 4.3): deletes the flow and registers the device in the
/// same transaction ([`devices::register`]). Returns `None` for a flow that is not (or no
/// longer) granted, and consumes the flow without registering anything when the account was
/// disabled since. Every outcome of [`Registration`] other than `TooMany` consumes the flow;
/// `TooMany` does too, since the user has to free a place and sign the device in again.
pub async fn complete_device(pool: &Pool, poll_token: &str, now: i64) -> Result<DeviceCompletion> {
    let mut tx = db::begin_immediate(pool).await?;
    type Row = (
        i64,
        String,
        i64,
        Option<String>,
        Vec<u8>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    // Selected, then deleted, as in `complete`.
    let flow: Option<Row> = sqlx::query_as(
        "SELECT id, client_name, granted_user_id, granted_client_ip, device_endpoint_id, \
         device_product, device_platform, device_version FROM login_flows \
         WHERE poll_token_hash = ? AND granted_user_id IS NOT NULL AND expires_at > ? \
         AND device_endpoint_id IS NOT NULL",
    )
    .bind(&secret::digest(poll_token)[..])
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((flow_id, name, user_id, granted_ip, endpoint_id, product, platform, version)) = flow
    else {
        return Ok(DeviceCompletion::Gone);
    };
    sqlx::query("DELETE FROM login_flows WHERE id = ?")
        .bind(flow_id)
        .execute(&mut *tx)
        .await?;
    let user: Option<(Text, Flag, Flag)> =
        sqlx::query_as("SELECT username, enabled, service_direct FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let (Some((Text(username), Flag(true), direct)), Some(endpoint_id)) =
        (user, EndpointId::from_slice(&endpoint_id))
    else {
        tx.commit().await?;
        return Ok(DeviceCompletion::Gone);
    };
    if !direct.0 {
        tx.commit().await?;
        return Ok(DeviceCompletion::ServiceNotEnabled);
    }
    let new = NewDevice {
        endpoint_id,
        product: product.unwrap_or_default(),
        platform: platform.unwrap_or_default(),
        name,
        version: version.unwrap_or_default(),
    };
    let granted_from = granted_ip.and_then(|ip| ip.parse().ok());
    let registration = devices::register(&mut tx, user_id, &new, granted_from, now).await?;
    tx.commit().await?;
    Ok(DeviceCompletion::Done(
        Username::new(username)?,
        registration,
    ))
}

/// Removes every flow that expired at `now`. Returns how many there were.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query("DELETE FROM login_flows WHERE expires_at <= ?")
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(purged)
}
