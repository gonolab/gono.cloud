//! The audit log (`audit_log` table): who did what to which device, and when.
//!
//! The kinds and their fields are listed in `docs/connect-protocol.md`, section 12. A record
//! never holds content (keys typed, clipboard, file names) and never an address that a device
//! published; `client_ip` is the address a request came from, recorded only for the kinds that
//! the protocol names. Records are removed after the retention period by [`purge`].

use std::net::IpAddr;

use sqlx::{FromRow, SqliteExecutor};

use crate::{
    db::{self, Pool},
    devices::EndpointId,
    error::Result,
};

/// Default retention of audit records, in seconds (180 days).
pub const DEFAULT_RETENTION_SECS: i64 = 180 * 24 * 60 * 60;

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// The account's user, in the browser.
    User,
    /// An admin, in the admin UI.
    Admin,
    /// The operator, with the `gono-cloud` command line.
    Cli,
    /// A device, on the control channel or with its app password.
    Device,
    /// The server itself (expiry, relay refusals).
    Server,
}

impl Actor {
    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Cli => "cli",
            Self::Device => "device",
            Self::Server => "server",
        }
    }
}

/// A record to write.
#[derive(Debug, Clone)]
pub struct Record {
    /// The account it belongs to.
    pub user_id: Option<i64>,
    /// `device.registered`, `connect.requested`, ...
    pub kind: &'static str,
    /// Who acted.
    pub actor: Actor,
    /// The device it is about.
    pub device: Option<EndpointId>,
    /// The other device involved.
    pub peer: Option<EndpointId>,
    /// Where the request came from, for the kinds that record it.
    pub client_ip: Option<IpAddr>,
    /// Further fields.
    pub details: serde_json::Value,
}

impl Record {
    /// A record of `kind` by `actor` for account `user_id`, without devices or details.
    pub fn new(user_id: i64, kind: &'static str, actor: Actor) -> Self {
        Self {
            user_id: Some(user_id),
            kind,
            actor,
            device: None,
            peer: None,
            client_ip: None,
            details: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Sets the device the record is about.
    pub fn device(mut self, device: EndpointId) -> Self {
        self.device = Some(device);
        self
    }

    /// Sets the other device involved.
    pub fn peer(mut self, peer: EndpointId) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Sets the client address.
    pub fn client_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.client_ip = ip;
        self
    }

    /// Sets the details.
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// A stored record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Row id; newer records have larger ids.
    pub id: i64,
    /// The account.
    pub user_id: Option<i64>,
    /// When, UNIX seconds.
    pub at: i64,
    /// The kind.
    pub kind: String,
    /// Who acted.
    pub actor: String,
    /// The device it is about.
    pub device: Option<EndpointId>,
    /// The other device.
    pub peer: Option<EndpointId>,
    /// Where the request came from.
    pub client_ip: Option<String>,
    /// Further fields, as JSON.
    pub details: String,
}

#[derive(FromRow)]
struct EntryRow {
    id: i64,
    user_id: Option<i64>,
    at: i64,
    kind: String,
    actor: String,
    device: Option<Vec<u8>>,
    peer: Option<Vec<u8>>,
    client_ip: Option<String>,
    details: String,
}

impl From<EntryRow> for Entry {
    fn from(row: EntryRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            at: row.at,
            kind: row.kind,
            actor: row.actor,
            device: row.device.as_deref().and_then(EndpointId::from_slice),
            peer: row.peer.as_deref().and_then(EndpointId::from_slice),
            client_ip: row.client_ip,
            details: row.details,
        }
    }
}

/// Writes `record` at `now`, inside a transaction or on its own.
pub async fn record<'c>(
    executor: impl SqliteExecutor<'c>,
    record: &Record,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (user_id, at, kind, actor, device, peer, client_ip, details) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(record.user_id)
    .bind(now)
    .bind(record.kind)
    .bind(record.actor.as_str())
    .bind(record.device.map(|id| id.0.to_vec()))
    .bind(record.peer.map(|id| id.0.to_vec()))
    .bind(record.client_ip.map(|ip| ip.to_canonical().to_string()))
    .bind(record.details.to_string())
    .execute(executor)
    .await?;
    Ok(())
}

/// The newest records, newest first: of account `user_id`, or of every account for `None`.
/// With `before`, only records older than that id (for paging).
pub async fn list(
    pool: &Pool,
    user_id: Option<i64>,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<Entry>> {
    let rows: Vec<EntryRow> = sqlx::query_as(
        "SELECT id, user_id, at, kind, actor, device, peer, client_ip, details FROM audit_log \
         WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR id < ?2) \
         ORDER BY id DESC LIMIT ?3",
    )
    .bind(user_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Entry::from).collect())
}

/// Removes every record written before `before`. Returns how many there were.
pub async fn purge(pool: &Pool, before: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query("DELETE FROM audit_log WHERE at < ?1")
        .bind(before)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(purged)
}
