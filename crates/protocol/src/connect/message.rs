//! The control channel's messages (protocol 5): one JSON object per WebSocket text frame,
//! with its kind in `type`.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::{DeviceId, Signed};

/// A directory entry (protocol 6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// The device's key.
    pub endpoint_id: DeviceId,
    /// Its name.
    pub name: String,
    /// `input-show`, ...
    pub product: String,
    /// `macos`, ...
    pub platform: String,
    /// Product version, possibly empty.
    #[serde(default)]
    pub version: String,
    /// When it registered.
    pub registered_at: i64,
    /// It has a control connection.
    #[serde(default)]
    pub online: bool,
    /// When it last had one.
    #[serde(default)]
    pub last_seen_at: Option<i64>,
    /// It accepts remote connections.
    #[serde(default)]
    pub accept_remote: bool,
    /// Unattended access is on.
    #[serde(default)]
    pub unattended: bool,
    /// The ALPNs it accepts.
    #[serde(default)]
    pub services: Vec<String>,
    /// When it was revoked.
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

/// Changes to a device's own entry (protocol 6.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsChange {
    /// New name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Accepts remote connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_remote: Option<bool>,
    /// Unattended access is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unattended: Option<bool>,
    /// The ALPNs it accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
}

/// Why a device opens a connection (protocol 7.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    /// An ordinary connection.
    #[default]
    Session,
    /// The approver of a pending pairing request dials the new device.
    Pair,
}

/// `started` or `ended` (protocol 12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionEvent {
    /// The session started.
    Started,
    /// The session ended.
    Ended,
}

/// The `hello` message (protocol 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloMessage {
    /// The signed `hello` statement.
    pub proof: Signed,
    /// The last logged event the device processed.
    #[serde(default)]
    pub since: i64,
    /// Product version.
    #[serde(default)]
    pub version: String,
    /// Optional features the device supports.
    #[serde(default)]
    pub features: Vec<String>,
    /// Settings to apply at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SettingsChange>,
}

/// A session report (protocol 12.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReport {
    /// `started` or `ended`.
    pub event: SessionEvent,
    /// Random, 16 bytes in base64url, the same in both reports of a session.
    pub session_id: String,
    /// The other device.
    pub peer: DeviceId,
    /// `controller`, `controlled`, `initiator` or `acceptor`.
    pub role: String,
    /// The ALPN.
    pub service: String,
    /// When it started.
    pub started_at: i64,
    /// When it ended.
    #[serde(default)]
    pub ended_at: Option<i64>,
    /// `direct`, `relayed` or `mixed`.
    pub path: String,
    /// Bytes over direct paths.
    #[serde(default)]
    pub bytes_direct: Option<u64>,
    /// Bytes over the relay.
    #[serde(default)]
    pub bytes_relayed: Option<u64>,
}

/// What a device sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Opens the channel (protocol 5.2).
    #[serde(rename = "hello")]
    Hello(HelloMessage),
    /// Changes the device's own entry (protocol 6.3).
    #[serde(rename = "settings")]
    Settings {
        /// Request id.
        id: u64,
        /// The changes.
        #[serde(flatten)]
        change: SettingsChange,
    },
    /// The device's addresses (protocol 7.1).
    #[serde(rename = "publish")]
    Publish {
        /// Request id.
        id: u64,
        /// Its home relay.
        #[serde(default)]
        relay_url: Option<String>,
        /// Its direct addresses.
        #[serde(default)]
        direct: Vec<SocketAddr>,
    },
    /// The device means to connect to `target` (protocol 7.2).
    #[serde(rename = "connect")]
    Connect {
        /// Request id.
        id: u64,
        /// The device to reach.
        target: DeviceId,
        /// The ALPN.
        service: String,
        /// Why.
        #[serde(default)]
        purpose: Purpose,
        /// For `pair`: the pending request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    /// Fresh addresses of a device the caller is connecting to (protocol 7.3).
    #[serde(rename = "lookup")]
    Lookup {
        /// Request id.
        id: u64,
        /// The device.
        target: DeviceId,
    },
    /// A session report (protocol 12.2).
    #[serde(rename = "session")]
    Session {
        /// Request id.
        id: u64,
        /// The report.
        #[serde(flatten)]
        report: SessionReport,
    },
    /// A new device asks to join (protocol 8.2, step 1).
    #[serde(rename = "pair.request")]
    PairRequest {
        /// Request id.
        id: u64,
        /// The signed `pair-request` statement.
        request: Signed,
    },
    /// An approver vouches for the new device (protocol 8.2, step 4).
    #[serde(rename = "pair.approve")]
    PairApprove {
        /// Request id.
        id: u64,
        /// The pending request.
        request_id: String,
        /// The signed `pair-approval` statement.
        approval: Signed,
    },
    /// A device of the account declines a pending request.
    #[serde(rename = "pair.decline")]
    PairDecline {
        /// Request id.
        id: u64,
        /// The pending request.
        request_id: String,
    },
    /// The new device withdraws its request.
    #[serde(rename = "pair.withdraw")]
    PairWithdraw {
        /// Request id.
        id: u64,
        /// The pending request.
        request_id: String,
    },
    /// The device applied revocations (protocol 9.3).
    #[serde(rename = "revocations.applied")]
    RevocationsApplied {
        /// Request id.
        id: u64,
        /// The revoked devices.
        endpoint_ids: Vec<DeviceId>,
    },
    /// The device processed the logged events up to `seq` (protocol 5.6).
    #[serde(rename = "ack")]
    Ack {
        /// Request id.
        id: u64,
        /// The last processed sequence number.
        seq: i64,
    },
    /// The device signs out (protocol 9.4).
    #[serde(rename = "leave")]
    Leave {
        /// Request id.
        id: u64,
    },
}

impl ClientMessage {
    /// The request id; `None` for `hello`.
    pub fn id(&self) -> Option<u64> {
        match self {
            Self::Hello(_) => None,
            Self::Settings { id, .. }
            | Self::Publish { id, .. }
            | Self::Connect { id, .. }
            | Self::Lookup { id, .. }
            | Self::Session { id, .. }
            | Self::PairRequest { id, .. }
            | Self::PairApprove { id, .. }
            | Self::PairDecline { id, .. }
            | Self::PairWithdraw { id, .. }
            | Self::RevocationsApplied { id, .. }
            | Self::Ack { id, .. }
            | Self::Leave { id } => Some(*id),
        }
    }

    /// The `type` values of version 1.
    pub const TYPES: &[&str] = &[
        "hello",
        "settings",
        "publish",
        "connect",
        "lookup",
        "session",
        "pair.request",
        "pair.approve",
        "pair.decline",
        "pair.withdraw",
        "revocations.applied",
        "ack",
        "leave",
    ];
}

/// The `type` and `id` of a frame, read before the rest so that an unknown type can be told
/// from a malformed message.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Envelope {
    /// The message kind.
    #[serde(rename = "type")]
    pub kind: String,
    /// The request id, if any.
    #[serde(default)]
    pub id: Option<u64>,
}

/// The account, as `welcome` describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Username.
    pub username: String,
    /// Display name.
    pub display_name: String,
    /// Remote access is available: the account may use direct connections and, if the server
    /// requires it, has two-step verification enrolled.
    pub remote_access: bool,
    /// How much of the relay the account's devices may use, while remote access is available
    /// (protocol 11.1). Absent from servers before services per account, which relay every
    /// device at the full rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayAccess>,
    /// Whether the account has two-step verification enrolled, whatever the server requires
    /// (`connect.require_two_factor`, which `two_factor_required` of the discovery document
    /// gives). Products may allow more to accounts that have it. Absent from older servers:
    /// `None` means unknown, never "off".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub two_factor: Option<bool>,
}

/// How much of the relay the devices of an account may use (protocol 11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAccess {
    /// Relaying at the full rate: the account has the relay service.
    Full,
    /// Relaying at a limited rate, enough for handshakes and for setting up a direct
    /// connection, but not for a session: the account has direct connections only.
    Limited,
    /// A value a newer server sent.
    #[serde(other)]
    Unknown,
}

/// A pending pairing request, as other devices see it (protocol 8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequested {
    /// Its id.
    pub request_id: String,
    /// When it expires.
    pub expires_at: i64,
    /// The new device's directory entry.
    pub requester: DeviceEntry,
    /// The signed `pair-request` statement.
    pub request: Signed,
}

/// The limits that apply to a connection (protocol 15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionLimits {
    /// Largest frame, in bytes.
    pub max_frame_bytes: usize,
    /// Requests per second.
    pub requests_per_second: u32,
    /// Burst of requests.
    pub request_burst: u32,
    /// Direct addresses per `publish`.
    pub max_direct_addresses: usize,
    /// How long after `connect` a `lookup` of the same target is allowed, in seconds.
    pub lookup_window_secs: u64,
}

/// The `welcome` message (protocol 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    /// The server's clock.
    pub server_time: i64,
    /// The account.
    pub account: AccountInfo,
    /// The device's own entry.
    pub device: DeviceEntry,
    /// The relay to use.
    pub relay_url: String,
    /// Every entry of the account, revoked ones included.
    pub devices: Vec<DeviceEntry>,
    /// Pending pairing requests.
    pub pair_requests: Vec<PairRequested>,
    /// Logged events after `hello.since`, oldest first.
    pub events: Vec<ServerMessage>,
    /// Events after `since` were removed or more are due than `events` holds.
    pub events_truncated: bool,
    /// The last sequence number the server has handed out.
    pub cursor: i64,
    /// Optional features the server supports.
    pub features: Vec<String>,
    /// The limits of this connection.
    pub limits: ConnectionLimits,
}

/// The error codes of protocol 5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed message or field.
    BadRequest,
    /// Unknown request type.
    UnknownType,
    /// A statement failed verification.
    BadSignature,
    /// No such device or request, or none the caller may know of.
    NotFound,
    /// The authorization rules refuse it.
    NotPermitted,
    /// Remote access is not available on this account: two-step verification is required.
    TwoFactorRequired,
    /// Remote access is not available on this account: it may not use direct connections
    /// (services per account).
    ServiceNotEnabled,
    /// The target has no control connection.
    NotOnline,
    /// The state changed.
    Conflict,
    /// Over a limit.
    RateLimited,
    /// The server cannot answer now.
    Unavailable,
    /// A code a newer server sent.
    #[serde(other)]
    Unknown,
}

/// What `connect` and `lookup` answer (protocol 7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressResult {
    /// The device.
    pub target: DeviceId,
    /// Its home relay.
    #[serde(default)]
    pub relay_url: Option<String>,
    /// Its direct addresses.
    #[serde(default)]
    pub direct: Vec<SocketAddr>,
    /// When it published them.
    #[serde(default)]
    pub published_at: Option<i64>,
}

/// What `pair.request` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequestResult {
    /// The request's id.
    pub request_id: String,
    /// When it expires.
    pub expires_at: i64,
}

/// What `settings` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsResult {
    /// The updated entry.
    pub device: DeviceEntry,
}

/// What the server sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// The first frame (protocol 5.2).
    #[serde(rename = "challenge")]
    Challenge {
        /// 32 random bytes, base64url.
        nonce: String,
        /// The server's clock.
        server_time: i64,
    },
    /// The answer to `hello`.
    #[serde(rename = "welcome")]
    Welcome(Box<Welcome>),
    /// The answer to a request.
    #[serde(rename = "result")]
    Result {
        /// The request's id.
        id: u64,
        /// The request's result fields.
        #[serde(flatten)]
        fields: serde_json::Map<String, serde_json::Value>,
    },
    /// A refused request, or a refused `hello` (without `id`).
    #[serde(rename = "error")]
    Error {
        /// The request's id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
        /// What went wrong.
        code: ErrorCode,
        /// For people.
        message: String,
        /// For `rate_limited`: when to try again, in seconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
        /// For `not_online`: when the target was last seen.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_seen_at: Option<i64>,
    },
    /// A device registered (logged).
    #[serde(rename = "device.added")]
    DeviceAdded {
        /// Sequence number.
        seq: i64,
        /// Its entry.
        device: DeviceEntry,
        /// When.
        at: i64,
    },
    /// Presence, name or settings of a device changed.
    #[serde(rename = "device.updated")]
    DeviceUpdated {
        /// Its entry.
        device: DeviceEntry,
    },
    /// A device was revoked (logged).
    #[serde(rename = "device.revoked")]
    DeviceRevoked {
        /// Sequence number.
        seq: i64,
        /// The device.
        endpoint_id: DeviceId,
        /// When.
        at: i64,
        /// `account_page`, `admin`, `cli` or `mini_program` (the user in the WeChat mini
        /// program); new kinds may appear.
        by: String,
    },
    /// A device signed out (protocol 9.4).
    #[serde(rename = "device.removed")]
    DeviceRemoved {
        /// The device.
        endpoint_id: DeviceId,
        /// When.
        at: i64,
    },
    /// Another device is connecting (protocol 7.2).
    #[serde(rename = "incoming")]
    Incoming {
        /// The connecting device.
        from: DeviceId,
        /// The ALPN.
        service: String,
        /// Why.
        purpose: Purpose,
        /// For `pair`: the pending request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },
    /// A new device asks to join (protocol 8.2).
    #[serde(rename = "pair.requested")]
    PairRequested(PairRequested),
    /// An approval (logged).
    #[serde(rename = "pair.approved")]
    PairApproved {
        /// Sequence number.
        seq: i64,
        /// The request it approves.
        request_id: String,
        /// The signed `pair-approval` statement.
        approval: Signed,
        /// When.
        at: i64,
    },
    /// A pairing request ended.
    #[serde(rename = "pair.closed")]
    PairClosed {
        /// The request.
        request_id: String,
        /// `approved`, `declined`, `withdrawn` or `expired`.
        outcome: String,
    },
    /// Remote access on the account changed (protocol 13.5), its relay access, or whether it has
    /// two-step verification.
    #[serde(rename = "account")]
    Account {
        /// Remote access is available.
        remote_access: bool,
        /// How much of the relay the account's devices may use, while remote access is
        /// available (as in [`AccountInfo::relay`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay: Option<RelayAccess>,
        /// Whether the account has two-step verification enrolled (as in
        /// [`AccountInfo::two_factor`]); `None` from older servers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        two_factor: Option<bool>,
    },
    /// A type a newer server sent (protocol 2.4: version 1 may add message types). Receivers
    /// ignore it (protocol 5.3); servers never send it.
    #[serde(other)]
    Unknown,
}

impl ServerMessage {
    /// A `result` for request `id` with the fields of `body`, which must serialize to an
    /// object (or to nothing, for `()`).
    pub fn result(id: u64, body: &impl Serialize) -> Self {
        let fields = match serde_json::to_value(body) {
            Ok(serde_json::Value::Object(fields)) => fields,
            _ => serde_json::Map::new(),
        };
        Self::Result { id, fields }
    }

    /// An `error` for request `id`.
    pub fn error(id: Option<u64>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            id,
            code,
            message: message.into(),
            retry_after: None,
            last_seen_at: None,
        }
    }

    /// The frame's text.
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    fn id(seed: u8) -> DeviceId {
        SecretKey::from_bytes(&[seed; 32]).public().into()
    }

    #[test]
    fn requests_round_trip_with_their_type() {
        let message = ClientMessage::Connect {
            id: 4,
            target: id(1),
            service: "inputshow/1".to_owned(),
            purpose: Purpose::Session,
            request_id: None,
        };
        let text = serde_json::to_string(&message).unwrap();
        assert!(text.starts_with(r#"{"type":"connect","id":4,"#), "{text}");
        assert_eq!(
            serde_json::from_str::<ClientMessage>(&text).unwrap(),
            message
        );

        let settings: ClientMessage =
            serde_json::from_str(r#"{"type":"settings","id":2,"name":"Study","extra":1}"#).unwrap();
        assert_eq!(
            settings,
            ClientMessage::Settings {
                id: 2,
                change: SettingsChange {
                    name: Some("Study".to_owned()),
                    ..SettingsChange::default()
                }
            }
        );
        let publish: ClientMessage = serde_json::from_str(
            r#"{"type":"publish","id":3,"relay_url":"https://r.example/","direct":["192.0.2.1:1","[2001:db8::1]:2"]}"#,
        )
        .unwrap();
        assert_eq!(publish.id(), Some(3));
        // An unknown type is not a message, but its envelope still reads.
        let unknown = r#"{"type":"from.the.future","id":9}"#;
        assert!(serde_json::from_str::<ClientMessage>(unknown).is_err());
        let envelope: Envelope = serde_json::from_str(unknown).unwrap();
        assert_eq!(envelope.id, Some(9));
        assert!(!ClientMessage::TYPES.contains(&envelope.kind.as_str()));
    }

    #[test]
    fn server_messages_carry_their_fields() {
        let result = ServerMessage::result(
            7,
            &PairRequestResult {
                request_id: "r".to_owned(),
                expires_at: 10,
            },
        );
        let text = result.to_text();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            serde_json::json!({"type": "result", "id": 7, "request_id": "r", "expires_at": 10})
        );
        assert_eq!(
            serde_json::from_str::<ServerMessage>(&text).unwrap(),
            result
        );
        assert_eq!(
            ServerMessage::result(8, &()).to_text(),
            r#"{"type":"result","id":8}"#
        );
        let error = ServerMessage::error(Some(1), ErrorCode::NotPermitted, "no");
        assert_eq!(
            error.to_text(),
            r#"{"type":"error","id":1,"code":"not_permitted","message":"no"}"#
        );
        let newer: ServerMessage =
            serde_json::from_str(r#"{"type":"error","code":"from_the_future","message":""}"#)
                .unwrap();
        assert!(matches!(
            newer,
            ServerMessage::Error {
                code: ErrorCode::Unknown,
                ..
            }
        ));
        // A type of a newer server reads, also inside `welcome.events`, and is ignored there.
        let future: ServerMessage =
            serde_json::from_str(r#"{"type":"from.the.future","seq":4,"what":{"x":1}}"#).unwrap();
        assert_eq!(future, ServerMessage::Unknown);
        let events: Vec<ServerMessage> = serde_json::from_str(
            r#"[{"type":"from.the.future"},{"type":"device.removed","endpoint_id":"$ID","at":1}]"#
                .replace("$ID", &id(3).to_hex())
                .as_str(),
        )
        .unwrap();
        assert_eq!(events[0], ServerMessage::Unknown);
        assert!(matches!(events[1], ServerMessage::DeviceRemoved { .. }));
        let revoked = ServerMessage::DeviceRevoked {
            seq: 3,
            endpoint_id: id(2),
            at: 5,
            by: "cli".to_owned(),
        };
        let text = revoked.to_text();
        assert!(
            text.starts_with(r#"{"type":"device.revoked","seq":3,"#),
            "{text}"
        );
    }
}
