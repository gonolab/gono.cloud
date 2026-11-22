//! The relay tab of the account page: the relay's address, the rate it reads the account's
//! devices at, those of them connected to it right now and the sessions they reported
//! (`docs/connect-protocol.md`, sections 11 and 12.2). The admin UI's relay page shows the same
//! of every account, with the relay's settings and counters.
//!
//! The tab belongs to direct connections: an account with them alone has its devices admitted
//! at `relay.limited_bytes_per_sec`, enough to set up direct connections, and the relay service
//! raises that to the full rate. The tab says which applies, so that a user whose sessions crawl
//! through the relay learns why.

use std::collections::HashMap;

use gono_server_core::{
    audit,
    devices::{Device, EndpointId},
    services::Service,
};

use crate::{
    admin::format_bytes,
    app::AppState,
    files::{Visitor, view::when},
    i18n::Text,
};

/// The newest audit records of the account the tab looks through for session reports: other
/// kinds share the log, and the tab must not read it all.
const RECORDS: i64 = 500;

/// The session reports the tab lists at most.
const SESSIONS: usize = 50;

/// What the relay tab shows.
#[derive(Debug, Clone)]
pub struct RelayView {
    /// The relay URL devices use (`relay.public_url`).
    pub url: String,
    /// The account has the relay service: the relay reads its devices at the full rate, else
    /// at the limited one.
    pub full: bool,
    /// The account's devices connected to the relay now, or `None` when this process does not
    /// run the relay (it always does when remote connectivity is on, except in tests).
    pub connected: Option<Vec<ConnectedRow>>,
    /// The sessions the account's devices reported, newest first.
    pub sessions: Vec<SessionRow>,
}

/// One of the account's devices connected to the relay.
#[derive(Debug, Clone)]
pub struct ConnectedRow {
    pub name: String,
    pub short: String,
    /// "Input Show · Windows".
    pub what: String,
    /// Its control channel is open.
    pub control: bool,
    /// Its relay connections.
    pub connections: usize,
}

/// One session report (`session.started` or `session.ended`).
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub when: String,
    /// "Started" or "Ended".
    pub event: &'static str,
    /// The reporting device, "Name (short id)".
    pub device: String,
    /// The other device.
    pub peer: String,
    /// The service of the session, for example `inputshow/1`.
    pub service: String,
    /// "Direct", "Relayed" or "Mixed".
    pub path: String,
    /// Some of it went through the relay.
    pub relayed: bool,
    /// "direct / relayed" bytes of an ended session, empty for a started one.
    pub bytes: String,
}

/// What the relay tab shows, or `None` while remote connectivity is off.
pub(super) async fn view(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
) -> gono_server_core::Result<Option<RelayView>> {
    let Some(connect) = &state.connect else {
        return Ok(None);
    };
    let t = visitor.t();
    let user_id = visitor.user.user_id;
    // The account's own devices only: the relay's list and the audit log name every account's.
    let devices = connect.devices_with_presence(user_id).await?;
    let own: HashMap<EndpointId, (&Device, bool)> = devices
        .iter()
        .map(|(device, online)| (device.endpoint_id, (device, *online)))
        .collect();
    let connected = connect.relay().map(|relay| {
        relay
            .connected_devices()
            .into_iter()
            .filter_map(|(key, connections)| {
                let key = EndpointId(*key.as_bytes());
                let (device, control) = own.get(&key)?;
                Some(ConnectedRow {
                    name: device.name.clone(),
                    short: key.short(),
                    what: format!(
                        "{} · {}",
                        crate::login_flow::product_name(&device.product),
                        crate::login_flow::platform_name(&device.platform)
                    ),
                    control: *control,
                    connections,
                })
            })
            .collect()
    });
    let name_of = |key: Option<EndpointId>| match key {
        None => String::new(),
        Some(key) => match own.get(&key) {
            Some((device, _)) => format!("{} ({})", device.name, key.short()),
            None => key.short(),
        },
    };
    let sessions = audit::list(&state.db, Some(user_id), None, RECORDS)
        .await?
        .iter()
        .filter(|record| matches!(record.kind.as_str(), "session.started" | "session.ended"))
        .take(SESSIONS)
        .map(|record| session_row(t, record, when(visitor.lang(), now, record.at).0, &name_of))
        .collect();
    Ok(Some(RelayView {
        url: connect.relay_url().to_owned(),
        full: visitor.user.services.has(Service::Relay),
        connected,
        sessions,
    }))
}

/// The row of a session report, which happened at `at` (in words), naming devices with
/// `name_of`. The details hold what the device reported.
fn session_row(
    t: &'static Text,
    record: &audit::Entry,
    at: String,
    name_of: &dyn Fn(Option<EndpointId>) -> String,
) -> SessionRow {
    let details = serde_json::from_str::<serde_json::Value>(&record.details).unwrap_or_default();
    let text = |field: &str| {
        details
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let bytes = |field: &str| {
        details
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .map_or_else(|| "–".to_owned(), format_bytes)
    };
    let ended = record.kind == "session.ended";
    let path = text("path");
    SessionRow {
        when: at,
        event: if ended {
            t.relay_ended
        } else {
            t.relay_started
        },
        device: name_of(record.device),
        peer: name_of(record.peer),
        service: text("service"),
        relayed: path != "direct",
        path: match path.as_str() {
            "direct" => t.relay_path_direct.to_owned(),
            "relayed" => t.relay_path_relayed.to_owned(),
            "mixed" => t.relay_path_mixed.to_owned(),
            _ => path,
        },
        bytes: if ended {
            format!("{} / {}", bytes("bytes_direct"), bytes("bytes_relayed"))
        } else {
            String::new()
        },
    }
}
