//! The S3 buckets and access keys of one account in the admin UI, while the S3 API is enabled.
//!
//! The user page lists them; an admin can revoke a key, make a bucket private and remove a
//! bucket (only the binding goes: the folder and its files stay). Creating keys and buckets is
//! left to the account page and the command line, since only the account's user should ever
//! see a secret key. Every change is written to the audit log of the account, with
//! [`Actor::Admin`], the admin's name and the client address.

use std::net::{IpAddr, SocketAddr};

use axum::{
    Form,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use gono_server_core::{
    audit::{Actor, Record},
    s3::{self, Anonymous},
    users::User,
};
use serde_json::json;

use super::{
    CsrfForm, Halt, Session, admin, find_user, form_session, internal_error, pages, see_other,
};
use crate::{
    app::AppState,
    client_ip::client_ip,
    files::account::s3::{BucketRow, KeyRow, grant_chips},
    i18n::{Text, ago, fill},
    s3::{S3Ui, audit},
};

/// What the user page shows of the account's S3 buckets and access keys.
#[derive(Debug, Clone)]
pub struct UserS3 {
    /// `s3.allow_anonymous`.
    pub allow_anonymous: bool,
    pub buckets: Vec<BucketRow>,
    pub keys: Vec<KeyRow>,
}

/// The S3 part of the page of account `user_id`.
pub(super) async fn user_view(
    state: &AppState,
    t: &Text,
    ui: &S3Ui,
    user_id: i64,
    now: i64,
) -> gono_server_core::Result<UserS3> {
    let buckets = s3::buckets_of(&state.db, user_id).await?;
    let keys = s3::list_keys(&state.db, user_id)
        .await?
        .iter()
        .map(|key| KeyRow {
            id: key.id,
            access_key_id: key.access_key_id.clone(),
            label: key.label.clone(),
            created: fill(t.created, &[&pages::date(key.created_at)]),
            grants: grant_chips(t, &key.grants, &buckets),
            last_used: key.last_used_at.map_or_else(
                || t.never_used.to_owned(),
                |at| ago(t, now, at, pages::date),
            ),
            expiry: pages::expiry(t, key.expires_at, now),
        })
        .collect();
    Ok(UserS3 {
        allow_anonymous: ui.allow_anonymous,
        buckets: buckets
            .iter()
            .map(|bucket| BucketRow::new(t, ui, bucket, &pages::date(bucket.created_at)))
            .collect(),
        keys,
    })
}

/// The admin session and the account of a form post, or the response to send instead (404
/// while the S3 API is off).
async fn guard(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    csrf: &str,
) -> Result<(Session, User, String), Halt> {
    let admin = admin(state)?;
    if state.s3.is_none() {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    }
    let session = form_session(state, &admin, headers, csrf).await?;
    let user = find_user(state, &admin, &session, name).await?;
    let base = admin.user_url(user.username.as_str());
    Ok((session, user, base))
}

/// An audit record of an S3 change by an admin to `user`'s account.
fn record(user: &User, kind: &'static str, client: IpAddr) -> Record {
    Record::new(user.id, kind, Actor::Admin).client_ip(Some(client))
}

/// `POST <admin>/users/<name>/s3/keys/<id>/delete`.
pub(super) async fn revoke_key(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let (session, user, base) = match guard(&state, &headers, &name, &form.csrf).await {
        Ok(found) => found,
        Err(halt) => return *halt,
    };
    let key = match s3::list_keys(&state.db, user.id).await {
        Ok(keys) => keys.into_iter().find(|key| key.id == id),
        Err(err) => return internal_error(&session.chrome, &err),
    };
    // Already revoked (for example in another tab): nothing to report.
    let Some(key) = key else {
        return see_other(&base);
    };
    match s3::delete_key(&state.db, user.id, id).await {
        Ok(true) => {}
        Ok(false) => return see_other(&base),
        Err(err) => return internal_error(&session.chrome, &err),
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let details = json!({
        "access_key_id": key.access_key_id,
        "label": key.label,
        "admin": session.user.username.as_str(),
    });
    audit(
        &state.db,
        record(&user, "s3.key.revoked", client).details(details),
    )
    .await;
    tracing::info!(
        by = %session.user.username,
        user = %user.username,
        access_key_id = %key.access_key_id,
        "admin revoked an S3 access key"
    );
    see_other(&format!("{base}?done=s3-key-revoked"))
}

/// `POST <admin>/users/<name>/s3/buckets/<id>/private`: no anonymous reads or listing.
pub(super) async fn make_bucket_private(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let (session, user, base) = match guard(&state, &headers, &name, &form.csrf).await {
        Ok(found) => found,
        Err(halt) => return *halt,
    };
    let bucket = match s3::bucket_by_id(&state.db, id).await {
        Ok(bucket) => bucket.filter(|bucket| bucket.owner_id == user.id),
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let Some(bucket) = bucket else {
        return see_other(&base);
    };
    if bucket.anonymous == Anonymous::Private && !bucket.anonymous_list {
        return see_other(&format!("{base}?done=s3-bucket-private"));
    }
    match s3::set_anonymous(&state.db, user.id, id, Anonymous::Private, false).await {
        Ok(true) => {}
        Ok(false) => return see_other(&base),
        Err(err) => return internal_error(&session.chrome, &err),
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let details = json!({
        "bucket": bucket.name,
        "anonymous": Anonymous::Private.as_str(),
        "list": false,
        "admin": session.user.username.as_str(),
    });
    audit(
        &state.db,
        record(&user, "s3.bucket.anonymous", client).details(details),
    )
    .await;
    tracing::info!(
        by = %session.user.username,
        user = %user.username,
        bucket = %bucket.name,
        "admin made an S3 bucket private"
    );
    see_other(&format!("{base}?done=s3-bucket-private"))
}

/// `POST <admin>/users/<name>/s3/buckets/<id>/delete`: unbinds the bucket; the folder stays.
pub(super) async fn remove_bucket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let (session, user, base) = match guard(&state, &headers, &name, &form.csrf).await {
        Ok(found) => found,
        Err(halt) => return *halt,
    };
    let bucket = match s3::bucket_by_id(&state.db, id).await {
        Ok(bucket) => bucket.filter(|bucket| bucket.owner_id == user.id),
        Err(err) => return internal_error(&session.chrome, &err),
    };
    let Some(bucket) = bucket else {
        return see_other(&base);
    };
    match s3::delete_bucket(&state.db, user.id, id).await {
        Ok(true) => {}
        Ok(false) => return see_other(&base),
        Err(err) => return internal_error(&session.chrome, &err),
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let details = json!({
        "bucket": bucket.name,
        "admin": session.user.username.as_str(),
    });
    audit(
        &state.db,
        record(&user, "s3.bucket.removed", client).details(details),
    )
    .await;
    tracing::info!(
        by = %session.user.username,
        user = %user.username,
        bucket = %bucket.name,
        "admin removed an S3 bucket"
    );
    see_other(&format!("{base}?done=s3-bucket-removed"))
}
