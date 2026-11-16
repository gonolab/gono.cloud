//! The S3 part of the account page: the user's buckets and access keys, shown while the S3 API
//! is enabled ([`S3Ui`]). The requests are listed in the table of [`super`]; while the S3 API
//! is off they answer 404 and the page shows nothing of S3.
//!
//! - **Buckets.** A new bucket gets the folder `<s3.bucket_folder>/<name>` of the user's files,
//!   created here as the S3 API's `CreateBucket` creates it, and is refused when that folder
//!   exists already: such a folder is bound instead, like any other existing folder. Removing a
//!   bucket only unbinds it; the folder and its files stay. Anonymous access other than private
//!   can be set only while `s3.allow_anonymous` is on (making a bucket private always works),
//!   and anonymous listing needs some anonymous access.
//! - **Access keys.** A new key is kept in memory for its session and shown once at
//!   `/apps/account/s3/created`, with the endpoint and region to configure; the URL carries no
//!   secret. Its secret key is sealed with the server's key file (`two_factor.key_file`).
//! - **Audit.** Every change is written to the audit log with the client address:
//!   `s3.bucket.created`, `s3.bucket.removed`, `s3.bucket.anonymous`, `s3.key.created` and
//!   `s3.key.revoked`. The records name buckets and keys, never folders or files.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    Error as CoreError, Permission, RelPath,
    audit::{Actor, Record},
    db,
    s3::{self, Anonymous, Bucket, BucketName, Grant},
};
use gono_server_dav::ObjectError;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::{ACCOUNT, CsrfForm, PageOptions, account_visitor, expiry, form_visitor, render};
use crate::{
    admin::{core_message, parse_expiry},
    app::AppState,
    client_ip::client_ip,
    files::{
        Visitor, internal,
        view::{display_path, url, when},
    },
    i18n::{Text, fill},
    s3::{S3Ui, audit, key_details},
    web::{self, Chrome, Nav, page},
};

/// The access a key grants, as chips: a bucket (or "all buckets") and a permission.
#[derive(Debug, Clone)]
pub struct GrantChip {
    pub bucket: String,
    pub permission: &'static str,
}

/// The chips of `grants`, naming buckets from `buckets` (the owner's).
pub fn grant_chips(t: &Text, grants: &[Grant], buckets: &[Bucket]) -> Vec<GrantChip> {
    grants
        .iter()
        .map(|grant| GrantChip {
            bucket: match grant.bucket_id {
                None => t.s3_all_buckets.to_owned(),
                Some(id) => buckets
                    .iter()
                    .find(|bucket| bucket.id == id)
                    .map_or_else(|| format!("#{id}"), |bucket| bucket.name.clone()),
            },
            permission: grant.permission.as_str(),
        })
        .collect()
}

/// What anonymous requests may read, in words.
pub fn anonymous_label(t: &Text, anonymous: Anonymous) -> &'static str {
    match anonymous {
        Anonymous::Private => t.s3_anon_private,
        Anonymous::Acl => t.s3_anon_acl,
        Anonymous::PublicRead => t.s3_anon_public,
    }
}

/// One bucket in a list.
#[derive(Debug, Clone)]
pub struct BucketRow {
    pub id: i64,
    pub name: String,
    /// The folder, for example `/Buckets/photos`.
    pub folder: String,
    /// The folder's page in the file UI.
    pub folder_href: String,
    /// "Created …".
    pub created: String,
    /// The stored mode: `private`, `acl` or `public-read`.
    pub anonymous: &'static str,
    /// The stored mode and listing in words, for example "Every object · anonymous listing
    /// on".
    pub anonymous_text: String,
    /// Anonymous listing, as stored.
    pub list: bool,
    /// "CORS: 2 rules", if the bucket has CORS rules (set through the S3 API).
    pub cors: Option<String>,
}

impl BucketRow {
    /// The row of `bucket`, created at the time `created` formats.
    pub fn new(t: &Text, bucket: &Bucket, created: &str) -> Self {
        let mut anonymous_text = anonymous_label(t, bucket.anonymous).to_owned();
        if bucket.anonymous_list {
            anonymous_text.push_str(" · ");
            anonymous_text.push_str(t.s3_listing_on);
        }
        Self {
            id: bucket.id,
            name: bucket.name.clone(),
            folder: display_path(&bucket.folder),
            folder_href: url(&bucket.folder, true),
            created: fill(t.created, &[created]),
            anonymous: bucket.anonymous.as_str(),
            anonymous_text,
            list: bucket.anonymous_list,
            cors: bucket.cors.as_deref().map(|stored| {
                // Only the S3 API writes the rules: a JSON array of rules.
                let rules = serde_json::from_str::<Vec<serde_json::Value>>(stored)
                    .map_or(0, |rules| rules.len());
                if rules == 1 {
                    t.s3_cors_rule.to_owned()
                } else {
                    fill(t.s3_cors_rules, &[&rules.to_string()])
                }
            }),
        }
    }

    /// Anonymous reads or listing are stored: they take effect while `s3.allow_anonymous` is
    /// on.
    pub fn is_public(&self) -> bool {
        self.anonymous != Anonymous::Private.as_str() || self.list
    }
}

/// One access key in a list.
#[derive(Debug, Clone)]
pub struct KeyRow {
    pub id: i64,
    pub access_key_id: String,
    pub label: String,
    /// "Created …".
    pub created: String,
    pub grants: Vec<GrantChip>,
    pub last_used: String,
    pub expiry: String,
}

/// One bucket of the new access key form, with the permission chosen for it.
#[derive(Debug, Clone)]
pub struct GrantInput {
    pub id: i64,
    pub name: String,
    /// `view`, `full` or empty (no access).
    pub permission: String,
}

/// The S3 forms of the account page, as entered (kept when the page is shown again with an
/// error).
#[derive(Debug, Clone, Default)]
pub struct S3Forms {
    /// New bucket: its name.
    pub bucket_name: String,
    /// Existing folder: the bucket's name.
    pub bind_name: String,
    /// Existing folder: its path.
    pub bind_folder: String,
    pub key_label: String,
    pub key_expires_in_days: String,
    /// `buckets` for chosen buckets, anything else for every bucket.
    pub key_access: String,
    /// The permission chosen per bucket id.
    pub key_grants: HashMap<i64, String>,
}

/// What the account page shows of S3.
#[derive(Debug, Clone)]
pub struct S3View {
    /// `s3.public_url`.
    pub endpoint: String,
    pub region: String,
    /// "Path style: https://s3.example.com/<bucket>/<key>", and the virtual-hosted style if
    /// enabled, one line each.
    pub addressing: Vec<String>,
    /// "Creates the folder /Buckets/<name> in your files."
    pub new_bucket_note: String,
    /// `s3.allow_anonymous`.
    pub allow_anonymous: bool,
    pub buckets: Vec<BucketRow>,
    pub keys: Vec<KeyRow>,
    pub forms: S3Forms,
    /// The buckets of the new access key form.
    pub grants: Vec<GrantInput>,
}

/// A new access key waiting to be shown once.
#[derive(Debug)]
pub struct NewKey {
    label: String,
    access_key_id: String,
    secret: SecretString,
    grants: Vec<GrantChip>,
    expires_at: Option<i64>,
}

/// `account/s3_created.html`: a new access key, once.
#[derive(Template)]
#[template(path = "account/s3_created.html")]
struct CreatedPage {
    chrome: Chrome,
    label: String,
    access_key_id: String,
    secret: String,
    grants: Vec<GrantChip>,
    expiry: String,
    endpoint: String,
    region: String,
    addressing: Vec<String>,
}

page!(CreatedPage);

/// The endpoint and the addressing styles of `ui`, in words.
fn endpoint(t: &Text, ui: &S3Ui) -> (String, Vec<String>) {
    let (endpoint, path_style) = match ui.endpoint() {
        Some(endpoint) => {
            let path_style = fill(t.s3_path_style, &[&endpoint]);
            (endpoint, path_style)
        }
        None => (
            t.s3_endpoint_unset.to_owned(),
            fill(t.s3_path_style, &["…"]),
        ),
    };
    let mut addressing = vec![path_style];
    if let Some(origin) = ui.virtual_host_origin("<bucket>") {
        addressing.push(fill(t.s3_virtual_style, &[&origin]));
    }
    (endpoint, addressing)
}

/// What the account page shows of S3, or `None` while the S3 API is off.
pub(super) async fn view(
    state: &AppState,
    visitor: &Visitor,
    now: i64,
    forms: S3Forms,
) -> gono_server_core::Result<Option<S3View>> {
    let Some(ui) = &state.s3 else {
        return Ok(None);
    };
    let t = visitor.t();
    let lang = visitor.lang();
    let buckets = s3::buckets_of(&state.db, visitor.user.user_id).await?;
    let keys = s3::list_keys(&state.db, visitor.user.user_id).await?;
    let keys = keys
        .iter()
        .map(|key| KeyRow {
            id: key.id,
            access_key_id: key.access_key_id.clone(),
            label: key.label.clone(),
            created: fill(t.created, &[&when(lang, now, key.created_at).0]),
            grants: grant_chips(t, &key.grants, &buckets),
            last_used: key
                .last_used_at
                .map_or_else(|| t.never_used.to_owned(), |at| when(lang, now, at).0),
            expiry: expiry(t, visitor, now, key.expires_at),
        })
        .collect();
    let grants = buckets
        .iter()
        .map(|bucket| GrantInput {
            id: bucket.id,
            name: bucket.name.clone(),
            permission: forms
                .key_grants
                .get(&bucket.id)
                .cloned()
                .unwrap_or_default(),
        })
        .collect();
    let rows = buckets
        .iter()
        .map(|bucket| BucketRow::new(t, bucket, &when(lang, now, bucket.created_at).0))
        .collect();
    let (endpoint, addressing) = endpoint(t, ui);
    Ok(Some(S3View {
        endpoint,
        region: ui.region.clone(),
        addressing,
        new_bucket_note: fill(
            t.s3_new_bucket_note,
            &[&format!(
                "{}/<name>",
                display_path(&RelPath::root().join(&ui.bucket_folder))
            )],
        ),
        allow_anonymous: ui.allow_anonymous,
        buckets: rows,
        keys,
        forms,
        grants,
    }))
}

/// The notice of `?done=<done>` after an S3 change.
pub(super) fn notice(t: &'static Text, done: &str) -> Option<&'static str> {
    match done {
        "s3-bucket-created" => Some(t.s3_notice_bucket_created),
        "s3-bucket-bound" => Some(t.s3_notice_bucket_bound),
        "s3-bucket-anonymous" => Some(t.s3_notice_anonymous),
        "s3-bucket-removed" => Some(t.s3_notice_bucket_removed),
        "s3-key-revoked" => Some(t.s3_notice_key_revoked),
        _ => None,
    }
}

/// What the user reads about a bucket that could not be created or bound, or `None` for a
/// failure of the server.
pub fn bucket_error(t: &Text, err: &CoreError) -> Option<String> {
    let shown = |path: &str| {
        if path.starts_with('/') || path.starts_with('#') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    };
    match err {
        CoreError::InvalidBucketName { .. } => Some(t.s3_err_bucket_name.to_owned()),
        CoreError::BucketExists { name, yours: true } => Some(fill(t.s3_err_bucket_yours, &[name])),
        CoreError::BucketExists { name, yours: false } => {
            Some(fill(t.s3_err_bucket_taken, &[name]))
        }
        CoreError::InvalidBucketFolder { path, reason } => Some(if reason.contains("root") {
            t.s3_err_root.to_owned()
        } else if reason.contains("a bucket already") {
            fill(t.s3_err_folder_bound, &[&shown(path)])
        } else if reason.contains("inside or above") {
            fill(t.s3_err_nested, &[&shown(path)])
        } else {
            fill(t.s3_err_folder, &[&shown(path), reason])
        }),
        _ => None,
    }
}

/// The S3 settings of the pages, or 404 while the S3 API is off.
fn enabled(state: &AppState) -> Result<Arc<S3Ui>, Box<Response>> {
    state
        .s3
        .clone()
        .ok_or_else(|| Box::new(StatusCode::NOT_FOUND.into_response()))
}

/// Shows the account page again with `error` and the S3 forms as entered; nothing changed.
async fn refuse(state: &AppState, visitor: &Visitor, forms: S3Forms, error: String) -> Response {
    let options = PageOptions {
        s3: forms,
        error: Some(error),
        ..PageOptions::default()
    };
    render(state, visitor, options).await
}

/// `303` to the account page with `?done=<done>`.
fn done(done: &str) -> Response {
    web::see_other(&format!("{ACCOUNT}/?done={done}"), &[])
}

/// The visitor's bucket `id`, `None` if there is none (any more).
async fn own_bucket(
    state: &AppState,
    visitor: &Visitor,
    id: i64,
) -> Result<Option<Bucket>, Box<Response>> {
    match s3::bucket_by_id(&state.db, id).await {
        Ok(bucket) => Ok(bucket.filter(|bucket| bucket.owner_id == visitor.user.user_id)),
        Err(err) => Err(Box::new(internal(visitor, "bucket", &err))),
    }
}

/// An audit record of an S3 change by the account's user.
fn record(visitor: &Visitor, kind: &'static str, client: IpAddr) -> Record {
    Record::new(visitor.user.user_id, kind, Actor::User).client_ip(Some(client))
}

#[derive(Deserialize)]
pub struct BucketForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    folder: String,
}

/// `POST /apps/account/s3/buckets`: a new bucket with a new folder.
pub async fn create_bucket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<BucketForm>,
) -> Response {
    let ui = match enabled(&state) {
        Ok(ui) => ui,
        Err(response) => return *response,
    };
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let forms = S3Forms {
        bucket_name: form.name.trim().to_owned(),
        ..S3Forms::default()
    };
    let Ok(name) = BucketName::new(&forms.bucket_name) else {
        return refuse(&state, &visitor, forms, t.s3_err_bucket_name.to_owned()).await;
    };
    match s3::bucket(&state.db, name.as_str()).await {
        Ok(None) => {}
        Ok(Some(existing)) => {
            let err = CoreError::BucketExists {
                name: name.to_string(),
                yours: existing.owner_id == visitor.user.user_id,
            };
            let message = bucket_error(t, &err).unwrap_or_default();
            return refuse(&state, &visitor, forms, message).await;
        }
        Err(err) => return internal(&visitor, "bucket", &err),
    }
    let folder = RelPath::root().join(&ui.bucket_folder).join(name.as_str());
    let fs = state.dav.fs();
    if fs.stat(visitor.identity.clone(), &folder).await.is_ok() {
        let message = fill(t.s3_err_folder_exists, &[&display_path(&folder)]);
        return refuse(&state, &visitor, forms, message).await;
    }
    let entry = match fs.put_folder(visitor.identity.clone(), &folder).await {
        Ok(entry) => entry,
        Err(ObjectError::ParentIsFile) => {
            let message = fill(t.s3_err_parent_is_file, &[&display_path(&folder)]);
            return refuse(&state, &visitor, forms, message).await;
        }
        Err(ObjectError::InsufficientStorage) => {
            return refuse(&state, &visitor, forms, t.err_storage.to_owned()).await;
        }
        Err(err) => return internal(&visitor, "bucket folder", &err),
    };
    let Some(folder_id) = entry.file_id else {
        return internal(&visitor, "bucket folder", &"the new folder has no file id");
    };
    let bucket = match s3::create_bucket(&state.db, visitor.user.user_id, &name, folder_id).await {
        Ok(bucket) => bucket,
        Err(err) => {
            // Do not leave the new, empty folder behind (another request took the name).
            let _ = fs
                .remove_empty_folder(visitor.identity.clone(), &folder)
                .await;
            return match bucket_error(t, &err) {
                Some(message) => refuse(&state, &visitor, forms, message).await,
                None => internal(&visitor, "bucket", &err),
            };
        }
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let details = json!({ "bucket": bucket.name, "new_folder": true });
    audit(
        &state.db,
        record(&visitor, "s3.bucket.created", client).details(details),
    )
    .await;
    tracing::info!(user = %visitor.user.username, bucket = %bucket.name, "user created an S3 bucket");
    done("s3-bucket-created")
}

/// `POST /apps/account/s3/buckets/bind`: an existing folder becomes a bucket.
pub async fn bind_bucket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<BucketForm>,
) -> Response {
    if let Err(response) = enabled(&state) {
        return *response;
    }
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let forms = S3Forms {
        bind_name: form.name.trim().to_owned(),
        bind_folder: form.folder.trim().to_owned(),
        ..S3Forms::default()
    };
    let Ok(name) = BucketName::new(&forms.bind_name) else {
        return refuse(&state, &visitor, forms, t.s3_err_bucket_name.to_owned()).await;
    };
    let Ok(folder) = RelPath::parse(&forms.bind_folder) else {
        let message = fill(t.err_invalid_path, &[&forms.bind_folder]);
        return refuse(&state, &visitor, forms, message).await;
    };
    if folder.is_root() {
        return refuse(&state, &visitor, forms, t.s3_err_root.to_owned()).await;
    }
    let entry = match state.dav.fs().stat(visitor.identity.clone(), &folder).await {
        Ok(entry) => entry,
        Err(_) => {
            let message = fill(t.s3_err_no_folder, &[&display_path(&folder)]);
            return refuse(&state, &visitor, forms, message).await;
        }
    };
    if !entry.is_dir() {
        let message = fill(t.s3_err_not_folder, &[&display_path(&folder)]);
        return refuse(&state, &visitor, forms, message).await;
    }
    let Some(folder_id) = entry.file_id else {
        return internal(&visitor, "bucket folder", &"the folder has no file id");
    };
    let bucket = match s3::create_bucket(&state.db, visitor.user.user_id, &name, folder_id).await {
        Ok(bucket) => bucket,
        Err(err) => {
            return match bucket_error(t, &err) {
                Some(message) => refuse(&state, &visitor, forms, message).await,
                None => internal(&visitor, "bucket", &err),
            };
        }
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let details = json!({ "bucket": bucket.name, "new_folder": false });
    audit(
        &state.db,
        record(&visitor, "s3.bucket.created", client).details(details),
    )
    .await;
    tracing::info!(user = %visitor.user.username, bucket = %bucket.name, "user made a folder an S3 bucket");
    done("s3-bucket-bound")
}

#[derive(Deserialize)]
pub struct AnonymousForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    anonymous: String,
    /// Present when the box is ticked.
    list: Option<String>,
}

/// `POST /apps/account/s3/buckets/<id>/anonymous`.
pub async fn set_anonymous(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(form): Form<AnonymousForm>,
) -> Response {
    let ui = match enabled(&state) {
        Ok(ui) => ui,
        Err(response) => return *response,
    };
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let bucket = match own_bucket(&state, &visitor, id).await {
        Ok(Some(bucket)) => bucket,
        Ok(None) => return super::super::not_found(&visitor),
        Err(response) => return *response,
    };
    let Ok(anonymous) = form.anonymous.parse::<Anonymous>() else {
        return refuse(
            &state,
            &visitor,
            S3Forms::default(),
            t.s3_err_anonymous.to_owned(),
        )
        .await;
    };
    // Listing reveals every key name: it goes with some anonymous access only.
    let list = form.list.is_some() && anonymous != Anonymous::Private;
    if !ui.allow_anonymous && (anonymous != Anonymous::Private || list) {
        return refuse(
            &state,
            &visitor,
            S3Forms::default(),
            t.s3_err_anonymous_off.to_owned(),
        )
        .await;
    }
    if (bucket.anonymous, bucket.anonymous_list) == (anonymous, list) {
        return done("s3-bucket-anonymous");
    }
    match s3::set_anonymous(&state.db, visitor.user.user_id, id, anonymous, list).await {
        Ok(true) => {}
        Ok(false) => return super::super::not_found(&visitor),
        Err(err) => return internal(&visitor, "bucket", &err),
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let details = json!({
        "bucket": bucket.name,
        "anonymous": anonymous.as_str(),
        "list": list,
    });
    audit(
        &state.db,
        record(&visitor, "s3.bucket.anonymous", client).details(details),
    )
    .await;
    tracing::info!(
        user = %visitor.user.username,
        bucket = %bucket.name,
        anonymous = anonymous.as_str(),
        list,
        "user changed the anonymous access of an S3 bucket"
    );
    done("s3-bucket-anonymous")
}

/// `POST /apps/account/s3/buckets/<id>/delete`: unbinds the bucket; the folder stays.
pub async fn remove_bucket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Err(response) = enabled(&state) {
        return *response;
    }
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let bucket = match own_bucket(&state, &visitor, id).await {
        Ok(Some(bucket)) => bucket,
        // Removed already (for example in another tab): nothing to report.
        Ok(None) => return web::see_other(&format!("{ACCOUNT}/"), &[]),
        Err(response) => return *response,
    };
    match s3::delete_bucket(&state.db, visitor.user.user_id, id).await {
        Ok(true) => {}
        Ok(false) => return web::see_other(&format!("{ACCOUNT}/"), &[]),
        Err(err) => return internal(&visitor, "bucket", &err),
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    audit(
        &state.db,
        record(&visitor, "s3.bucket.removed", client).details(json!({ "bucket": bucket.name })),
    )
    .await;
    tracing::info!(user = %visitor.user.username, bucket = %bucket.name, "user removed an S3 bucket");
    done("s3-bucket-removed")
}

/// The grants of the new access key form: one for every bucket, or the chosen ones (fields
/// `bucket_<id>` = `view` or `full`) among `buckets`.
fn parse_grants(t: &Text, forms: &S3Forms, buckets: &[Bucket]) -> Result<Vec<Grant>, &'static str> {
    if forms.key_access != "buckets" {
        return Ok(vec![Grant::everything()]);
    }
    let grants: Vec<Grant> = buckets
        .iter()
        .filter_map(|bucket| {
            let permission = match forms.key_grants.get(&bucket.id).map(String::as_str) {
                Some("view") => Permission::View,
                Some("full") => Permission::Full,
                _ => return None,
            };
            Some(Grant {
                bucket_id: Some(bucket.id),
                permission,
            })
        })
        .collect();
    if grants.is_empty() {
        return Err(t.s3_err_no_grants);
    }
    Ok(grants)
}

/// `POST /apps/account/s3/keys`.
pub async fn create_key(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    if let Err(response) = enabled(&state) {
        return *response;
    }
    let field = |name: &str| {
        fields
            .get(name)
            .map_or_else(String::new, |value| value.trim().to_owned())
    };
    let visitor = match form_visitor(&state, &headers, &uri, &field("csrf")).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let t = visitor.t();
    let forms = S3Forms {
        key_label: field("label"),
        key_expires_in_days: field("expires_in_days"),
        key_access: field("access"),
        key_grants: fields
            .iter()
            .filter_map(|(name, value)| {
                let id = name.strip_prefix("bucket_")?.parse().ok()?;
                Some((id, value.trim().to_owned()))
            })
            .collect(),
        ..S3Forms::default()
    };
    let label = match gono_server_core::app_passwords::check_label(&forms.key_label) {
        Ok(label) => label,
        Err(err) => return refuse(&state, &visitor, forms, core_message(t, &err)).await,
    };
    let expires_at = match parse_expiry(t, &forms.key_expires_in_days, db::unix_now()) {
        Ok(expires_at) => expires_at,
        Err(message) => return refuse(&state, &visitor, forms, message).await,
    };
    let buckets = match s3::buckets_of(&state.db, visitor.user.user_id).await {
        Ok(buckets) => buckets,
        Err(err) => return internal(&visitor, "bucket list", &err),
    };
    let grants = match parse_grants(t, &forms, &buckets) {
        Ok(grants) => grants,
        Err(message) => return refuse(&state, &visitor, forms, message.to_owned()).await,
    };
    let Some(sealing) = state.web.two_factor_key() else {
        return web::unavailable(visitor.chrome(Nav::Account));
    };
    let (key, secret) = match s3::create_key(
        &state.db,
        sealing,
        visitor.user.user_id,
        &label,
        grants,
        expires_at,
    )
    .await
    {
        Ok(created) => created,
        Err(err @ CoreError::InvalidGrants(_)) => {
            // The buckets changed since the page was shown (removed in another tab).
            let message = fill(t.s3_err_grants, &[&err.to_string()]);
            return refuse(&state, &visitor, forms, message).await;
        }
        Err(err) => return internal(&visitor, "S3 access key", &err),
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    audit(
        &state.db,
        record(&visitor, "s3.key.created", client).details(key_details(&key, &buckets)),
    )
    .await;
    tracing::info!(
        user = %visitor.user.username,
        access_key_id = %key.access_key_id,
        "user created an S3 access key"
    );
    files.s3_created.put(
        &visitor.user,
        NewKey {
            grants: grant_chips(t, &key.grants, &buckets),
            label: key.label,
            access_key_id: key.access_key_id,
            secret,
            expires_at: key.expires_at,
        },
    );
    web::see_other(&format!("{ACCOUNT}/s3/created"), &[])
}

/// `GET /apps/account/s3/created`: the new access key with its secret key, once.
pub async fn created(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let ui = match enabled(&state) {
        Ok(ui) => ui,
        Err(response) => return *response,
    };
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(key) = files.s3_created.take(&visitor.user) else {
        return web::see_other(&format!("{ACCOUNT}/"), &[]);
    };
    let t = visitor.t();
    let (endpoint, addressing) = endpoint(t, &ui);
    let page = CreatedPage {
        chrome: visitor.chrome(Nav::Account),
        label: key.label,
        access_key_id: key.access_key_id,
        secret: key.secret.expose_secret().to_owned(),
        grants: key.grants,
        expiry: expiry(t, &visitor, db::unix_now(), key.expires_at),
        endpoint,
        region: ui.region.clone(),
        addressing,
    };
    web::render(StatusCode::OK, &page)
}

/// `POST /apps/account/s3/keys/<id>/delete`.
pub async fn revoke_key(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Err(response) = enabled(&state) {
        return *response;
    }
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    // Only the user's own: both queries name the owner.
    let key = match s3::list_keys(&state.db, visitor.user.user_id).await {
        Ok(keys) => keys.into_iter().find(|key| key.id == id),
        Err(err) => return internal(&visitor, "S3 access keys", &err),
    };
    let Some(key) = key else {
        // Revoked already (for example in another tab): nothing to report.
        return web::see_other(&format!("{ACCOUNT}/"), &[]);
    };
    match s3::delete_key(&state.db, visitor.user.user_id, id).await {
        Ok(true) => {}
        Ok(false) => return web::see_other(&format!("{ACCOUNT}/"), &[]),
        Err(err) => return internal(&visitor, "revoke an S3 access key", &err),
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let details = json!({ "access_key_id": key.access_key_id, "label": key.label });
    audit(
        &state.db,
        record(&visitor, "s3.key.revoked", client).details(details),
    )
    .await;
    tracing::info!(
        user = %visitor.user.username,
        access_key_id = %key.access_key_id,
        "user revoked an S3 access key"
    );
    done("s3-key-revoked")
}
