//! The S3 operations: [`GonoS3`] implements the s3s trait.
//!
//! Every operation starts from the [`Authorized`] the access check left in the request's
//! extensions, builds an [`Identity`] whose mounts are the buckets involved (each mounted at its
//! name), and reaches the tree only through [`gono_server_dav::ScopedFs`].
//!
//! - **Listings** come from the `files` table in S3 key order (`MetaStore::list_objects`), with
//!   opaque continuation tokens and `encoding-type=url`. Versioning is never enabled, so
//!   `ListObjectVersions` lists each object as its only version, `null`, as S3 does for a
//!   bucket that never had versioning.
//! - **Writes** receive the body into `tmp/` and verify it ([`crate::upload`]), refuse files
//!   locked by WebDAV clients (`OperationAborted`), and install with the object's metadata.
//! - **Reads** honor `Range`, the conditional headers and, for signed requests only, the
//!   `response-*` overrides. Content types not stored with an object are guessed from its name
//!   as for WebDAV. Anonymous responses carry `X-Content-Type-Options: nosniff`, and in a bucket
//!   that honors object ACLs they need the object's `public-read` ACL.
//! - **ACLs** are canned: `private` and `public-read`, plus `bucket-owner-read` and
//!   `bucket-owner-full-control`, which mean private here. A `public-read` object needs a bucket
//!   that publishes something; elsewhere it is refused (`AccessControlListNotSupported`) instead
//!   of being ignored, so an application learns at upload time that its links would not work.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use gono_server_core::{
    Permission, RelPath,
    audit::{self, Actor, Record},
    db,
    meta::{ListEntry, ObjectMeta, ObjectQuery},
    s3::{self, Anonymous, Bucket, BucketName},
};
use gono_server_dav::{Identity, Mount, ObjectError, WriteCondition, locks, metadata::Entry};
use http::{HeaderMap, HeaderValue};
use s3s::{
    S3, S3Error, S3ErrorCode, S3Request, S3Response, S3Result,
    dto::{self, ETag, ETagCondition, Timestamp},
    s3_error,
};
use serde_json::json;
use tokio::io::AsyncReadExt as _;

use crate::{
    access::{self, Authorized, Caller},
    cors, error,
    form::FormAcl,
    keys::{self, Target},
    policy,
    state::S3State,
    upload,
};

/// The URI of S3's group of all users, in ACLs.
const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

/// The ETag of empty content (folder markers).
const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// Most keys in one listing and in one `DeleteObjects`.
const MAX_KEYS: usize = 1000;

/// The version id of every object: versioning is never enabled.
pub(crate) const NULL_VERSION: &str = "null";

/// Bytes read from a file at once for a download.
const READ_CHUNK: usize = 256 * 1024;

/// The s3s trait implementation. Cheap to clone.
#[derive(Clone)]
pub(crate) struct GonoS3 {
    state: S3State,
}

impl GonoS3 {
    pub(crate) fn new(state: S3State) -> Self {
        Self { state }
    }

    pub(crate) fn state(&self) -> &S3State {
        &self.state
    }

    fn allow_anonymous(&self) -> bool {
        self.state.settings().allow_anonymous
    }
}

/// The outcome of the access check, which every operation runs after.
fn authorized<T>(req: &S3Request<T>) -> S3Result<Authorized> {
    req.extensions
        .get::<Authorized>()
        .cloned()
        .ok_or_else(|| s3_error!(InternalError, "the access check did not run"))
}

/// The key a request was signed with; operations that only keys reach use it.
fn signing_key(auth: &Authorized) -> S3Result<&Arc<s3::SigningKey>> {
    match &auth.caller {
        Caller::Key(key) => Ok(key),
        Caller::Anonymous => Err(s3_error!(AccessDenied)),
    }
}

fn timestamp_from_secs(seconds: i64) -> Timestamp {
    Timestamp::from(UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0)))
}

fn timestamp_from_ns(nanos: i64) -> Timestamp {
    Timestamp::from(UNIX_EPOCH + Duration::from_nanos(u64::try_from(nanos).unwrap_or(0)))
}

/// Seconds since the epoch, the precision of HTTP dates.
fn unix_seconds(timestamp: &Timestamp) -> i64 {
    time::OffsetDateTime::from(timestamp.clone()).unix_timestamp()
}

fn system_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |since| {
        i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
    })
}

fn owner_of(bucket: &Bucket) -> dto::Owner {
    dto::Owner {
        display_name: Some(bucket.owner_display_name.clone()),
        id: Some(bucket.owner_name.to_string()),
    }
}

/// The grants of an ACL: the owner's `FULL_CONTROL`, and `READ` for everyone if `public`.
fn acl_grants(owner: &dto::Owner, public: bool) -> Vec<dto::Grant> {
    let mut grants = vec![dto::Grant {
        grantee: Some(dto::Grantee {
            display_name: owner.display_name.clone(),
            email_address: None,
            id: owner.id.clone(),
            type_: dto::Type::from_static(dto::Type::CANONICAL_USER),
            uri: None,
        }),
        permission: Some(dto::Permission::from_static(dto::Permission::FULL_CONTROL)),
    }];
    if public {
        grants.push(dto::Grant {
            grantee: Some(dto::Grantee {
                display_name: None,
                email_address: None,
                id: None,
                type_: dto::Type::from_static(dto::Type::GROUP),
                uri: Some(ALL_USERS.to_owned()),
            }),
            permission: Some(dto::Permission::from_static(dto::Permission::READ)),
        });
    }
    grants
}

/// What a canned object ACL asks for: `Some(true)` public, `Some(false)` private.
fn object_acl(acl: Option<&dto::ObjectCannedACL>) -> S3Result<bool> {
    match acl.map(dto::ObjectCannedACL::as_str) {
        None | Some("private" | "bucket-owner-read" | "bucket-owner-full-control") => Ok(false),
        Some("public-read") => Ok(true),
        Some(other) => Err(unsupported_acl(other)),
    }
}

/// The error for a canned ACL other than the supported ones: `NotImplemented` for the other
/// canned ACLs of S3, `400 InvalidArgument` for a value that is none of them.
pub(crate) fn unsupported_acl(value: &str) -> S3Error {
    const CANNED: [&str; 8] = [
        "private",
        "public-read",
        "public-read-write",
        "authenticated-read",
        "aws-exec-read",
        "bucket-owner-read",
        "bucket-owner-full-control",
        "log-delivery-write",
    ];
    if CANNED.contains(&value) {
        s3_error!(
            NotImplemented,
            "Only the canned ACLs private and public-read are supported"
        )
    } else {
        s3_error!(InvalidArgument, "The canned ACL is not valid")
    }
}

/// Refuses explicit grant headers, which are not supported.
fn no_grants(grants: &[Option<&String>]) -> S3Result<()> {
    if grants.iter().any(Option::is_some) {
        return Err(s3_error!(
            NotImplemented,
            "Explicit grants are not supported; use a canned ACL"
        ));
    }
    Ok(())
}

/// Whether an object may get the `public-read` ACL in `bucket` right now.
fn check_public_acl(bucket: &Bucket, allow_anonymous: bool) -> S3Result<()> {
    if access::Public::of(bucket, allow_anonymous).read == Anonymous::Private {
        return Err(s3_error!(
            AccessControlListNotSupported,
            "The bucket does not publish objects; public-read objects would not be readable"
        ));
    }
    Ok(())
}

/// The target of `key` in `bucket`.
fn target(bucket: &Bucket, key: &str) -> S3Result<Target> {
    keys::target(&bucket.name, key).map_err(|err| error::key(&err))
}

/// The storage path of client path `client` (below `bucket`'s mount).
fn storage_of(bucket: &Bucket, client: &RelPath) -> S3Result<RelPath> {
    let mount = RelPath::parse(&bucket.name).map_err(|_| s3_error!(InternalError))?;
    let below = client
        .strip_prefix(&mount)
        .ok_or_else(|| s3_error!(InternalError))?;
    Ok(bucket.folder.join_path(&below))
}

/// The S3 ETag of a file version: the one stored with it, else the MD5 of its content, else
/// its WebDAV ETag.
fn etag_of(entry: &Entry, meta: Option<&ObjectMeta>) -> String {
    entry.s3_etag(meta)
}

/// The content type of `entry`: stored with it, or guessed from its name as for WebDAV.
fn content_type_of(client: &RelPath, meta: Option<&ObjectMeta>) -> String {
    if let Some(stored) = meta.and_then(|meta| meta.content_type.clone()) {
        return stored;
    }
    client
        .file_name()
        .and_then(|name| name.rsplit_once('.'))
        .and_then(|(_, ext)| mime_guess::from_ext(ext).first_raw())
        .unwrap_or("application/octet-stream")
        .to_owned()
}

/// Evaluates the conditional headers of a read (RFC 9110, section 13.2.2).
fn check_read_conditions(
    etag: &str,
    modified: SystemTime,
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
    if_modified_since: Option<&Timestamp>,
    if_unmodified_since: Option<&Timestamp>,
) -> S3Result<()> {
    let current = ETag::Strong(etag.to_owned());
    let matches = |condition: &ETagCondition| match condition {
        ETagCondition::Any => true,
        ETagCondition::ETag(other) => current.strong_cmp(other),
    };
    let modified = system_seconds(modified);
    match (if_match, if_unmodified_since) {
        (Some(condition), _) if !matches(condition) => return Err(s3_error!(PreconditionFailed)),
        (None, Some(since)) if modified > unix_seconds(since) => {
            return Err(s3_error!(PreconditionFailed));
        }
        _ => {}
    }
    match (if_none_match, if_modified_since) {
        (Some(condition), _) if matches(condition) => Err(s3_error!(NotModified)),
        (None, Some(since)) if modified <= unix_seconds(since) => Err(s3_error!(NotModified)),
        _ => Ok(()),
    }
}

/// A `304 Not Modified` carries the object's `ETag` and `Last-Modified`, as from S3, so that
/// caches can refresh what they hold; other errors are left as they are.
fn with_validators(mut err: S3Error, etag: &str, modified: SystemTime) -> S3Error {
    if *err.code() != S3ErrorCode::NotModified {
        return err;
    }
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!("\"{etag}\"")) {
        headers.insert(http::header::ETAG, value);
    }
    let mut date = Vec::new();
    if Timestamp::from(modified)
        .format(dto::TimestampFormat::HttpDate, &mut date)
        .is_ok()
        && let Ok(value) = HeaderValue::from_bytes(&date)
    {
        headers.insert(http::header::LAST_MODIFIED, value);
    }
    err.set_headers(headers);
    err
}

/// Evaluates the `x-amz-copy-source-if-*` headers of a copy: like the conditional headers of a
/// read, except that a failed condition is a `412` in every case.
pub(crate) fn check_copy_source_conditions(
    etag: &str,
    modified: SystemTime,
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
    if_modified_since: Option<&Timestamp>,
    if_unmodified_since: Option<&Timestamp>,
) -> S3Result<()> {
    check_read_conditions(
        etag,
        modified,
        if_match,
        if_none_match,
        if_modified_since,
        if_unmodified_since,
    )
    .map_err(|err| {
        if *err.code() == S3ErrorCode::NotModified {
            s3_error!(PreconditionFailed)
        } else {
            err
        }
    })
}

/// The region whose CreateBucket answers 200 for a bucket the caller owns already.
const US_EAST_1: &str = "us-east-1";

/// Which buckets one `ListBuckets` answer lists: those after the continuation token that start
/// with the prefix, at most `max-buckets` (1 to 10000) of them. Without `max-buckets` every
/// bucket fits, as S3's default page size is 10000.
struct BucketPage {
    after: Option<String>,
    prefix: String,
    max: usize,
}

impl BucketPage {
    const MAX: usize = 10_000;

    fn new(input: &dto::ListBucketsInput) -> S3Result<Self> {
        let max = match input.max_buckets {
            None => Self::MAX,
            Some(max) => usize::try_from(max)
                .ok()
                .filter(|max| (1..=Self::MAX).contains(max))
                .ok_or_else(|| {
                    s3_error!(InvalidArgument, "max-buckets must be between 1 and 10000")
                })?,
        };
        let after = match input.continuation_token.as_deref() {
            None | Some("") => None,
            Some(token) => Some(keys::marker_of_token(token).ok_or_else(|| {
                s3_error!(InvalidArgument, "The continuation token is not valid")
            })?),
        };
        Ok(Self {
            after,
            prefix: input.prefix.clone().unwrap_or_default(),
            max,
        })
    }

    /// The page of `sorted` (in name order) and whether more follow.
    fn select<'a, T>(&self, sorted: &[&'a T], name: impl Fn(&T) -> &str) -> (Vec<&'a T>, bool) {
        let mut candidates = sorted.iter().copied().filter(|item| {
            let name = name(item);
            name.starts_with(&self.prefix) && self.after.as_deref().is_none_or(|after| name > after)
        });
        let page: Vec<&T> = candidates.by_ref().take(self.max).collect();
        let more = candidates.next().is_some();
        (page, more)
    }
}

/// Refuses every version but `null`: versioning is never enabled.
fn check_null_version(version: Option<&str>) -> S3Result<()> {
    if version.is_some_and(|id| id != NULL_VERSION) {
        Err(s3_error!(NoSuchVersion))
    } else {
        Ok(())
    }
}

/// The condition of a write from `If-Match` and `If-None-Match`. `If-Match` (an ETag or `*`)
/// needs an object (404 `NoSuchKey` otherwise); `If-None-Match` with an ETag lets every other
/// version be replaced, and a missing object be created.
pub(crate) fn write_condition(
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
) -> S3Result<WriteCondition> {
    match (if_match, if_none_match) {
        (None, None) => Ok(WriteCondition::Always),
        (None, Some(ETagCondition::Any)) => Ok(WriteCondition::CreateOnly),
        (None, Some(ETagCondition::ETag(etag))) => {
            Ok(WriteCondition::IfNoneMatch(etag.value().to_owned()))
        }
        (Some(ETagCondition::ETag(etag)), None) => {
            Ok(WriteCondition::IfMatch(etag.value().to_owned()))
        }
        (Some(ETagCondition::Any), None) => Ok(WriteCondition::IfExists),
        (Some(_), Some(_)) => Err(s3_error!(
            NotImplemented,
            "If-Match and If-None-Match together are not supported for writes"
        )),
    }
}

/// `x-amz-meta-*` as stored: names in lowercase.
fn user_meta(metadata: Option<dto::Metadata>) -> BTreeMap<String, String> {
    metadata
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect()
}

/// Reads `length` bytes of `file` in chunks.
fn file_body(file: tokio::fs::File, length: u64) -> dto::StreamingBlob {
    let stream = futures_util::stream::unfold((file, length), |(mut file, remaining)| async move {
        if remaining == 0 {
            return None;
        }
        let want = usize::try_from(remaining.min(READ_CHUNK as u64)).unwrap_or(READ_CHUNK);
        let mut buffer = vec![0; want];
        match file.read(&mut buffer).await {
            Ok(0) => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the file became shorter while it was sent",
                )),
                (file, 0),
            )),
            Ok(read) => {
                buffer.truncate(read);
                Some((Ok(Bytes::from(buffer)), (file, remaining - read as u64)))
            }
            Err(err) => Some((Err(err), (file, 0))),
        }
    });
    dto::StreamingBlob::wrap(stream)
}

/// What a listing asks for, from the input of either version.
struct ListRequest<'a> {
    prefix: &'a str,
    delimiter: Option<&'a str>,
    start_after: Option<&'a str>,
    max_keys: Option<i32>,
    /// `encoding-type=url`.
    url: bool,
    /// Report each object's owner.
    owner: bool,
}

/// What a listing returns, before it is put into the output of either version.
struct Listed {
    objects: Vec<dto::Object>,
    prefixes: Vec<dto::CommonPrefix>,
    truncated: bool,
    /// The last key or common prefix (where the next page starts after).
    last: Option<String>,
    /// Whether that last entry is a common prefix.
    last_is_prefix: bool,
}

impl GonoS3 {
    /// Writes an audit record of a change made with access key `key`. A failure is logged;
    /// the change stands.
    async fn audit(
        &self,
        key: &s3::SigningKey,
        kind: &'static str,
        mut details: serde_json::Value,
    ) {
        if let Some(details) = details.as_object_mut() {
            details.insert("access_key_id".to_owned(), json!(key.access_key_id));
        }
        // The actor of S3 requests is the key's account, like a user in the browser.
        let record = Record::new(key.user_id, kind, Actor::User).details(details);
        if let Err(err) = audit::record(self.state.pool(), &record, db::unix_now()).await {
            tracing::warn!(kind, error = %err, "cannot write an audit record");
        }
    }

    /// Sets the anonymous access of `bucket` to `mode` and `list`, with an audit record, unless
    /// it is so already.
    async fn set_anonymous(
        &self,
        auth: &Authorized,
        bucket: &Bucket,
        mode: Anonymous,
        list: bool,
    ) -> S3Result<()> {
        if (bucket.anonymous, bucket.anonymous_list) == (mode, list) {
            return Ok(());
        }
        s3::set_anonymous(self.state.pool(), bucket.owner_id, bucket.id, mode, list)
            .await
            .map_err(error::database)?;
        self.audit(
            signing_key(auth)?,
            "s3.bucket.anonymous",
            json!({ "bucket": bucket.name, "anonymous": mode.as_str(), "list": list }),
        )
        .await;
        Ok(())
    }

    /// The checks every write of a file shares: not locked by a WebDAV client.
    async fn check_locks(&self, bucket: &Bucket, client: &RelPath) -> S3Result<()> {
        let storage = storage_of(bucket, client)?;
        match locks::write_conflict(
            self.state.locks(),
            bucket.owner_id,
            &storage,
            bucket.owner_name.as_str(),
            &[],
        )
        .await
        {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(s3_error!(
                OperationAborted,
                "The object is locked by a WebDAV client"
            )),
            Err(err) => Err(error::database(err)),
        }
    }

    /// An identity of `bucket`'s owner with that bucket mounted, writable or not.
    fn bucket_identity(
        auth: &Authorized,
        bucket: &Bucket,
        writable: bool,
    ) -> S3Result<Arc<Identity>> {
        auth.identity(&[(bucket, writable)])
    }

    /// An identity of `owner` with the whole tree mounted, for creating and removing bucket
    /// folders.
    fn tree_identity(key: &s3::SigningKey) -> Arc<Identity> {
        Arc::new(Identity {
            user_id: key.user_id,
            username: key.username.clone(),
            display_name: key.display_name.clone(),
            app_password_id: Some(key.id),
            mounts: vec![Mount {
                mount_path: RelPath::root(),
                storage_path: RelPath::root(),
                writable: true,
            }],
        })
    }

    async fn list(&self, bucket: &Bucket, request: ListRequest<'_>) -> S3Result<Listed> {
        let ListRequest {
            prefix,
            delimiter,
            start_after,
            max_keys,
            url,
            owner,
        } = request;
        let max = max_keys.map_or(MAX_KEYS, |max| {
            usize::try_from(max.max(0)).unwrap_or(0).min(MAX_KEYS)
        });
        if max == 0 {
            // Nothing asked for, nothing more to come: S3 answers an empty page that is not
            // truncated.
            return Ok(Listed {
                objects: Vec::new(),
                prefixes: Vec::new(),
                truncated: false,
                last: None,
                last_is_prefix: false,
            });
        }
        let listing = self
            .state
            .fs()
            .meta()
            .list_objects(
                bucket.owner_id,
                ObjectQuery {
                    root: &bucket.folder,
                    prefix,
                    delimiter,
                    start_after,
                    max_entries: max,
                },
            )
            .await
            .map_err(error::database)?;
        let encode = |value: &str| {
            if url {
                keys::url_encode(value)
            } else {
                value.to_owned()
            }
        };
        let mut listed = Listed {
            objects: Vec::new(),
            prefixes: Vec::new(),
            truncated: listing.truncated,
            last: listing
                .entries
                .last()
                .map(|entry| entry.marker().to_owned()),
            last_is_prefix: matches!(listing.entries.last(), Some(ListEntry::CommonPrefix(_))),
        };
        for entry in listing.entries {
            match entry {
                ListEntry::Object(object) => listed.objects.push(dto::Object {
                    e_tag: Some(ETag::Strong(object.etag())),
                    key: Some(encode(&object.key)),
                    last_modified: Some(timestamp_from_ns(object.file.mtime_ns)),
                    owner: owner.then(|| owner_of(bucket)),
                    size: Some(i64::try_from(object.file.size).unwrap_or(i64::MAX)),
                    storage_class: Some(dto::ObjectStorageClass::from_static(
                        dto::ObjectStorageClass::STANDARD,
                    )),
                    ..Default::default()
                }),
                ListEntry::CommonPrefix(prefix) => listed.prefixes.push(dto::CommonPrefix {
                    prefix: Some(encode(&prefix)),
                }),
            }
        }
        Ok(listed)
    }

    /// The body of `GetObject` and `HeadObject` up to the body itself: the object, its
    /// metadata and the checks of the request.
    async fn open_for_read(
        &self,
        auth: &Authorized,
        key: &str,
    ) -> S3Result<(
        RelPath,
        Arc<Entry>,
        Option<ObjectMeta>,
        Option<std::fs::File>,
    )> {
        let bucket = auth.bucket()?;
        let anonymous = auth.caller.is_anonymous();
        let target = match keys::target(&bucket.name, key) {
            Ok(target) => target,
            // A key the tree cannot hold names nothing.
            Err(_) if anonymous => return Err(s3_error!(AccessDenied)),
            Err(_) => return Err(s3_error!(NoSuchKey)),
        };
        let identity = Self::bucket_identity(auth, bucket, false)?;
        let not_found = || {
            if anonymous {
                s3_error!(AccessDenied)
            } else {
                s3_error!(NoSuchKey)
            }
        };
        if !self.spelled_as(bucket, target.path(), key).await? {
            return Err(not_found());
        }
        match &target {
            Target::Folder(client) => {
                // A folder marker reads as an empty object.
                let entry = self
                    .state
                    .fs()
                    .stat(identity, client)
                    .await
                    .map_err(|_| not_found())?;
                if !entry.is_dir() || anonymous {
                    return Err(not_found());
                }
                Ok((client.clone(), entry, None, None))
            }
            Target::File(client) => {
                let (entry, meta, file) = self
                    .state
                    .fs()
                    .open_object(identity, client)
                    .await
                    .map_err(|err| match err {
                        ObjectError::IsFolder | ObjectError::NotFound => not_found(),
                        other => error::object(other, anonymous),
                    })?;
                if anonymous
                    && auth.public(self.allow_anonymous()).read == Anonymous::Acl
                    && !meta.as_ref().is_some_and(|meta| meta.public_read)
                {
                    return Err(s3_error!(AccessDenied));
                }
                Ok((client.clone(), entry, meta, Some(file)))
            }
        }
    }

    /// Part `number` of the file `entry` (with S3 metadata `meta`), for `partNumber` reads.
    async fn object_part(
        &self,
        entry: &Entry,
        meta: Option<&ObjectMeta>,
        number: i32,
    ) -> S3Result<PartRead> {
        let parts = match (meta, entry.file_id) {
            (Some(_), Some(file_id)) if !entry.is_dir() => self
                .state
                .fs()
                .meta()
                .object_parts(file_id)
                .await
                .map_err(error::database)?,
            _ => Vec::new(),
        };
        let index = usize::try_from(number)
            .ok()
            .and_then(|number| number.checked_sub(1))
            .ok_or_else(invalid_part_number)?;
        if parts.is_empty() {
            return if index == 0 {
                Ok(PartRead {
                    start: 0,
                    length: if entry.is_dir() { 0 } else { entry.size },
                    checksum: None,
                    count: None,
                })
            } else {
                Err(invalid_part_number())
            };
        }
        let part = parts.get(index).ok_or_else(invalid_part_number)?;
        Ok(PartRead {
            start: parts[..index].iter().map(|part| part.size).sum(),
            length: part.size,
            checksum: part.checksum.clone(),
            count: Some(parts.len()),
        })
    }

    /// Sets the tags of the object `key` of the request's bucket (empty: removes them), for
    /// its current version.
    async fn set_tags(
        &self,
        auth: &Authorized,
        key: &str,
        tags: &BTreeMap<String, String>,
    ) -> S3Result<()> {
        let bucket = auth.bucket()?;
        let client = match target(bucket, key)? {
            Target::File(path) => path,
            Target::Folder(_) => return Err(s3_error!(NoSuchKey)),
        };
        if !self.spelled_as(bucket, &client, key).await? {
            return Err(s3_error!(NoSuchKey));
        }
        let identity = Self::bucket_identity(auth, bucket, true)?;
        let entry = self
            .state
            .fs()
            .stat(identity, &client)
            .await
            .map_err(|_| s3_error!(NoSuchKey))?;
        let file_id = entry
            .file_id
            .filter(|_| !entry.is_dir())
            .ok_or_else(|| s3_error!(NoSuchKey))?;
        let set = self
            .state
            .fs()
            .meta()
            .set_object_tags(file_id, &entry.etag, tags)
            .await
            .map_err(error::database)?;
        if !set {
            return Err(s3_error!(
                OperationAborted,
                "The object changed while its tags were set; try again"
            ));
        }
        Ok(())
    }

    /// Writes the body of `PutObject` (or an empty folder marker).
    async fn put(&self, req: S3Request<dto::PutObjectInput>) -> S3Result<dto::PutObjectOutput> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?.clone();
        let input = req.input;
        if input.server_side_encryption.is_some()
            || input.sse_customer_algorithm.is_some()
            || input.ssekms_key_id.is_some()
        {
            return Err(s3_error!(
                NotImplemented,
                "Server-side encryption is not supported"
            ));
        }
        if input
            .storage_class
            .as_ref()
            .is_some_and(|class| class.as_str() != dto::StorageClass::STANDARD)
        {
            return Err(s3_error!(InvalidStorageClass));
        }
        if input.object_lock_mode.is_some() || input.write_offset_bytes.is_some() {
            return Err(s3_error!(NotImplemented));
        }
        no_grants(&[
            input.grant_full_control.as_ref(),
            input.grant_read.as_ref(),
            input.grant_read_acp.as_ref(),
            input.grant_write_acp.as_ref(),
        ])?;
        let public = object_acl(input.acl.as_ref())?;
        if public {
            check_public_acl(&bucket, self.allow_anonymous())?;
        }
        let condition = write_condition(input.if_match.as_ref(), input.if_none_match.as_ref())?;
        let target = target(&bucket, &input.key)?;
        self.check_locks(&bucket, target.path()).await?;
        let identity = Self::bucket_identity(&auth, &bucket, true)?;

        if let Target::Folder(client) = &target {
            if input.content_length.is_some_and(|length| length > 0) {
                return Err(s3_error!(
                    InvalidArgument,
                    "A key ending in '/' names a folder and takes no content"
                ));
            }
            self.state
                .fs()
                .put_spelled_folder(
                    identity,
                    client,
                    Some(&keys::spelled(&bucket.name, &input.key)),
                )
                .await
                .map_err(|err| error::object(err, false))?;
            return Ok(dto::PutObjectOutput {
                e_tag: Some(ETag::Strong(EMPTY_MD5.to_owned())),
                ..Default::default()
            });
        }

        let body = input.body.ok_or_else(|| s3_error!(IncompleteBody))?;
        let mut claimed = dto::Checksum {
            checksum_crc32: input.checksum_crc32,
            checksum_crc32c: input.checksum_crc32c,
            checksum_crc64nvme: input.checksum_crc64nvme,
            checksum_md5: input.checksum_md5,
            checksum_sha1: input.checksum_sha1,
            checksum_sha256: input.checksum_sha256,
            checksum_sha512: input.checksum_sha512,
            checksum_xxhash128: input.checksum_xxhash128,
            checksum_xxhash3: input.checksum_xxhash3,
            checksum_xxhash64: input.checksum_xxhash64,
            ..Default::default()
        };
        let algorithms = upload::announced(
            &claimed,
            input
                .checksum_algorithm
                .as_ref()
                .map(dto::ChecksumAlgorithm::as_str),
            &req.headers,
        );
        let received =
            upload::receive(&self.state, body, input.content_length, &algorithms).await?;
        let trailers = req
            .trailing_headers
            .as_ref()
            .and_then(s3s::TrailingHeaders::take);
        upload::apply_trailers(&mut claimed, trailers.as_ref())?;
        let content_md5 = upload::content_md5(&req.headers, input.content_md5.as_deref());
        let checksum = upload::verify(&received, content_md5, &claimed)?;
        let etag = received.etag();
        let meta = ObjectMeta {
            s3_etag: Some(etag.clone()),
            public_read: public,
            content_type: input.content_type,
            content_encoding: upload::stored_content_encoding(input.content_encoding),
            content_disposition: input.content_disposition,
            content_language: input.content_language,
            cache_control: input.cache_control,
            expires: input.expires,
            user_meta: user_meta(input.metadata),
            tags: crate::tags::from_header(input.tagging.as_deref())?,
            checksum: checksum.clone(),
            parts: Vec::new(),
        };
        if let Some(time) = upload::mtime_of(&meta) {
            upload::set_mtime(received.temp.path(), time).await?;
        }
        self.state
            .fs()
            .put_object(
                identity,
                target.path(),
                Some(&keys::spelled(&bucket.name, &input.key)),
                received.temp.path().to_path_buf(),
                meta,
                condition,
            )
            .await
            .map_err(|err| error::object(err, false))?;
        Ok(dto::PutObjectOutput {
            e_tag: Some(ETag::Strong(etag)),
            size: Some(i64::try_from(received.size).unwrap_or(i64::MAX)),
            ..upload_output(checksum.as_ref())
        })
    }
}

/// A `PutObjectOutput` that echoes the stored checksum.
fn upload_output(checksum: Option<&gono_server_core::meta::Checksum>) -> dto::PutObjectOutput {
    let checksum = upload::stored_checksum(checksum);
    dto::PutObjectOutput {
        checksum_crc32: checksum.checksum_crc32,
        checksum_crc32c: checksum.checksum_crc32c,
        checksum_crc64nvme: checksum.checksum_crc64nvme,
        checksum_md5: checksum.checksum_md5,
        checksum_sha1: checksum.checksum_sha1,
        checksum_sha256: checksum.checksum_sha256,
        checksum_sha512: checksum.checksum_sha512,
        checksum_xxhash128: checksum.checksum_xxhash128,
        checksum_xxhash3: checksum.checksum_xxhash3,
        checksum_xxhash64: checksum.checksum_xxhash64,
        checksum_type: checksum.checksum_type,
        ..Default::default()
    }
}

/// One part of an object, as `partNumber` names it.
#[derive(Debug)]
struct PartRead {
    /// Its first byte in the object.
    start: u64,
    /// Its length in bytes.
    length: u64,
    /// Its checksum (base64) in the object's algorithm.
    checksum: Option<String>,
    /// How many parts the object has; `None` if a multipart upload did not write it (it is its
    /// own and only part then).
    count: Option<usize>,
}

/// S3's answer to a part number the object does not have.
fn invalid_part_number() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("InvalidPartNumber".into()),
        "The requested partnumber is not satisfiable",
    );
    err.set_status_code(http::StatusCode::RANGE_NOT_SATISFIABLE);
    err
}

/// The checksum to answer a read with (only with `x-amz-checksum-mode`): the object's for the
/// whole object, a part's for one part of a multipart object, none for a byte range.
fn read_checksum(
    mode: bool,
    meta: Option<&ObjectMeta>,
    part: Option<&PartRead>,
    whole: bool,
) -> dto::Checksum {
    let Some(stored) = meta
        .and_then(|meta| meta.checksum.as_ref())
        .filter(|_| mode)
    else {
        return dto::Checksum::default();
    };
    match part {
        Some(PartRead {
            count: Some(_),
            checksum,
            ..
        }) => upload::stored_checksum(
            checksum
                .as_ref()
                .map(|value| gono_server_core::meta::Checksum {
                    value: value.clone(),
                    ..stored.clone()
                })
                .as_ref(),
        ),
        _ if whole => upload::stored_checksum(Some(stored)),
        _ => dto::Checksum::default(),
    }
}

/// The page of `parts` `GetObjectAttributes` asks for (`part-number-marker`, `max-parts`, at most
/// 1000), with their sizes and, if the object has a checksum, their checksums.
fn object_parts_page(
    parts: &[gono_server_core::meta::ObjectPart],
    checksum: Option<&gono_server_core::meta::Checksum>,
    input: &dto::GetObjectAttributesInput,
) -> dto::GetObjectAttributesParts {
    let marker = input
        .part_number_marker
        .and_then(|marker| usize::try_from(marker).ok())
        .unwrap_or(0);
    let max = input
        .max_parts
        .and_then(|max| usize::try_from(max).ok())
        .map_or(1000, |max| max.min(1000));
    let listed: Vec<dto::ObjectPart> = parts
        .iter()
        .enumerate()
        .skip(marker)
        .take(max)
        .map(|(index, part)| {
            let fields = upload::stored_checksum(
                checksum
                    .zip(part.checksum.as_ref())
                    .map(|(checksum, value)| gono_server_core::meta::Checksum {
                        value: value.clone(),
                        ..checksum.clone()
                    })
                    .as_ref(),
            );
            dto::ObjectPart {
                part_number: i32::try_from(index + 1).ok(),
                size: i64::try_from(part.size).ok(),
                checksum_crc32: fields.checksum_crc32,
                checksum_crc32c: fields.checksum_crc32c,
                checksum_crc64nvme: fields.checksum_crc64nvme,
                checksum_sha1: fields.checksum_sha1,
                checksum_sha256: fields.checksum_sha256,
                ..Default::default()
            }
        })
        .collect();
    let next = marker + listed.len();
    let truncated = next < parts.len();
    dto::GetObjectAttributesParts {
        total_parts_count: i32::try_from(parts.len()).ok(),
        part_number_marker: input.part_number_marker,
        next_part_number_marker: truncated.then(|| i32::try_from(next).ok()).flatten(),
        max_parts: i32::try_from(max).ok(),
        is_truncated: Some(truncated),
        parts: Some(listed),
    }
}

/// s3s's own `PostObject`, which turns the form into a `PutObject`, over [`GonoS3::put`].
struct FormUpload(GonoS3);

#[async_trait::async_trait]
impl S3 for FormUpload {
    async fn put_object(
        &self,
        req: S3Request<dto::PutObjectInput>,
    ) -> S3Result<S3Response<dto::PutObjectOutput>> {
        Ok(S3Response::new(self.0.put(req).await?))
    }
}

/// `X-Content-Type-Options: nosniff` for responses to anonymous requests.
fn nosniff(headers: &mut HeaderMap, anonymous: bool) {
    if anonymous {
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
    }
}

#[async_trait::async_trait]
impl S3 for GonoS3 {
    async fn list_buckets(
        &self,
        req: S3Request<dto::ListBucketsInput>,
    ) -> S3Result<S3Response<dto::ListBucketsOutput>> {
        let auth = authorized(&req)?;
        let key = signing_key(&auth)?;
        let input = req.input;
        let region = &self.state.settings().region;
        let page = BucketPage::new(&input)?;
        let buckets = s3::buckets_of(self.state.pool(), key.user_id)
            .await
            .map_err(error::database)?;
        // Every bucket is in this server's region.
        let in_region = input
            .bucket_region
            .as_ref()
            .is_none_or(|wanted| wanted == region);
        let visible: Vec<&Bucket> = buckets
            .iter()
            .filter(|bucket| in_region && access::permission(key, bucket).is_some())
            .collect();
        let (listed, more) = page.select(&visible, |bucket| bucket.name.as_str());
        let continuation_token = more
            .then(|| {
                listed
                    .last()
                    .map(|bucket| keys::continuation_token(&bucket.name))
            })
            .flatten();
        let listed = listed
            .iter()
            .map(|bucket| dto::Bucket {
                creation_date: Some(timestamp_from_secs(bucket.created_at)),
                name: Some(bucket.name.clone()),
                bucket_region: Some(region.clone()),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(dto::ListBucketsOutput {
            buckets: Some(listed),
            continuation_token,
            owner: Some(dto::Owner {
                display_name: Some(key.display_name.clone()),
                id: Some(key.username.to_string()),
            }),
            prefix: input.prefix,
        }))
    }

    async fn create_bucket(
        &self,
        req: S3Request<dto::CreateBucketInput>,
    ) -> S3Result<S3Response<dto::CreateBucketOutput>> {
        let auth = authorized(&req)?;
        let key = signing_key(&auth)?;
        let input = req.input;
        let name = BucketName::new(&input.bucket).map_err(|err| {
            S3Error::with_message(S3ErrorCode::InvalidBucketName, err.to_string())
        })?;
        let region = &self.state.settings().region;
        if let Some(constraint) = input
            .create_bucket_configuration
            .as_ref()
            .and_then(|config| config.location_constraint.as_ref())
            .map(dto::BucketLocationConstraint::as_str)
            && !constraint.is_empty()
            && constraint != region
        {
            return Err(S3Error::with_message(
                S3ErrorCode::InvalidLocationConstraint,
                format!("This server's region is {region}"),
            ));
        }
        no_grants(&[
            input.grant_full_control.as_ref(),
            input.grant_read.as_ref(),
            input.grant_read_acp.as_ref(),
            input.grant_write.as_ref(),
            input.grant_write_acp.as_ref(),
        ])?;
        if input.object_lock_enabled_for_bucket == Some(true) {
            return Err(s3_error!(NotImplemented, "Object lock is not supported"));
        }
        let public = match input.acl.as_ref().map(dto::BucketCannedACL::as_str) {
            None | Some("private") => false,
            Some("public-read") if self.allow_anonymous() => true,
            Some("public-read") => {
                return Err(s3_error!(
                    AccessDenied,
                    "Anonymous access is off on this server"
                ));
            }
            Some(other) => return Err(unsupported_acl(other)),
        };
        if let Some(existing) = s3::bucket(self.state.pool(), name.as_str())
            .await
            .map_err(error::database)?
        {
            if existing.owner_id != key.user_id {
                return Err(s3_error!(BucketAlreadyExists));
            }
            // S3 in us-east-1 answers a repeated CreateBucket of one's own bucket with 200 and
            // resets the bucket's ACL to the requested one (`private` without one); every
            // other region with BucketAlreadyOwnedByYou. Its objects stay.
            if region != US_EAST_1 {
                return Err(s3_error!(BucketAlreadyOwnedByYou));
            }
            let mode = if public {
                Anonymous::PublicRead
            } else {
                Anonymous::Private
            };
            let list = mode != Anonymous::Private && existing.anonymous_list;
            self.set_anonymous(&auth, &existing, mode, list).await?;
            return Ok(S3Response::new(dto::CreateBucketOutput {
                location: Some(format!("/{name}")),
                ..Default::default()
            }));
        }

        let identity = Self::tree_identity(key);
        let client = RelPath::root()
            .join(&self.state.settings().bucket_folder)
            .join(name.as_str());
        if self
            .state
            .fs()
            .stat(identity.clone(), &client)
            .await
            .is_ok()
        {
            return Err(S3Error::with_message(
                S3ErrorCode::BucketAlreadyExists,
                format!(
                    "The folder {client} exists already; bind it as a bucket from the account page"
                ),
            ));
        }
        let folder = self
            .state
            .fs()
            .put_folder(identity.clone(), &client)
            .await
            .map_err(|err| error::object(err, false))?;
        let folder_id = folder.file_id.ok_or_else(|| s3_error!(InternalError))?;
        let bucket = match s3::create_bucket(self.state.pool(), key.user_id, &name, folder_id).await
        {
            Ok(bucket) => bucket,
            Err(err) => {
                // Do not leave the new, empty folder behind.
                let _ = self.state.fs().remove_empty_folder(identity, &client).await;
                return Err(match err {
                    gono_server_core::Error::BucketExists { yours: true, .. } => {
                        s3_error!(BucketAlreadyOwnedByYou)
                    }
                    gono_server_core::Error::BucketExists { yours: false, .. } => {
                        s3_error!(BucketAlreadyExists)
                    }
                    gono_server_core::Error::InvalidBucketFolder { .. } => {
                        S3Error::with_message(S3ErrorCode::InvalidBucketState, err.to_string())
                    }
                    other => error::database(other),
                });
            }
        };
        self.audit(
            key,
            "s3.bucket.created",
            json!({ "bucket": bucket.name, "new_folder": true }),
        )
        .await;
        if public {
            s3::set_anonymous(
                self.state.pool(),
                key.user_id,
                bucket.id,
                Anonymous::PublicRead,
                false,
            )
            .await
            .map_err(error::database)?;
            self.audit(
                key,
                "s3.bucket.anonymous",
                json!({ "bucket": bucket.name, "anonymous": "public-read", "list": false }),
            )
            .await;
        }
        Ok(S3Response::new(dto::CreateBucketOutput {
            location: Some(format!("/{name}")),
            ..Default::default()
        }))
    }

    async fn delete_bucket(
        &self,
        req: S3Request<dto::DeleteBucketInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketOutput>> {
        let auth = authorized(&req)?;
        let key = signing_key(&auth)?;
        let bucket = auth.bucket()?;
        let left = self
            .state
            .fs()
            .meta()
            .list_objects(
                bucket.owner_id,
                ObjectQuery {
                    root: &bucket.folder,
                    prefix: "",
                    delimiter: None,
                    start_after: None,
                    max_entries: 1,
                },
            )
            .await
            .map_err(error::database)?;
        if !left.entries.is_empty() {
            return Err(s3_error!(BucketNotEmpty));
        }
        s3::delete_bucket(self.state.pool(), bucket.owner_id, bucket.id)
            .await
            .map_err(error::database)?;
        self.audit(key, "s3.bucket.removed", json!({ "bucket": bucket.name }))
            .await;
        // The folder goes too, if nothing has arrived in it since.
        if let Err(err) = self
            .state
            .fs()
            .remove_empty_folder(Self::tree_identity(key), &bucket.folder)
            .await
        {
            tracing::warn!(bucket = %bucket.name, error = %err, "cannot remove a bucket's folder");
        }
        Ok(S3Response::new(dto::DeleteBucketOutput::default()))
    }

    async fn head_bucket(
        &self,
        req: S3Request<dto::HeadBucketInput>,
    ) -> S3Result<S3Response<dto::HeadBucketOutput>> {
        authorized(&req)?.bucket()?;
        Ok(S3Response::new(dto::HeadBucketOutput {
            bucket_region: Some(self.state.settings().region.clone()),
            ..Default::default()
        }))
    }

    async fn get_bucket_location(
        &self,
        req: S3Request<dto::GetBucketLocationInput>,
    ) -> S3Result<S3Response<dto::GetBucketLocationOutput>> {
        authorized(&req)?.bucket()?;
        let region = &self.state.settings().region;
        // S3 reports us-east-1 as no constraint at all.
        let location_constraint =
            (region != "us-east-1").then(|| dto::BucketLocationConstraint::from(region.clone()));
        Ok(S3Response::new(dto::GetBucketLocationOutput {
            location_constraint,
        }))
    }

    async fn get_bucket_versioning(
        &self,
        req: S3Request<dto::GetBucketVersioningInput>,
    ) -> S3Result<S3Response<dto::GetBucketVersioningOutput>> {
        authorized(&req)?.bucket()?;
        Ok(S3Response::new(dto::GetBucketVersioningOutput::default()))
    }

    async fn get_bucket_acl(
        &self,
        req: S3Request<dto::GetBucketAclInput>,
    ) -> S3Result<S3Response<dto::GetBucketAclOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let owner = owner_of(bucket);
        let public = auth.public(self.allow_anonymous()).read == Anonymous::PublicRead;
        Ok(S3Response::new(dto::GetBucketAclOutput {
            grants: Some(acl_grants(&owner, public)),
            owner: Some(owner),
        }))
    }

    async fn put_bucket_acl(
        &self,
        req: S3Request<dto::PutBucketAclInput>,
    ) -> S3Result<S3Response<dto::PutBucketAclOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        if input.access_control_policy.is_some() {
            return Err(s3_error!(
                NotImplemented,
                "Only the canned ACLs private and public-read are supported"
            ));
        }
        no_grants(&[
            input.grant_full_control.as_ref(),
            input.grant_read.as_ref(),
            input.grant_read_acp.as_ref(),
            input.grant_write.as_ref(),
            input.grant_write_acp.as_ref(),
        ])?;
        let mode = match input.acl.as_ref().map(dto::BucketCannedACL::as_str) {
            Some("private") => Anonymous::Private,
            Some("public-read") if self.allow_anonymous() => Anonymous::PublicRead,
            Some("public-read") => {
                return Err(s3_error!(
                    AccessDenied,
                    "Anonymous access is off on this server"
                ));
            }
            Some(other) => return Err(unsupported_acl(other)),
            None => {
                return Err(s3_error!(
                    NotImplemented,
                    "Only the canned ACLs private and public-read are supported"
                ));
            }
        };
        let list = mode != Anonymous::Private && bucket.anonymous_list;
        self.set_anonymous(&auth, bucket, mode, list).await?;
        Ok(S3Response::new(dto::PutBucketAclOutput::default()))
    }

    async fn put_bucket_policy(
        &self,
        req: S3Request<dto::PutBucketPolicyInput>,
    ) -> S3Result<S3Response<dto::PutBucketPolicyOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let download = policy::parse(&bucket.name, &req.input.policy)?;
        if !self.allow_anonymous() {
            return Err(s3_error!(
                AccessDenied,
                "Anonymous access is off on this server"
            ));
        }
        self.set_anonymous(&auth, bucket, Anonymous::PublicRead, download.list)
            .await?;
        Ok(S3Response::new(dto::PutBucketPolicyOutput::default()))
    }

    async fn get_bucket_policy(
        &self,
        req: S3Request<dto::GetBucketPolicyInput>,
    ) -> S3Result<S3Response<dto::GetBucketPolicyOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let policy = policy::document(&bucket.name, auth.public(self.allow_anonymous()))
            .ok_or_else(|| s3_error!(NoSuchBucketPolicy))?;
        Ok(S3Response::new(dto::GetBucketPolicyOutput {
            policy: Some(policy),
        }))
    }

    async fn get_bucket_policy_status(
        &self,
        req: S3Request<dto::GetBucketPolicyStatusInput>,
    ) -> S3Result<S3Response<dto::GetBucketPolicyStatusOutput>> {
        let auth = authorized(&req)?;
        auth.bucket()?;
        let public = auth.public(self.allow_anonymous());
        Ok(S3Response::new(dto::GetBucketPolicyStatusOutput {
            policy_status: Some(dto::PolicyStatus {
                is_public: Some(public.read == Anonymous::PublicRead || public.list),
            }),
        }))
    }

    async fn delete_bucket_policy(
        &self,
        req: S3Request<dto::DeleteBucketPolicyInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketPolicyOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        // What a policy can say goes: reads of every object and listings. Objects with a
        // public-read ACL stay public in a bucket that honors ACLs.
        let mode = match bucket.anonymous {
            Anonymous::PublicRead => Anonymous::Private,
            other => other,
        };
        self.set_anonymous(&auth, bucket, mode, false).await?;
        Ok(S3Response::new(dto::DeleteBucketPolicyOutput::default()))
    }

    async fn put_bucket_cors(
        &self,
        req: S3Request<dto::PutBucketCorsInput>,
    ) -> S3Result<S3Response<dto::PutBucketCorsOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let rules = cors::rules_from_dto(req.input.cors_configuration)?;
        let stored = cors::to_stored(&rules)?;
        if !s3::set_cors(self.state.pool(), bucket.owner_id, bucket.id, Some(&stored))
            .await
            .map_err(error::database)?
        {
            return Err(s3_error!(NoSuchBucket));
        }
        self.audit(
            signing_key(&auth)?,
            "s3.bucket.cors",
            json!({ "bucket": bucket.name, "rules": rules.len() }),
        )
        .await;
        Ok(S3Response::new(dto::PutBucketCorsOutput::default()))
    }

    async fn get_bucket_cors(
        &self,
        req: S3Request<dto::GetBucketCorsInput>,
    ) -> S3Result<S3Response<dto::GetBucketCorsOutput>> {
        let bucket = authorized(&req)?.bucket()?.clone();
        let rules = bucket
            .cors
            .as_deref()
            .map(cors::from_stored)
            .ok_or_else(|| s3_error!(NoSuchCORSConfiguration))?;
        Ok(S3Response::new(dto::GetBucketCorsOutput {
            cors_rules: Some(cors::rules_to_dto(rules)),
        }))
    }

    async fn delete_bucket_cors(
        &self,
        req: S3Request<dto::DeleteBucketCorsInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketCorsOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        if bucket.cors.is_some() {
            s3::set_cors(self.state.pool(), bucket.owner_id, bucket.id, None)
                .await
                .map_err(error::database)?;
            self.audit(
                signing_key(&auth)?,
                "s3.bucket.cors",
                json!({ "bucket": bucket.name, "rules": 0 }),
            )
            .await;
        }
        Ok(S3Response::new(dto::DeleteBucketCorsOutput::default()))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<dto::ListObjectsV2Input>,
    ) -> S3Result<S3Response<dto::ListObjectsV2Output>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        let url = input
            .encoding_type
            .as_ref()
            .is_some_and(|encoding| encoding.as_str() == dto::EncodingType::URL);
        let after = match input.continuation_token.as_deref() {
            Some(token) => Some(keys::marker_of_token(token).ok_or_else(|| {
                s3_error!(InvalidArgument, "The continuation token is not valid")
            })?),
            None => input.start_after.clone(),
        };
        let prefix = input.prefix.clone().unwrap_or_default();
        // An empty delimiter is no delimiter, and S3 does not echo it.
        let delimiter = input
            .delimiter
            .clone()
            .filter(|delimiter| !delimiter.is_empty());
        let listed = self
            .list(
                bucket,
                ListRequest {
                    prefix: &prefix,
                    delimiter: delimiter.as_deref(),
                    start_after: after.as_deref(),
                    max_keys: input.max_keys,
                    url,
                    owner: input.fetch_owner == Some(true),
                },
            )
            .await?;
        let encode = |value: Option<String>| {
            value.map(|value| if url { keys::url_encode(&value) } else { value })
        };
        let key_count = i32::try_from(listed.objects.len() + listed.prefixes.len()).ok();
        let mut response = S3Response::new(dto::ListObjectsV2Output {
            name: Some(bucket.name.clone()),
            prefix: encode(input.prefix),
            max_keys: Some(input.max_keys.unwrap_or(MAX_KEYS as i32)),
            key_count,
            continuation_token: input.continuation_token,
            is_truncated: Some(listed.truncated),
            next_continuation_token: listed
                .truncated
                .then(|| listed.last.as_deref().map(keys::continuation_token))
                .flatten(),
            contents: Some(listed.objects),
            common_prefixes: Some(listed.prefixes),
            delimiter: encode(delimiter),
            encoding_type: input.encoding_type,
            start_after: encode(input.start_after),
            ..Default::default()
        });
        nosniff(&mut response.headers, auth.caller.is_anonymous());
        Ok(response)
    }

    async fn list_objects(
        &self,
        req: S3Request<dto::ListObjectsInput>,
    ) -> S3Result<S3Response<dto::ListObjectsOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        let url = input
            .encoding_type
            .as_ref()
            .is_some_and(|encoding| encoding.as_str() == dto::EncodingType::URL);
        let prefix = input.prefix.clone().unwrap_or_default();
        // An empty delimiter is no delimiter, and S3 does not echo it.
        let delimiter = input
            .delimiter
            .clone()
            .filter(|delimiter| !delimiter.is_empty());
        let listed = self
            .list(
                bucket,
                ListRequest {
                    prefix: &prefix,
                    delimiter: delimiter.as_deref(),
                    start_after: input.marker.as_deref(),
                    max_keys: input.max_keys,
                    url,
                    owner: true,
                },
            )
            .await?;
        let encode = |value: Option<String>| {
            value.map(|value| if url { keys::url_encode(&value) } else { value })
        };
        // In a v1 listing S3 encodes the marker, the delimiter and the keys but not the prefix,
        // and clients (botocore) decode exactly those; the marker is always there.
        let mut response = S3Response::new(dto::ListObjectsOutput {
            name: Some(bucket.name.clone()),
            prefix: input.prefix,
            marker: Some(encode(input.marker).unwrap_or_default()),
            max_keys: Some(input.max_keys.unwrap_or(MAX_KEYS as i32)),
            is_truncated: Some(listed.truncated),
            next_marker: listed
                .truncated
                .then(|| encode(listed.last.clone()))
                .flatten(),
            contents: Some(listed.objects),
            common_prefixes: Some(listed.prefixes),
            delimiter: encode(delimiter),
            encoding_type: input.encoding_type,
            ..Default::default()
        });
        nosniff(&mut response.headers, auth.caller.is_anonymous());
        Ok(response)
    }

    async fn list_object_versions(
        &self,
        req: S3Request<dto::ListObjectVersionsInput>,
    ) -> S3Result<S3Response<dto::ListObjectVersionsOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        // Every object has the one version `null`, so a version id marker can only name that
        // version of the key marker, after which the listing goes on with the next key.
        let key_marker = input
            .key_marker
            .as_deref()
            .filter(|marker| !marker.is_empty());
        if input
            .version_id_marker
            .as_deref()
            .is_some_and(|marker| !marker.is_empty())
            && key_marker.is_none()
        {
            return Err(s3_error!(
                InvalidArgument,
                "A version-id marker cannot be specified without a key marker"
            ));
        }
        let url = input
            .encoding_type
            .as_ref()
            .is_some_and(|encoding| encoding.as_str() == dto::EncodingType::URL);
        let prefix = input.prefix.clone().unwrap_or_default();
        // An empty delimiter is no delimiter, and S3 does not echo it.
        let delimiter = input
            .delimiter
            .clone()
            .filter(|delimiter| !delimiter.is_empty());
        let listed = self
            .list(
                bucket,
                ListRequest {
                    prefix: &prefix,
                    delimiter: delimiter.as_deref(),
                    start_after: key_marker,
                    max_keys: input.max_keys,
                    url,
                    owner: true,
                },
            )
            .await?;
        let encode = |value: Option<String>| {
            value.map(|value| if url { keys::url_encode(&value) } else { value })
        };
        // A page that ends with an object goes on after its version; one that ends with a
        // common prefix goes on after the prefix.
        let ends_with_object = listed.truncated && !listed.last_is_prefix;
        let versions = listed
            .objects
            .into_iter()
            .map(|object| dto::ObjectVersion {
                e_tag: object.e_tag,
                is_latest: Some(true),
                key: object.key,
                last_modified: object.last_modified,
                owner: object.owner,
                size: object.size,
                storage_class: Some(dto::ObjectVersionStorageClass::from_static(
                    dto::ObjectVersionStorageClass::STANDARD,
                )),
                version_id: Some(NULL_VERSION.to_owned()),
                ..Default::default()
            })
            .collect();
        let mut response = S3Response::new(dto::ListObjectVersionsOutput {
            name: Some(bucket.name.clone()),
            prefix: encode(input.prefix),
            key_marker: encode(input.key_marker),
            version_id_marker: input.version_id_marker,
            max_keys: Some(input.max_keys.unwrap_or(MAX_KEYS as i32)),
            is_truncated: Some(listed.truncated),
            next_key_marker: listed
                .truncated
                .then(|| encode(listed.last.clone()))
                .flatten(),
            next_version_id_marker: ends_with_object.then(|| NULL_VERSION.to_owned()),
            versions: Some(versions),
            common_prefixes: Some(listed.prefixes),
            delimiter: encode(delimiter),
            encoding_type: input.encoding_type,
            ..Default::default()
        });
        nosniff(&mut response.headers, auth.caller.is_anonymous());
        Ok(response)
    }

    async fn put_object(
        &self,
        req: S3Request<dto::PutObjectInput>,
    ) -> S3Result<S3Response<dto::PutObjectOutput>> {
        Ok(S3Response::new(self.put(req).await?))
    }

    async fn post_object(
        &self,
        mut req: S3Request<dto::PostObjectInput>,
    ) -> S3Result<S3Response<dto::PostObjectOutput>> {
        // The `acl` field, which s3s does not read (see `crate::form`).
        if req.input.acl.is_none() {
            match req.extensions.get::<FormAcl>() {
                Some(FormAcl::Named(acl)) => {
                    req.input.acl = Some(dto::ObjectCannedACL::from(acl.clone()));
                }
                Some(FormAcl::Repeated) => {
                    return Err(s3_error!(
                        InvalidArgument,
                        "The form names an acl more than once"
                    ));
                }
                None => {}
            }
        }
        FormUpload(self.clone()).post_object(req).await
    }

    async fn get_object(
        &self,
        req: S3Request<dto::GetObjectInput>,
    ) -> S3Result<S3Response<dto::GetObjectOutput>> {
        let auth = authorized(&req)?;
        let anonymous = auth.caller.is_anonymous();
        let input = req.input;
        let overrides = input.response_cache_control.is_some()
            || input.response_content_disposition.is_some()
            || input.response_content_encoding.is_some()
            || input.response_content_language.is_some()
            || input.response_content_type.is_some()
            || input.response_expires.is_some();
        if overrides && anonymous {
            return Err(s3_error!(
                InvalidRequest,
                "Response overrides are only supported for signed requests"
            ));
        }
        if input
            .version_id
            .as_deref()
            .is_some_and(|id| id != NULL_VERSION)
        {
            return Err(s3_error!(NoSuchVersion));
        }
        if input.part_number.is_some() && input.range.is_some() {
            return Err(s3_error!(
                InvalidRequest,
                "Cannot specify both Range header and partNumber query parameter"
            ));
        }
        let (client, entry, meta, file) = self.open_for_read(&auth, &input.key).await?;
        let etag = if entry.is_dir() {
            EMPTY_MD5.to_owned()
        } else {
            etag_of(&entry, meta.as_ref())
        };
        check_read_conditions(
            &etag,
            entry.modified,
            input.if_match.as_ref(),
            input.if_none_match.as_ref(),
            input.if_modified_since.as_ref(),
            input.if_unmodified_since.as_ref(),
        )
        .map_err(|err| with_validators(err, &etag, entry.modified))?;
        let size = if entry.is_dir() { 0 } else { entry.size };
        let part = match input.part_number {
            Some(number) => Some(self.object_part(&entry, meta.as_ref(), number).await?),
            None => None,
        };
        let (start, length, content_range) = match (&part, input.range) {
            // A part of a multipart object is answered like a range of it.
            (Some(part), _) if part.count.is_some() && part.length > 0 => (
                part.start,
                part.length,
                Some(format!(
                    "bytes {}-{}/{size}",
                    part.start,
                    part.start + part.length - 1
                )),
            ),
            (Some(part), _) => (part.start, part.length, None),
            (None, Some(range)) => {
                let range = range.check(size)?;
                let content_range = format!("bytes {}-{}/{size}", range.start, range.end - 1);
                (range.start, range.end - range.start, Some(content_range))
            }
            (None, None) => (0, size, None),
        };
        let whole = start == 0 && length == size;
        let body = match file {
            Some(file) => {
                let mut file = tokio::fs::File::from_std(file);
                if start > 0 {
                    use tokio::io::AsyncSeekExt as _;
                    file.seek(std::io::SeekFrom::Start(start))
                        .await
                        .map_err(error::io)?;
                }
                file_body(file, length)
            }
            None => dto::StreamingBlob::from(Bytes::new()),
        };
        let checksum = read_checksum(
            input.checksum_mode.is_some(),
            meta.as_ref(),
            part.as_ref(),
            whole,
        );
        let parts_count = part
            .as_ref()
            .and_then(|part| part.count)
            .and_then(|count| i32::try_from(count).ok());
        let meta = meta.unwrap_or_default();
        let tags = meta.tags.clone();
        let mut response = S3Response::new(dto::GetObjectOutput {
            body: Some(body),
            content_length: Some(i64::try_from(length).unwrap_or(i64::MAX)),
            content_range,
            accept_ranges: Some("bytes".to_owned()),
            last_modified: Some(Timestamp::from(entry.modified)),
            e_tag: Some(ETag::Strong(etag)),
            content_type: Some(
                input
                    .response_content_type
                    .unwrap_or_else(|| content_type_of(&client, Some(&meta))),
            ),
            content_encoding: input.response_content_encoding.or(meta.content_encoding),
            content_disposition: input
                .response_content_disposition
                .or(meta.content_disposition),
            content_language: input.response_content_language.or(meta.content_language),
            cache_control: input.response_cache_control.or(meta.cache_control),
            expires: input
                .response_expires
                .map(|expires| {
                    let mut out = Vec::new();
                    let _ = expires.format(dto::TimestampFormat::HttpDate, &mut out);
                    String::from_utf8_lossy(&out).into_owned()
                })
                .or(meta.expires),
            metadata: (!meta.user_meta.is_empty()).then(|| meta.user_meta.into_iter().collect()),
            checksum_crc32: checksum.checksum_crc32,
            checksum_crc32c: checksum.checksum_crc32c,
            checksum_crc64nvme: checksum.checksum_crc64nvme,
            checksum_sha1: checksum.checksum_sha1,
            checksum_sha256: checksum.checksum_sha256,
            checksum_type: checksum.checksum_type,
            parts_count,
            tag_count: crate::tags::count(&tags),
            ..Default::default()
        });
        nosniff(&mut response.headers, anonymous);
        Ok(response)
    }

    async fn head_object(
        &self,
        req: S3Request<dto::HeadObjectInput>,
    ) -> S3Result<S3Response<dto::HeadObjectOutput>> {
        let auth = authorized(&req)?;
        let anonymous = auth.caller.is_anonymous();
        let input = req.input;
        if input
            .version_id
            .as_deref()
            .is_some_and(|id| id != NULL_VERSION)
        {
            return Err(s3_error!(NoSuchVersion));
        }
        let (client, entry, meta, _) = self.open_for_read(&auth, &input.key).await?;
        let etag = if entry.is_dir() {
            EMPTY_MD5.to_owned()
        } else {
            etag_of(&entry, meta.as_ref())
        };
        check_read_conditions(
            &etag,
            entry.modified,
            input.if_match.as_ref(),
            input.if_none_match.as_ref(),
            input.if_modified_since.as_ref(),
            input.if_unmodified_since.as_ref(),
        )
        .map_err(|err| with_validators(err, &etag, entry.modified))?;
        let size = if entry.is_dir() { 0 } else { entry.size };
        let part = match input.part_number {
            Some(number) => Some(self.object_part(&entry, meta.as_ref(), number).await?),
            None => None,
        };
        let checksum = read_checksum(
            input.checksum_mode.is_some(),
            meta.as_ref(),
            part.as_ref(),
            true,
        );
        let length = part.as_ref().map_or(size, |part| part.length);
        let parts_count = part
            .as_ref()
            .and_then(|part| part.count)
            .and_then(|count| i32::try_from(count).ok());
        let meta = meta.unwrap_or_default();
        let tags = meta.tags.clone();
        let mut response = S3Response::new(dto::HeadObjectOutput {
            content_length: Some(i64::try_from(length).unwrap_or(i64::MAX)),
            accept_ranges: Some("bytes".to_owned()),
            last_modified: Some(Timestamp::from(entry.modified)),
            e_tag: Some(ETag::Strong(etag)),
            content_type: Some(content_type_of(&client, Some(&meta))),
            content_encoding: meta.content_encoding,
            content_disposition: meta.content_disposition,
            content_language: meta.content_language,
            cache_control: meta.cache_control,
            expires: meta.expires,
            metadata: (!meta.user_meta.is_empty()).then(|| meta.user_meta.into_iter().collect()),
            checksum_crc32: checksum.checksum_crc32,
            checksum_crc32c: checksum.checksum_crc32c,
            checksum_crc64nvme: checksum.checksum_crc64nvme,
            checksum_sha1: checksum.checksum_sha1,
            checksum_sha256: checksum.checksum_sha256,
            checksum_type: checksum.checksum_type,
            parts_count,
            tag_count: crate::tags::count(&tags),
            ..Default::default()
        });
        nosniff(&mut response.headers, anonymous);
        Ok(response)
    }

    async fn get_object_attributes(
        &self,
        req: S3Request<dto::GetObjectAttributesInput>,
    ) -> S3Result<S3Response<dto::GetObjectAttributesOutput>> {
        let auth = authorized(&req)?;
        let input = req.input;
        if input
            .version_id
            .as_deref()
            .is_some_and(|id| id != NULL_VERSION)
        {
            return Err(s3_error!(NoSuchVersion));
        }
        if input.sse_customer_algorithm.is_some() {
            return Err(s3_error!(
                NotImplemented,
                "Server-side encryption is not supported"
            ));
        }
        let (_, entry, meta, _) = self.open_for_read(&auth, &input.key).await?;
        // Clients send the attributes in one header, separated by commas; s3s may hand them
        // over as one value.
        let wanted = |name: &str| {
            input
                .object_attributes
                .iter()
                .flat_map(|attribute| attribute.as_str().split(','))
                .any(|attribute| attribute.trim().eq_ignore_ascii_case(name))
        };
        let size = if entry.is_dir() { 0 } else { entry.size };
        let etag = if entry.is_dir() {
            EMPTY_MD5.to_owned()
        } else {
            etag_of(&entry, meta.as_ref())
        };
        let stored = meta.as_ref().and_then(|meta| meta.checksum.as_ref());
        let checksum =
            (wanted("Checksum") && stored.is_some()).then(|| upload::stored_checksum(stored));
        let object_parts = if wanted("ObjectParts") {
            let parts = match (&meta, entry.file_id) {
                (Some(_), Some(file_id)) if !entry.is_dir() => self
                    .state
                    .fs()
                    .meta()
                    .object_parts(file_id)
                    .await
                    .map_err(error::database)?,
                _ => Vec::new(),
            };
            (!parts.is_empty()).then(|| object_parts_page(&parts, stored, &input))
        } else {
            None
        };
        Ok(S3Response::new(dto::GetObjectAttributesOutput {
            e_tag: wanted("ETag").then_some(ETag::Strong(etag)),
            last_modified: Some(Timestamp::from(entry.modified)),
            object_size: wanted("ObjectSize").then(|| i64::try_from(size).unwrap_or(i64::MAX)),
            storage_class: wanted("StorageClass")
                .then(|| dto::StorageClass::from_static(dto::StorageClass::STANDARD)),
            checksum,
            object_parts,
            ..Default::default()
        }))
    }

    async fn delete_object(
        &self,
        req: S3Request<dto::DeleteObjectInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        if input
            .version_id
            .as_deref()
            .is_some_and(|id| id != NULL_VERSION)
        {
            return Err(s3_error!(NotImplemented, "Versioning is not supported"));
        }
        self.delete_one(&auth, bucket, &input.key).await?;
        Ok(S3Response::new(dto::DeleteObjectOutput::default()))
    }

    async fn delete_objects(
        &self,
        req: S3Request<dto::DeleteObjectsInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectsOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        if input.delete.objects.len() > MAX_KEYS {
            return Err(s3_error!(
                MalformedXML,
                "A request deletes at most 1000 objects"
            ));
        }
        let quiet = input.delete.quiet == Some(true);
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for object in input.delete.objects {
            let result = if object
                .version_id
                .as_deref()
                .is_some_and(|id| id != NULL_VERSION)
            {
                Err(s3_error!(NotImplemented, "Versioning is not supported"))
            } else {
                self.delete_one(&auth, bucket, &object.key).await
            };
            match result {
                Ok(()) if quiet => {}
                Ok(()) => deleted.push(dto::DeletedObject {
                    key: Some(object.key),
                    ..Default::default()
                }),
                Err(err) => errors.push(dto::Error {
                    code: Some(err.code().as_str().to_owned()),
                    key: Some(object.key),
                    message: err.message().map(str::to_owned),
                    version_id: None,
                }),
            }
        }
        Ok(S3Response::new(dto::DeleteObjectsOutput {
            deleted: Some(deleted),
            errors: Some(errors),
            ..Default::default()
        }))
    }

    async fn copy_object(
        &self,
        req: S3Request<dto::CopyObjectInput>,
    ) -> S3Result<S3Response<dto::CopyObjectOutput>> {
        let auth = authorized(&req)?;
        let key = signing_key(&auth)?.clone();
        let destination = auth.bucket()?.clone();
        let input = req.input;
        let dto::CopySource::Bucket {
            bucket: source_bucket,
            key: source_key,
            version_id,
        } = &input.copy_source
        else {
            return Err(s3_error!(
                NotImplemented,
                "Only bucket copy sources are supported"
            ));
        };
        if version_id.as_deref().is_some_and(|id| id != NULL_VERSION) {
            return Err(s3_error!(NoSuchVersion));
        }
        if input.server_side_encryption.is_some() || input.sse_customer_algorithm.is_some() {
            return Err(s3_error!(
                NotImplemented,
                "Server-side encryption is not supported"
            ));
        }
        no_grants(&[
            input.grant_full_control.as_ref(),
            input.grant_read.as_ref(),
            input.grant_read_acp.as_ref(),
            input.grant_write_acp.as_ref(),
        ])?;
        let public = object_acl(input.acl.as_ref())?;
        if public {
            check_public_acl(&destination, self.allow_anonymous())?;
        }
        let (source, from) = self
            .copy_source(&key, &destination, source_bucket, source_key)
            .await?;
        let to = match target(&destination, &input.key)? {
            Target::File(path) => path,
            Target::Folder(_) => {
                return Err(s3_error!(
                    InvalidArgument,
                    "A key ending in '/' names a folder and cannot be copied to"
                ));
            }
        };
        let identity = auth.identity(&[(&destination, true), (&source, false)])?;
        let (source_entry, source_meta) = self
            .state
            .fs()
            .object(identity.clone(), &from)
            .await
            .map_err(|err| match err {
                ObjectError::IsFolder | ObjectError::NotFound => s3_error!(NoSuchKey),
                other => error::object(other, false),
            })?;
        check_copy_source_conditions(
            &etag_of(&source_entry, source_meta.as_ref()),
            source_entry.modified,
            input.copy_source_if_match.as_ref(),
            input.copy_source_if_none_match.as_ref(),
            input.copy_source_if_modified_since.as_ref(),
            input.copy_source_if_unmodified_since.as_ref(),
        )?;

        let replace = input
            .metadata_directive
            .as_ref()
            .is_some_and(|directive| directive.as_str() == dto::MetadataDirective::REPLACE);
        if from == to && !replace && input.acl.is_none() {
            return Err(s3_error!(
                InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself \
                 without changing the object's metadata"
            ));
        }
        // An S3 ETag of the content (an MD5) stays valid for an identical copy; a WebDAV ETag
        // belongs to its version and does not. A multipart ETag keeps its parts.
        let parts = match (&source_meta, source_entry.file_id) {
            (Some(_), Some(file_id)) => self
                .state
                .fs()
                .meta()
                .object_parts(file_id)
                .await
                .map_err(error::database)?,
            _ => Vec::new(),
        };
        let source_meta = source_meta.unwrap_or_default();
        let s3_etag = source_meta.s3_etag.clone();
        // Tags are copied unless the request replaces them.
        let tags = if input
            .tagging_directive
            .as_ref()
            .is_some_and(|directive| directive.as_str() == dto::TaggingDirective::REPLACE)
        {
            crate::tags::from_header(input.tagging.as_deref())?
        } else {
            source_meta.tags.clone()
        };
        let meta = if replace {
            ObjectMeta {
                s3_etag,
                public_read: public,
                content_type: input.content_type,
                content_encoding: upload::stored_content_encoding(input.content_encoding),
                content_disposition: input.content_disposition,
                content_language: input.content_language,
                cache_control: input.cache_control,
                expires: input.expires,
                user_meta: user_meta(input.metadata),
                tags,
                checksum: source_meta.checksum,
                parts,
            }
        } else {
            ObjectMeta {
                s3_etag,
                public_read: public,
                tags,
                parts,
                ..source_meta
            }
        };
        self.check_locks(&destination, &to).await?;
        let condition = write_condition(input.if_match.as_ref(), input.if_none_match.as_ref())?;
        let entry = self
            .state
            .fs()
            .copy_object(
                identity,
                &from,
                &to,
                Some(&keys::spelled(&destination.name, &input.key)),
                meta.clone(),
                condition,
                upload::mtime_of(&meta),
            )
            .await
            .map_err(|err| error::object(err, false))?;
        Ok(S3Response::new(dto::CopyObjectOutput {
            copy_object_result: Some(dto::CopyObjectResult {
                e_tag: Some(ETag::Strong(entry.s3_etag(Some(&meta)))),
                last_modified: Some(Timestamp::from(entry.modified)),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    async fn get_object_acl(
        &self,
        req: S3Request<dto::GetObjectAclInput>,
    ) -> S3Result<S3Response<dto::GetObjectAclOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let client = match target(bucket, &req.input.key)? {
            Target::File(path) => path,
            Target::Folder(_) => return Err(s3_error!(NoSuchKey)),
        };
        if !self.spelled_as(bucket, &client, &req.input.key).await? {
            return Err(s3_error!(NoSuchKey));
        }
        let identity = Self::bucket_identity(&auth, bucket, false)?;
        let (_, meta) =
            self.state
                .fs()
                .object(identity, &client)
                .await
                .map_err(|err| match err {
                    ObjectError::IsFolder | ObjectError::NotFound => s3_error!(NoSuchKey),
                    other => error::object(other, false),
                })?;
        let public = match auth.public(self.allow_anonymous()).read {
            Anonymous::PublicRead => true,
            Anonymous::Acl => meta.is_some_and(|meta| meta.public_read),
            Anonymous::Private => false,
        };
        let owner = owner_of(bucket);
        Ok(S3Response::new(dto::GetObjectAclOutput {
            grants: Some(acl_grants(&owner, public)),
            owner: Some(owner),
            ..Default::default()
        }))
    }

    async fn get_object_tagging(
        &self,
        req: S3Request<dto::GetObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::GetObjectTaggingOutput>> {
        let auth = authorized(&req)?;
        let input = req.input;
        check_null_version(input.version_id.as_deref())?;
        let (_, entry, meta, _) = self.open_for_read(&auth, &input.key).await?;
        if entry.is_dir() {
            return Err(s3_error!(NoSuchKey));
        }
        let tags = meta.map(|meta| meta.tags).unwrap_or_default();
        Ok(S3Response::new(dto::GetObjectTaggingOutput {
            tag_set: crate::tags::to_tag_set(&tags),
            version_id: None,
        }))
    }

    async fn put_object_tagging(
        &self,
        req: S3Request<dto::PutObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::PutObjectTaggingOutput>> {
        let auth = authorized(&req)?;
        let input = req.input;
        check_null_version(input.version_id.as_deref())?;
        let tags = crate::tags::from_tagging(input.tagging, false)?;
        self.set_tags(&auth, &input.key, &tags).await?;
        Ok(S3Response::new(dto::PutObjectTaggingOutput::default()))
    }

    async fn delete_object_tagging(
        &self,
        req: S3Request<dto::DeleteObjectTaggingInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectTaggingOutput>> {
        let auth = authorized(&req)?;
        let input = req.input;
        check_null_version(input.version_id.as_deref())?;
        self.set_tags(&auth, &input.key, &BTreeMap::new()).await?;
        Ok(S3Response::new(dto::DeleteObjectTaggingOutput::default()))
    }

    async fn get_bucket_website(
        &self,
        req: S3Request<dto::GetBucketWebsiteInput>,
    ) -> S3Result<S3Response<dto::GetBucketWebsiteOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let website = crate::website::from_stored(bucket.website.as_deref())
            .ok_or_else(|| s3_error!(NoSuchWebsiteConfiguration))?;
        Ok(S3Response::new(crate::website::to_config(&website)))
    }

    async fn put_bucket_website(
        &self,
        req: S3Request<dto::PutBucketWebsiteInput>,
    ) -> S3Result<S3Response<dto::PutBucketWebsiteOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let website = crate::website::from_config(req.input.website_configuration)?;
        s3::set_bucket_website(
            self.state.pool(),
            bucket.owner_id,
            bucket.id,
            Some(&crate::website::to_stored(&website)),
        )
        .await
        .map_err(error::database)?;
        Ok(S3Response::new(dto::PutBucketWebsiteOutput::default()))
    }

    async fn delete_bucket_website(
        &self,
        req: S3Request<dto::DeleteBucketWebsiteInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketWebsiteOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        s3::set_bucket_website(self.state.pool(), bucket.owner_id, bucket.id, None)
            .await
            .map_err(error::database)?;
        Ok(S3Response::new(dto::DeleteBucketWebsiteOutput::default()))
    }

    async fn get_bucket_lifecycle_configuration(
        &self,
        req: S3Request<dto::GetBucketLifecycleConfigurationInput>,
    ) -> S3Result<S3Response<dto::GetBucketLifecycleConfigurationOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let rules = crate::lifecycle::from_stored(bucket.lifecycle.as_deref());
        if rules.is_empty() {
            return Err(s3_error!(NoSuchLifecycleConfiguration));
        }
        Ok(S3Response::new(
            dto::GetBucketLifecycleConfigurationOutput {
                rules: Some(crate::lifecycle::to_config(&rules)),
                ..Default::default()
            },
        ))
    }

    async fn put_bucket_lifecycle_configuration(
        &self,
        req: S3Request<dto::PutBucketLifecycleConfigurationInput>,
    ) -> S3Result<S3Response<dto::PutBucketLifecycleConfigurationOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let config = req
            .input
            .lifecycle_configuration
            .ok_or_else(|| s3_error!(MalformedXML, "The lifecycle configuration is missing"))?;
        let rules = crate::lifecycle::from_config(config)?;
        s3::set_bucket_lifecycle(
            self.state.pool(),
            bucket.owner_id,
            bucket.id,
            Some(&crate::lifecycle::to_stored(&rules)),
        )
        .await
        .map_err(error::database)?;
        // Rules delete files: their changes are recorded.
        self.audit(
            signing_key(&auth)?,
            "s3.bucket.lifecycle",
            json!({ "bucket": bucket.name, "rules": rules.len() }),
        )
        .await;
        Ok(S3Response::new(
            dto::PutBucketLifecycleConfigurationOutput::default(),
        ))
    }

    async fn delete_bucket_lifecycle(
        &self,
        req: S3Request<dto::DeleteBucketLifecycleInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketLifecycleOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        s3::set_bucket_lifecycle(self.state.pool(), bucket.owner_id, bucket.id, None)
            .await
            .map_err(error::database)?;
        if bucket.lifecycle.is_some() {
            self.audit(
                signing_key(&auth)?,
                "s3.bucket.lifecycle",
                json!({ "bucket": bucket.name, "rules": 0 }),
            )
            .await;
        }
        Ok(S3Response::new(dto::DeleteBucketLifecycleOutput::default()))
    }

    async fn get_bucket_tagging(
        &self,
        req: S3Request<dto::GetBucketTaggingInput>,
    ) -> S3Result<S3Response<dto::GetBucketTaggingOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let tags = crate::tags::from_stored(bucket.tags.as_deref());
        if tags.is_empty() {
            return Err(s3_error!(NoSuchTagSet));
        }
        Ok(S3Response::new(dto::GetBucketTaggingOutput {
            tag_set: crate::tags::to_tag_set(&tags),
        }))
    }

    async fn put_bucket_tagging(
        &self,
        req: S3Request<dto::PutBucketTaggingInput>,
    ) -> S3Result<S3Response<dto::PutBucketTaggingOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let tags = crate::tags::from_tagging(req.input.tagging, true)?;
        let stored = serde_json::to_string(&tags).map_err(|_| s3_error!(InternalError))?;
        s3::set_bucket_tags(
            self.state.pool(),
            bucket.owner_id,
            bucket.id,
            (!tags.is_empty()).then_some(stored.as_str()),
        )
        .await
        .map_err(error::database)?;
        Ok(S3Response::new(dto::PutBucketTaggingOutput::default()))
    }

    async fn delete_bucket_tagging(
        &self,
        req: S3Request<dto::DeleteBucketTaggingInput>,
    ) -> S3Result<S3Response<dto::DeleteBucketTaggingOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        s3::set_bucket_tags(self.state.pool(), bucket.owner_id, bucket.id, None)
            .await
            .map_err(error::database)?;
        Ok(S3Response::new(dto::DeleteBucketTaggingOutput::default()))
    }

    async fn put_object_acl(
        &self,
        req: S3Request<dto::PutObjectAclInput>,
    ) -> S3Result<S3Response<dto::PutObjectAclOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        if input.access_control_policy.is_some() {
            return Err(s3_error!(
                NotImplemented,
                "Only the canned ACLs private and public-read are supported"
            ));
        }
        no_grants(&[
            input.grant_full_control.as_ref(),
            input.grant_read.as_ref(),
            input.grant_read_acp.as_ref(),
            input.grant_write.as_ref(),
            input.grant_write_acp.as_ref(),
        ])?;
        let public = object_acl(input.acl.as_ref())?;
        if public {
            check_public_acl(bucket, self.allow_anonymous())?;
        }
        let client = match target(bucket, &input.key)? {
            Target::File(path) => path,
            Target::Folder(_) => return Err(s3_error!(NoSuchKey)),
        };
        if !self.spelled_as(bucket, &client, &input.key).await? {
            return Err(s3_error!(NoSuchKey));
        }
        let identity = Self::bucket_identity(&auth, bucket, true)?;
        let entry = self
            .state
            .fs()
            .stat(identity, &client)
            .await
            .map_err(|_| s3_error!(NoSuchKey))?;
        let file_id = entry
            .file_id
            .filter(|_| !entry.is_dir())
            .ok_or_else(|| s3_error!(NoSuchKey))?;
        let set = self
            .state
            .fs()
            .meta()
            .set_object_public(file_id, &entry.etag, public)
            .await
            .map_err(error::database)?;
        if !set {
            return Err(s3_error!(
                OperationAborted,
                "The object changed while its ACL was set; try again"
            ));
        }
        Ok(S3Response::new(dto::PutObjectAclOutput::default()))
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<dto::CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::CreateMultipartUploadOutput>> {
        crate::multipart::create(&self.state, req).await
    }

    async fn upload_part(
        &self,
        req: S3Request<dto::UploadPartInput>,
    ) -> S3Result<S3Response<dto::UploadPartOutput>> {
        crate::multipart::upload_part(&self.state, req).await
    }

    async fn upload_part_copy(
        &self,
        req: S3Request<dto::UploadPartCopyInput>,
    ) -> S3Result<S3Response<dto::UploadPartCopyOutput>> {
        crate::multipart::upload_part_copy(self, req).await
    }

    async fn list_parts(
        &self,
        req: S3Request<dto::ListPartsInput>,
    ) -> S3Result<S3Response<dto::ListPartsOutput>> {
        crate::multipart::list_parts(&self.state, req).await
    }

    async fn list_multipart_uploads(
        &self,
        req: S3Request<dto::ListMultipartUploadsInput>,
    ) -> S3Result<S3Response<dto::ListMultipartUploadsOutput>> {
        crate::multipart::list_uploads(&self.state, req).await
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<dto::AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::AbortMultipartUploadOutput>> {
        crate::multipart::abort(&self.state, req).await
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<dto::CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::CompleteMultipartUploadOutput>> {
        crate::multipart::complete(self, req).await
    }
}

impl GonoS3 {
    /// Deletes one key of `bucket`: a file, or an empty folder for a folder marker. A key that
    /// names nothing is deleted already.
    async fn delete_one(&self, auth: &Authorized, bucket: &Bucket, key: &str) -> S3Result<()> {
        let target = match keys::target(&bucket.name, key) {
            Ok(target) => target,
            // Nothing can be stored under such a key, so it is gone already.
            Err(_) => return Ok(()),
        };
        if !self.spelled_as(bucket, target.path(), key).await? {
            // Another spelling of the key is stored there: this one names nothing.
            return Ok(());
        }
        self.check_locks(bucket, target.path()).await?;
        let identity = Self::bucket_identity(auth, bucket, true)?;
        let result = match &target {
            Target::File(client) => self.state.fs().delete_object(identity, client).await,
            Target::Folder(client) => self.state.fs().remove_empty_folder(identity, client).await,
        };
        match result {
            Ok(_) | Err(ObjectError::NotFound) => Ok(()),
            Err(err) => Err(error::object(err, false)),
        }
    }

    /// Installs an assembled multipart upload as `key`; see [`crate::multipart::complete`].
    pub(crate) async fn install(
        &self,
        auth: &Authorized,
        bucket: &Bucket,
        key: &str,
        temp: std::path::PathBuf,
        meta: ObjectMeta,
        condition: WriteCondition,
    ) -> S3Result<Arc<Entry>> {
        let Target::File(client) = target(bucket, key)? else {
            return Err(s3_error!(InvalidArgument));
        };
        self.check_locks(bucket, &client).await?;
        let identity = Self::bucket_identity(auth, bucket, true)?;
        self.state
            .fs()
            .put_object(
                identity,
                &client,
                Some(&keys::spelled(&bucket.name, key)),
                temp,
                meta,
                condition,
            )
            .await
            .map_err(|err| error::object(err, false))
    }

    /// Whether what is stored at `client`, the place of `key` in `bucket`, answers to `key`:
    /// keys need not be in NFC while the tree's names are, so keys that differ only in Unicode
    /// normalization share one place, which answers only to the spelling it was written with
    /// (see [`crate::keys`]). True when nothing is there.
    pub(crate) async fn spelled_as(
        &self,
        bucket: &Bucket,
        client: &RelPath,
        key: &str,
    ) -> S3Result<bool> {
        let storage = storage_of(bucket, client)?;
        let meta = self.state.fs().meta();
        let Some(row) = meta
            .get(bucket.owner_id, &storage)
            .await
            .map_err(error::database)?
        else {
            return Ok(true);
        };
        let key = key.strip_suffix('/').unwrap_or(key);
        let Some(s3_path) = &row.s3_path else {
            // Spelled as the tree, which is in NFC: only the NFC key names it.
            let below = storage
                .as_str()
                .strip_prefix(bucket.folder.as_str())
                .and_then(|rest| rest.strip_prefix('/'));
            return Ok(below == Some(key));
        };
        let root = meta
            .get(bucket.owner_id, &bucket.folder)
            .await
            .map_err(error::database)?;
        let root = root
            .as_ref()
            .map_or(bucket.folder.as_str(), |row| row.spelled());
        Ok(*s3_path == format!("{root}/{key}"))
    }

    /// Checks `condition` against the object at `client` as it is now, before a write that
    /// cannot report a failure with its status any more (a multipart completion). The write
    /// checks it again atomically.
    pub(crate) async fn check_write_condition(
        &self,
        auth: &Authorized,
        bucket: &Bucket,
        client: &RelPath,
        condition: &WriteCondition,
    ) -> S3Result<()> {
        if *condition == WriteCondition::Always {
            return Ok(());
        }
        let identity = Self::bucket_identity(auth, bucket, false)?;
        let current = match self.state.fs().object(identity, client).await {
            Ok((entry, meta)) => Some(etag_of(&entry, meta.as_ref())),
            // A folder is in the way of all of them: the name is taken, and it has no ETag to
            // match.
            Err(ObjectError::IsFolder) => Some(String::new()),
            Err(ObjectError::NotFound) => None,
            Err(err) => return Err(error::object(err, false)),
        };
        let holds = match (condition, current.as_deref()) {
            (WriteCondition::Always, _) => true,
            (WriteCondition::CreateOnly, current) => current.is_none(),
            (WriteCondition::IfMatch(_) | WriteCondition::IfExists, None) => {
                return Err(s3_error!(NoSuchKey));
            }
            (WriteCondition::IfMatch(expected), Some(current)) => {
                !current.is_empty() && current == expected
            }
            (WriteCondition::IfExists, Some(current)) => !current.is_empty(),
            (WriteCondition::IfNoneMatch(unwanted), current) => current != Some(unwanted.as_str()),
        };
        if holds {
            Ok(())
        } else {
            Err(s3_error!(PreconditionFailed))
        }
    }

    /// The source of a copy into `destination`: `source_key` of the bucket `source_bucket`,
    /// which `key` needs a grant on too (buckets of other accounts have none). Returns the
    /// bucket and the client path of the file.
    pub(crate) async fn copy_source(
        &self,
        key: &s3::SigningKey,
        destination: &Arc<Bucket>,
        source_bucket: &str,
        source_key: &str,
    ) -> S3Result<(Arc<Bucket>, RelPath)> {
        let source = if source_bucket == destination.name {
            destination.clone()
        } else {
            let bucket = s3::bucket(self.state.pool(), source_bucket)
                .await
                .map_err(error::database)?
                .ok_or_else(|| s3_error!(NoSuchBucket))?;
            Arc::new(bucket)
        };
        if access::permission(key, &source).is_none() {
            return Err(s3_error!(AccessDenied));
        }
        let from = match keys::target(&source.name, source_key) {
            Ok(Target::File(path)) => path,
            _ => return Err(s3_error!(NoSuchKey)),
        };
        if !self.spelled_as(&source, &from, source_key).await? {
            return Err(s3_error!(NoSuchKey));
        }
        Ok((source, from))
    }

    /// The permission check of the multipart operations, which the access check already made.
    pub(crate) fn write_permission(auth: &Authorized) -> S3Result<()> {
        if auth.permission == Some(Permission::Full) {
            Ok(())
        } else {
            Err(s3_error!(AccessDenied))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn ts(seconds: u64) -> Timestamp {
        Timestamp::from(at(seconds))
    }

    fn tag(value: &str) -> ETagCondition {
        ETagCondition::ETag(ETag::Strong(value.to_owned()))
    }

    fn code(result: S3Result<()>) -> Option<S3ErrorCode> {
        result.err().map(|err| err.code().clone())
    }

    #[test]
    fn read_conditions_follow_http() {
        let check = |m: Option<&ETagCondition>,
                     n: Option<&ETagCondition>,
                     ims: Option<&Timestamp>,
                     ius: Option<&Timestamp>| {
            code(check_read_conditions("abc", at(100), m, n, ims, ius))
        };
        assert_eq!(check(None, None, None, None), None);
        assert_eq!(check(Some(&tag("abc")), None, None, None), None);
        assert_eq!(check(Some(&ETagCondition::Any), None, None, None), None);
        assert_eq!(
            check(Some(&tag("x")), None, None, None),
            Some(S3ErrorCode::PreconditionFailed)
        );
        assert_eq!(
            check(None, Some(&tag("abc")), None, None),
            Some(S3ErrorCode::NotModified)
        );
        assert_eq!(check(None, Some(&tag("x")), None, None), None);
        assert_eq!(
            check(None, None, Some(&ts(100)), None),
            Some(S3ErrorCode::NotModified)
        );
        assert_eq!(check(None, None, Some(&ts(99)), None), None);
        assert_eq!(
            check(None, None, None, Some(&ts(99))),
            Some(S3ErrorCode::PreconditionFailed)
        );
        assert_eq!(check(None, None, None, Some(&ts(100))), None);
        // If-Match wins over If-Unmodified-Since, If-None-Match over If-Modified-Since.
        assert_eq!(check(Some(&tag("abc")), None, None, Some(&ts(1))), None);
        assert_eq!(check(None, Some(&tag("x")), Some(&ts(200)), None), None);
    }

    #[test]
    fn write_conditions_come_from_if_match_and_if_none_match() {
        assert_eq!(write_condition(None, None).unwrap(), WriteCondition::Always);
        assert_eq!(
            write_condition(None, Some(&ETagCondition::Any)).unwrap(),
            WriteCondition::CreateOnly
        );
        assert_eq!(
            write_condition(Some(&tag("e")), None).unwrap(),
            WriteCondition::IfMatch("e".into())
        );
        assert_eq!(
            write_condition(None, Some(&tag("e"))).unwrap(),
            WriteCondition::IfNoneMatch("e".into())
        );
        assert_eq!(
            write_condition(Some(&ETagCondition::Any), None).unwrap(),
            WriteCondition::IfExists
        );
        assert!(write_condition(Some(&tag("e")), Some(&ETagCondition::Any)).is_err());
    }

    #[test]
    fn bucket_pages_continue_after_the_token() {
        let names = ["a", "b", "ba", "c"];
        let sorted: Vec<&&str> = names.iter().collect();
        let page = |max: Option<i32>, token: Option<&str>, prefix: Option<&str>| {
            let input = dto::ListBucketsInput {
                max_buckets: max,
                continuation_token: token.map(keys::continuation_token),
                prefix: prefix.map(str::to_owned),
                ..Default::default()
            };
            let (page, more) = BucketPage::new(&input).unwrap().select(&sorted, |n| n);
            (page.into_iter().copied().collect::<Vec<_>>(), more)
        };
        assert_eq!(page(None, None, None), (names.to_vec(), false));
        assert_eq!(page(Some(2), None, None), (vec!["a", "b"], true));
        assert_eq!(page(Some(2), Some("b"), None), (vec!["ba", "c"], false));
        assert_eq!(page(Some(1), None, Some("b")), (vec!["b"], true));
        assert_eq!(page(Some(1), Some("b"), Some("b")), (vec!["ba"], false));
        for bad in [0, 10_001] {
            let input = dto::ListBucketsInput {
                max_buckets: Some(bad),
                ..Default::default()
            };
            assert!(BucketPage::new(&input).is_err());
        }
    }

    #[test]
    fn canned_acls() {
        let acl = |value: &str| dto::ObjectCannedACL::from(value.to_owned());
        assert!(!object_acl(None).unwrap());
        assert!(!object_acl(Some(&acl("private"))).unwrap());
        assert!(!object_acl(Some(&acl("bucket-owner-full-control"))).unwrap());
        assert!(object_acl(Some(&acl("public-read"))).unwrap());
        for unsupported in ["public-read-write", "authenticated-read", "aws-exec-read"] {
            assert_eq!(
                *object_acl(Some(&acl(unsupported))).unwrap_err().code(),
                S3ErrorCode::NotImplemented,
                "{unsupported}"
            );
        }
        // A value that is no canned ACL at all is the client's mistake.
        assert_eq!(
            *object_acl(Some(&acl("public-ready"))).unwrap_err().code(),
            S3ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn not_modified_answers_carry_validators() {
        let at = UNIX_EPOCH + Duration::from_secs(86_400);
        let err = with_validators(s3_error!(NotModified), "abc", at);
        let headers = err.headers().unwrap();
        assert_eq!(headers[http::header::ETAG], "\"abc\"");
        assert_eq!(
            headers[http::header::LAST_MODIFIED],
            "Fri, 02 Jan 1970 00:00:00 GMT"
        );
        let other = with_validators(s3_error!(PreconditionFailed), "abc", at);
        assert!(other.headers().is_none());
    }

    #[test]
    fn content_types_are_stored_or_guessed() {
        let path = RelPath::parse("b/photo.JPG").unwrap();
        assert_eq!(content_type_of(&path, None), "image/jpeg");
        let stored = ObjectMeta {
            content_type: Some("image/x-custom".into()),
            ..ObjectMeta::default()
        };
        assert_eq!(content_type_of(&path, Some(&stored)), "image/x-custom");
        assert_eq!(
            content_type_of(&RelPath::parse("b/noext").unwrap(), None),
            "application/octet-stream"
        );
    }
}
