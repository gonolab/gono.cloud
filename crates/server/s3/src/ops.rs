//! The S3 operations: [`GonoS3`] implements the s3s trait.
//!
//! Every operation starts from the [`Authorized`] the access check left in the request's
//! extensions, builds an [`Identity`] whose mounts are the buckets involved (each mounted at its
//! name), and reaches the tree only through [`gono_server_dav::ScopedFs`].
//!
//! - **Listings** come from the `files` table in S3 key order (`MetaStore::list_objects`), with
//!   opaque continuation tokens and `encoding-type=url`.
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
    state::S3State,
    upload,
};

/// The URI of S3's group of all users, in ACLs.
const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

/// The ETag of empty content (folder markers).
const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// Most keys in one listing and in one `DeleteObjects`.
const MAX_KEYS: usize = 1000;

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
        Some(_) => Err(s3_error!(
            NotImplemented,
            "Only the canned ACLs private and public-read are supported"
        )),
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

/// The S3 ETag of a file version.
fn etag_of(entry: &Entry, meta: Option<&ObjectMeta>) -> String {
    meta.map_or_else(
        || entry.etag.clone(),
        |meta| meta.etag_or(&entry.etag).to_owned(),
    )
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

/// The condition of a write from `If-Match` and `If-None-Match`.
fn write_condition(
    if_match: Option<&ETagCondition>,
    if_none_match: Option<&ETagCondition>,
) -> S3Result<WriteCondition> {
    match (if_match, if_none_match) {
        (None, None) => Ok(WriteCondition::Always),
        (None, Some(ETagCondition::Any)) => Ok(WriteCondition::CreateOnly),
        (Some(ETagCondition::ETag(etag)), None) => {
            Ok(WriteCondition::IfMatch(etag.value().to_owned()))
        }
        (Some(ETagCondition::Any), None) => Err(s3_error!(
            NotImplemented,
            "If-Match: * is not supported for writes"
        )),
        _ => Err(s3_error!(
            NotImplemented,
            "Only If-None-Match: * or If-Match with an ETag is supported for writes"
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
        };
        for entry in listing.entries {
            match entry {
                ListEntry::Object(object) => listed.objects.push(dto::Object {
                    e_tag: Some(ETag::Strong(object.etag().to_owned())),
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
                .put_folder(identity, client)
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
        let checksum = upload::verify(&received, input.content_md5.as_deref(), &claimed)?;
        let etag = received.etag();
        let meta = ObjectMeta {
            s3_etag: Some(etag.clone()),
            public_read: public,
            content_type: input.content_type,
            content_encoding: input.content_encoding,
            content_disposition: input.content_disposition,
            content_language: input.content_language,
            cache_control: input.cache_control,
            expires: input.expires,
            user_meta: user_meta(input.metadata),
            checksum: checksum.clone(),
        };
        self.state
            .fs()
            .put_object(
                identity,
                target.path(),
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
        ..Default::default()
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
        let buckets = s3::buckets_of(self.state.pool(), key.user_id)
            .await
            .map_err(error::database)?;
        let listed = buckets
            .iter()
            .filter(|bucket| access::permission(key, bucket).is_some())
            .map(|bucket| dto::Bucket {
                creation_date: Some(timestamp_from_secs(bucket.created_at)),
                name: Some(bucket.name.clone()),
                bucket_region: Some(self.state.settings().region.clone()),
                ..Default::default()
            })
            .collect();
        Ok(S3Response::new(dto::ListBucketsOutput {
            buckets: Some(listed),
            owner: Some(dto::Owner {
                display_name: Some(key.display_name.clone()),
                id: Some(key.username.to_string()),
            }),
            ..Default::default()
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
            Some(_) => {
                return Err(s3_error!(
                    NotImplemented,
                    "Only the canned ACLs private and public-read are supported"
                ));
            }
        };
        if let Some(existing) = s3::bucket(self.state.pool(), name.as_str())
            .await
            .map_err(error::database)?
        {
            return Err(if existing.owner_id == key.user_id {
                s3_error!(BucketAlreadyOwnedByYou)
            } else {
                s3_error!(BucketAlreadyExists)
            });
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
            _ => {
                return Err(s3_error!(
                    NotImplemented,
                    "Only the canned ACLs private and public-read are supported"
                ));
            }
        };
        let list = mode != Anonymous::Private && bucket.anonymous_list;
        if (bucket.anonymous, bucket.anonymous_list) != (mode, list) {
            s3::set_anonymous(self.state.pool(), bucket.owner_id, bucket.id, mode, list)
                .await
                .map_err(error::database)?;
            self.audit(
                signing_key(&auth)?,
                "s3.bucket.anonymous",
                json!({ "bucket": bucket.name, "anonymous": mode.as_str(), "list": list }),
            )
            .await;
        }
        Ok(S3Response::new(dto::PutBucketAclOutput::default()))
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
        let listed = self
            .list(
                bucket,
                ListRequest {
                    prefix: &prefix,
                    delimiter: input.delimiter.as_deref(),
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
            delimiter: encode(input.delimiter),
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
        let listed = self
            .list(
                bucket,
                ListRequest {
                    prefix: &prefix,
                    delimiter: input.delimiter.as_deref(),
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
        let mut response = S3Response::new(dto::ListObjectsOutput {
            name: Some(bucket.name.clone()),
            prefix: encode(input.prefix),
            marker: encode(input.marker),
            max_keys: Some(input.max_keys.unwrap_or(MAX_KEYS as i32)),
            is_truncated: Some(listed.truncated),
            next_marker: listed
                .truncated
                .then(|| encode(listed.last.clone()))
                .flatten(),
            contents: Some(listed.objects),
            common_prefixes: Some(listed.prefixes),
            delimiter: encode(input.delimiter),
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
        if input.version_id.as_deref().is_some_and(|id| id != "null") {
            return Err(s3_error!(NoSuchVersion));
        }
        if input.part_number.is_some_and(|part| part != 1) {
            // Objects keep no part boundaries; the whole object is its only part.
            let mut err = S3Error::with_message(
                S3ErrorCode::Custom("InvalidPartNumber".into()),
                "The object has a single part",
            );
            err.set_status_code(http::StatusCode::RANGE_NOT_SATISFIABLE);
            return Err(err);
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
        )?;
        let size = if entry.is_dir() { 0 } else { entry.size };
        let (start, length, content_range) = match input.range {
            Some(range) => {
                let range = range.check(size)?;
                let content_range = format!("bytes {}-{}/{size}", range.start, range.end - 1);
                (range.start, range.end - range.start, Some(content_range))
            }
            None => (0, size, None),
        };
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
        let full = content_range.is_none();
        let checksum = if full && input.checksum_mode.is_some() {
            upload::stored_checksum(meta.as_ref().and_then(|meta| meta.checksum.as_ref()))
        } else {
            dto::Checksum::default()
        };
        let meta = meta.unwrap_or_default();
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
        if input.version_id.as_deref().is_some_and(|id| id != "null") {
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
        )?;
        let size = if entry.is_dir() { 0 } else { entry.size };
        let checksum = if input.checksum_mode.is_some() {
            upload::stored_checksum(meta.as_ref().and_then(|meta| meta.checksum.as_ref()))
        } else {
            dto::Checksum::default()
        };
        let meta = meta.unwrap_or_default();
        let mut response = S3Response::new(dto::HeadObjectOutput {
            content_length: Some(i64::try_from(size).unwrap_or(i64::MAX)),
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
            ..Default::default()
        });
        nosniff(&mut response.headers, anonymous);
        Ok(response)
    }

    async fn delete_object(
        &self,
        req: S3Request<dto::DeleteObjectInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectOutput>> {
        let auth = authorized(&req)?;
        let bucket = auth.bucket()?;
        let input = req.input;
        if input.version_id.as_deref().is_some_and(|id| id != "null") {
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
            let result = if object.version_id.as_deref().is_some_and(|id| id != "null") {
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
        if version_id.as_deref().is_some_and(|id| id != "null") {
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

        // The key needs a grant on the source bucket of its own account too.
        let source = if **source_bucket == *destination.name {
            destination.clone()
        } else {
            let bucket = s3::bucket(self.state.pool(), source_bucket)
                .await
                .map_err(error::database)?
                .ok_or_else(|| s3_error!(NoSuchBucket))?;
            Arc::new(bucket)
        };
        if access::permission(&key, &source).is_none() {
            return Err(s3_error!(AccessDenied));
        }
        let from = match keys::target(&source.name, source_key) {
            Ok(Target::File(path)) => path,
            _ => return Err(s3_error!(NoSuchKey)),
        };
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
        let source_etag = etag_of(&source_entry, source_meta.as_ref());
        check_read_conditions(
            &source_etag,
            source_entry.modified,
            input.copy_source_if_match.as_ref(),
            input.copy_source_if_none_match.as_ref(),
            input.copy_source_if_modified_since.as_ref(),
            input.copy_source_if_unmodified_since.as_ref(),
        )
        .map_err(|err| {
            // A failed copy-source condition is a 412 in every case.
            if *err.code() == S3ErrorCode::NotModified {
                s3_error!(PreconditionFailed)
            } else {
                err
            }
        })?;

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
        let source_meta = source_meta.unwrap_or_default();
        // An S3 ETag of the content (an MD5) stays valid for an identical copy; a WebDAV ETag
        // belongs to its version and does not.
        let s3_etag = source_meta.s3_etag.clone();
        let meta = if replace {
            ObjectMeta {
                s3_etag,
                public_read: public,
                content_type: input.content_type,
                content_encoding: input.content_encoding,
                content_disposition: input.content_disposition,
                content_language: input.content_language,
                cache_control: input.cache_control,
                expires: input.expires,
                user_meta: user_meta(input.metadata),
                checksum: source_meta.checksum,
            }
        } else {
            ObjectMeta {
                s3_etag,
                public_read: public,
                ..source_meta
            }
        };
        self.check_locks(&destination, &to).await?;
        let condition = write_condition(input.if_match.as_ref(), input.if_none_match.as_ref())?;
        let entry = self
            .state
            .fs()
            .copy_object(identity, &from, &to, meta.clone(), condition)
            .await
            .map_err(|err| error::object(err, false))?;
        Ok(S3Response::new(dto::CopyObjectOutput {
            copy_object_result: Some(dto::CopyObjectResult {
                e_tag: Some(ETag::Strong(meta.etag_or(&entry.etag).to_owned())),
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

    /// Installs an assembled multipart upload; see [`crate::multipart::complete`].
    pub(crate) async fn install(
        &self,
        auth: &Authorized,
        bucket: &Bucket,
        client: &RelPath,
        temp: std::path::PathBuf,
        meta: ObjectMeta,
        condition: WriteCondition,
    ) -> S3Result<Arc<Entry>> {
        self.check_locks(bucket, client).await?;
        let identity = Self::bucket_identity(auth, bucket, true)?;
        self.state
            .fs()
            .put_object(identity, client, temp, meta, condition)
            .await
            .map_err(|err| error::object(err, false))
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
    fn write_conditions_are_create_only_or_compare_and_swap() {
        assert_eq!(write_condition(None, None).unwrap(), WriteCondition::Always);
        assert_eq!(
            write_condition(None, Some(&ETagCondition::Any)).unwrap(),
            WriteCondition::CreateOnly
        );
        assert_eq!(
            write_condition(Some(&tag("e")), None).unwrap(),
            WriteCondition::IfMatch("e".into())
        );
        assert!(write_condition(None, Some(&tag("e"))).is_err());
        assert!(write_condition(Some(&ETagCondition::Any), None).is_err());
    }

    #[test]
    fn canned_acls() {
        let acl = |value: &str| dto::ObjectCannedACL::from(value.to_owned());
        assert!(!object_acl(None).unwrap());
        assert!(!object_acl(Some(&acl("private"))).unwrap());
        assert!(!object_acl(Some(&acl("bucket-owner-full-control"))).unwrap());
        assert!(object_acl(Some(&acl("public-read"))).unwrap());
        for unsupported in ["public-read-write", "authenticated-read", "aws-exec-read"] {
            assert!(
                object_acl(Some(&acl(unsupported))).is_err(),
                "{unsupported}"
            );
        }
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
