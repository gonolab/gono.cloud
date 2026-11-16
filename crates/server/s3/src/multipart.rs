//! Multipart uploads.
//!
//! - **Staging**: `CreateMultipartUpload` records the upload (`s3_uploads`) with the metadata of
//!   the object to create and a server-chosen id. Each part is received into `tmp/` like a
//!   `PutObject` body ([`crate::upload`]) and renamed into `s3-uploads/<upload id>/` under a name
//!   of its own (`<part>.<random>`), so a part uploaded twice at once never pairs one file with
//!   the other's ETag; the replaced file is removed.
//! - **Completion** checks the part list against what arrived (ascending part numbers, matching
//!   ETags, every part but the last at least 5 MiB, as in S3), then answers `200` right away and
//!   assembles the parts in `tmp/` while s3s keeps the connection alive with whitespace. The
//!   object is installed like a `PutObject` (WebDAV locks, conditions), its ETag is the MD5 of
//!   the part MD5s followed by `-<parts>`, and the upload ends. While one completion runs, the
//!   upload takes no parts and no second completion.
//! - **Expiry**: an upload expires `s3.multipart_ttl_secs` after its last part (or its
//!   creation); [`purge`], run by a background task, removes it, and staging directories that
//!   belong to no upload.

use std::{
    io::{Read as _, Write as _},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use gono_server_core::{
    db,
    meta::{Checksum, ObjectMeta},
    s3::{self, Bucket, Upload, UploadPart},
};
use gono_server_dav::{ObjectError, WriteCondition};
use rand::RngExt as _;
use s3s::{
    S3Request, S3Response, S3Result,
    crypto::{Checksum as _, Md5},
    dto::{self, ETag, Timestamp},
    s3_error,
};
use serde_json::{Map, Value, json};

use crate::{
    access::{Authorized, Caller},
    error,
    keys::{self, Target},
    ops::GonoS3,
    state::S3State,
    upload,
};

/// Smallest part but the last, as in S3.
pub const MIN_PART_BYTES: u64 = 5 * 1024 * 1024;

/// Most parts of an upload.
const MAX_PARTS: i32 = 10_000;

/// Most parts or uploads in one listing.
const MAX_LISTED: usize = 1000;

/// Staging directories without an upload are left alone this long, so that a part that is
/// being renamed in is never taken for an orphan.
const ORPHAN_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

fn authorized<T>(req: &S3Request<T>) -> S3Result<Authorized> {
    req.extensions
        .get::<Authorized>()
        .cloned()
        .ok_or_else(|| s3_error!(InternalError, "the access check did not run"))
}

fn timestamp_from_secs(seconds: i64) -> Timestamp {
    Timestamp::from(UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0)))
}

/// The metadata of the object to create, as stored with the upload.
fn meta_to_json(meta: &ObjectMeta) -> String {
    let user: Map<String, Value> = meta
        .user_meta
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    json!({
        "public_read": meta.public_read,
        "content_type": meta.content_type,
        "content_encoding": meta.content_encoding,
        "content_disposition": meta.content_disposition,
        "content_language": meta.content_language,
        "cache_control": meta.cache_control,
        "expires": meta.expires,
        "user_meta": user,
    })
    .to_string()
}

fn meta_from_json(value: &str) -> ObjectMeta {
    let value: Value = serde_json::from_str(value).unwrap_or(Value::Null);
    let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    ObjectMeta {
        s3_etag: None,
        public_read: value
            .get("public_read")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        content_type: text("content_type"),
        content_encoding: text("content_encoding"),
        content_disposition: text("content_disposition"),
        content_language: text("content_language"),
        cache_control: text("cache_control"),
        expires: text("expires"),
        user_meta: value
            .get("user_meta")
            .and_then(Value::as_object)
            .map(|user| {
                user.iter()
                    .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default(),
        checksum: None::<Checksum>,
    }
}

/// The upload `upload_id` of `key` in `bucket`, or `NoSuchUpload`.
async fn find_upload(
    state: &S3State,
    bucket: &Bucket,
    key: &str,
    upload_id: &str,
) -> S3Result<Upload> {
    let upload = s3::upload(state.pool(), upload_id)
        .await
        .map_err(error::database)?
        .filter(|upload| upload.bucket_id == bucket.id && upload.key == key)
        .ok_or_else(|| s3_error!(NoSuchUpload))?;
    Ok(upload)
}

/// `CreateMultipartUpload`.
pub(crate) async fn create(
    state: &S3State,
    req: S3Request<dto::CreateMultipartUploadInput>,
) -> S3Result<S3Response<dto::CreateMultipartUploadOutput>> {
    let auth = authorized(&req)?;
    GonoS3::write_permission(&auth)?;
    let bucket = auth.bucket()?;
    let input = req.input;
    if input.server_side_encryption.is_some()
        || input.sse_customer_algorithm.is_some()
        || input.ssekms_key_id.is_some()
        || input.object_lock_mode.is_some()
    {
        return Err(s3_error!(NotImplemented));
    }
    if input.grant_full_control.is_some()
        || input.grant_read.is_some()
        || input.grant_read_acp.is_some()
        || input.grant_write_acp.is_some()
    {
        return Err(s3_error!(
            NotImplemented,
            "Explicit grants are not supported; use a canned ACL"
        ));
    }
    let public = match input.acl.as_ref().map(dto::ObjectCannedACL::as_str) {
        None | Some("private" | "bucket-owner-read" | "bucket-owner-full-control") => false,
        Some("public-read") => true,
        Some(_) => {
            return Err(s3_error!(
                NotImplemented,
                "Only the canned ACLs private and public-read are supported"
            ));
        }
    };
    if public
        && crate::access::Public::of(bucket, state.settings().allow_anonymous).read
            == s3::Anonymous::Private
    {
        return Err(s3_error!(
            AccessControlListNotSupported,
            "The bucket does not publish objects; public-read objects would not be readable"
        ));
    }
    match keys::target(&bucket.name, &input.key) {
        Ok(Target::File(_)) => {}
        Ok(Target::Folder(_)) => {
            return Err(s3_error!(
                InvalidArgument,
                "A key ending in '/' names a folder and takes no content"
            ));
        }
        Err(err) => return Err(error::key(&err)),
    }
    let meta = ObjectMeta {
        public_read: public,
        content_type: input.content_type,
        content_encoding: input.content_encoding,
        content_disposition: input.content_disposition,
        content_language: input.content_language,
        cache_control: input.cache_control,
        expires: input.expires,
        user_meta: input
            .metadata
            .unwrap_or_default()
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect(),
        ..ObjectMeta::default()
    };
    let now = db::unix_now();
    let ttl = i64::try_from(state.settings().multipart_ttl_secs).unwrap_or(i64::MAX);
    let upload_id = s3::create_upload(
        state.pool(),
        bucket.id,
        &input.key,
        &meta_to_json(&meta),
        now,
        now.saturating_add(ttl),
    )
    .await
    .map_err(error::database)?;
    let dir = state.fs().layout().s3_upload_dir(&upload_id);
    tokio::fs::create_dir(&dir).await.map_err(error::io)?;
    Ok(S3Response::new(dto::CreateMultipartUploadOutput {
        bucket: Some(bucket.name.clone()),
        key: Some(input.key),
        upload_id: Some(upload_id),
        ..Default::default()
    }))
}

/// `UploadPart`.
pub(crate) async fn upload_part(
    state: &S3State,
    req: S3Request<dto::UploadPartInput>,
) -> S3Result<S3Response<dto::UploadPartOutput>> {
    let auth = authorized(&req)?;
    GonoS3::write_permission(&auth)?;
    let bucket = auth.bucket()?;
    let input = req.input;
    if !(1..=MAX_PARTS).contains(&input.part_number) {
        return Err(s3_error!(
            InvalidArgument,
            "Part numbers are between 1 and 10000"
        ));
    }
    if input.sse_customer_algorithm.is_some() {
        return Err(s3_error!(NotImplemented));
    }
    find_upload(state, bucket, &input.key, &input.upload_id).await?;
    if state.is_completing(&input.upload_id) {
        return Err(s3_error!(OperationAborted, "The upload is being completed"));
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
    let received = upload::receive(state, body, input.content_length, &algorithms).await?;
    let trailers = req
        .trailing_headers
        .as_ref()
        .and_then(s3s::TrailingHeaders::take);
    upload::apply_trailers(&mut claimed, trailers.as_ref())?;
    let checksum = upload::verify(&received, input.content_md5.as_deref(), &claimed)?;
    let etag = received.etag();
    store_part(
        state,
        &input.upload_id,
        input.part_number,
        &received.temp,
        received.size,
        &etag,
    )
    .await?;
    let checksum = upload::stored_checksum(checksum.as_ref());
    Ok(S3Response::new(dto::UploadPartOutput {
        e_tag: Some(ETag::Strong(etag)),
        checksum_crc32: checksum.checksum_crc32,
        checksum_crc32c: checksum.checksum_crc32c,
        checksum_crc64nvme: checksum.checksum_crc64nvme,
        checksum_sha1: checksum.checksum_sha1,
        checksum_sha256: checksum.checksum_sha256,
        ..Default::default()
    }))
}

/// Moves the part file `temp` (`size` bytes, ETag `etag`) into the staging directory of
/// `upload_id` under a name of its own and records it, replacing an earlier part of the same
/// number.
async fn store_part(
    state: &S3State,
    upload_id: &str,
    part_number: i32,
    temp: &upload::Temp,
    size: u64,
    etag: &str,
) -> S3Result<()> {
    let part_number = u32::try_from(part_number).unwrap_or(0);
    let file_name = format!("{part_number}.{:016x}", rand::rng().random::<u64>());
    let dir = state.fs().layout().s3_upload_dir(upload_id);
    tokio::fs::rename(temp.path(), dir.join(&file_name))
        .await
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                // The upload was aborted or completed meanwhile.
                s3_error!(NoSuchUpload)
            } else {
                error::io(err)
            }
        })?;
    let now = db::unix_now();
    let ttl = i64::try_from(state.settings().multipart_ttl_secs).unwrap_or(i64::MAX);
    let part = UploadPart {
        part_number,
        file_name: file_name.clone(),
        etag: etag.to_owned(),
        size,
        uploaded_at: now,
    };
    let recorded = s3::record_part(state.pool(), upload_id, &part, now.saturating_add(ttl))
        .await
        .map_err(error::database)?;
    let Some(replaced) = recorded else {
        let _ = tokio::fs::remove_file(dir.join(&file_name)).await;
        return Err(s3_error!(NoSuchUpload));
    };
    if let Some(replaced) = replaced {
        let _ = tokio::fs::remove_file(dir.join(replaced)).await;
    }
    Ok(())
}

/// The bytes `x-amz-copy-source-range` names in an object of `size` bytes: the offset of the
/// first and the number of bytes. Without a range, the whole object.
fn copy_range(range: Option<&str>, size: u64) -> S3Result<(u64, u64)> {
    let Some(range) = range else {
        return Ok((0, size));
    };
    let malformed = || {
        s3_error!(
            InvalidArgument,
            "The x-amz-copy-source-range value must be of the form bytes=first-last where first \
             and last are the zero-based offsets of the first and last bytes to copy"
        )
    };
    let (first, last) = range
        .trim()
        .strip_prefix("bytes=")
        .and_then(|bytes| bytes.split_once('-'))
        .ok_or_else(malformed)?;
    let first: u64 = first.trim().parse().map_err(|_| malformed())?;
    let last: u64 = last.trim().parse().map_err(|_| malformed())?;
    if first > last || last >= size {
        return Err(s3_error!(
            InvalidRange,
            "The range is not valid for a source object of {size} bytes"
        ));
    }
    Ok((first, last - first + 1))
}

/// Copies `length` bytes of `source` from `start` on into the new file `temp`, synced. Returns
/// their MD5.
fn copy_part(
    mut source: std::fs::File,
    start: u64,
    length: u64,
    temp: &Path,
) -> std::io::Result<[u8; 16]> {
    use std::io::{Seek as _, SeekFrom};

    source.seek(SeekFrom::Start(start))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = options.open(temp)?;
    let mut md5 = Md5::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut remaining = length;
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = source.read(&mut buffer[..want])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the source object became shorter while it was copied",
            ));
        }
        md5.update(&buffer[..read]);
        out.write_all(&buffer[..read])?;
        remaining -= read as u64;
    }
    out.sync_all()?;
    Ok(md5.finalize())
}

/// `UploadPartCopy`: a part from (a range of) an object the key may read, in this or another
/// bucket of its account.
pub(crate) async fn upload_part_copy(
    s3: &GonoS3,
    req: S3Request<dto::UploadPartCopyInput>,
) -> S3Result<S3Response<dto::UploadPartCopyOutput>> {
    let state = s3.state();
    let auth = authorized(&req)?;
    GonoS3::write_permission(&auth)?;
    let key = match &auth.caller {
        Caller::Key(key) => key.clone(),
        Caller::Anonymous => return Err(s3_error!(AccessDenied)),
    };
    let destination = auth.bucket()?.clone();
    let input = req.input;
    if !(1..=MAX_PARTS).contains(&input.part_number) {
        return Err(s3_error!(
            InvalidArgument,
            "Part numbers are between 1 and 10000"
        ));
    }
    if input.sse_customer_algorithm.is_some() || input.copy_source_sse_customer_algorithm.is_some()
    {
        return Err(s3_error!(NotImplemented));
    }
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
    if version_id
        .as_deref()
        .is_some_and(|id| id != crate::ops::NULL_VERSION)
    {
        return Err(s3_error!(NoSuchVersion));
    }
    find_upload(state, &destination, &input.key, &input.upload_id).await?;
    if state.is_completing(&input.upload_id) {
        return Err(s3_error!(OperationAborted, "The upload is being completed"));
    }
    let (source, from) = s3
        .copy_source(&key, &destination, source_bucket, source_key)
        .await?;
    let identity = auth.identity(&[(&source, false)])?;
    let (entry, meta, file) =
        state
            .fs()
            .open_object(identity, &from)
            .await
            .map_err(|err| match err {
                ObjectError::IsFolder | ObjectError::NotFound => s3_error!(NoSuchKey),
                other => error::object(other, false),
            })?;
    let source_etag = meta
        .as_ref()
        .map_or(entry.etag.as_str(), |meta| meta.etag_or(&entry.etag))
        .to_owned();
    crate::ops::check_copy_source_conditions(
        &source_etag,
        entry.modified,
        input.copy_source_if_match.as_ref(),
        input.copy_source_if_none_match.as_ref(),
        input.copy_source_if_modified_since.as_ref(),
        input.copy_source_if_unmodified_since.as_ref(),
    )?;
    let (start, length) = copy_range(input.copy_source_range.as_deref(), entry.size)?;

    let temp = upload::Temp::new_in(&state.fs().layout().tmp_dir());
    let path = temp.path().to_path_buf();
    let md5 = tokio::task::spawn_blocking(move || copy_part(file, start, length, &path))
        .await
        .map_err(|_| s3_error!(InternalError))?
        .map_err(error::io)?;
    let etag = upload::hex(&md5);
    store_part(
        state,
        &input.upload_id,
        input.part_number,
        &temp,
        length,
        &etag,
    )
    .await?;
    Ok(S3Response::new(dto::UploadPartCopyOutput {
        copy_part_result: Some(dto::CopyPartResult {
            e_tag: Some(ETag::Strong(etag)),
            last_modified: Some(Timestamp::from(SystemTime::now())),
            ..Default::default()
        }),
        ..Default::default()
    }))
}

/// `ListParts`.
pub(crate) async fn list_parts(
    state: &S3State,
    req: S3Request<dto::ListPartsInput>,
) -> S3Result<S3Response<dto::ListPartsOutput>> {
    let auth = authorized(&req)?;
    let bucket = auth.bucket()?;
    let input = req.input;
    find_upload(state, bucket, &input.key, &input.upload_id).await?;
    let marker = input
        .part_number_marker
        .and_then(|marker| u32::try_from(marker).ok())
        .unwrap_or(0);
    let max = input.max_parts.map_or(MAX_LISTED, |max| {
        usize::try_from(max.max(0)).unwrap_or(0).min(MAX_LISTED)
    });
    let mut parts: Vec<UploadPart> = s3::parts(state.pool(), &input.upload_id)
        .await
        .map_err(error::database)?
        .into_iter()
        .filter(|part| part.part_number > marker)
        .collect();
    let truncated = parts.len() > max;
    parts.truncate(max);
    let next = parts
        .last()
        .map(|part| i32::try_from(part.part_number).unwrap_or(i32::MAX));
    let owner = dto::Owner {
        display_name: Some(bucket.owner_display_name.clone()),
        id: Some(bucket.owner_name.to_string()),
    };
    Ok(S3Response::new(dto::ListPartsOutput {
        bucket: Some(bucket.name.clone()),
        key: Some(input.key),
        upload_id: Some(input.upload_id),
        part_number_marker: input.part_number_marker,
        next_part_number_marker: truncated.then_some(next).flatten(),
        max_parts: Some(i32::try_from(max).unwrap_or(i32::MAX)),
        is_truncated: Some(truncated),
        initiator: Some(dto::Initiator {
            display_name: owner.display_name.clone(),
            id: owner.id.clone(),
        }),
        owner: Some(owner),
        storage_class: Some(dto::StorageClass::from_static(dto::StorageClass::STANDARD)),
        parts: Some(
            parts
                .into_iter()
                .map(|part| dto::Part {
                    e_tag: Some(ETag::Strong(part.etag)),
                    last_modified: Some(timestamp_from_secs(part.uploaded_at)),
                    part_number: i32::try_from(part.part_number).ok(),
                    size: i64::try_from(part.size).ok(),
                    ..Default::default()
                })
                .collect(),
        ),
        ..Default::default()
    }))
}

/// `ListMultipartUploads`: by key, then upload id, from the markers on, filtered by prefix.
pub(crate) async fn list_uploads(
    state: &S3State,
    req: S3Request<dto::ListMultipartUploadsInput>,
) -> S3Result<S3Response<dto::ListMultipartUploadsOutput>> {
    let auth = authorized(&req)?;
    let bucket = auth.bucket()?;
    let input = req.input;
    if input.delimiter.as_deref().is_some_and(|d| !d.is_empty()) {
        return Err(s3_error!(
            NotImplemented,
            "Listing multipart uploads with a delimiter is not supported"
        ));
    }
    let max = input.max_uploads.map_or(MAX_LISTED, |max| {
        usize::try_from(max.max(0)).unwrap_or(0).min(MAX_LISTED)
    });
    let prefix = input.prefix.clone().unwrap_or_default();
    let key_marker = input.key_marker.clone().unwrap_or_default();
    let id_marker = input.upload_id_marker.clone().unwrap_or_default();
    let mut uploads: Vec<Upload> = s3::uploads_of_bucket(state.pool(), bucket.id)
        .await
        .map_err(error::database)?
        .into_iter()
        .filter(|upload| upload.key.starts_with(&prefix))
        .filter(|upload| {
            key_marker.is_empty()
                || upload.key > key_marker
                || (upload.key == key_marker
                    && !id_marker.is_empty()
                    && upload.upload_id > id_marker)
        })
        .collect();
    let truncated = uploads.len() > max;
    uploads.truncate(max);
    let last = uploads.last().cloned();
    let owner = dto::Owner {
        display_name: Some(bucket.owner_display_name.clone()),
        id: Some(bucket.owner_name.to_string()),
    };
    let url = input
        .encoding_type
        .as_ref()
        .is_some_and(|encoding| encoding.as_str() == dto::EncodingType::URL);
    let encode = |value: String| if url { keys::url_encode(&value) } else { value };
    Ok(S3Response::new(dto::ListMultipartUploadsOutput {
        bucket: Some(bucket.name.clone()),
        prefix: input.prefix.map(encode),
        key_marker: input.key_marker.map(encode),
        upload_id_marker: input.upload_id_marker,
        max_uploads: Some(i32::try_from(max).unwrap_or(i32::MAX)),
        is_truncated: Some(truncated),
        next_key_marker: last
            .as_ref()
            .filter(|_| truncated)
            .map(|upload| encode(upload.key.clone())),
        next_upload_id_marker: last.filter(|_| truncated).map(|upload| upload.upload_id),
        encoding_type: input.encoding_type,
        uploads: Some(
            uploads
                .into_iter()
                .map(|upload| dto::MultipartUpload {
                    initiated: Some(timestamp_from_secs(upload.created_at)),
                    initiator: Some(dto::Initiator {
                        display_name: owner.display_name.clone(),
                        id: owner.id.clone(),
                    }),
                    key: Some(encode(upload.key)),
                    owner: Some(owner.clone()),
                    storage_class: Some(dto::StorageClass::from_static(
                        dto::StorageClass::STANDARD,
                    )),
                    upload_id: Some(upload.upload_id),
                    ..Default::default()
                })
                .collect(),
        ),
        ..Default::default()
    }))
}

/// `AbortMultipartUpload`.
pub(crate) async fn abort(
    state: &S3State,
    req: S3Request<dto::AbortMultipartUploadInput>,
) -> S3Result<S3Response<dto::AbortMultipartUploadOutput>> {
    let auth = authorized(&req)?;
    GonoS3::write_permission(&auth)?;
    let bucket = auth.bucket()?;
    let input = req.input;
    find_upload(state, bucket, &input.key, &input.upload_id).await?;
    let Some(_completing) = state.begin_completion(&input.upload_id) else {
        return Err(s3_error!(OperationAborted, "The upload is being completed"));
    };
    if !s3::delete_upload(state.pool(), &input.upload_id)
        .await
        .map_err(error::database)?
    {
        return Err(s3_error!(NoSuchUpload));
    }
    remove_staging(state, &input.upload_id).await;
    Ok(S3Response::new(dto::AbortMultipartUploadOutput::default()))
}

/// Removes the staging directory of `upload_id`.
async fn remove_staging(state: &S3State, upload_id: &str) {
    let dir = state.fs().layout().s3_upload_dir(upload_id);
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!(upload_id, error = %err, "cannot remove an S3 upload's parts"),
    }
}

/// The parts a completion names, checked against the parts that arrived.
fn chosen_parts(
    requested: &[dto::CompletedPart],
    stored: &[UploadPart],
) -> S3Result<Vec<UploadPart>> {
    if requested.is_empty() {
        return Err(s3_error!(
            MalformedXML,
            "The list of parts must not be empty"
        ));
    }
    let mut chosen: Vec<UploadPart> = Vec::with_capacity(requested.len());
    for part in requested {
        let number = part
            .part_number
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(|| s3_error!(InvalidPart))?;
        if chosen.last().is_some_and(|last| last.part_number >= number) {
            return Err(s3_error!(InvalidPartOrder));
        }
        let found = stored
            .iter()
            .find(|stored| stored.part_number == number)
            .ok_or_else(|| s3_error!(InvalidPart, "Part {number} was not uploaded"))?;
        if part
            .e_tag
            .as_ref()
            .is_some_and(|etag| etag.value() != found.etag)
        {
            return Err(s3_error!(
                InvalidPart,
                "The ETag of part {number} does not match"
            ));
        }
        chosen.push(found.clone());
    }
    if let Some((_, rest)) = chosen.split_last()
        && let Some(small) = rest.iter().find(|part| part.size < MIN_PART_BYTES)
    {
        return Err(s3_error!(
            EntityTooSmall,
            "Part {} is smaller than 5 MiB and not the last part",
            small.part_number
        ));
    }
    Ok(chosen)
}

/// The ETag of a multipart object: the MD5 of the parts' MD5s, a dash and the number of parts.
fn multipart_etag(parts: &[UploadPart]) -> S3Result<String> {
    let mut md5 = Md5::new();
    for part in parts {
        let mut digest = [0u8; 16];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = part
                .etag
                .get(index * 2..index * 2 + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| s3_error!(InternalError, "a stored part ETag is not an MD5"))?;
        }
        md5.update(&digest);
    }
    Ok(format!("{}-{}", upload::hex(&md5.finalize()), parts.len()))
}

/// Concatenates the parts in `dir` into a new synced file in `tmp_dir`.
fn assemble(dir: &Path, parts: &[UploadPart], temp: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = options.open(temp)?;
    let mut buffer = vec![0; 1024 * 1024];
    for part in parts {
        let mut file = std::fs::File::open(dir.join(&part.file_name))?;
        let mut copied: u64 = 0;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            out.write_all(&buffer[..read])?;
            copied += read as u64;
        }
        if copied != part.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a part's file does not have the part's size",
            ));
        }
    }
    out.sync_all()
}

/// `CompleteMultipartUpload`.
pub(crate) async fn complete(
    s3: &GonoS3,
    req: S3Request<dto::CompleteMultipartUploadInput>,
) -> S3Result<S3Response<dto::CompleteMultipartUploadOutput>> {
    let state = s3.state().clone();
    let auth = authorized(&req)?;
    GonoS3::write_permission(&auth)?;
    let bucket = auth.bucket()?.clone();
    let input = req.input;
    let upload = find_upload(&state, &bucket, &input.key, &input.upload_id).await?;
    let client = match keys::target(&bucket.name, &input.key) {
        Ok(Target::File(client)) => client,
        _ => return Err(s3_error!(InvalidArgument)),
    };
    let condition = match (input.if_match.as_ref(), input.if_none_match.as_ref()) {
        (None, None) => WriteCondition::Always,
        (None, Some(dto::ETagCondition::Any)) => WriteCondition::CreateOnly,
        (Some(dto::ETagCondition::ETag(etag)), None) => {
            WriteCondition::IfMatch(etag.value().to_owned())
        }
        _ => return Err(s3_error!(NotImplemented)),
    };
    let Some(completing) = state.begin_completion(&upload.upload_id) else {
        return Err(s3_error!(
            OperationAborted,
            "The upload is being completed already"
        ));
    };
    let stored = s3::parts(state.pool(), &upload.upload_id)
        .await
        .map_err(error::database)?;
    let requested = input
        .multipart_upload
        .and_then(|upload| upload.parts)
        .unwrap_or_default();
    let parts = chosen_parts(&requested, &stored)?;
    let total: u64 = parts.iter().map(|part| part.size).sum();
    if input
        .mpu_object_size
        .is_some_and(|size| u64::try_from(size).ok() != Some(total))
    {
        return Err(s3_error!(
            InvalidRequest,
            "The object size does not match the parts"
        ));
    }
    let etag = multipart_etag(&parts)?;
    let mut meta = meta_from_json(&upload.meta);
    meta.s3_etag = Some(etag.clone());

    // From here on the answer is 200 with whitespace until the object is in place; failures
    // arrive as an error document in the body.
    let s3 = s3.clone();
    let key = input.key.clone();
    let bucket_name = bucket.name.clone();
    let future = async move {
        let _completing = completing;
        let dir = state.fs().layout().s3_upload_dir(&upload.upload_id);
        let temp = upload::Temp::new_in(&state.fs().layout().tmp_dir());
        let path = temp.path().to_path_buf();
        tokio::task::spawn_blocking(move || assemble(&dir, &parts, &path))
            .await
            .map_err(|_| s3_error!(InternalError))?
            .map_err(error::io)?;
        if let Some(time) = upload::mtime_of(&meta) {
            upload::set_mtime(temp.path(), time).await?;
        }
        s3.install(
            &auth,
            &bucket,
            &client,
            temp.path().to_path_buf(),
            meta,
            condition,
        )
        .await?;
        s3::delete_upload(state.pool(), &upload.upload_id)
            .await
            .map_err(error::database)?;
        remove_staging(&state, &upload.upload_id).await;
        Ok(dto::CompleteMultipartUploadOutput {
            bucket: Some(bucket_name.clone()),
            key: Some(key.clone()),
            e_tag: Some(ETag::Strong(etag)),
            location: Some(format!("/{bucket_name}/{key}")),
            ..Default::default()
        })
    };
    Ok(S3Response::new(dto::CompleteMultipartUploadOutput {
        future: Some(Box::pin(future)),
        ..Default::default()
    }))
}

/// Removes expired uploads and staging directories that belong to no upload. Returns the
/// number of directories removed.
pub async fn purge(state: &S3State) -> gono_server_core::Result<usize> {
    let expired = s3::purge_expired_uploads(state.pool(), db::unix_now()).await?;
    for upload_id in &expired {
        remove_staging(state, upload_id).await;
    }
    let live = s3::upload_ids(state.pool()).await?;
    let root = state.fs().layout().s3_uploads_root();
    let orphans = tokio::task::spawn_blocking(move || -> std::io::Result<usize> {
        let mut removed = 0;
        let now = SystemTime::now();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(err),
        };
        for entry in entries {
            let entry = entry?;
            let known = entry
                .file_name()
                .to_str()
                .is_some_and(|name| live.contains(name));
            let old = entry
                .metadata()?
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age > ORPHAN_GRACE);
            if !known && old {
                let path = entry.path();
                let result = if entry.file_type()?.is_dir() {
                    std::fs::remove_dir_all(&path)
                } else {
                    std::fs::remove_file(&path)
                };
                match result {
                    Ok(()) => removed += 1,
                    Err(err) => tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "cannot remove an orphaned S3 upload"
                    ),
                }
            }
        }
        Ok(removed)
    })
    .await
    .map_err(|_| gono_server_core::Error::Io {
        path: state.fs().layout().s3_uploads_root(),
        source: std::io::Error::other("the purge task failed"),
    })?
    .map_err(|source| gono_server_core::Error::Io {
        path: state.fs().layout().s3_uploads_root(),
        source,
    })?;
    Ok(expired.len() + orphans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(number: u32, etag: &str, size: u64) -> UploadPart {
        UploadPart {
            part_number: number,
            file_name: format!("{number}.x"),
            etag: etag.to_owned(),
            size,
            uploaded_at: 0,
        }
    }

    fn completed(number: i32, etag: &str) -> dto::CompletedPart {
        dto::CompletedPart {
            part_number: Some(number),
            e_tag: Some(ETag::Strong(etag.to_owned())),
            ..Default::default()
        }
    }

    #[test]
    fn completions_name_uploaded_parts_in_order() {
        let big = MIN_PART_BYTES;
        let stored = [
            part(1, "a".repeat(32).as_str(), big),
            part(2, "b".repeat(32).as_str(), big),
            part(3, "c".repeat(32).as_str(), 1),
        ];
        let a = "a".repeat(32);
        let b = "b".repeat(32);
        let c = "c".repeat(32);
        let chosen = chosen_parts(&[completed(1, &a), completed(3, &c)], &stored).unwrap();
        assert_eq!(chosen.len(), 2);
        let code = |requested: &[dto::CompletedPart]| {
            chosen_parts(requested, &stored).unwrap_err().code().clone()
        };
        assert_eq!(code(&[]), s3s::S3ErrorCode::MalformedXML);
        assert_eq!(
            code(&[completed(2, &b), completed(1, &a)]),
            s3s::S3ErrorCode::InvalidPartOrder
        );
        assert_eq!(code(&[completed(4, &a)]), s3s::S3ErrorCode::InvalidPart);
        assert_eq!(code(&[completed(1, &b)]), s3s::S3ErrorCode::InvalidPart);
        assert_eq!(
            code(&[completed(3, &c), completed(4, &c)]),
            s3s::S3ErrorCode::InvalidPart
        );
        let small = [part(1, &a, 1), part(2, &b, 1)];
        assert_eq!(
            chosen_parts(&[completed(1, &a), completed(2, &b)], &small)
                .unwrap_err()
                .code(),
            &s3s::S3ErrorCode::EntityTooSmall
        );
    }

    #[test]
    fn multipart_etags_hash_the_part_md5s() {
        // The MD5s of "a" and "b", and the MD5 of their concatenated digests.
        let parts = [
            part(1, "0cc175b9c0f1b6a831c399e269772661", 1),
            part(2, "92eb5ffee6ae2fec3ad71c777531578f", 1),
        ];
        let etag = multipart_etag(&parts).unwrap();
        assert!(etag.ends_with("-2"), "{etag}");
        let mut expected = Md5::new();
        expected.update(&[
            0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77,
            0x26, 0x61,
        ]);
        expected.update(&[
            0x92, 0xeb, 0x5f, 0xfe, 0xe6, 0xae, 0x2f, 0xec, 0x3a, 0xd7, 0x1c, 0x77, 0x75, 0x31,
            0x57, 0x8f,
        ]);
        assert_eq!(etag, format!("{}-2", upload::hex(&expected.finalize())));
        assert!(multipart_etag(&[part(1, "zz", 1)]).is_err());
    }

    #[test]
    fn copy_ranges_name_inclusive_offsets() {
        assert_eq!(copy_range(None, 10).unwrap(), (0, 10));
        assert_eq!(copy_range(Some("bytes=0-9"), 10).unwrap(), (0, 10));
        assert_eq!(copy_range(Some("bytes=3-3"), 10).unwrap(), (3, 1));
        let code = |range: &str| copy_range(Some(range), 10).unwrap_err().code().clone();
        assert_eq!(code("bytes=0-10"), s3s::S3ErrorCode::InvalidRange);
        assert_eq!(code("bytes=5-4"), s3s::S3ErrorCode::InvalidRange);
        for malformed in ["0-9", "bytes=-5", "bytes=5-", "bytes=a-b", "items=0-1"] {
            assert_eq!(
                code(malformed),
                s3s::S3ErrorCode::InvalidArgument,
                "{malformed}"
            );
        }
    }

    #[test]
    fn copied_parts_are_hashed_while_they_are_written() {
        let dir = std::env::temp_dir().join(format!(
            "gono-s3-copy-part-{:016x}",
            rand::rng().random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("source");
        std::fs::write(&source, b"0123456789").unwrap();
        let part = dir.join("part");
        let md5 = copy_part(std::fs::File::open(&source).unwrap(), 2, 5, &part).unwrap();
        assert_eq!(std::fs::read(&part).unwrap(), b"23456");
        assert_eq!(md5, Md5::checksum(b"23456"));
        let short = copy_part(
            std::fs::File::open(&source).unwrap(),
            8,
            5,
            &dir.join("short"),
        );
        assert_eq!(short.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn upload_metadata_round_trips() {
        let meta = ObjectMeta {
            public_read: true,
            content_type: Some("video/mp4".into()),
            cache_control: Some("no-cache".into()),
            user_meta: [("mtime".to_owned(), "1".to_owned())].into(),
            ..ObjectMeta::default()
        };
        assert_eq!(meta_from_json(&meta_to_json(&meta)), meta);
        assert_eq!(meta_from_json("not json"), ObjectMeta::default());
    }
}
