//! Request bodies into `tmp/`: hashed while they arrive, verified before anything is installed.
//!
//! s3s has already decoded `aws-chunked` bodies and checks the signature of each chunk and the
//! SHA-256 of single-chunk payloads; a mismatch ends the body stream with an error. A body is
//! written to a new file in `tmp/` while its MD5 (the S3 ETag) and the checksums the client
//! announced are computed; it is synced, and only after `Content-MD5` and `x-amz-checksum-*`
//! (sent as headers or as `aws-chunked` trailers) have been compared is it installed. Until
//! then the file is a [`Temp`], removed when dropped.

use std::path::{Path, PathBuf};

use futures_util::StreamExt as _;
use gono_server_core::meta;
use http::HeaderMap;
use rand::RngExt as _;
use s3s::{
    S3Error, S3ErrorCode, S3Result,
    checksum::ChecksumHasher,
    crypto::{Checksum as _, Md5},
    dto::{self, Checksum, StreamingBlob},
    s3_error,
};
use tokio::io::AsyncWriteExt as _;

use crate::{error, state::S3State};

/// The checksum algorithms of S3 in the order a stored checksum is chosen, with the header
/// that carries each.
pub(crate) const ALGORITHMS: [(&str, &str); 10] = [
    ("CRC32", "x-amz-checksum-crc32"),
    ("CRC32C", "x-amz-checksum-crc32c"),
    ("CRC64NVME", "x-amz-checksum-crc64nvme"),
    ("SHA1", "x-amz-checksum-sha1"),
    ("SHA256", "x-amz-checksum-sha256"),
    ("SHA512", "x-amz-checksum-sha512"),
    ("MD5", "x-amz-checksum-md5"),
    ("XXHASH64", "x-amz-checksum-xxhash64"),
    ("XXHASH3", "x-amz-checksum-xxhash3"),
    ("XXHASH128", "x-amz-checksum-xxhash128"),
];

/// The value of `algorithm` in `checksum`.
pub(crate) fn field<'a>(checksum: &'a Checksum, algorithm: &str) -> &'a Option<String> {
    match algorithm {
        "CRC32" => &checksum.checksum_crc32,
        "CRC32C" => &checksum.checksum_crc32c,
        "CRC64NVME" => &checksum.checksum_crc64nvme,
        "SHA1" => &checksum.checksum_sha1,
        "SHA256" => &checksum.checksum_sha256,
        "SHA512" => &checksum.checksum_sha512,
        "MD5" => &checksum.checksum_md5,
        "XXHASH64" => &checksum.checksum_xxhash64,
        "XXHASH3" => &checksum.checksum_xxhash3,
        _ => &checksum.checksum_xxhash128,
    }
}

fn field_mut<'a>(checksum: &'a mut Checksum, algorithm: &str) -> &'a mut Option<String> {
    match algorithm {
        "CRC32" => &mut checksum.checksum_crc32,
        "CRC32C" => &mut checksum.checksum_crc32c,
        "CRC64NVME" => &mut checksum.checksum_crc64nvme,
        "SHA1" => &mut checksum.checksum_sha1,
        "SHA256" => &mut checksum.checksum_sha256,
        "SHA512" => &mut checksum.checksum_sha512,
        "MD5" => &mut checksum.checksum_md5,
        "XXHASH64" => &mut checksum.checksum_xxhash64,
        "XXHASH3" => &mut checksum.checksum_xxhash3,
        _ => &mut checksum.checksum_xxhash128,
    }
}

/// A checksum stored with an object, as returned in a response, with its type.
pub(crate) fn stored_checksum(stored: Option<&meta::Checksum>) -> Checksum {
    let mut checksum = Checksum::default();
    if let Some(stored) = stored
        && let Some((algorithm, _)) = ALGORITHMS
            .iter()
            .find(|(algorithm, _)| *algorithm == stored.algorithm)
    {
        *field_mut(&mut checksum, algorithm) = Some(stored.value.clone());
        checksum.checksum_type = Some(dto::ChecksumType::from(
            if stored.composite {
                "COMPOSITE"
            } else {
                "FULL_OBJECT"
            }
            .to_owned(),
        ));
    }
    checksum
}

/// The algorithms whose checksums a request announces: claimed values, the
/// `x-amz-sdk-checksum-algorithm` header, and trailers announced in `x-amz-trailer`.
pub(crate) fn announced(
    claimed: &Checksum,
    algorithm: Option<&str>,
    headers: &HeaderMap,
) -> Vec<&'static str> {
    let trailers: Vec<String> = headers
        .get_all("x-amz-trailer")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    ALGORITHMS
        .iter()
        .filter(|(name, header)| {
            field(claimed, name).is_some()
                || algorithm.is_some_and(|algorithm| algorithm.eq_ignore_ascii_case(name))
                || trailers.iter().any(|trailer| trailer == header)
        })
        .map(|(name, _)| *name)
        .collect()
}

/// Copies the checksums sent as `aws-chunked` trailers into `claimed`.
pub(crate) fn apply_trailers(claimed: &mut Checksum, trailers: Option<&HeaderMap>) -> S3Result<()> {
    let Some(trailers) = trailers else {
        return Ok(());
    };
    for (name, header) in ALGORITHMS {
        if let Some(value) = trailers.get(header) {
            let value = value
                .to_str()
                .map_err(|_| s3_error!(InvalidArgument, "invalid checksum trailer"))?;
            *field_mut(claimed, name) = Some(value.to_owned());
        }
    }
    Ok(())
}

/// Latest modification time taken from metadata: the end of year 9999.
const MAX_MTIME_SECS: u64 = 253_402_300_799;

/// The modification time an object's user metadata names in `mtime` (`X-Amz-Meta-Mtime`, as
/// rclone, s3fs and other tools send it): UNIX seconds, with a fraction of up to nine digits.
/// Other values stay metadata only.
pub(crate) fn mtime_of(meta: &meta::ObjectMeta) -> Option<std::time::SystemTime> {
    let value = meta.user_meta.get("mtime")?.trim();
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let digits = |text: &str| text.bytes().all(|b| b.is_ascii_digit());
    if seconds.is_empty() || seconds.len() > 12 || !digits(seconds) {
        return None;
    }
    if fraction.len() > 9 || !digits(fraction) {
        return None;
    }
    let seconds: u64 = seconds.parse().ok()?;
    if seconds == 0 || seconds > MAX_MTIME_SECS {
        return None;
    }
    let nanos: u32 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<9}").parse().ok()?
    };
    Some(std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanos))
}

/// Sets the modification time of the file at `path` (a received body in `tmp/`), so that
/// WebDAV and the Nextcloud clients see the time the object's metadata names.
pub(crate) async fn set_mtime(path: &Path, time: std::time::SystemTime) -> S3Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_modified(time)
    })
    .await
    .map_err(|_| s3_error!(InternalError))?
    .map_err(error::io)
}

/// A file in `tmp/`, removed when dropped unless it was moved away (installed) before.
#[derive(Debug)]
pub(crate) struct Temp(PathBuf);

impl Temp {
    /// A new, unique path in `dir`; nothing is created yet.
    pub(crate) fn new_in(dir: &Path) -> Self {
        Self(dir.join(format!("{:032x}.part", rand::rng().random::<u128>())))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(path = %self.0.display(), error = %err, "cannot remove an upload");
            }
        }
    }
}

/// A body received into `tmp/`.
#[derive(Debug)]
pub(crate) struct Received {
    pub(crate) temp: Temp,
    pub(crate) size: u64,
    pub(crate) md5: [u8; 16],
    /// The checksums of the announced algorithms.
    pub(crate) computed: Checksum,
}

impl Received {
    /// The S3 ETag of a single upload: the MD5 in lowercase hex.
    pub(crate) fn etag(&self) -> String {
        hex(&self.md5)
    }
}

/// Lowercase hex digits of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The error with which an s3s body stream ended: its own S3 error (a chunk signature or the
/// payload hash did not match), or an incomplete body.
fn body_error(err: s3s::StdError) -> S3Error {
    match err.downcast::<S3Error>() {
        Ok(err) => *err,
        Err(err) => S3Error::with_source(S3ErrorCode::IncompleteBody, err),
    }
}

/// Receives `body` into a new synced file in `tmp/`, computing the MD5 and the checksums of
/// `algorithms`. A body announced larger than the free space is refused up front.
pub(crate) async fn receive(
    state: &S3State,
    body: StreamingBlob,
    content_length: Option<i64>,
    algorithms: &[&'static str],
) -> S3Result<Received> {
    let tmp_dir = state.fs().layout().tmp_dir();
    if let Some(length) = content_length.and_then(|length| u64::try_from(length).ok()) {
        let dir = tmp_dir.clone();
        let free = tokio::task::spawn_blocking(move || gono_server_dav::fs::free_space(&dir))
            .await
            .ok()
            .flatten();
        if free.is_some_and(|free| free < length) {
            return Err(s3_error!(
                ServiceUnavailable,
                "The server does not have room for this object"
            ));
        }
    }
    let temp = Temp::new_in(&tmp_dir);
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(temp.path()).await.map_err(error::io)?;

    let mut md5 = Md5::new();
    let mut hasher = ChecksumHasher::default();
    for algorithm in algorithms {
        enable(&mut hasher, algorithm);
    }
    let mut size: u64 = 0;
    let mut body = body;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(body_error)?;
        md5.update(&chunk);
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(error::io)?;
        size += chunk.len() as u64;
    }
    if let Some(length) = content_length
        && u64::try_from(length).ok() != Some(size)
    {
        return Err(s3_error!(IncompleteBody));
    }
    file.flush().await.map_err(error::io)?;
    file.sync_all().await.map_err(error::io)?;
    Ok(Received {
        temp,
        size,
        md5: md5.finalize(),
        computed: hasher.finalize(),
    })
}

/// Turns on `algorithm` in `hasher`.
pub(crate) fn enable(hasher: &mut ChecksumHasher, algorithm: &str) {
    match algorithm {
        "CRC32" => hasher.crc32 = Some(Default::default()),
        "CRC32C" => hasher.crc32c = Some(Default::default()),
        "CRC64NVME" => hasher.crc64nvme = Some(Default::default()),
        "SHA1" => hasher.sha1 = Some(Default::default()),
        "SHA256" => hasher.sha256 = Some(Default::default()),
        "SHA512" => hasher.sha512 = Some(Default::default()),
        "MD5" => hasher.md5 = Some(Default::default()),
        "XXHASH64" => hasher.xxhash64 = Some(Default::default()),
        "XXHASH3" => hasher.xxhash3 = Some(Default::default()),
        _ => hasher.xxhash128 = Some(Default::default()),
    }
}

/// The `Content-MD5` of a request: the parsed value, or the header as sent when s3s dropped it
/// (it drops an empty one, which must be refused as `InvalidDigest`).
pub(crate) fn content_md5<'a>(headers: &'a HeaderMap, parsed: Option<&'a str>) -> Option<&'a str> {
    parsed.or_else(|| {
        headers
            .get(http::header::HeaderName::from_static("content-md5"))
            .map(|value| value.to_str().unwrap_or("?"))
    })
}

/// The `Content-Encoding` to store with an object: without `aws-chunked`, which only describes
/// how the request carried the body (S3 removes it too); `None` if nothing is left.
pub(crate) fn stored_content_encoding(value: Option<String>) -> Option<String> {
    let value = value?;
    let kept: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("aws-chunked"))
        .collect();
    (!kept.is_empty()).then(|| kept.join(", "))
}

/// Compares what a client announced with what arrived: `Content-MD5` (base64) and every
/// claimed checksum. Returns the checksum to store with the object: the first claimed one in
/// [`ALGORITHMS`] order.
pub(crate) fn verify(
    received: &Received,
    content_md5: Option<&str>,
    claimed: &Checksum,
) -> S3Result<Option<meta::Checksum>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    if let Some(content_md5) = content_md5 {
        let expected = STANDARD
            .decode(content_md5.trim())
            .ok()
            .filter(|digest| digest.len() == 16)
            .ok_or_else(|| s3_error!(InvalidDigest))?;
        if expected != received.md5 {
            return Err(s3_error!(
                BadDigest,
                "The Content-MD5 you specified did not match what we received"
            ));
        }
    }
    let mut stored = None;
    for (algorithm, _) in ALGORITHMS {
        let Some(expected) = field(claimed, algorithm) else {
            continue;
        };
        if field(&received.computed, algorithm).as_ref() != Some(expected) {
            return Err(S3Error::with_message(
                S3ErrorCode::BadDigest,
                format!("The {algorithm} checksum you specified did not match what we received"),
            ));
        }
        stored.get_or_insert_with(|| meta::Checksum {
            algorithm: algorithm.to_owned(),
            value: expected.clone(),
            composite: false,
        });
    }
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_chunked_is_not_stored_as_a_content_encoding() {
        let stored = |value: &str| stored_content_encoding(Some(value.to_owned()));
        assert_eq!(stored("gzip").as_deref(), Some("gzip"));
        assert_eq!(stored("deflate, gzip").as_deref(), Some("deflate, gzip"));
        assert_eq!(stored("gzip, aws-chunked").as_deref(), Some("gzip"));
        assert_eq!(stored("aws-chunked,gzip").as_deref(), Some("gzip"));
        assert_eq!(stored("aws-chunked"), None);
        assert_eq!(stored("AWS-CHUNKED, aws-chunked"), None);
        assert_eq!(stored_content_encoding(None), None);
    }

    #[test]
    fn content_md5_must_be_a_base64_md5() {
        let content = received(b"hello", &[]);
        let none = Checksum::default();
        let code = |value: &str| {
            verify(&content, Some(value), &none)
                .unwrap_err()
                .code()
                .clone()
        };
        // Empty, not base64, or not 16 bytes: the header itself is wrong.
        assert_eq!(code(""), S3ErrorCode::InvalidDigest);
        assert_eq!(code("not base64!"), S3ErrorCode::InvalidDigest);
        assert_eq!(code("aGVsbG8="), S3ErrorCode::InvalidDigest);
        // A well-formed MD5 of other content: the body is wrong.
        assert_eq!(code("1B2M2Y8AsgTpgAmY7PhCfg=="), S3ErrorCode::BadDigest);
        assert!(verify(&content, Some("XUFAKrxLKna5cZ2REBfFkg=="), &none).is_ok());
        // An empty header, which s3s drops, still reaches the check.
        let mut headers = HeaderMap::new();
        headers.insert("content-md5", http::HeaderValue::from_static(""));
        assert_eq!(content_md5(&headers, None), Some(""));
        assert_eq!(content_md5(&HeaderMap::new(), None), None);
    }

    fn received(content: &[u8], algorithms: &[&str]) -> Received {
        let mut hasher = ChecksumHasher::default();
        for algorithm in algorithms {
            enable(&mut hasher, algorithm);
        }
        hasher.update(content);
        Received {
            temp: Temp(PathBuf::from("/nonexistent/upload.part")),
            size: content.len() as u64,
            md5: Md5::checksum(content),
            computed: hasher.finalize(),
        }
    }

    #[test]
    fn content_md5_and_checksums_are_compared() {
        let ok = received(b"hello", &["CRC32"]);
        assert_eq!(ok.etag(), "5d41402abc4b2a76b9719d911017c592");
        // base64 of the MD5 of "hello".
        assert!(verify(&ok, Some("XUFAKrxLKna5cZ2REBfFkg=="), &Checksum::default()).is_ok());
        assert_eq!(
            verify(&ok, Some("AAAAAAAAAAAAAAAAAAAAAA=="), &Checksum::default())
                .unwrap_err()
                .code(),
            &S3ErrorCode::BadDigest
        );
        assert_eq!(
            verify(&ok, Some("not base64"), &Checksum::default())
                .unwrap_err()
                .code(),
            &S3ErrorCode::InvalidDigest
        );

        let mut claimed = Checksum {
            checksum_crc32: ok.computed.checksum_crc32.clone(),
            ..Checksum::default()
        };
        let stored = verify(&ok, None, &claimed).unwrap().unwrap();
        assert_eq!(stored.algorithm, "CRC32");
        claimed.checksum_crc32 = Some("AAAAAA==".into());
        assert_eq!(
            verify(&ok, None, &claimed).unwrap_err().code(),
            &S3ErrorCode::BadDigest
        );
    }

    #[test]
    fn announced_algorithms_come_from_values_headers_and_trailers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-trailer", "x-amz-checksum-crc64nvme".parse().unwrap());
        let claimed = Checksum {
            checksum_sha256: Some("x".into()),
            ..Checksum::default()
        };
        assert_eq!(
            announced(&claimed, Some("crc32c"), &headers),
            ["CRC32C", "CRC64NVME", "SHA256"]
        );
        let mut trailers = HeaderMap::new();
        trailers.insert("x-amz-checksum-crc64nvme", "AAAA".parse().unwrap());
        let mut claimed = Checksum::default();
        apply_trailers(&mut claimed, Some(&trailers)).unwrap();
        assert_eq!(claimed.checksum_crc64nvme.as_deref(), Some("AAAA"));
    }

    #[test]
    fn mtime_metadata_names_unix_seconds() {
        use std::time::{Duration, UNIX_EPOCH};
        let mtime = |value: &str| {
            mtime_of(&meta::ObjectMeta {
                user_meta: [("mtime".to_owned(), value.to_owned())].into(),
                ..meta::ObjectMeta::default()
            })
        };
        assert_eq!(
            mtime("1700000000"),
            Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );
        // rclone: nanoseconds as a fraction.
        assert_eq!(
            mtime("1700000000.123456789"),
            Some(UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789))
        );
        assert_eq!(
            mtime(" 1700000000.5 "),
            Some(UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000))
        );
        for ignored in [
            "",
            "0",
            "-1",
            "1e9",
            "abc",
            ".5",
            "1700000000.1234567891",
            "2023-11-14T22:13:20Z",
            "999999999999",
        ] {
            assert_eq!(mtime(ignored), None, "{ignored:?}");
        }
        assert_eq!(mtime_of(&meta::ObjectMeta::default()), None);
    }

    #[test]
    fn stored_checksums_are_returned_under_their_algorithm() {
        let checksum = stored_checksum(Some(&meta::Checksum {
            algorithm: "CRC32C".into(),
            value: "v".into(),
            composite: false,
        }));
        assert_eq!(checksum.checksum_crc32c.as_deref(), Some("v"));
        assert_eq!(checksum.checksum_crc32, None);
        assert_eq!(stored_checksum(None), Checksum::default());
    }
}
