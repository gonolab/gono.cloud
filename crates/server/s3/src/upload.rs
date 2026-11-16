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
    dto::{Checksum, StreamingBlob},
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

/// A checksum stored with an object, as returned in a response.
pub(crate) fn stored_checksum(stored: Option<&meta::Checksum>) -> Checksum {
    let mut checksum = Checksum::default();
    if let Some(stored) = stored
        && let Some((algorithm, _)) = ALGORITHMS
            .iter()
            .find(|(algorithm, _)| *algorithm == stored.algorithm)
    {
        *field_mut(&mut checksum, algorithm) = Some(stored.value.clone());
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

fn enable(hasher: &mut ChecksumHasher, algorithm: &str) {
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
            .map_err(|_| s3_error!(InvalidDigest))?;
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
        });
    }
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn stored_checksums_are_returned_under_their_algorithm() {
        let checksum = stored_checksum(Some(&meta::Checksum {
            algorithm: "CRC32C".into(),
            value: "v".into(),
        }));
        assert_eq!(checksum.checksum_crc32c.as_deref(), Some("v"));
        assert_eq!(checksum.checksum_crc32, None);
        assert_eq!(stored_checksum(None), Checksum::default());
    }
}
