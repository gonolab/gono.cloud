//! The S3 API, driven by the AWS SDK as it ships (SigV4, default CRC32 checksums in
//! `aws-chunked` trailers, presigned URLs), plus plain HTTP for anonymous requests.
//!
//! Needs, besides the usual `GONO_ACCEPT_*` variables:
//!
//! - `GONO_ACCEPT_S3_ENDPOINT`: the S3 endpoint, e.g. `http://127.0.0.1:16104`;
//! - `GONO_ACCEPT_S3_ACCESS_KEY` / `GONO_ACCEPT_S3_SECRET_KEY`: a key of `GONO_ACCEPT_USER` with
//!   full access to every bucket;
//! - `GONO_ACCEPT_S3_BUCKET`: a bucket of that user that honors object ACLs (`acl`), bound to
//!   the folder `Buckets/<name>`;
//! - `GONO_ACCEPT_S3_PUBLIC_BUCKET`: a bucket that is `public-read` with anonymous listing;
//! - `GONO_ACCEPT_S3_VIRTUAL_HOST_DOMAIN` (optional): the server's `s3.virtual_host_domain`;
//!   requests to `<bucket>.<domain>` are sent to the endpoint's address, so no DNS is needed;
//! - a server with `s3.allow_anonymous = true`.
//!
//! Every test works below its own random key prefix and deletes what it wrote.

use std::time::Duration;

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    presigning::PresigningConfig,
    primitives::{ByteStream, DateTime, DateTimeFormat},
    types::{
        BucketCannedAcl, ChecksumAlgorithm, ChecksumMode, ChecksumType, CompletedMultipartUpload,
        CompletedPart, CorsConfiguration, CorsRule, ObjectAttributes, ObjectCannedAcl,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gono_acceptance::{Cred, Ctx, require, skip, unique_name};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct S3 {
    client: Client,
    access_key: String,
    secret_key: String,
    endpoint: String,
    bucket: String,
    public_bucket: Option<String>,
    http: reqwest::Client,
    ctx: Ctx,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn client(endpoint: &str, access_key: &str, secret_key: &str) -> Client {
    client_with_style(endpoint, access_key, secret_key, true)
}

fn client_with_style(
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    path_style: bool,
) -> Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .force_path_style(path_style)
        .credentials_provider(Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "acceptance",
        ))
        .build();
    Client::from_conf(config)
}

impl S3 {
    fn new() -> Option<S3> {
        let ctx = Ctx::bare()?;
        let Some(endpoint) = env("GONO_ACCEPT_S3_ENDPOINT") else {
            skip("GONO_ACCEPT_S3_ENDPOINT is not set; the S3 tests are skipped");
            return None;
        };
        let (Some(access_key), Some(secret_key), Some(bucket)) = (
            env("GONO_ACCEPT_S3_ACCESS_KEY"),
            env("GONO_ACCEPT_S3_SECRET_KEY"),
            env("GONO_ACCEPT_S3_BUCKET"),
        ) else {
            skip("GONO_ACCEPT_S3_ACCESS_KEY, _SECRET_KEY or _BUCKET is not set");
            return None;
        };
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        Some(S3 {
            client: client(&endpoint, &access_key, &secret_key),
            access_key,
            secret_key,
            endpoint,
            bucket,
            public_bucket: env("GONO_ACCEPT_S3_PUBLIC_BUCKET"),
            http: ctx.http.clone(),
            ctx,
        })
    }

    /// A key below a prefix of this test.
    fn key(&self, prefix: &str, rest: &str) -> String {
        format!("{prefix}/{rest}")
    }

    /// The URL of an object for plain HTTP requests.
    fn url(&self, bucket: &str, key: &str) -> String {
        format!("{}/{bucket}/{key}", self.endpoint)
    }

    async fn put(&self, bucket: &str, key: &str, body: &str) {
        self.client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(body.as_bytes().to_vec()))
            .send()
            .await
            .unwrap_or_else(|err| panic!("put {key}: {err:?}"));
    }

    async fn get(&self, bucket: &str, key: &str) -> Vec<u8> {
        self.client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .unwrap_or_else(|err| panic!("get {key}: {err:?}"))
            .body
            .collect()
            .await
            .unwrap()
            .to_vec()
    }

    /// Deletes everything below `prefix` in `bucket`, and the folder the prefix became.
    async fn clean(&self, bucket: &str, prefix: &str) {
        let listed = self
            .client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(format!("{prefix}/"))
            .send()
            .await;
        if let Ok(listed) = listed {
            for object in listed.contents() {
                if let Some(key) = object.key() {
                    let _ = self
                        .client
                        .delete_object()
                        .bucket(bucket)
                        .key(key)
                        .send()
                        .await;
                }
            }
        }
        let _ = self
            .client
            .delete_object()
            .bucket(bucket)
            .key(format!("{prefix}/"))
            .send()
            .await;
    }

    fn webdav_path(&self, key: &str) -> String {
        format!("Buckets/{}/{key}", self.bucket)
    }
}

#[tokio::test]
async fn objects_round_trip_with_their_metadata() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let key = s3.key(&prefix, "notes/hello.txt");
    let put = s3
        .client
        .put_object()
        .bucket(&s3.bucket)
        .key(&key)
        .content_type("text/plain; charset=utf-8")
        .cache_control("max-age=60")
        .metadata("mtime", "1700000000.5")
        .body(ByteStream::from_static(b"hello s3"))
        .send()
        .await
        .unwrap();
    // The ETag of a single upload is the MD5 of the content.
    assert_eq!(put.e_tag(), Some("\"b60d991fa6dbd33863c7cec70d15dbac\""));

    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(8));
    assert_eq!(head.content_type(), Some("text/plain; charset=utf-8"));
    assert_eq!(head.cache_control(), Some("max-age=60"));
    assert_eq!(
        head.metadata()
            .and_then(|meta| meta.get("mtime"))
            .map(String::as_str),
        Some("1700000000.5")
    );
    assert_eq!(s3.get(&s3.bucket, &key).await, b"hello s3");

    let range = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .range("bytes=6-")
        .send()
        .await
        .unwrap();
    assert_eq!(range.content_range(), Some("bytes 6-7/8"));
    assert_eq!(range.body.collect().await.unwrap().to_vec(), b"s3");

    s3.client
        .delete_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    let gone = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await;
    assert!(gone.is_err(), "deleted objects are gone");
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn listings_page_through_keys_and_common_prefixes() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    for rest in ["a-b", "a/1", "a/2", "a0", "c d+e"] {
        s3.put(&s3.bucket, &s3.key(&prefix, rest), rest).await;
    }

    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let page = s3
            .client
            .list_objects_v2()
            .bucket(&s3.bucket)
            .prefix(format!("{prefix}/"))
            .delimiter("/")
            .max_keys(2)
            .set_continuation_token(token.clone())
            .send()
            .await
            .unwrap();
        for object in page.contents() {
            seen.push(object.key().unwrap().to_owned());
        }
        for common in page.common_prefixes() {
            seen.push(format!("{}*", common.prefix().unwrap()));
        }
        if page.is_truncated() != Some(true) {
            break;
        }
        token = page.next_continuation_token().map(str::to_owned);
    }
    seen.sort();
    let expected: Vec<String> = ["a-b", "a/*", "a0", "c d+e"]
        .iter()
        .map(|rest| s3.key(&prefix, rest))
        .collect();
    assert_eq!(seen, expected);

    // The v1 listing, with url encoding (as the AWS CLI asks for it).
    let v1 = s3
        .client
        .list_objects()
        .bucket(&s3.bucket)
        .prefix(format!("{prefix}/c"))
        .encoding_type(aws_sdk_s3::types::EncodingType::Url)
        .send()
        .await
        .unwrap();
    assert_eq!(v1.contents().len(), 1);

    // Version listings: versioning is never enabled, so every object is its only version,
    // `null`, as in an S3 bucket that never had versioning. Cleanup tools page through them.
    let mut seen = Vec::new();
    let mut markers: (Option<String>, Option<String>) = (None, None);
    loop {
        let page = s3
            .client
            .list_object_versions()
            .bucket(&s3.bucket)
            .prefix(format!("{prefix}/"))
            .delimiter("/")
            .max_keys(2)
            .set_key_marker(markers.0.clone())
            .set_version_id_marker(markers.1.clone())
            .send()
            .await
            .unwrap();
        assert!(page.delete_markers().is_empty());
        for version in page.versions() {
            assert_eq!(version.version_id(), Some("null"));
            assert_eq!(version.is_latest(), Some(true));
            assert!(version.owner().is_some());
            seen.push(version.key().unwrap().to_owned());
        }
        for common in page.common_prefixes() {
            seen.push(format!("{}*", common.prefix().unwrap()));
        }
        if page.is_truncated() != Some(true) {
            break;
        }
        markers = (
            page.next_key_marker().map(str::to_owned),
            page.next_version_id_marker().map(str::to_owned),
        );
    }
    seen.sort();
    assert_eq!(seen, expected);
    // A version id marker needs a key marker.
    let err = s3
        .client
        .list_object_versions()
        .bucket(&s3.bucket)
        .version_id_marker("null")
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        err.raw_response()
            .map(|response| response.status().as_u16()),
        Some(400)
    );
    // Deleting the `null` version deletes the object.
    s3.client
        .delete_object()
        .bucket(&s3.bucket)
        .key(s3.key(&prefix, "a0"))
        .version_id("null")
        .send()
        .await
        .unwrap();
    let after = s3
        .client
        .list_object_versions()
        .bucket(&s3.bucket)
        .prefix(s3.key(&prefix, "a0"))
        .send()
        .await
        .unwrap();
    assert!(after.versions().is_empty());
    // Anonymous version listings follow the listing switch, like other listings.
    let anonymous = s3
        .http
        .get(format!("{}/{}?versions", s3.endpoint, s3.bucket))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 403);
    if let Some(public_bucket) = &s3.public_bucket {
        let anonymous = s3
            .http
            .get(format!("{}/{public_bucket}?versions", s3.endpoint))
            .send()
            .await
            .unwrap();
        assert_eq!(anonymous.status(), 200);
    }
    s3.clean(&s3.bucket, &prefix).await;
    for rest in ["a/1", "a/2"] {
        let _ = s3
            .client
            .delete_object()
            .bucket(&s3.bucket)
            .key(s3.key(&prefix, rest))
            .send()
            .await;
    }
}

#[tokio::test]
async fn multipart_uploads_assemble_their_parts() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let key = s3.key(&prefix, "big.bin");
    let part1: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let part2 = b"the end".to_vec();
    let upload = s3
        .client
        .create_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .content_type("application/x-test")
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let mut parts = Vec::new();
    for (number, body) in [(1, part1.clone()), (2, part2.clone())] {
        let uploaded = s3
            .client
            .upload_part()
            .bucket(&s3.bucket)
            .key(&key)
            .upload_id(id)
            .part_number(number)
            .body(ByteStream::from(body))
            .send()
            .await
            .unwrap();
        parts.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(uploaded.e_tag().unwrap())
                .build(),
        );
    }
    let listed = s3
        .client
        .list_parts()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.parts().len(), 2);
    let done = s3
        .client
        .complete_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts.clone()))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(
        done.e_tag().unwrap().ends_with("-2\""),
        "{:?}",
        done.e_tag()
    );
    // A client that lost the answer and completes again gets the same one, as from S3; the
    // upload takes no parts any more.
    let again = s3
        .client
        .complete_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts.clone()))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(again.e_tag(), done.e_tag());
    let late_part = s3
        .client
        .upload_part()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .part_number(3)
        .body(ByteStream::from_static(b"late"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        late_part.raw_response().map(|r| r.status().as_u16()),
        Some(404)
    );
    let other_parts = s3
        .client
        .complete_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts[..1].to_vec()))
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        other_parts.raw_response().map(|r| r.status().as_u16()),
        Some(400)
    );

    // A completion that may only create the object fails with a real 412 when the key exists,
    // before the answer starts.
    let conditional = s3
        .client
        .create_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    let conditional_id = conditional.upload_id().unwrap();
    let small = s3
        .client
        .upload_part()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(conditional_id)
        .part_number(1)
        .body(ByteStream::from_static(b"small"))
        .send()
        .await
        .unwrap();
    let refused = s3
        .client
        .complete_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(conditional_id)
        .if_none_match("*")
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(
                    CompletedPart::builder()
                        .part_number(1)
                        .e_tag(small.e_tag().unwrap())
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        refused.raw_response().map(|r| r.status().as_u16()),
        Some(412)
    );
    s3.client
        .abort_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(conditional_id)
        .send()
        .await
        .unwrap();
    let mut expected = part1;
    expected.extend_from_slice(&part2);
    assert_eq!(s3.get(&s3.bucket, &key).await, expected);
    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_type(), Some("application/x-test"));

    // An aborted upload is gone.
    let aborted = s3
        .client
        .create_multipart_upload()
        .bucket(&s3.bucket)
        .key(s3.key(&prefix, "aborted"))
        .send()
        .await
        .unwrap();
    s3.client
        .abort_multipart_upload()
        .bucket(&s3.bucket)
        .key(s3.key(&prefix, "aborted"))
        .upload_id(aborted.upload_id().unwrap())
        .send()
        .await
        .unwrap();
    let uploads = s3
        .client
        .list_multipart_uploads()
        .bucket(&s3.bucket)
        .prefix(format!("{prefix}/"))
        .send()
        .await
        .unwrap();
    assert!(uploads.uploads().is_empty());
    s3.clean(&s3.bucket, &prefix).await;
}

/// Details that Ceph's s3-tests found to differ from S3.
#[tokio::test]
async fn requests_and_answers_follow_s3_in_the_details() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");

    // A Content-MD5 that is no MD5 is the header's fault (InvalidDigest), not the body's.
    let err = s3
        .client
        .put_object()
        .bucket(&s3.bucket)
        .key(s3.key(&prefix, "md5"))
        .content_md5("aGVsbG8=")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        err.as_service_error().and_then(|e| e.meta().code()),
        Some("InvalidDigest")
    );

    // `aws-chunked` describes the request, not the object.
    let key = s3.key(&prefix, "encoded");
    s3.client
        .put_object()
        .bucket(&s3.bucket)
        .key(&key)
        .content_encoding("gzip, aws-chunked")
        .body(ByteStream::from_static(b"zzz"))
        .send()
        .await
        .unwrap();
    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_encoding(), Some("gzip"));

    // A 304 names the version the client holds.
    let etag = head.e_tag().unwrap().to_owned();
    let not_modified = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .if_none_match(&etag)
        .send()
        .await
        .unwrap_err();
    let raw = not_modified.raw_response().unwrap();
    assert_eq!(raw.status().as_u16(), 304);
    assert_eq!(raw.headers().get("etag"), Some(etag.as_str()));
    assert!(raw.headers().get("last-modified").is_some());

    // Listings: no keys asked for, nothing truncated; an empty delimiter is no delimiter.
    s3.put(&s3.bucket, &s3.key(&prefix, "dir/a"), "a").await;
    let zero = s3
        .client
        .list_objects_v2()
        .bucket(&s3.bucket)
        .prefix(format!("{prefix}/"))
        .max_keys(0)
        .send()
        .await
        .unwrap();
    assert_eq!(zero.is_truncated(), Some(false));
    assert!(zero.contents().is_empty());
    let flat = s3
        .client
        .list_objects()
        .bucket(&s3.bucket)
        .prefix(format!("{prefix}/"))
        .delimiter("")
        .send()
        .await
        .unwrap();
    assert_eq!(flat.delimiter(), None);
    assert!(flat.common_prefixes().is_empty());
    assert_eq!(flat.contents().len(), 2);
    assert_eq!(flat.marker(), Some(""));

    // A canned ACL that does not exist is the client's mistake (400), unlike an existing one
    // that is not supported (501).
    let bad = s3
        .client
        .put_object_acl()
        .bucket(&s3.bucket)
        .key(&key)
        .acl(ObjectCannedAcl::from("public-ready"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(bad.raw_response().map(|r| r.status().as_u16()), Some(400));
    let unsupported = s3
        .client
        .put_object_acl()
        .bucket(&s3.bucket)
        .key(&key)
        .acl(ObjectCannedAcl::AuthenticatedRead)
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        unsupported.raw_response().map(|r| r.status().as_u16()),
        Some(501)
    );
    s3.clean(&s3.bucket, &prefix).await;
    let _ = s3
        .client
        .delete_object()
        .bucket(&s3.bucket)
        .key(s3.key(&prefix, "dir/a"))
        .send()
        .await;
}

#[tokio::test]
async fn copies_and_conditional_writes() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let source = s3.key(&prefix, "source.txt");
    s3.put(&s3.bucket, &source, "original").await;
    s3.client
        .copy_object()
        .bucket(&s3.bucket)
        .key(s3.key(&prefix, "copy.txt"))
        .copy_source(format!("{}/{source}", s3.bucket))
        .send()
        .await
        .unwrap();
    assert_eq!(
        s3.get(&s3.bucket, &s3.key(&prefix, "copy.txt")).await,
        b"original"
    );

    let lock = s3.key(&prefix, "lock");
    let create = |body: &'static str| {
        s3.client
            .put_object()
            .bucket(&s3.bucket)
            .key(&lock)
            .if_none_match("*")
            .body(ByteStream::from_static(body.as_bytes()))
            .send()
    };
    create("first").await.unwrap();
    let second = create("second").await;
    assert!(second.is_err(), "If-None-Match: * never replaces");
    assert_eq!(s3.get(&s3.bucket, &lock).await, b"first");
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn presigned_urls_work_without_credentials() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let key = s3.key(&prefix, "shared.txt");
    let presign = PresigningConfig::expires_in(Duration::from_secs(300)).unwrap();
    let put = s3
        .client
        .put_object()
        .bucket(&s3.bucket)
        .key(&key)
        .presigned(presign.clone())
        .await
        .unwrap();
    let response = s3
        .http
        .put(put.uri())
        .body("presigned body")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    let get = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .presigned(presign)
        .await
        .unwrap();
    let response = s3.http.get(get.uri()).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "presigned body");
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn anonymous_requests_read_only_what_is_published() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let private = s3.key(&prefix, "private.txt");
    let public = s3.key(&prefix, "public.html");
    s3.put(&s3.bucket, &private, "secret").await;
    s3.client
        .put_object()
        .bucket(&s3.bucket)
        .key(&public)
        .acl(ObjectCannedAcl::PublicRead)
        .content_type("text/html")
        .body(ByteStream::from_static(b"<p>hi</p>"))
        .send()
        .await
        .unwrap();

    let get = |url: String| s3.http.get(url).send();
    let response = get(s3.url(&s3.bucket, &public)).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    // Private objects, missing ones, listings and writes are all refused alike.
    for url in [
        s3.url(&s3.bucket, &private),
        s3.url(&s3.bucket, &s3.key(&prefix, "missing")),
        format!("{}/{}?list-type=2", s3.endpoint, s3.bucket),
    ] {
        assert_eq!(get(url.clone()).await.unwrap().status(), 403, "{url}");
    }
    let write = s3
        .http
        .put(s3.url(&s3.bucket, &s3.key(&prefix, "anonymous.txt")))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(write.status(), 403);

    if let Some(public_bucket) = &s3.public_bucket {
        let key = s3.key(&prefix, "everyone.txt");
        s3.put(public_bucket, &key, "everyone").await;
        assert_eq!(
            get(s3.url(public_bucket, &key)).await.unwrap().status(),
            200
        );
        let listing = get(format!(
            "{}/{public_bucket}?list-type=2&prefix={prefix}/",
            s3.endpoint
        ))
        .await
        .unwrap();
        assert_eq!(listing.status(), 200);
        assert!(listing.text().await.unwrap().contains("everyone.txt"));
        s3.clean(public_bucket, &prefix).await;
    } else {
        skip("GONO_ACCEPT_S3_PUBLIC_BUCKET is not set; the public bucket is not checked");
    }
    s3.clean(&s3.bucket, &prefix).await;
}

/// Keys need not be in NFC (file names from older macOS are NFD), while the tree's names are:
/// the file is stored under the NFC name and answers only to the key as it was written, which
/// listings return.
#[tokio::test]
async fn keys_keep_their_unicode_spelling() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let nfd = s3.key(&prefix, "Cafe\u{301}/a.txt");
    let nfc = s3.key(&prefix, "Caf\u{e9}/a.txt");
    s3.put(&s3.bucket, &nfd, "decomposed").await;

    let listed = s3
        .client
        .list_objects_v2()
        .bucket(&s3.bucket)
        .prefix(format!("{prefix}/"))
        .send()
        .await
        .unwrap();
    let keys: Vec<&str> = listed.contents().iter().filter_map(|o| o.key()).collect();
    assert_eq!(keys, [nfd.as_str()], "the bytes that were written");
    assert_eq!(s3.get(&s3.bucket, &nfd).await, b"decomposed");
    let other = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&nfc)
        .send()
        .await
        .unwrap_err();
    assert_eq!(other.raw_response().map(|r| r.status().as_u16()), Some(404));

    // The other spelling cannot be stored next to it, neither the file nor in its folder.
    for key in [nfc.clone(), s3.key(&prefix, "Caf\u{e9}/b.txt")] {
        let conflict = s3
            .client
            .put_object()
            .bucket(&s3.bucket)
            .key(&key)
            .body(ByteStream::from_static(b"composed"))
            .send()
            .await
            .unwrap_err();
        assert_eq!(
            conflict.raw_response().map(|r| r.status().as_u16()),
            Some(409),
            "{key}"
        );
    }

    // A multipart upload of the other spelling fails at its completion, after the parts were
    // assembled, and stays complete-able: its first part was put back.
    let upload = s3
        .client
        .create_multipart_upload()
        .bucket(&s3.bucket)
        .key(&nfc)
        .send()
        .await
        .unwrap();
    let upload_id = upload.upload_id().unwrap();
    let mut parts = Vec::new();
    for (number, body) in [(1, vec![b'a'; 5 * 1024 * 1024]), (2, b"tail".to_vec())] {
        let uploaded = s3
            .client
            .upload_part()
            .bucket(&s3.bucket)
            .key(&nfc)
            .upload_id(upload_id)
            .part_number(number)
            .body(ByteStream::from(body))
            .send()
            .await
            .unwrap();
        parts.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(uploaded.e_tag().unwrap())
                .build(),
        );
    }
    let complete = || {
        s3.client
            .complete_multipart_upload()
            .bucket(&s3.bucket)
            .key(&nfc)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts.clone()))
                    .build(),
            )
            .send()
    };
    let refused = complete().await.unwrap_err();
    assert_eq!(
        refused.as_service_error().and_then(|e| e.meta().code()),
        Some("KeyConflict")
    );
    assert_eq!(s3.get(&s3.bucket, &nfd).await, b"decomposed");

    // WebDAV and the Nextcloud clients see the NFC name.
    let dav = s3.ctx.dav();
    let got = dav.get(&s3.webdav_path(&nfc)).await;
    got.expect(&[200]);
    assert_eq!(got.text(), "decomposed");

    // Deleting the other spelling deletes nothing; deleting the key deletes the file.
    s3.client
        .delete_object()
        .bucket(&s3.bucket)
        .key(&nfc)
        .send()
        .await
        .unwrap();
    assert_eq!(s3.get(&s3.bucket, &nfd).await, b"decomposed");
    s3.client
        .delete_object()
        .bucket(&s3.bucket)
        .key(&nfd)
        .send()
        .await
        .unwrap();
    dav.get(&s3.webdav_path(&nfc)).await.expect(&[404]);

    // With the place free, the same completion succeeds and the object is whole.
    complete().await.unwrap();
    let mut expected = vec![b'a'; 5 * 1024 * 1024];
    expected.extend_from_slice(b"tail");
    assert_eq!(s3.get(&s3.bucket, &nfc).await, expected);
    s3.client
        .delete_object()
        .bucket(&s3.bucket)
        .key(&nfc)
        .send()
        .await
        .unwrap();
    let _ = dav.delete(&s3.webdav_path(&prefix)).await;
}

#[tokio::test]
async fn webdav_and_s3_see_the_same_files() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let dav = s3.ctx.dav();
    let key = s3.key(&prefix, "from-s3.txt");
    s3.put(&s3.bucket, &key, "via s3").await;
    let got = dav.get(&s3.webdav_path(&key)).await;
    got.expect(&[200]);
    assert_eq!(got.text(), "via s3");

    // A WebDAV overwrite is what S3 serves afterwards, and it drops the public ACL.
    s3.client
        .put_object_acl()
        .bucket(&s3.bucket)
        .key(&key)
        .acl(ObjectCannedAcl::PublicRead)
        .send()
        .await
        .unwrap();
    assert_eq!(
        s3.http
            .get(s3.url(&s3.bucket, &key))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    dav.put(&s3.webdav_path(&key), "via webdav")
        .await
        .expect_success();
    assert_eq!(s3.get(&s3.bucket, &key).await, b"via webdav");
    // Its S3 ETag is the MD5 of the content, which the WebDAV upload recorded.
    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(head.e_tag(), Some("\"0ada0323b9d8bbfacb2b3334b7daf605\""));
    assert_eq!(
        s3.http
            .get(s3.url(&s3.bucket, &key))
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "an overwritten public object is private again"
    );
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn wrong_credentials_are_refused() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let unknown = client(
        &s3.endpoint,
        "GONOAAAAAAAAAAAAAAAA",
        "x".repeat(40).as_str(),
    );
    let err = unknown.list_buckets().send().await.unwrap_err();
    assert!(format!("{err:?}").contains("InvalidAccessKeyId"), "{err:?}");

    let access_key = env("GONO_ACCEPT_S3_ACCESS_KEY").unwrap();
    let wrong_secret = client(&s3.endpoint, &access_key, "y".repeat(40).as_str());
    let err = wrong_secret.list_buckets().send().await.unwrap_err();
    assert!(
        format!("{err:?}").contains("SignatureDoesNotMatch"),
        "{err:?}"
    );

    // The secret is no app password, and an app password signs nothing.
    let secret = env("GONO_ACCEPT_S3_SECRET_KEY").unwrap();
    let as_basic = s3.ctx.dav_as(&Cred::new(&s3.ctx.cfg.full.user, secret));
    as_basic.propfind("", "0", "").await.expect(&[401]);
    let as_key = client(
        &s3.endpoint,
        &s3.ctx.cfg.full.user,
        &s3.ctx.cfg.full.password,
    );
    assert!(as_key.list_buckets().send().await.is_err());

    let buckets = s3.client.list_buckets().send().await.unwrap();
    assert!(
        buckets
            .buckets()
            .iter()
            .any(|bucket| bucket.name() == Some(s3.bucket.as_str()))
    );
}

#[tokio::test]
async fn virtual_hosted_style_names_the_bucket_in_the_host() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let Some(domain) = env("GONO_ACCEPT_S3_VIRTUAL_HOST_DOMAIN") else {
        skip("GONO_ACCEPT_S3_VIRTUAL_HOST_DOMAIN is not set; virtual-hosted style is not checked");
        return;
    };
    let endpoint = url::Url::parse(&s3.endpoint).unwrap();
    let address = endpoint.socket_addrs(|| None).unwrap()[0];
    let port = endpoint.port_or_known_default().unwrap();
    // Every host name below the domain goes to the S3 listener.
    let mut http = reqwest::Client::builder().resolve(&domain, address);
    let missing = "no-such-bucket".to_owned();
    for bucket in [Some(&s3.bucket), s3.public_bucket.as_ref(), Some(&missing)]
        .into_iter()
        .flatten()
    {
        http = http.resolve(&format!("{bucket}.{domain}"), address);
    }
    let http = http.build().unwrap();
    let virtual_client = client_with_style(
        &format!("http://{domain}:{port}"),
        &s3.access_key,
        &s3.secret_key,
        false,
    );

    // Signed requests (presigned, so that the host name never needs DNS) sign the bucket's host.
    let prefix = unique_name("s3");
    let key = s3.key(&prefix, "virtual.txt");
    let presign = PresigningConfig::expires_in(Duration::from_secs(300)).unwrap();
    let put = virtual_client
        .put_object()
        .bucket(&s3.bucket)
        .key(&key)
        .presigned(presign.clone())
        .await
        .unwrap();
    assert!(
        put.uri()
            .starts_with(&format!("http://{}.{domain}:{port}/", s3.bucket)),
        "{}",
        put.uri()
    );
    let response = http.put(put.uri()).body("by host").send().await.unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    // Path style sees the same object.
    assert_eq!(s3.get(&s3.bucket, &key).await, b"by host");
    let get = virtual_client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .presigned(presign)
        .await
        .unwrap();
    let response = http.get(get.uri()).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "by host");

    // Anonymous downloads and listings by host name, and path style on the domain itself.
    if let Some(public_bucket) = &s3.public_bucket {
        let key = s3.key(&prefix, "everyone.txt");
        s3.put(public_bucket, &key, "everyone").await;
        for url in [
            format!("http://{public_bucket}.{domain}:{port}/{key}"),
            format!("http://{domain}:{port}/{public_bucket}/{key}"),
        ] {
            let response = http.get(&url).send().await.unwrap();
            assert_eq!(response.status(), 200, "{url}");
            assert_eq!(response.text().await.unwrap(), "everyone", "{url}");
        }
        let listing = http
            .get(format!(
                "http://{public_bucket}.{domain}:{port}/?list-type=2&prefix={prefix}/"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(listing.status(), 200);
        let listing = listing.text().await.unwrap();
        assert!(
            listing.contains(&format!("<Name>{public_bucket}</Name>")),
            "{listing}"
        );
        assert!(listing.contains("everyone.txt"), "{listing}");
        s3.clean(public_bucket, &prefix).await;
    }
    // A bucket that does not exist is refused like any other.
    let response = http
        .get(format!("http://{missing}.{domain}:{port}/key"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn cors_rules_answer_browsers() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let key = s3.key(&prefix, "cors.txt");
    let app = "https://app.example";
    let object_url = s3.url(&s3.bucket, &key);
    let preflight = |origin: &str, method: &str, headers: &str| {
        s3.http
            .request(reqwest::Method::OPTIONS, &object_url)
            .header("origin", origin.to_owned())
            .header("access-control-request-method", method.to_owned())
            .header("access-control-request-headers", headers.to_owned())
            .send()
    };
    // Without rules, browsers may do nothing.
    let refused = preflight(app, "PUT", "content-type").await.unwrap();
    assert_eq!(refused.status(), 403);
    assert!(
        refused
            .text()
            .await
            .unwrap()
            .contains("<Code>AccessForbidden</Code>")
    );

    let rule = CorsRule::builder()
        .id("uploads")
        .allowed_origins(app)
        .allowed_methods("PUT")
        .allowed_methods("POST")
        .allowed_methods("GET")
        .allowed_headers("*")
        .expose_headers("ETag")
        .max_age_seconds(600)
        .build()
        .unwrap();
    s3.client
        .put_bucket_cors()
        .bucket(&s3.bucket)
        .cors_configuration(
            CorsConfiguration::builder()
                .cors_rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let stored = s3
        .client
        .get_bucket_cors()
        .bucket(&s3.bucket)
        .send()
        .await
        .unwrap();
    let stored = &stored.cors_rules()[0];
    assert_eq!(stored.id(), Some("uploads"));
    assert_eq!(stored.allowed_methods(), ["PUT", "POST", "GET"]);
    assert_eq!(stored.expose_headers(), ["ETag"]);
    assert_eq!(stored.max_age_seconds(), Some(600));

    // A preflight request needs no signature.
    let allowed = preflight(app, "PUT", "content-type, x-amz-date")
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);
    let header = |response: &reqwest::Response, name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(
        header(&allowed, "access-control-allow-origin").as_deref(),
        Some(app)
    );
    assert_eq!(
        header(&allowed, "access-control-allow-methods").as_deref(),
        Some("PUT, POST, GET")
    );
    assert_eq!(
        header(&allowed, "access-control-allow-headers").as_deref(),
        Some("content-type, x-amz-date")
    );
    assert_eq!(
        header(&allowed, "access-control-max-age").as_deref(),
        Some("600")
    );
    for (origin, method) in [("https://evil.example", "PUT"), (app, "DELETE")] {
        let refused = preflight(origin, method, "").await.unwrap();
        assert_eq!(refused.status(), 403, "{origin} {method}");
    }

    // The actual request gets the headers too, and the page may read the ETag.
    let presign = PresigningConfig::expires_in(Duration::from_secs(300)).unwrap();
    let put = s3
        .client
        .put_object()
        .bucket(&s3.bucket)
        .key(&key)
        .presigned(presign)
        .await
        .unwrap();
    let uploaded = s3
        .http
        .put(put.uri())
        .header("origin", app)
        .body("from a browser")
        .send()
        .await
        .unwrap();
    assert!(uploaded.status().is_success(), "{}", uploaded.status());
    assert_eq!(
        header(&uploaded, "access-control-allow-origin").as_deref(),
        Some(app)
    );
    assert_eq!(
        header(&uploaded, "access-control-expose-headers").as_deref(),
        Some("ETag")
    );
    // Even a refusal carries them, so that the page can read the error.
    let denied = s3
        .http
        .get(&object_url)
        .header("origin", app)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(
        header(&denied, "access-control-allow-origin").as_deref(),
        Some(app)
    );
    let other = s3
        .http
        .get(&object_url)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(header(&other, "access-control-allow-origin"), None);

    s3.client
        .delete_bucket_cors()
        .bucket(&s3.bucket)
        .send()
        .await
        .unwrap();
    let gone = s3.client.get_bucket_cors().bucket(&s3.bucket).send().await;
    let err = gone.unwrap_err().into_service_error();
    assert_eq!(err.meta().code(), Some("NoSuchCORSConfiguration"));
    assert_eq!(preflight(app, "PUT", "").await.unwrap().status(), 403);
    s3.clean(&s3.bucket, &prefix).await;
}

/// A `multipart/form-data` body with `fields` and then the file.
fn form_body(boundary: &str, fields: &[(&str, String)], file: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

impl S3 {
    /// The fields of a browser form upload into `bucket` below `prefix`, signed for this
    /// test's key with a policy of `conditions` plus the signature fields.
    fn signed_form(
        &self,
        bucket: &str,
        conditions: Vec<serde_json::Value>,
        fields: Vec<(&'static str, String)>,
    ) -> Vec<(&'static str, String)> {
        let now = std::time::SystemTime::now();
        let seconds = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let format = |seconds: u64| {
            DateTime::from_secs(i64::try_from(seconds).unwrap())
                .fmt(DateTimeFormat::DateTime)
                .unwrap()
        };
        let amz_date = format(seconds).replace(['-', ':'], "");
        let credential = format!(
            "{}/{}/us-east-1/s3/aws4_request",
            self.access_key,
            &amz_date[..8]
        );
        let mut conditions = conditions;
        conditions.push(serde_json::json!({ "bucket": bucket }));
        conditions.push(serde_json::json!({ "x-amz-algorithm": "AWS4-HMAC-SHA256" }));
        conditions.push(serde_json::json!({ "x-amz-credential": credential }));
        conditions.push(serde_json::json!({ "x-amz-date": amz_date }));
        let policy = serde_json::json!({
            "expiration": format(seconds + 600),
            "conditions": conditions,
        });
        let policy = STANDARD.encode(policy.to_string());
        let signing_key =
            aws_sigv4::sign::v4::generate_signing_key(&self.secret_key, now, "us-east-1", "s3");
        let signature = aws_sigv4::sign::v4::calculate_signature(signing_key, policy.as_bytes());
        let mut signed = fields;
        signed.push(("policy", policy));
        signed.push(("x-amz-algorithm", "AWS4-HMAC-SHA256".to_owned()));
        signed.push(("x-amz-credential", credential));
        signed.push(("x-amz-date", amz_date));
        signed.push(("x-amz-signature", signature));
        signed
    }

    async fn post_form(
        &self,
        bucket: &str,
        fields: &[(&str, String)],
        file: &[u8],
    ) -> reqwest::Response {
        let boundary = "gono-acceptance-boundary";
        self.http
            .post(format!("{}/{bucket}", self.endpoint))
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(form_body(boundary, fields, file))
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn browser_form_uploads_need_a_signed_policy() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let conditions = vec![
        serde_json::json!(["starts-with", "$key", format!("{prefix}/form/")]),
        serde_json::json!({ "acl": "public-read" }),
        serde_json::json!(["starts-with", "$Content-Type", "text/"]),
        serde_json::json!({ "success_action_status": "201" }),
        serde_json::json!(["content-length-range", 1, 64]),
    ];
    let fields = vec![
        ("key", format!("{prefix}/form/${{filename}}")),
        ("acl", "public-read".to_owned()),
        ("Content-Type", "text/plain".to_owned()),
        ("success_action_status", "201".to_owned()),
    ];
    let signed = s3.signed_form(&s3.bucket, conditions.clone(), fields.clone());
    let response = s3.post_form(&s3.bucket, &signed, b"posted by a form").await;
    assert_eq!(response.status(), 201);
    let body = response.text().await.unwrap();
    let key = s3.key(&prefix, "form/hello.txt");
    assert!(body.contains(&format!("<Key>{key}</Key>")), "{body}");
    // The ETag is the MD5 of the content.
    assert!(body.contains("db883b2ed4b7aa744af0ee014e91e3ba"), "{body}");
    assert_eq!(s3.get(&s3.bucket, &key).await, b"posted by a form");
    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_type(), Some("text/plain"));
    // The public-read ACL of the form applies: anyone may download it.
    let anonymous = s3.http.get(s3.url(&s3.bucket, &key)).send().await.unwrap();
    assert_eq!(anonymous.status(), 200);

    // The policy's limits hold.
    let too_large = s3.post_form(&s3.bucket, &signed, &[b'x'; 65]).await;
    assert_eq!(
        too_large.status(),
        400,
        "{}",
        too_large.text().await.unwrap()
    );
    let mut outside = signed.clone();
    outside[0].1 = "elsewhere/hello.txt".to_owned();
    let outside = s3.post_form(&s3.bucket, &outside, b"x").await;
    assert_eq!(outside.status(), 400);
    assert!(
        outside
            .text()
            .await
            .unwrap()
            .contains("<Code>InvalidPolicyDocument</Code>")
    );
    // A forged signature, and a form without any, are refused.
    let mut forged = signed.clone();
    let signature = forged
        .iter_mut()
        .find(|(name, _)| *name == "x-amz-signature")
        .unwrap();
    signature.1 = "0".repeat(64);
    let forged = s3.post_form(&s3.bucket, &forged, b"x").await;
    assert_eq!(forged.status(), 403);
    let unsigned = s3.post_form(&s3.bucket, &fields, b"x").await;
    assert_eq!(unsigned.status(), 403);
    assert!(unsigned.text().await.unwrap().contains("AccessDenied"));

    // A form whose length is unknown is refused before its file is read.
    let endpoint = url::Url::parse(&s3.endpoint).unwrap();
    let address = endpoint.socket_addrs(|| None).unwrap()[0];
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let boundary = "gono-acceptance-boundary";
    let body = form_body(boundary, &fields, b"x");
    let mut request = format!(
        "POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        s3.bucket,
        endpoint.authority(),
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    request.extend_from_slice(b"\r\n0\r\n\r\n");
    stream.write_all(&request).await.unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 411"), "{answer}");
    assert!(answer.contains("MissingContentLength"), "{answer}");
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn parts_can_be_copied_from_objects() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let big: Vec<u8> = (0..6 * 1024 * 1024).map(|i| (i % 253) as u8).collect();
    let big_key = s3.key(&prefix, "source.bin");
    s3.client
        .put_object()
        .bucket(&s3.bucket)
        .key(&big_key)
        .body(ByteStream::from(big.clone()))
        .send()
        .await
        .unwrap();
    let small_key = s3.key(&prefix, "tail.txt");
    s3.put(&s3.bucket, &small_key, "tail").await;
    let key = s3.key(&prefix, "assembled.bin");
    let upload = s3
        .client
        .create_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let source = |key: &str| format!("{}/{key}", s3.bucket);

    // A range of one object, then the whole of another.
    let first = s3
        .client
        .upload_part_copy()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .part_number(1)
        .copy_source(source(&big_key))
        .copy_source_range(format!("bytes=1-{}", 5 * 1024 * 1024))
        .send()
        .await
        .unwrap();
    let second = s3
        .client
        .upload_part_copy()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .part_number(2)
        .copy_source(source(&small_key))
        .send()
        .await
        .unwrap();
    // A part's ETag is the MD5 of its bytes: the whole small object has the same one.
    let small_etag = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&small_key)
        .send()
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_owned();
    assert_eq!(
        second.copy_part_result().unwrap().e_tag(),
        Some(small_etag.as_str())
    );

    // Conditions and ranges are checked.
    let stale = s3
        .client
        .upload_part_copy()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .part_number(3)
        .copy_source(source(&small_key))
        .copy_source_if_match("\"00000000000000000000000000000000\"")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(stale.meta().code(), Some("PreconditionFailed"));
    let outside = s3
        .client
        .upload_part_copy()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .part_number(3)
        .copy_source(source(&small_key))
        .copy_source_range("bytes=0-4")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(outside.meta().code(), Some("InvalidRange"));
    let missing = s3
        .client
        .upload_part_copy()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .part_number(3)
        .copy_source(source(&s3.key(&prefix, "missing")))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(missing.meta().code(), Some("NoSuchKey"));

    let parts = [first.copy_part_result(), second.copy_part_result()]
        .into_iter()
        .zip(1..)
        .map(|(result, number)| {
            CompletedPart::builder()
                .part_number(number)
                .e_tag(result.unwrap().e_tag().unwrap())
                .build()
        })
        .collect();
    s3.client
        .complete_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let mut expected = big[1..=5 * 1024 * 1024].to_vec();
    expected.extend_from_slice(b"tail");
    assert_eq!(s3.get(&s3.bucket, &key).await, expected);
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn the_download_policy_publishes_a_bucket() {
    let s3 = require!(S3::new(), "S3 is not configured");
    // A bucket of its own: the policy changes what the whole bucket publishes.
    let bucket = format!(
        "policy-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    s3.client
        .create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
    s3.put(&bucket, "a.txt", "published").await;
    let anonymous = |url: String| s3.http.get(url).send();
    let object = s3.url(&bucket, "a.txt");
    let listing = format!("{}/{bucket}?list-type=2", s3.endpoint);
    assert_eq!(anonymous(object.clone()).await.unwrap().status(), 403);
    let none = s3
        .client
        .get_bucket_policy()
        .bucket(&bucket)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(none.meta().code(), Some("NoSuchBucketPolicy"));

    // What `mc anonymous set download` writes.
    let download = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":["arn:aws:s3:::{bucket}"]}},{{"Effect":"Allow","Principal":{{"AWS":["*"]}},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::{bucket}/*"]}}]}}"#
    );
    s3.client
        .put_bucket_policy()
        .bucket(&bucket)
        .policy(&download)
        .send()
        .await
        .unwrap();
    let response = anonymous(object.clone()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "published");
    let listed = anonymous(listing.clone()).await.unwrap();
    assert_eq!(listed.status(), 200);
    assert!(listed.text().await.unwrap().contains("<Key>a.txt</Key>"));
    let policy = s3
        .client
        .get_bucket_policy()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
    let policy = policy.policy().unwrap();
    assert!(
        policy.contains("s3:GetObject") && policy.contains("s3:ListBucket"),
        "{policy}"
    );
    let status = s3
        .client
        .get_bucket_policy_status()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(
        status.policy_status().and_then(|status| status.is_public()),
        Some(true)
    );

    // Anonymous writes (`mc anonymous set upload` or `public`) are not supported, and change
    // nothing.
    let upload = download.replace(r#""s3:GetObject""#, r#""s3:GetObject","s3:PutObject""#);
    let refused = s3
        .client
        .put_bucket_policy()
        .bucket(&bucket)
        .policy(upload)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(refused.meta().code(), Some("NotImplemented"));
    assert_eq!(anonymous(object.clone()).await.unwrap().status(), 200);

    // `mc anonymous set none` deletes the policy: the bucket is private again.
    s3.client
        .delete_bucket_policy()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous(object).await.unwrap().status(), 403);
    assert_eq!(anonymous(listing).await.unwrap().status(), 403);

    s3.client
        .delete_object()
        .bucket(&bucket)
        .key("a.txt")
        .send()
        .await
        .unwrap();
    s3.client
        .delete_bucket()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
}

/// A multipart upload with a full-object CRC32: the SDK checks the object's checksum when it
/// downloads it, `partNumber` reads one part with its checksum, `GetObjectAttributes` lists the
/// parts, and a WebDAV overwrite leaves a file of one part.
#[tokio::test]
async fn multipart_objects_keep_their_parts_and_checksums() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    let key = s3.key(&prefix, "parts.bin");
    let parts = [vec![b'p'; 5 * 1024 * 1024], b"tail".to_vec()];
    let created = s3
        .client
        .create_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .checksum_algorithm(ChecksumAlgorithm::Crc32)
        .checksum_type(ChecksumType::FullObject)
        .send()
        .await
        .unwrap();
    assert_eq!(created.checksum_type(), Some(&ChecksumType::FullObject));
    let upload_id = created.upload_id().unwrap();
    let mut completed = Vec::new();
    let mut part_sums = Vec::new();
    for (number, body) in (1..).zip(&parts) {
        let uploaded = s3
            .client
            .upload_part()
            .bucket(&s3.bucket)
            .key(&key)
            .upload_id(upload_id)
            .part_number(number)
            .checksum_algorithm(ChecksumAlgorithm::Crc32)
            .body(ByteStream::from(body.clone()))
            .send()
            .await
            .unwrap();
        let sum = uploaded.checksum_crc32().unwrap().to_owned();
        completed.push(
            CompletedPart::builder()
                .part_number(number)
                .e_tag(uploaded.e_tag().unwrap())
                .checksum_crc32(&sum)
                .build(),
        );
        part_sums.push(sum);
    }
    let done = s3
        .client
        .complete_multipart_upload()
        .bucket(&s3.bucket)
        .key(&key)
        .upload_id(upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(completed))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(done.checksum_type(), Some(&ChecksumType::FullObject));
    let object_sum = done.checksum_crc32().unwrap().to_owned();
    assert!(
        !object_sum.contains('-'),
        "a full-object checksum: {object_sum}"
    );

    // The SDK compares the body with the full-object CRC32 as it reads it.
    let whole = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(whole.checksum_crc32(), Some(object_sum.as_str()));
    assert_eq!(whole.checksum_type(), Some(&ChecksumType::FullObject));
    let body = whole.body.collect().await.unwrap().to_vec();
    assert_eq!(body, parts.concat());

    let second = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .part_number(2)
        .checksum_mode(ChecksumMode::Enabled)
        .send()
        .await
        .unwrap();
    assert_eq!(second.parts_count(), Some(2));
    assert_eq!(second.content_length(), Some(4));
    assert_eq!(second.checksum_crc32(), Some(part_sums[1].as_str()));
    assert_eq!(second.body.collect().await.unwrap().to_vec(), b"tail");
    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .part_number(1)
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(5 * 1024 * 1024));
    assert_eq!(head.parts_count(), Some(2));
    let missing = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .part_number(3)
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        missing.raw_response().map(|r| r.status().as_u16()),
        Some(416)
    );

    let attributes = s3
        .client
        .get_object_attributes()
        .bucket(&s3.bucket)
        .key(&key)
        .object_attributes(ObjectAttributes::Checksum)
        .object_attributes(ObjectAttributes::ObjectParts)
        .object_attributes(ObjectAttributes::ObjectSize)
        .send()
        .await
        .unwrap();
    assert_eq!(attributes.object_size(), Some(5 * 1024 * 1024 + 4));
    assert_eq!(
        attributes.checksum().and_then(|c| c.checksum_crc32()),
        Some(object_sum.as_str())
    );
    let listed = attributes.object_parts().unwrap();
    assert_eq!(listed.total_parts_count(), Some(2));
    let sizes: Vec<Option<i64>> = listed.parts().iter().map(|part| part.size()).collect();
    assert_eq!(sizes, [Some(5 * 1024 * 1024), Some(4)]);

    // Written through WebDAV, the file is one part without a checksum.
    let dav = s3.ctx.dav();
    dav.put(&s3.webdav_path(&key), "via webdav")
        .await
        .expect_success();
    let single = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .part_number(1)
        .send()
        .await
        .unwrap();
    assert_eq!(single.parts_count(), None);
    assert_eq!(single.body.collect().await.unwrap().to_vec(), b"via webdav");
    let gone = s3
        .client
        .get_object()
        .bucket(&s3.bucket)
        .key(&key)
        .part_number(2)
        .send()
        .await
        .unwrap_err();
    assert_eq!(gone.raw_response().map(|r| r.status().as_u16()), Some(416));
    s3.clean(&s3.bucket, &prefix).await;
}

/// In us-east-1 (the region the suite signs for), S3 answers a CreateBucket of a bucket the
/// caller owns with 200 and resets the bucket's ACL to the requested one; the objects stay.
#[tokio::test]
async fn re_creating_ones_bucket_resets_its_acl() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let bucket = format!(
        "recreate-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let create = |acl: Option<BucketCannedAcl>| {
        s3.client
            .create_bucket()
            .bucket(&bucket)
            .set_acl(acl)
            .send()
    };
    create(Some(BucketCannedAcl::PublicRead)).await.unwrap();
    s3.put(&bucket, "a.txt", "kept").await;
    let object = s3.url(&bucket, "a.txt");
    let anonymous = || s3.http.get(object.clone()).send();
    assert_eq!(anonymous().await.unwrap().status(), 200);

    // Without an ACL: private again.
    create(None).await.unwrap();
    assert_eq!(anonymous().await.unwrap().status(), 403);
    assert_eq!(s3.get(&bucket, "a.txt").await, b"kept");
    create(Some(BucketCannedAcl::PublicRead)).await.unwrap();
    assert_eq!(anonymous().await.unwrap().status(), 200);

    s3.client
        .delete_object()
        .bucket(&bucket)
        .key("a.txt")
        .send()
        .await
        .unwrap();
    s3.client
        .delete_bucket()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn the_file_ui_links_to_published_objects() {
    use gono_acceptance::web::{AfterLogin, Browser};

    let s3 = require!(S3::new(), "S3 is not configured");
    let web = require!(s3.ctx.web(), "GONO_ACCEPT_WEB_PASSWORD not set");
    let prefix = unique_name("s3");
    let key = s3.key(&prefix, "shared photo.txt");
    s3.client
        .put_object()
        .bucket(&s3.bucket)
        .key(&key)
        .acl(ObjectCannedAcl::PublicRead)
        .body(ByteStream::from_static(b"linked"))
        .send()
        .await
        .unwrap();
    s3.put(&s3.bucket, &s3.key(&prefix, "private.txt"), "private")
        .await;

    let browser = Browser::new("gono-acceptance browser");
    let folder = s3
        .ctx
        .url(&format!("/apps/files/Buckets/{}/{prefix}/", s3.bucket));
    let folder = url::Url::parse(&folder).unwrap();
    browser
        .login(&folder, &web, AfterLogin::Stop)
        .await
        .unwrap_or_else(|err| panic!("signing in to the file UI failed: {err}"));
    let page = browser.get(&folder, None).await;
    assert_eq!(page.status, 200, "{}", page.describe());
    let links: Vec<&str> = page
        .body
        .split("data-copy-link")
        .filter_map(|before| {
            let start = before.rfind("href=\"")? + 6;
            before[start..].split('"').next()
        })
        .filter(|href| href.contains("://"))
        .collect();
    assert_eq!(links.len(), 1, "only the public object: {links:?}");
    let link = url::Url::parse(links[0]).unwrap();
    assert!(link.path().ends_with("/shared%20photo.txt"), "{link}");

    // The link works for anyone: it is sent to the S3 listener, whatever its host name.
    let endpoint = url::Url::parse(&s3.endpoint).unwrap();
    let address = endpoint.socket_addrs(|| None).unwrap()[0];
    let anonymous = reqwest::Client::builder()
        .resolve(link.host_str().unwrap(), address)
        .build()
        .unwrap();
    let response = anonymous.get(link.as_str()).send().await.unwrap();
    assert_eq!(response.status(), 200, "{link}");
    assert_eq!(response.text().await.unwrap(), "linked");
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn mtime_metadata_sets_the_files_modification_time() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let prefix = unique_name("s3");
    // The time WebDAV reports for the file of `key`.
    let s3 = &s3;
    let modified = |key: String| async move {
        s3.ctx
            .dav()
            .stat(&s3.webdav_path(&key))
            .await
            .text("DAV:", "getlastmodified")
    };
    // rclone sends the time in nanoseconds as a fraction of the seconds.
    let key = s3.key(&prefix, "synced.txt");
    s3.client
        .put_object()
        .bucket(&s3.bucket)
        .key(&key)
        .metadata("mtime", "1700000000.123456789")
        .body(ByteStream::from_static(b"synced"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        modified(key.clone()).await.as_deref(),
        Some("Tue, 14 Nov 2023 22:13:20 GMT")
    );
    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.last_modified().map(|time| time.secs()),
        Some(1_700_000_000)
    );
    assert_eq!(
        head.metadata()
            .and_then(|meta| meta.get("mtime"))
            .map(String::as_str),
        Some("1700000000.123456789"),
        "the metadata stays as sent"
    );

    // rclone changes the time of an object by copying it onto itself.
    s3.client
        .copy_object()
        .bucket(&s3.bucket)
        .key(&key)
        .copy_source(format!("{}/{key}", s3.bucket))
        .metadata_directive(aws_sdk_s3::types::MetadataDirective::Replace)
        .metadata("mtime", "1600000000")
        .send()
        .await
        .unwrap();
    assert_eq!(
        modified(key.clone()).await.as_deref(),
        Some("Sun, 13 Sep 2020 12:26:40 GMT")
    );
    assert_eq!(s3.get(&s3.bucket, &key).await, b"synced");

    // A multipart upload takes the time named when it was created.
    let big = s3.key(&prefix, "big.bin");
    let upload = s3
        .client
        .create_multipart_upload()
        .bucket(&s3.bucket)
        .key(&big)
        .metadata("mtime", "1500000000")
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    let part = s3
        .client
        .upload_part()
        .bucket(&s3.bucket)
        .key(&big)
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from_static(b"one part"))
        .send()
        .await
        .unwrap();
    s3.client
        .complete_multipart_upload()
        .bucket(&s3.bucket)
        .key(&big)
        .upload_id(id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(
                    CompletedPart::builder()
                        .part_number(1)
                        .e_tag(part.e_tag().unwrap())
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        modified(big).await.as_deref(),
        Some("Fri, 14 Jul 2017 02:40:00 GMT")
    );

    // Without it, or with a value that is not a time, the upload is new.
    let plain = s3.key(&prefix, "plain.txt");
    s3.client
        .put_object()
        .bucket(&s3.bucket)
        .key(&plain)
        .metadata("mtime", "yesterday")
        .body(ByteStream::from_static(b"plain"))
        .send()
        .await
        .unwrap();
    let head = s3
        .client
        .head_object()
        .bucket(&s3.bucket)
        .key(&plain)
        .send()
        .await
        .unwrap();
    let age = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - head.last_modified().unwrap().secs();
    assert!(age.abs() < 600, "{age}");
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn the_capabilities_name_the_s3_endpoint() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let capabilities = s3.ctx.capabilities().await;
    let announced = &capabilities["gono_cloud"]["s3"];
    let endpoint = announced["endpoint"]
        .as_str()
        .unwrap_or_else(|| panic!("no S3 endpoint in {capabilities}"));
    // The suite talks to s3.bind; the capability names the public URL, on the same port here.
    let public = url::Url::parse(endpoint).unwrap();
    let bound = url::Url::parse(&s3.endpoint).unwrap();
    assert_eq!(
        public.port_or_known_default(),
        bound.port_or_known_default()
    );
    assert!(!endpoint.ends_with('/'), "{endpoint}");
    assert_eq!(announced["region"], "us-east-1");
    assert_eq!(announced["path_style"], true);
    assert_eq!(announced["bucket_folder"], "Buckets");
    assert_eq!(announced["anonymous"], true);
    match env("GONO_ACCEPT_S3_VIRTUAL_HOST_DOMAIN") {
        Some(domain) => {
            assert_eq!(announced["virtual_hosted_style"], true);
            assert_eq!(announced["virtual_host_domain"], domain.as_str());
        }
        None => skip("GONO_ACCEPT_S3_VIRTUAL_HOST_DOMAIN is not set"),
    }
}
