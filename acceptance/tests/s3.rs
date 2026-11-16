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
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart, ObjectCannedAcl},
};
use gono_acceptance::{Cred, Ctx, require, skip, unique_name};

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
    std::env::var(name).ok().filter(|value| !value.trim().is_empty())
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
        head.metadata().and_then(|meta| meta.get("mtime")).map(String::as_str),
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
                .set_parts(Some(parts))
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(done.e_tag().unwrap().ends_with("-2\""), "{:?}", done.e_tag());
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
        s3.http.get(s3.url(&s3.bucket, &key)).send().await.unwrap().status(),
        200
    );
    dav.put(&s3.webdav_path(&key), "via webdav").await.expect_success();
    assert_eq!(s3.get(&s3.bucket, &key).await, b"via webdav");
    assert_eq!(
        s3.http.get(s3.url(&s3.bucket, &key)).send().await.unwrap().status(),
        403,
        "an overwritten public object is private again"
    );
    s3.clean(&s3.bucket, &prefix).await;
}

#[tokio::test]
async fn wrong_credentials_are_refused() {
    let s3 = require!(S3::new(), "S3 is not configured");
    let unknown = client(&s3.endpoint, "GONOAAAAAAAAAAAAAAAA", "x".repeat(40).as_str());
    let err = unknown.list_buckets().send().await.unwrap_err();
    assert!(format!("{err:?}").contains("InvalidAccessKeyId"), "{err:?}");

    let access_key = env("GONO_ACCEPT_S3_ACCESS_KEY").unwrap();
    let wrong_secret = client(&s3.endpoint, &access_key, "y".repeat(40).as_str());
    let err = wrong_secret.list_buckets().send().await.unwrap_err();
    assert!(format!("{err:?}").contains("SignatureDoesNotMatch"), "{err:?}");

    // The secret is no app password, and an app password signs nothing.
    let secret = env("GONO_ACCEPT_S3_SECRET_KEY").unwrap();
    let as_basic = s3.ctx.dav_as(&Cred::new(&s3.ctx.cfg.full.user, secret));
    as_basic.propfind("", "0", "").await.expect(&[401]);
    let as_key = client(&s3.endpoint, &s3.ctx.cfg.full.user, &s3.ctx.cfg.full.password);
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
