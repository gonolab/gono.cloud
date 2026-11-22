//! S3 buckets and access keys against a real database: bindings that follow their folders,
//! names unique across accounts, grants, and keys that sign but never pass HTTP Basic.

use gono_server_core::{
    Error, Permission, RelPath, Username, app_passwords,
    db::{self, Pool},
    meta::{DiskStat, MetaStore},
    s3::{self, Anonymous, BucketName, Grant},
    sealing::Key,
    users::{self, NewUser},
};
use secrecy::{ExposeSecret as _, SecretString};

struct Fixture {
    _dir: tempfile::TempDir,
    pool: Pool,
    meta: MetaStore,
    sealing: Key,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    Fixture {
        _dir: dir,
        meta: MetaStore::new(pool.clone()),
        pool,
        sealing: Key::from_bytes(&[7; 32]),
    }
}

impl Fixture {
    async fn user(&self, name: &str) -> i64 {
        let username = Username::new(name).unwrap();
        let id = users::create(
            &self.pool,
            &NewUser {
                username: &username,
                display_name: name,
                password_hash: "x",
                is_admin: false,
                services: gono_server_core::services::Services::ALL,
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        self.meta
            .adopt(
                id,
                &[(
                    RelPath::root(),
                    DiskStat {
                        is_dir: true,
                        mtime_ns: 1,
                        size: 0,
                    },
                )],
            )
            .await
            .unwrap();
        id
    }

    async fn folder(&self, owner: i64, path: &str) -> i64 {
        self.meta
            .record_mkdir(owner, &RelPath::parse(path).unwrap(), 1)
            .await
            .unwrap()
            .id
    }

    async fn bucket(&self, owner: i64, name: &str, folder: i64) -> Result<s3::Bucket, Error> {
        s3::create_bucket(&self.pool, owner, &BucketName::new(name).unwrap(), folder).await
    }
}

#[tokio::test]
async fn buckets_are_named_folders_that_follow_moves() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let photos = f.folder(alice, "Photos").await;
    let bucket = f.bucket(alice, "photos", photos).await.unwrap();
    assert_eq!(bucket.folder.as_str(), "Photos");
    assert_eq!(bucket.anonymous, Anonymous::Private);
    assert!(!bucket.anonymous_list);

    f.meta
        .record_move(
            alice,
            &RelPath::parse("Photos").unwrap(),
            &RelPath::parse("Archive").unwrap(),
            DiskStat {
                is_dir: true,
                mtime_ns: 2,
                size: 0,
            },
        )
        .await
        .unwrap();
    let moved = s3::bucket(&f.pool, "photos").await.unwrap().unwrap();
    assert_eq!(moved.folder.as_str(), "Archive");
    assert_eq!(moved.id, bucket.id);

    f.meta
        .record_delete(alice, &RelPath::parse("Archive").unwrap())
        .await
        .unwrap();
    assert_eq!(s3::bucket(&f.pool, "photos").await.unwrap(), None);
}

#[tokio::test]
async fn bucket_names_are_unique_across_accounts() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let bob = f.user("bob").await;
    let a = f.folder(alice, "A").await;
    let a2 = f.folder(alice, "A2").await;
    let b = f.folder(bob, "B").await;
    f.bucket(alice, "shared", a).await.unwrap();
    assert!(matches!(
        f.bucket(alice, "shared", a2).await,
        Err(Error::BucketExists { yours: true, .. })
    ));
    assert!(matches!(
        f.bucket(bob, "shared", b).await,
        Err(Error::BucketExists { yours: false, .. })
    ));
    f.bucket(bob, "bobs", b).await.unwrap();
    let names: Vec<String> = s3::buckets_of(&f.pool, alice)
        .await
        .unwrap()
        .into_iter()
        .map(|bucket| bucket.name)
        .collect();
    assert_eq!(names, ["shared"]);
}

#[tokio::test]
async fn only_separate_folders_of_the_owner_can_be_buckets() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let bob = f.user("bob").await;
    let outer = f.folder(alice, "Outer").await;
    let inner = f.folder(alice, "Outer/Inner").await;
    let sibling = f.folder(alice, "Outer-2").await;
    let file = f
        .meta
        .record_write(
            alice,
            &RelPath::parse("note.txt").unwrap(),
            DiskStat {
                is_dir: false,
                mtime_ns: 1,
                size: 1,
            },
            None,
        )
        .await
        .unwrap()
        .id;
    let root = f
        .meta
        .get(alice, &RelPath::root())
        .await
        .unwrap()
        .unwrap()
        .id;
    let bobs = f.folder(bob, "Mine").await;

    f.bucket(alice, "inner", inner).await.unwrap();
    for (name, folder) in [
        ("outer", outer),
        ("again", inner),
        ("root", root),
        ("file", file),
        ("foreign", bobs),
        ("missing", i64::MAX),
    ] {
        assert!(
            matches!(
                f.bucket(alice, name, folder).await,
                Err(Error::InvalidBucketFolder { .. })
            ),
            "{name}"
        );
    }
    // Prefixes are compared per segment.
    f.bucket(alice, "sibling", sibling).await.unwrap();
}

#[tokio::test]
async fn buckets_can_be_unbound_and_opened_to_anonymous_reads() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let bob = f.user("bob").await;
    let folder = f.folder(alice, "Public").await;
    let bucket = f.bucket(alice, "public", folder).await.unwrap();
    assert!(
        !s3::set_anonymous(&f.pool, bob, bucket.id, Anonymous::PublicRead, true)
            .await
            .unwrap(),
        "not bob's bucket"
    );
    assert!(
        s3::set_anonymous(&f.pool, alice, bucket.id, Anonymous::Acl, true)
            .await
            .unwrap()
    );
    let stored = s3::bucket(&f.pool, "public").await.unwrap().unwrap();
    assert_eq!(stored.anonymous, Anonymous::Acl);
    assert!(stored.anonymous_list);

    // CORS rules are stored as the S3 API wrote them, only for the owner, and only as JSON.
    assert_eq!(stored.cors, None);
    let rules = r#"[{"allowed_origins":["https://app.example"],"allowed_methods":["PUT"]}]"#;
    assert!(
        !s3::set_cors(&f.pool, bob, bucket.id, Some(rules))
            .await
            .unwrap()
    );
    assert!(
        s3::set_cors(&f.pool, alice, bucket.id, Some(rules))
            .await
            .unwrap()
    );
    let stored = s3::bucket(&f.pool, "public").await.unwrap().unwrap();
    assert_eq!(stored.cors.as_deref(), Some(rules));
    assert!(
        s3::set_cors(&f.pool, alice, bucket.id, Some("not json"))
            .await
            .is_err()
    );
    assert!(s3::set_cors(&f.pool, alice, bucket.id, None).await.unwrap());
    let stored = s3::bucket(&f.pool, "public").await.unwrap().unwrap();
    assert_eq!(stored.cors, None);

    assert!(!s3::delete_bucket(&f.pool, bob, bucket.id).await.unwrap());
    assert!(s3::delete_bucket(&f.pool, alice, bucket.id).await.unwrap());
    assert_eq!(s3::bucket(&f.pool, "public").await.unwrap(), None);
    assert!(
        f.meta
            .get(alice, &RelPath::parse("Public").unwrap())
            .await
            .unwrap()
            .is_some(),
        "the folder stays"
    );
}

#[tokio::test]
async fn keys_sign_with_their_sealed_secret() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let (key, secret) = s3::create_key(
        &f.pool,
        &f.sealing,
        alice,
        "laptop",
        vec![Grant::everything()],
        None,
    )
    .await
    .unwrap();
    assert!(s3::is_access_key_id(&key.access_key_id));
    assert_eq!(secret.expose_secret().len(), 40);

    let signing = s3::signing_key(&f.pool, &f.sealing, &key.access_key_id, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signing.secret.expose_secret(), secret.expose_secret());
    assert_eq!(signing.username.as_str(), "alice");
    assert_eq!(signing.grants, [Grant::everything()]);

    // The stored secret is not the secret.
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT secret_sealed FROM app_passwords WHERE id = ?")
            .bind(key.id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(
        !stored
            .windows(secret.expose_secret().len())
            .any(|w| w == secret.expose_secret().as_bytes())
    );
    // Another key file opens nothing.
    assert!(
        s3::signing_key(&f.pool, &Key::from_bytes(&[8; 32]), &key.access_key_id, 0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        s3::signing_key(&f.pool, &f.sealing, "GONOAAAAAAAAAAAAAAAA", 0)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn keys_are_no_app_passwords() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let (key, secret) = s3::create_key(
        &f.pool,
        &f.sealing,
        alice,
        "s3",
        vec![Grant::everything()],
        None,
    )
    .await
    .unwrap();
    assert!(
        app_passwords::authenticate(&f.pool, "alice", &secret, 0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        app_passwords::authenticate(
            &f.pool,
            "alice",
            &SecretString::from(key.access_key_id.clone()),
            0
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        app_passwords::device(&f.pool, key.id, 0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        app_passwords::list(&f.pool, alice)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!app_passwords::delete(&f.pool, alice, key.id).await.unwrap());

    // And app passwords are no keys.
    let (dav, _) = app_passwords::create(&f.pool, alice, "phone", Vec::new(), None)
        .await
        .unwrap();
    assert_eq!(s3::list_keys(&f.pool, alice).await.unwrap().len(), 1);
    assert!(!s3::delete_key(&f.pool, alice, dav).await.unwrap());
    assert!(s3::delete_key(&f.pool, alice, key.id).await.unwrap());
    assert!(s3::list_keys(&f.pool, alice).await.unwrap().is_empty());
}

#[tokio::test]
async fn keys_stop_signing_when_they_expire_or_the_account_is_disabled() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let (key, _) = s3::create_key(
        &f.pool,
        &f.sealing,
        alice,
        "temporary",
        vec![Grant::everything()],
        Some(100),
    )
    .await
    .unwrap();
    let signs = |now| {
        let f = &f;
        let id = key.access_key_id.clone();
        async move {
            s3::signing_key(&f.pool, &f.sealing, &id, now)
                .await
                .unwrap()
                .is_some()
        }
    };
    assert!(signs(99).await);
    assert!(!signs(100).await);
    sqlx::query("UPDATE app_passwords SET expires_at = NULL WHERE id = ?")
        .bind(key.id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(signs(100).await);
    users::set_enabled(&f.pool, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    assert!(!signs(100).await);
}

#[tokio::test]
async fn grants_name_buckets_of_the_owner() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let bob = f.user("bob").await;
    let one = f
        .bucket(alice, "one", f.folder(alice, "One").await)
        .await
        .unwrap();
    let two = f
        .bucket(alice, "two", f.folder(alice, "Two").await)
        .await
        .unwrap();
    let bobs = f
        .bucket(bob, "bobs", f.folder(bob, "B").await)
        .await
        .unwrap();
    let grant = |bucket: &s3::Bucket, permission| Grant {
        bucket_id: Some(bucket.id),
        permission,
    };
    let create = |grants: Vec<Grant>| {
        let f = &f;
        async move { s3::create_key(&f.pool, &f.sealing, alice, "k", grants, None).await }
    };
    for bad in [
        Vec::new(),
        vec![Grant::everything(), grant(&one, Permission::View)],
        vec![grant(&one, Permission::View), grant(&one, Permission::Full)],
        vec![grant(&bobs, Permission::View)],
    ] {
        assert!(
            matches!(create(bad.clone()).await, Err(Error::InvalidGrants(_))),
            "{bad:?}"
        );
    }
    let (key, _) = create(vec![
        grant(&two, Permission::Full),
        grant(&one, Permission::View),
    ])
    .await
    .unwrap();
    assert_eq!(
        key.grants,
        [grant(&one, Permission::View), grant(&two, Permission::Full)]
    );
    assert_eq!(
        s3::list_keys(&f.pool, alice).await.unwrap()[0].grants,
        key.grants
    );

    // Unbinding a bucket takes its grants along.
    s3::delete_bucket(&f.pool, alice, one.id).await.unwrap();
    let signing = s3::signing_key(&f.pool, &f.sealing, &key.access_key_id, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signing.grants, [grant(&two, Permission::Full)]);
}

#[tokio::test]
async fn multipart_uploads_keep_their_latest_parts_until_they_end() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let bucket = f
        .bucket(alice, "media", f.folder(alice, "Media").await)
        .await
        .unwrap();
    let id = s3::create_upload(&f.pool, bucket.id, "video.mp4", "{}", 10, 100)
        .await
        .unwrap();
    assert_eq!(id.len(), 32);
    let upload = s3::upload(&f.pool, &id).await.unwrap().unwrap();
    assert_eq!(upload.key, "video.mp4");
    assert_eq!(upload.expires_at, 100);

    let part = |number: u32, file: &str| s3::UploadPart {
        part_number: number,
        file_name: file.to_owned(),
        etag: format!("etag-{file}"),
        size: 5,
        uploaded_at: 20,
        checksum: (number == 1).then(|| "sum".to_owned()),
    };
    assert_eq!(
        s3::record_part(&f.pool, &id, &part(2, "2.a"), 200)
            .await
            .unwrap(),
        Some(None)
    );
    assert_eq!(
        s3::record_part(&f.pool, &id, &part(1, "1.a"), 200)
            .await
            .unwrap(),
        Some(None)
    );
    assert_eq!(
        s3::record_part(&f.pool, &id, &part(2, "2.b"), 300)
            .await
            .unwrap(),
        Some(Some("2.a".to_owned())),
        "the replaced file is reported for removal"
    );
    let files: Vec<String> = s3::parts(&f.pool, &id)
        .await
        .unwrap()
        .into_iter()
        .map(|part| part.file_name)
        .collect();
    assert_eq!(files, ["1.a", "2.b"]);
    let checksums: Vec<Option<String>> = s3::parts(&f.pool, &id)
        .await
        .unwrap()
        .into_iter()
        .map(|part| part.checksum)
        .collect();
    assert_eq!(checksums, [Some("sum".to_owned()), None]);
    assert_eq!(
        s3::upload(&f.pool, &id).await.unwrap().unwrap().expires_at,
        300
    );
    assert_eq!(
        s3::uploads_of_bucket(&f.pool, bucket.id)
            .await
            .unwrap()
            .len(),
        1
    );

    // A completed upload loses its parts and leaves the listing, but is kept with the ETag
    // for repeated completions; it takes no parts any more.
    let other = s3::create_upload(&f.pool, bucket.id, "clip.mp4", "{}", 10, 100)
        .await
        .unwrap();
    s3::record_part(&f.pool, &other, &part(1, "1.c"), 200)
        .await
        .unwrap();
    assert!(
        s3::complete_upload(&f.pool, &other, "abc-1", Some("sum-1"), 250)
            .await
            .unwrap()
    );
    assert!(
        !s3::complete_upload(&f.pool, &other, "abc-1", None, 260)
            .await
            .unwrap(),
        "completed once only"
    );
    let completed = s3::upload(&f.pool, &other).await.unwrap().unwrap();
    assert_eq!(completed.completed_etag.as_deref(), Some("abc-1"));
    assert_eq!(completed.completed_checksum.as_deref(), Some("sum-1"));
    assert_eq!(completed.expires_at, 250);
    assert!(s3::parts(&f.pool, &other).await.unwrap().is_empty());
    assert_eq!(
        s3::record_part(&f.pool, &other, &part(2, "2.c"), 700)
            .await
            .unwrap(),
        None
    );
    let listed: Vec<String> = s3::uploads_of_bucket(&f.pool, bucket.id)
        .await
        .unwrap()
        .into_iter()
        .map(|upload| upload.upload_id)
        .collect();
    assert_eq!(listed, std::slice::from_ref(&id));
    assert_eq!(
        s3::purge_expired_uploads(&f.pool, 260).await.unwrap(),
        [other]
    );

    assert!(s3::delete_upload(&f.pool, &id).await.unwrap());
    assert!(!s3::delete_upload(&f.pool, &id).await.unwrap());
    assert!(s3::parts(&f.pool, &id).await.unwrap().is_empty());
    assert_eq!(
        s3::record_part(&f.pool, &id, &part(3, "3.a"), 400)
            .await
            .unwrap(),
        None,
        "no parts for a finished upload"
    );
}

#[tokio::test]
async fn expired_uploads_are_purged_and_buckets_take_theirs_along() {
    let f = fixture().await;
    let alice = f.user("alice").await;
    let bucket = f
        .bucket(alice, "media", f.folder(alice, "Media").await)
        .await
        .unwrap();
    let old = s3::create_upload(&f.pool, bucket.id, "a", "{}", 0, 50)
        .await
        .unwrap();
    let fresh = s3::create_upload(&f.pool, bucket.id, "b", "{}", 0, 500)
        .await
        .unwrap();
    assert_eq!(
        s3::purge_expired_uploads(&f.pool, 100).await.unwrap(),
        [old]
    );
    assert_eq!(
        s3::upload_ids(&f.pool).await.unwrap(),
        std::collections::HashSet::from([fresh.clone()])
    );
    s3::delete_bucket(&f.pool, alice, bucket.id).await.unwrap();
    assert!(s3::upload(&f.pool, &fresh).await.unwrap().is_none());
}
