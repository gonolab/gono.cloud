//! Lifecycle rules applied to a bucket: which files expire and which stay.

use std::{collections::BTreeMap, sync::Arc};

use gono_server_core::{
    RelPath, Username, db,
    locks::LockStore,
    meta::{MetaStore, ObjectMeta},
    s3, sealing, settings,
    storage::DataLayout,
    users::{self, NewUser},
};
use gono_server_dav::{Identity, Mount, ScopedFs, WriteCondition};
use gono_server_s3::{S3Settings, S3State, lifecycle};

const DAY: i64 = 24 * 60 * 60;

struct Fixture {
    _dir: tempfile::TempDir,
    state: S3State,
    owner: i64,
    identity: Arc<Identity>,
    layout: DataLayout,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let layout = DataLayout::new(dir.path().join("data"));
    layout.create().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let username = Username::new("alice").unwrap();
    let owner = users::create(
        &pool,
        &NewUser {
            username: &username,
            display_name: "Alice",
            password_hash: "x",
            is_admin: false,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap();
    let instance_id = settings::instance_id(&pool).await.unwrap();
    let fs = ScopedFs::new(layout.clone(), MetaStore::new(pool.clone()), instance_id);
    let identity = Arc::new(Identity {
        user_id: owner,
        username: username.clone(),
        display_name: "Alice".into(),
        app_password_id: None,
        services: gono_server_core::services::Services::ALL,
        mounts: vec![Mount {
            mount_path: RelPath::root(),
            storage_path: RelPath::root(),
            writable: true,
        }],
    });
    let folder = fs
        .put_folder(identity.clone(), &RelPath::parse("Buckets/logs").unwrap())
        .await
        .unwrap();
    let name = s3::BucketName::new("logs").unwrap();
    s3::create_bucket(&pool, owner, &name, folder.file_id.unwrap())
        .await
        .unwrap();
    let state = S3State::new(
        pool.clone(),
        fs,
        LockStore::new(pool),
        sealing::Key::from_bytes(&[7; 32]),
        S3Settings {
            region: "us-east-1".into(),
            bucket_folder: "Buckets".into(),
            allow_anonymous: false,
            multipart_ttl_secs: 3600,
            virtual_host_domain: None,
            website_domain: None,
        },
    );
    Fixture {
        _dir: dir,
        state,
        owner,
        identity,
        layout,
    }
}

impl Fixture {
    /// Writes `rel` through the S3 path of the file system (with `tags`), as written
    /// `days_ago` days ago.
    async fn put_s3(&self, rel: &str, tags: &[(&str, &str)], days_ago: i64) {
        let temp = self
            .layout
            .tmp_dir()
            .join(format!("{}.part", rel.replace('/', "_")));
        std::fs::write(&temp, rel).unwrap();
        let meta = ObjectMeta {
            s3_etag: Some("0123456789abcdef0123456789abcdef".into()),
            tags: tags
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            ..ObjectMeta::default()
        };
        let entry = self
            .state
            .fs()
            .put_object(
                self.identity.clone(),
                &RelPath::parse(rel).unwrap(),
                None,
                temp,
                meta,
                WriteCondition::Always,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE object_meta SET written_at = ? WHERE file_id = ?")
            .bind(db::unix_now() - days_ago * DAY)
            .bind(entry.file_id.unwrap())
            .execute(self.state.pool())
            .await
            .unwrap();
    }

    fn exists(&self, rel: &str) -> bool {
        RelPath::parse(rel)
            .unwrap()
            .to_fs_path(&self.layout.user_files(self.owner))
            .exists()
    }

    /// The `x-amz-expiration` header of the object `key` of the bucket, file `file_id` with
    /// `tags`.
    async fn expiration(
        &self,
        key: &str,
        tags: &BTreeMap<String, String>,
        file_id: i64,
    ) -> Option<String> {
        let bucket = s3::bucket(self.state.pool(), "logs")
            .await
            .unwrap()
            .unwrap();
        lifecycle::expiration(&self.state, &bucket, key, 1, tags, file_id).await
    }

    async fn rules(&self, xml: &str) {
        let bucket = s3::bucket(self.state.pool(), "logs")
            .await
            .unwrap()
            .unwrap();
        sqlx::query("UPDATE s3_buckets SET lifecycle = ? WHERE id = ?")
            .bind(xml)
            .bind(bucket.id)
            .execute(self.state.pool())
            .await
            .unwrap();
    }
}

/// A rule of 2 days on `tmp/` for objects tagged `kind=cache`: old S3 objects that match go;
/// new ones, other prefixes and tags, and files written through WebDAV stay.
#[tokio::test]
async fn expired_s3_objects_are_deleted_and_nothing_else() {
    let f = fixture().await;
    f.put_s3("Buckets/logs/tmp/old", &[("kind", "cache")], 3)
        .await;
    f.put_s3("Buckets/logs/tmp/new", &[("kind", "cache")], 1)
        .await;
    f.put_s3("Buckets/logs/tmp/untagged", &[], 3).await;
    f.put_s3("Buckets/logs/keep/old", &[("kind", "cache")], 3)
        .await;
    // Written through WebDAV long ago (no S3 metadata): never expires.
    let dav = RelPath::parse("Buckets/logs/tmp/dav").unwrap();
    std::fs::write(dav.to_fs_path(&f.layout.user_files(f.owner)), "dav").unwrap();
    f.state
        .fs()
        .meta()
        .record_write(
            f.owner,
            &dav,
            gono_server_core::meta::DiskStat {
                is_dir: false,
                mtime_ns: 1,
                size: 3,
            },
            None,
        )
        .await
        .unwrap();
    f.rules(
        r#"[{"id":"cache","enabled":true,"prefix":"tmp/","tags":{"kind":"cache"},
            "size_greater_than":null,"size_less_than":null,"expiration_days":2,
            "expiration_date":null,"expired_object_delete_marker":null,"abort_days":null}]"#,
    )
    .await;

    let applied = lifecycle::apply(&f.state, db::unix_now()).await.unwrap();
    assert_eq!(applied.expired, 1);
    assert!(!f.exists("Buckets/logs/tmp/old"));
    assert!(f.exists("Buckets/logs/tmp/new"));
    assert!(f.exists("Buckets/logs/tmp/untagged"));
    assert!(f.exists("Buckets/logs/keep/old"));
    assert!(f.exists("Buckets/logs/tmp/dav"));
    assert!(
        f.state
            .fs()
            .meta()
            .get(f.owner, &RelPath::parse("Buckets/logs/tmp/old").unwrap())
            .await
            .unwrap()
            .is_none(),
        "the metadata goes with the file"
    );
    // A disabled rule does nothing.
    f.rules(
        r#"[{"id":"cache","enabled":false,"prefix":"","tags":{},
            "size_greater_than":null,"size_less_than":null,"expiration_days":1,
            "expiration_date":null,"expired_object_delete_marker":null,"abort_days":null}]"#,
    )
    .await;
    assert_eq!(
        lifecycle::apply(&f.state, db::unix_now()).await.unwrap(),
        lifecycle::Applied::default()
    );
}

/// The `x-amz-expiration` header of an object: the earliest rule that expires it, counted from
/// when S3 wrote it; files written through WebDAV get none, even with tags.
#[tokio::test]
async fn expiration_headers_count_from_the_s3_write() {
    let f = fixture().await;
    f.put_s3("Buckets/logs/tmp/a", &[("kind", "cache")], 0)
        .await;
    let meta = f.state.fs().meta();
    let object = meta
        .get(f.owner, &RelPath::parse("Buckets/logs/tmp/a").unwrap())
        .await
        .unwrap()
        .unwrap();
    // Written at 2025-11-16 10:00 UTC.
    sqlx::query("UPDATE object_meta SET written_at = 1763287200 WHERE file_id = ?")
        .bind(object.id)
        .execute(f.state.pool())
        .await
        .unwrap();
    // Written through WebDAV, then tagged: S3 metadata without an S3 ETag.
    let dav = RelPath::parse("Buckets/logs/tmp/dav").unwrap();
    std::fs::write(dav.to_fs_path(&f.layout.user_files(f.owner)), "dav").unwrap();
    let dav = meta
        .record_write(
            f.owner,
            &dav,
            gono_server_core::meta::DiskStat {
                is_dir: false,
                mtime_ns: 1,
                size: 3,
            },
            None,
        )
        .await
        .unwrap();
    let cache: BTreeMap<String, String> = [("kind".to_owned(), "cache".to_owned())].into();
    assert!(
        meta.set_object_tags(dav.id, &dav.etag, &cache)
            .await
            .unwrap()
    );

    // No rules: no header.
    assert_eq!(f.expiration("tmp/a", &cache, object.id).await, None);

    f.rules(
        r#"[{"id":"week","enabled":true,"prefix":"","tags":{},
            "size_greater_than":null,"size_less_than":null,"expiration_days":7,
            "expiration_date":null,"expired_object_delete_marker":null,"abort_days":null},
            {"id":"cache","enabled":true,"prefix":"tmp/","tags":{"kind":"cache"},
            "size_greater_than":null,"size_less_than":null,"expiration_days":2,
            "expiration_date":null,"expired_object_delete_marker":null,"abort_days":null}]"#,
    )
    .await;
    assert_eq!(
        f.expiration("tmp/a", &cache, object.id).await.as_deref(),
        Some("expiry-date=\"Wed, 19 Nov 2025 00:00:00 GMT\", rule-id=\"cache\"")
    );
    assert_eq!(
        f.expiration("tmp/a", &BTreeMap::new(), object.id)
            .await
            .as_deref(),
        Some("expiry-date=\"Mon, 24 Nov 2025 00:00:00 GMT\", rule-id=\"week\"")
    );
    assert_eq!(f.expiration("tmp/dav", &cache, dav.id).await, None);
}
