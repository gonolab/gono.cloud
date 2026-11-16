//! Object operations by client path (the S3 API's view of the tree): parent folders, key
//! conflicts, conditional writes, S3 metadata of one version, deletes and copies.

mod common;

use std::{path::PathBuf, sync::Arc};

use common::{Harness, mount};
use gono_server_core::{RelPath, meta::ObjectMeta};
use gono_server_dav::{Identity, ObjectError, WriteCondition};

fn p(path: &str) -> RelPath {
    RelPath::parse(path).unwrap()
}

fn object(etag: &str) -> ObjectMeta {
    ObjectMeta {
        s3_etag: Some(etag.to_owned()),
        content_type: Some("text/plain".to_owned()),
        ..ObjectMeta::default()
    }
}

impl Harness {
    /// A synced upload in `tmp/`, as the S3 API leaves it before installing.
    fn upload(&self, content: &str) -> PathBuf {
        let temp = self
            .layout
            .tmp_dir()
            .join(format!("{:x}.part", rand_name()));
        std::fs::write(&temp, content).unwrap();
        temp
    }

    async fn put_object(
        &self,
        identity: &Arc<Identity>,
        client: &str,
        content: &str,
        meta: ObjectMeta,
        condition: WriteCondition,
    ) -> Result<String, ObjectError> {
        let temp = self.upload(content);
        let result = self
            .fs
            .put_object(
                identity.clone(),
                &p(client),
                None,
                temp.clone(),
                meta,
                condition,
            )
            .await;
        if result.is_err() {
            assert!(
                temp.exists(),
                "a failed install leaves the upload to the caller"
            );
            std::fs::remove_file(temp).unwrap();
        }
        result.map(|entry| entry.etag.clone())
    }

    fn content(&self, rel: &str) -> String {
        std::fs::read_to_string(self.disk(rel)).unwrap()
    }
}

fn rand_name() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        ^ (u128::from(n) << 64)
}

#[tokio::test]
async fn writes_create_parents_and_store_s3_metadata() {
    let h = Harness::new().await;
    let full = h.full();
    let before = h.change_count().await;
    h.put_object(
        &full,
        "a/b/c.txt",
        "hello",
        object("md5"),
        WriteCondition::Always,
    )
    .await
    .unwrap();
    assert_eq!(h.content("a/b/c.txt"), "hello");
    // Two folders and the file, each logged.
    assert_eq!(h.change_count().await - before, 3);

    let (entry, meta) = h.fs.object(full.clone(), &p("a/b/c.txt")).await.unwrap();
    assert_eq!(entry.size, 5);
    assert_eq!(meta.unwrap(), object("md5"));
    // The same file through WebDAV.
    let get = h.send(&full, "GET", "a/b/c.txt", &[], "").await;
    get.expect(200);
    assert_eq!(get.body.as_ref(), b"hello");
    // Folders are not objects.
    assert_eq!(
        h.fs.object(full.clone(), &p("a/b")).await.unwrap_err(),
        ObjectError::IsFolder
    );
    assert_eq!(
        h.fs.object(full, &p("a/missing")).await.unwrap_err(),
        ObjectError::NotFound
    );
}

#[tokio::test]
async fn keys_never_name_folders_or_live_below_files() {
    let h = Harness::new().await;
    let full = h.full();
    h.put_object(&full, "dir/file", "x", object("1"), WriteCondition::Always)
        .await
        .unwrap();
    assert_eq!(
        h.put_object(&full, "dir", "x", object("2"), WriteCondition::Always)
            .await,
        Err(ObjectError::IsFolder)
    );
    assert_eq!(
        h.put_object(
            &full,
            "dir/file/below",
            "x",
            object("3"),
            WriteCondition::Always
        )
        .await,
        Err(ObjectError::ParentIsFile)
    );
    assert_eq!(
        h.fs.put_folder(full.clone(), &p("dir/file/sub"))
            .await
            .unwrap_err(),
        ObjectError::ParentIsFile
    );
    assert_eq!(
        h.fs.put_folder(full, &p("dir/file")).await.unwrap_err(),
        ObjectError::ParentIsFile
    );
    assert_eq!(h.content("dir/file"), "x");
}

#[tokio::test]
async fn create_only_writes_never_replace_anything() {
    let h = Harness::new().await;
    let full = h.full();
    h.put_object(
        &full,
        "lock",
        "first",
        object("1"),
        WriteCondition::CreateOnly,
    )
    .await
    .unwrap();
    assert_eq!(
        h.put_object(
            &full,
            "lock",
            "second",
            object("2"),
            WriteCondition::CreateOnly
        )
        .await,
        Err(ObjectError::PreconditionFailed)
    );
    assert_eq!(h.content("lock"), "first");
    h.mkcol(&full, "folder").await.expect(201);
    assert_eq!(
        h.put_object(
            &full,
            "folder",
            "x",
            object("3"),
            WriteCondition::CreateOnly
        )
        .await,
        Err(ObjectError::IsFolder)
    );

    // Of many writers racing for one name, exactly one wins.
    let attempts = (0..8).map(|i| {
        let h = &h;
        let full = full.clone();
        async move {
            h.put_object(
                &full,
                "race",
                &format!("{i}"),
                object(&i.to_string()),
                WriteCondition::CreateOnly,
            )
            .await
        }
    });
    let results = futures_util::future::join_all(attempts).await;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
}

#[tokio::test]
async fn if_match_compares_the_s3_etag() {
    let h = Harness::new().await;
    let full = h.full();
    assert_eq!(
        h.put_object(
            &full,
            "f",
            "x",
            object("1"),
            WriteCondition::IfMatch("1".into())
        )
        .await,
        Err(ObjectError::NotFound),
        "nothing to match"
    );
    h.put_object(&full, "f", "one", object("md5-1"), WriteCondition::Always)
        .await
        .unwrap();
    assert_eq!(
        h.put_object(
            &full,
            "f",
            "two",
            object("md5-2"),
            WriteCondition::IfMatch("other".into())
        )
        .await,
        Err(ObjectError::PreconditionFailed)
    );
    h.put_object(
        &full,
        "f",
        "two",
        object("md5-2"),
        WriteCondition::IfMatch("md5-1".into()),
    )
    .await
    .unwrap();
    assert_eq!(h.content("f"), "two");

    // After a WebDAV write the S3 ETag is the WebDAV one.
    h.put(&full, "f", "three").await.expect(204);
    let (entry, meta) = h.fs.object(full.clone(), &p("f")).await.unwrap();
    assert_eq!(meta, None);
    assert_eq!(
        h.put_object(
            &full,
            "f",
            "four",
            object("md5-4"),
            WriteCondition::IfMatch("md5-2".into())
        )
        .await,
        Err(ObjectError::PreconditionFailed)
    );
    h.put_object(
        &full,
        "f",
        "four",
        object("md5-4"),
        WriteCondition::IfMatch(entry.etag.clone()),
    )
    .await
    .unwrap();
    assert_eq!(h.content("f"), "four");
}

#[tokio::test]
async fn if_exists_and_if_none_match_compare_the_s3_etag() {
    let h = Harness::new().await;
    let full = h.full();
    let put = |content: &'static str, etag: &'static str, condition: WriteCondition| {
        let h = &h;
        let full = full.clone();
        async move {
            h.put_object(&full, "f", content, object(etag), condition)
                .await
        }
    };
    assert_eq!(
        put("x", "1", WriteCondition::IfExists).await,
        Err(ObjectError::NotFound)
    );
    // Nothing there: no ETag matches, so the write happens.
    put("one", "md5-1", WriteCondition::IfNoneMatch("md5-1".into()))
        .await
        .unwrap();
    assert_eq!(
        put("two", "md5-2", WriteCondition::IfNoneMatch("md5-1".into())).await,
        Err(ObjectError::PreconditionFailed)
    );
    put("two", "md5-2", WriteCondition::IfNoneMatch("other".into()))
        .await
        .unwrap();
    put("three", "md5-3", WriteCondition::IfExists)
        .await
        .unwrap();
    assert_eq!(h.content("f"), "three");
    // A folder is no object to replace.
    h.fs.put_folder(full.clone(), &p("dir")).await.unwrap();
    assert_eq!(
        h.put_object(&full, "dir", "x", object("1"), WriteCondition::IfExists)
            .await,
        Err(ObjectError::PreconditionFailed)
    );
}

#[tokio::test]
async fn s3_metadata_describes_only_the_version_it_was_written_with() {
    let h = Harness::new().await;
    let full = h.full();
    h.put_object(&full, "f", "same", object("md5"), WriteCondition::Always)
        .await
        .unwrap();
    assert!(
        h.fs.object(full.clone(), &p("f"))
            .await
            .unwrap()
            .1
            .is_some()
    );
    // Changed behind the server's back: other size, so the recorded version is gone.
    std::fs::write(h.disk("f"), "changed on disk").unwrap();
    let (entry, meta) = h.fs.object(full, &p("f")).await.unwrap();
    assert_eq!(meta, None);
    assert_eq!(entry.size, 15);
}

#[tokio::test]
async fn deletes_remove_files_only() {
    let h = Harness::new().await;
    let full = h.full();
    h.put_object(&full, "a/b/c", "x", object("1"), WriteCondition::Always)
        .await
        .unwrap();
    assert!(h.fs.delete_object(full.clone(), &p("a/b/c")).await.unwrap());
    assert!(!h.disk("a/b/c").exists());
    assert!(h.disk("a/b").is_dir(), "parents stay");
    assert!(!h.fs.delete_object(full.clone(), &p("a/b/c")).await.unwrap());
    assert!(!h.fs.delete_object(full.clone(), &p("a/b")).await.unwrap());
    assert!(h.disk("a/b").is_dir(), "folders are not objects");
    assert_eq!(
        h.fs.delete_object(full.clone(), &p("a/b/c")).await,
        Ok(false)
    );
    let row = h.fs.meta().get(h.owner, &p("a/b/c")).await.unwrap();
    assert_eq!(row, None);
}

#[tokio::test]
async fn copies_are_new_versions_with_their_own_metadata() {
    let h = Harness::new().await;
    let full = h.full();
    h.put_object(
        &full,
        "src",
        "content",
        object("md5-src"),
        WriteCondition::Always,
    )
    .await
    .unwrap();
    let mut meta = object("md5-src");
    meta.content_type = Some("image/png".into());
    let copy =
        h.fs.copy_object(
            full.clone(),
            &p("src"),
            &p("dst/copy"),
            None,
            meta.clone(),
            WriteCondition::Always,
            None,
        )
        .await
        .unwrap();
    assert_eq!(h.content("dst/copy"), "content");
    let (_, stored) = h.fs.object(full.clone(), &p("dst/copy")).await.unwrap();
    assert_eq!(stored, Some(meta));
    let (source, source_meta) = h.fs.object(full.clone(), &p("src")).await.unwrap();
    assert_eq!(
        source_meta.unwrap().content_type.as_deref(),
        Some("text/plain")
    );
    assert_ne!(source.file_id, copy.file_id);
    assert!(copy.modified >= source.modified);
    // A copy can carry a modification time of its own (rclone's mtime metadata).
    let then = std::time::UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 500_000_000);
    let dated =
        h.fs.copy_object(
            full.clone(),
            &p("src"),
            &p("dst/dated"),
            None,
            object("md5-src"),
            WriteCondition::Always,
            Some(then),
        )
        .await
        .unwrap();
    assert_eq!(dated.modified, then);

    h.mkcol(&full, "folder").await.expect(201);
    assert_eq!(
        h.fs.copy_object(
            full.clone(),
            &p("folder"),
            &p("x"),
            None,
            object("1"),
            WriteCondition::Always,
            None
        )
        .await
        .unwrap_err(),
        ObjectError::IsFolder
    );
    assert_eq!(
        h.fs.copy_object(
            full.clone(),
            &p("src"),
            &p("dst/copy"),
            None,
            object("1"),
            WriteCondition::CreateOnly,
            None
        )
        .await
        .unwrap_err(),
        ObjectError::PreconditionFailed
    );
    let leftovers = std::fs::read_dir(h.layout.tmp_dir()).unwrap().count();
    assert_eq!(leftovers, 0, "failed copies leave nothing in tmp/");
}

#[tokio::test]
async fn folder_markers_create_folders() {
    let h = Harness::new().await;
    let full = h.full();
    let entry = h.fs.put_folder(full.clone(), &p("m/n/o")).await.unwrap();
    assert!(entry.is_dir());
    assert!(h.disk("m/n/o").is_dir());
    assert!(h.fs.meta().get(h.owner, &p("m/n")).await.unwrap().is_some());
    h.fs.put_folder(full, &p("m/n/o")).await.unwrap();
}

#[tokio::test]
async fn scopes_apply_as_for_webdav() {
    let h = Harness::new().await;
    let full = h.full();
    h.mkcol(&full, "Buckets").await.expect(201);
    h.mkcol(&full, "Buckets/photos").await.expect(201);
    h.mkcol(&full, "Private").await.expect(201);
    let bucket = h.identity(vec![mount("photos", "Buckets/photos", true)]);
    let read_only = h.identity(vec![mount("photos", "Buckets/photos", false)]);

    h.put_object(
        &bucket,
        "photos/2026/a.jpg",
        "jpg",
        object("1"),
        WriteCondition::Always,
    )
    .await
    .unwrap();
    assert_eq!(h.content("Buckets/photos/2026/a.jpg"), "jpg");
    assert!(
        h.fs.object(read_only.clone(), &p("photos/2026/a.jpg"))
            .await
            .is_ok()
    );

    for (identity, client, error) in [
        (&read_only, "photos/b.jpg", ObjectError::Forbidden),
        (&bucket, "photos", ObjectError::Forbidden),
        (&bucket, "Private/x", ObjectError::NotFound),
    ] {
        assert_eq!(
            h.put_object(identity, client, "x", object("2"), WriteCondition::Always)
                .await,
            Err(error),
            "{client}"
        );
    }
    assert_eq!(
        h.fs.delete_object(read_only.clone(), &p("photos/2026/a.jpg"))
            .await,
        Err(ObjectError::Forbidden)
    );
    assert_eq!(
        h.fs.put_folder(read_only, &p("photos/new"))
            .await
            .unwrap_err(),
        ObjectError::Forbidden
    );
    assert!(h.disk("Buckets/photos/2026/a.jpg").exists());
}

/// Writers racing to create the same new folders. Recording a folder clears stale rows below
/// it, so a file recorded before its new parent would lose its S3 metadata; the account's lock
/// prevents that. The interleaving is timing-dependent and this test does not force it: it
/// checks that parallel writes stay correct, not that the race is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_writes_into_new_folders_keep_their_metadata() {
    let h = Arc::new(Harness::new().await);
    let full = h.full();
    // Collected, so that every task is spawned before the first is awaited.
    let writes: Vec<_> = (0..16)
        .map(|i| {
            let h = h.clone();
            let full = full.clone();
            tokio::spawn(async move {
                h.put_object(
                    &full,
                    &format!("new/deep/{}/file-{i}", i % 2),
                    "x",
                    object(&format!("md5-{i}")),
                    WriteCondition::Always,
                )
                .await
                .unwrap();
            })
        })
        .collect();
    for write in writes {
        write.await.unwrap();
    }
    for i in 0..16 {
        let client = p(&format!("new/deep/{}/file-{i}", i % 2));
        let (_, meta) = h.fs.object(full.clone(), &client).await.unwrap();
        assert_eq!(
            meta.and_then(|meta| meta.s3_etag),
            Some(format!("md5-{i}")),
            "{client}"
        );
    }
}

/// Many parallel writes into a few new folders: every file and folder ends up in the metadata
/// (rows, not just files on disk) with the file's S3 metadata. A writer must not skip the
/// account's lock merely because its folders are on disk (another writer may not have recorded
/// them yet); that race needs real fsync latency to show and was caught by
/// acceptance/scripts/s3-load.sh (rclone check), so this test guards the outcome, not the race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_writes_record_every_file_and_folder() {
    let h = Arc::new(Harness::new().await);
    let full = h.full();
    // Collected, so that every task is spawned before the first is awaited.
    let writes: Vec<_> = (0..64)
        .map(|i| {
            let h = h.clone();
            let full = full.clone();
            tokio::spawn(async move {
                h.put_object(
                    &full,
                    &format!("burst/{}/{}/file-{i}", i % 4, i % 3),
                    "x",
                    object(&format!("md5-{i}")),
                    WriteCondition::Always,
                )
                .await
                .unwrap();
            })
        })
        .collect();
    for write in writes {
        write.await.unwrap();
    }
    let meta = h.fs.meta();
    for folder in (0..4).flat_map(|a| (0..3).map(move |b| format!("burst/{a}/{b}"))) {
        let row = meta.get(h.owner, &p(&folder)).await.unwrap();
        assert!(
            row.is_some_and(|row| row.is_dir),
            "{folder} is not recorded"
        );
    }
    for i in 0..64 {
        let file = format!("burst/{}/{}/file-{i}", i % 4, i % 3);
        let row = meta.get(h.owner, &p(&file)).await.unwrap();
        assert!(row.is_some_and(|row| !row.is_dir), "{file} is not recorded");
        let (_, object) = h.fs.object(full.clone(), &p(&file)).await.unwrap();
        assert_eq!(
            object.and_then(|object| object.s3_etag),
            Some(format!("md5-{i}")),
            "{file} lost its S3 metadata"
        );
    }
}

#[tokio::test]
async fn objects_open_for_reading_with_their_metadata() {
    use std::io::Read as _;

    let h = Harness::new().await;
    let full = h.full();
    h.put_object(
        &full,
        "r/file",
        "content",
        object("md5"),
        WriteCondition::Always,
    )
    .await
    .unwrap();
    let (entry, meta, mut file) = h.fs.open_object(full.clone(), &p("r/file")).await.unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content, "content");
    assert_eq!(entry.size, 7);
    assert_eq!(meta.unwrap().s3_etag.as_deref(), Some("md5"));
    assert_eq!(
        h.fs.open_object(full, &p("r")).await.unwrap_err(),
        ObjectError::IsFolder
    );
}

#[tokio::test]
async fn only_folders_without_files_are_removed() {
    let h = Harness::new().await;
    let full = h.full();
    h.fs.put_folder(full.clone(), &p("empty/a/b"))
        .await
        .unwrap();
    h.put_object(
        &full,
        "kept/a/file",
        "x",
        object("1"),
        WriteCondition::Always,
    )
    .await
    .unwrap();
    assert!(
        h.fs.remove_empty_folder(full.clone(), &p("empty"))
            .await
            .unwrap()
    );
    assert!(!h.disk("empty").exists());
    assert!(
        h.fs.meta()
            .get(h.owner, &p("empty/a"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !h.fs
            .remove_empty_folder(full.clone(), &p("kept"))
            .await
            .unwrap()
    );
    assert!(h.disk("kept/a/file").exists());
    assert!(
        !h.fs
            .remove_empty_folder(full.clone(), &p("missing"))
            .await
            .unwrap()
    );
    assert!(
        !h.fs
            .remove_empty_folder(full.clone(), &p("kept/a/file"))
            .await
            .unwrap()
    );

    let bucket = h.identity(vec![mount("bucket", "kept", true)]);
    assert_eq!(
        h.fs.remove_empty_folder(bucket, &p("bucket")).await,
        Err(ObjectError::Forbidden),
        "a mount root"
    );
}

/// Writes may name the client path as an S3 key spelled it: the file and the folders created
/// for it record the spelling, and another spelling of the same place (a key that differs only
/// in Unicode normalization, in any segment) is refused.
#[tokio::test]
async fn spellings_are_recorded_and_other_spellings_refused() {
    let h = Harness::new().await;
    let full = h.full();
    let nfc = "Caf\u{e9}";
    let nfd = "Cafe\u{301}";
    let put = |client: String, spelled: String| {
        let h = &h;
        let full = full.clone();
        async move {
            let temp = h.upload("x");
            let result =
                h.fs.put_object(
                    full,
                    &p(&client),
                    Some(&spelled),
                    temp.clone(),
                    object("1"),
                    WriteCondition::Always,
                )
                .await;
            if result.is_err() {
                std::fs::remove_file(temp).unwrap();
            }
            result.map(|_| ())
        }
    };
    put(format!("{nfc}/a.txt"), format!("{nfd}/a.txt"))
        .await
        .unwrap();
    let meta = h.fs.meta();
    let row = |rel: String| {
        let meta = meta.clone();
        let owner = h.owner;
        async move { meta.get(owner, &p(&rel)).await.unwrap().unwrap() }
    };
    assert_eq!(row(nfc.to_owned()).await.spelled(), nfd);
    assert_eq!(
        row(format!("{nfc}/a.txt")).await.spelled(),
        format!("{nfd}/a.txt")
    );
    // The same spelling overwrites; another one of the file or of its folder is refused.
    put(format!("{nfc}/a.txt"), format!("{nfd}/a.txt"))
        .await
        .unwrap();
    assert_eq!(
        put(format!("{nfc}/a.txt"), format!("{nfc}/a.txt")).await,
        Err(ObjectError::KeyConflict)
    );
    assert_eq!(
        put(format!("{nfc}/b.txt"), format!("{nfc}/b.txt")).await,
        Err(ObjectError::KeyConflict)
    );
    put(format!("{nfc}/b.txt"), format!("{nfd}/b.txt"))
        .await
        .unwrap();
    // Also when the key's folders below the spelled one are new.
    assert_eq!(
        put(format!("{nfc}/new/c.txt"), format!("{nfc}/new/c.txt")).await,
        Err(ObjectError::KeyConflict)
    );
    assert_eq!(
        row(format!("{nfc}/new")).await.spelled(),
        format!("{nfd}/new"),
        "a new folder is spelled as its parent"
    );
    // Folder markers: the folder's spelling must match too.
    assert_eq!(
        h.fs.put_spelled_folder(full.clone(), &p(nfc), Some(nfc))
            .await
            .unwrap_err(),
        ObjectError::KeyConflict
    );
    h.fs.put_spelled_folder(full.clone(), &p(nfc), Some(nfd))
        .await
        .unwrap();

    // Once no file is below it, the folder holds no key, and another spelling may use it.
    for name in ["a.txt", "b.txt"] {
        assert!(
            h.fs.delete_object(full.clone(), &p(&format!("{nfc}/{name}")))
                .await
                .unwrap()
        );
    }
    put(format!("{nfc}/c.txt"), format!("{nfc}/c.txt"))
        .await
        .unwrap();
    assert_eq!(row(nfc.to_owned()).await.s3_path, None);
    assert_eq!(row(format!("{nfc}/c.txt")).await.s3_path, None);
}

/// Writers of two spellings race into a folder without files: one of them may give the folder
/// its spelling, and every write of the other spelling then fails, so no file is recorded below
/// a folder spelled otherwise. The writers of one spelling start first and the others follow
/// after a delay that differs from round to round, so that in some rounds the folder is respelled
/// while the first ones are between their checks and their records.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn respelling_an_empty_folder_excludes_writers_of_the_old_spelling() {
    let h = Arc::new(Harness::new().await);
    let full = h.full();
    let nfc = "Caf\u{e9}";
    let nfd = "Cafe\u{301}";
    for round in 0..48 {
        let folder = format!("r{round}/{nfc}");
        let spelled_folder = |spelling: &str| format!("r{round}/{spelling}");
        // A folder spelled in NFD without files: it holds no key.
        h.fs.put_spelled_folder(full.clone(), &p(&folder), Some(&spelled_folder(nfd)))
            .await
            .unwrap();
        let delay = std::time::Duration::from_micros(500 * (round % 12));
        let later = if round % 2 == 0 { nfc } else { nfd };
        // Collected, so that every task is spawned before the first is awaited.
        let writes: Vec<_> = (0..16)
            .map(|i| {
                let h = h.clone();
                let full = full.clone();
                let spelling = if i % 2 == 0 { nfc } else { nfd };
                let client = format!("{folder}/f{i}");
                let spelled = format!("{}/f{i}", spelled_folder(spelling));
                tokio::spawn(async move {
                    if spelling == later {
                        tokio::time::sleep(delay).await;
                    }
                    let temp = h.upload("x");
                    let result =
                        h.fs.put_object(
                            full,
                            &p(&client),
                            Some(&spelled),
                            temp.clone(),
                            object("1"),
                            WriteCondition::Always,
                        )
                        .await;
                    match result {
                        Ok(_) => Some(spelling),
                        Err(err) => {
                            assert_eq!(err, ObjectError::KeyConflict, "{spelled}");
                            std::fs::remove_file(temp).unwrap();
                            None
                        }
                    }
                })
            })
            .collect();
        let mut written = Vec::new();
        for write in writes {
            written.push(write.await.unwrap());
        }
        let meta = h.fs.meta();
        let folder_row = meta.get(h.owner, &p(&folder)).await.unwrap().unwrap();
        let winner = folder_row.spelled().rsplit('/').next().unwrap().to_owned();
        for (i, spelling) in written.iter().enumerate() {
            let row = meta
                .get(h.owner, &p(&format!("{folder}/f{i}")))
                .await
                .unwrap();
            match spelling {
                Some(spelling) => {
                    assert_eq!(
                        *spelling, winner,
                        "round {round}: f{i} written as the loser"
                    );
                    let row = row.expect("a written file is recorded");
                    assert_eq!(
                        row.spelled(),
                        format!("{}/f{i}", folder_row.spelled()),
                        "round {round}: f{i} is spelled unlike its folder"
                    );
                }
                None => assert!(row.is_none(), "round {round}: refused f{i} is recorded"),
            }
        }
    }
}
