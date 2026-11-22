//! MetaStore against a real database (SQLite, or MySQL with `GONO_TEST_MYSQL_URL`, see
//! `db::testing`): file ids, ETag and size propagation, dead properties, and subtree operations
//! on names that `LIKE` would get wrong.

use gono_server_core::{
    RelPath, Username,
    db::{self, Backend, Pool, Text},
    meta::{
        Checksum, DeadProp, DiskStat, ListEntry, MetaStore, ObjectListing, ObjectMeta, ObjectPart,
        ObjectQuery, PropChange,
    },
    users::{self, NewUser},
};
use sqlx::Row as _;

struct Fixture {
    _dir: tempfile::TempDir,
    store: MetaStore,
    owner: i64,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let owner = add_user(&pool, "alice").await;
    let store = MetaStore::new(pool);
    store
        .adopt(owner, &[(RelPath::root(), dir_stat())])
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        owner,
    }
}

async fn add_user(pool: &Pool, name: &str) -> i64 {
    let username = Username::new(name).unwrap();
    users::create(
        pool,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: "x",
            is_admin: false,
        },
        |_| Ok(()),
    )
    .await
    .unwrap()
}

fn p(path: &str) -> RelPath {
    RelPath::parse(path).unwrap()
}

fn dir_stat() -> DiskStat {
    DiskStat {
        is_dir: true,
        mtime_ns: 1,
        size: 0,
    }
}

fn file_stat(size: u64) -> DiskStat {
    DiskStat {
        is_dir: false,
        mtime_ns: 1_000,
        size,
    }
}

fn dead(name: &str, value: &str) -> DeadProp {
    DeadProp {
        namespace: "urn:test".into(),
        name: name.into(),
        xml: format!("<x:{name} xmlns:x=\"urn:test\">{value}</x:{name}>").into_bytes(),
    }
}

impl Fixture {
    async fn mkdir(&self, path: &str) -> i64 {
        self.store
            .record_mkdir(self.owner, &p(path), 5)
            .await
            .unwrap()
            .id
    }

    async fn write(&self, path: &str, size: u64) -> i64 {
        self.store
            .record_write(self.owner, &p(path), file_stat(size), None)
            .await
            .unwrap()
            .id
    }

    async fn etag(&self, path: &str) -> String {
        self.store
            .get(self.owner, &p(path))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no row for {path}"))
            .etag
    }

    async fn etags(&self, paths: &[&str]) -> Vec<String> {
        let mut etags = Vec::new();
        for path in paths {
            etags.push(self.etag(path).await);
        }
        etags
    }

    async fn size(&self, path: &str) -> u64 {
        self.store
            .get(self.owner, &p(path))
            .await
            .unwrap()
            .unwrap()
            .size
    }

    async fn exists(&self, path: &str) -> bool {
        self.store
            .get(self.owner, &p(path))
            .await
            .unwrap()
            .is_some()
    }

    async fn tag(&self, path: &str) -> i64 {
        let row = self.store.get(self.owner, &p(path)).await.unwrap().unwrap();
        self.store
            .patch_dead_props(row.id, &[PropChange::Set(dead("marker", "keep-me"))])
            .await
            .unwrap();
        row.id
    }

    async fn marker(&self, id: i64) -> Option<Vec<u8>> {
        self.store
            .dead_prop(id, "urn:test", "marker")
            .await
            .unwrap()
    }

    async fn changes(&self) -> Vec<(String, String, Option<String>)> {
        let rows: Vec<(String, Text, Option<Text>)> = sqlx::query_as(
            "SELECT operation, rel_path, old_rel_path FROM change_log WHERE owner_id = ? \
             ORDER BY id",
        )
        .bind(self.owner)
        .fetch_all(self.store.pool())
        .await
        .unwrap();
        rows.into_iter()
            .map(|(operation, path, old)| (operation, path.0, old.map(String::from)))
            .collect()
    }
}

fn all_changed(before: &[String], after: &[String]) -> bool {
    before.iter().zip(after).all(|(old, new)| old != new)
}

#[tokio::test]
async fn file_ids_are_numeric_stable_and_never_reused() {
    let f = fixture().await;
    f.mkdir("d").await;
    let id = f.write("d/a.txt", 3).await;
    assert_eq!(f.write("d/a.txt", 5).await, id, "overwrite keeps the id");

    let moved = f
        .store
        .record_move(f.owner, &p("d/a.txt"), &p("d/b.txt"), file_stat(5))
        .await
        .unwrap();
    assert_eq!(moved.id, id, "move keeps the id");

    let copy = f
        .store
        .record_copy(
            f.owner,
            &p("d/b.txt"),
            &p("d/c.txt"),
            &[(RelPath::root(), file_stat(5))],
        )
        .await
        .unwrap();
    assert_ne!(copy.id, id, "copy allocates a new id");

    f.store.record_delete(f.owner, &p("d/b.txt")).await.unwrap();
    let recreated = f.write("d/b.txt", 1).await;
    assert!(recreated > copy.id, "ids of deleted entries are not reused");
}

#[tokio::test]
async fn file_etags_change_with_every_write() {
    let f = fixture().await;
    f.write("same.txt", 4).await;
    let first = f.etag("same.txt").await;
    // Same size and mtime: only the per-write nonce distinguishes the versions.
    f.write("same.txt", 4).await;
    assert_ne!(f.etag("same.txt").await, first);
}

#[tokio::test]
async fn every_change_propagates_to_all_ancestors() {
    let f = fixture().await;
    f.mkdir("d1").await;
    f.mkdir("d1/d2").await;
    f.mkdir("other").await;
    f.write("d1/d2/f.txt", 10).await;
    let ancestors = ["", "d1", "d1/d2"];

    let mut before = f.etags(&ancestors).await;
    f.write("d1/d2/f.txt", 12).await;
    let mut after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "modify: {before:?} {after:?}");

    before = after;
    f.write("d1/d2/new.txt", 1).await;
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "create");

    before = after;
    f.mkdir("d1/d2/sub").await;
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "mkdir");

    before = after;
    f.store
        .record_copy(
            f.owner,
            &p("d1/d2/f.txt"),
            &p("d1/d2/g.txt"),
            &[(RelPath::root(), file_stat(12))],
        )
        .await
        .unwrap();
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "copy");

    before = after;
    f.store
        .record_delete(f.owner, &p("d1/d2/new.txt"))
        .await
        .unwrap();
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "delete");

    let both = ["", "d1", "d1/d2", "other"];
    let before = f.etags(&both).await;
    f.store
        .record_move(f.owner, &p("d1/d2/g.txt"), &p("other/g.txt"), file_stat(12))
        .await
        .unwrap();
    let after = f.etags(&both).await;
    assert!(all_changed(&before, &after), "move updates both parents");

    let unrelated = f.etag("other").await;
    f.write("d1/x.txt", 1).await;
    assert_eq!(f.etag("other").await, unrelated, "siblings are not touched");
}

#[tokio::test]
async fn folder_sizes_are_recursive() {
    let f = fixture().await;
    f.mkdir("dir").await;
    f.mkdir("dir/sub").await;
    f.write("dir/a.txt", 5).await;
    f.write("dir/sub/b.txt", 7).await;
    assert_eq!(f.size("dir").await, 12);
    assert_eq!(f.size("").await, 12);

    f.write("dir/a.txt", 2).await;
    assert_eq!(f.size("dir").await, 9);

    f.mkdir("elsewhere").await;
    f.store
        .record_move(f.owner, &p("dir/sub"), &p("elsewhere/sub"), dir_stat())
        .await
        .unwrap();
    assert_eq!(f.size("dir").await, 2);
    assert_eq!(f.size("elsewhere").await, 7);
    assert_eq!(f.size("elsewhere/sub").await, 7);

    f.store
        .record_copy(
            f.owner,
            &p("elsewhere/sub"),
            &p("dir/copy"),
            &[(RelPath::root(), dir_stat()), (p("b.txt"), file_stat(7))],
        )
        .await
        .unwrap();
    assert_eq!(f.size("dir/copy").await, 7);
    assert_eq!(f.size("dir").await, 9);

    f.store.record_delete(f.owner, &p("dir")).await.unwrap();
    assert_eq!(f.size("").await, 7);
}

/// Regression for the legacy `LIKE 'photos_1/%'` bug: `_` and `%` are ordinary characters.
#[tokio::test]
async fn wildcard_characters_do_not_leak_into_siblings() {
    let f = fixture().await;
    for (doomed, sibling) in [("photos_1", "photosX1"), ("a%", "ab"), ("c_d", "c%d")] {
        f.mkdir(doomed).await;
        f.write(&format!("{doomed}/inner.txt"), 1).await;
        f.mkdir(sibling).await;
        f.write(&format!("{sibling}/x.txt"), 1).await;
        let id = f.tag(&format!("{sibling}/x.txt")).await;

        f.store.record_delete(f.owner, &p(doomed)).await.unwrap();
        assert!(!f.exists(&format!("{doomed}/inner.txt")).await);
        assert!(
            f.exists(&format!("{sibling}/x.txt")).await,
            "{sibling} after deleting {doomed}"
        );
        assert!(
            f.marker(id).await.is_some(),
            "dead property of {sibling}/x.txt"
        );
    }
}

#[tokio::test]
async fn moving_a_wildcard_name_leaves_siblings_alone() {
    let f = fixture().await;
    f.mkdir("photos_1").await;
    f.write("photos_1/inner.txt", 1).await;
    f.mkdir("photosX1").await;
    f.write("photosX1/x.txt", 1).await;
    let id = f.tag("photosX1/x.txt").await;

    f.store
        .record_move(f.owner, &p("photos_1"), &p("renamed"), dir_stat())
        .await
        .unwrap();
    assert!(f.exists("renamed/inner.txt").await);
    assert!(!f.exists("photos_1/inner.txt").await);
    let sibling = f
        .store
        .get(f.owner, &p("photosX1/x.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sibling.id, id);
    assert!(f.marker(id).await.is_some());
}

/// `Docs` and `docs` are different entries; SQLite's `LIKE` would have matched both.
#[tokio::test]
async fn names_differing_only_in_case_are_distinct() {
    let f = fixture().await;
    f.mkdir("Docs").await;
    f.write("Docs/inner.txt", 1).await;
    f.mkdir("docs").await;
    f.write("docs/x.txt", 1).await;
    let id = f.tag("docs/x.txt").await;
    assert_ne!(
        f.store.get(f.owner, &p("Docs")).await.unwrap().unwrap().id,
        f.store.get(f.owner, &p("docs")).await.unwrap().unwrap().id
    );

    f.store.record_delete(f.owner, &p("Docs")).await.unwrap();
    assert!(f.exists("docs/x.txt").await);
    assert!(f.marker(id).await.is_some());

    f.mkdir("DOCS").await;
    f.store
        .record_move(f.owner, &p("docs"), &p("Moved"), dir_stat())
        .await
        .unwrap();
    assert!(f.exists("DOCS").await, "case variant untouched by the move");
    assert!(f.exists("Moved/x.txt").await);
}

/// MySQL's `utf8mb4_bin` would call `a` and `a ` equal; the paths are VARBINARY there, so
/// every backend keeps them apart, like the file system does.
#[tokio::test]
async fn names_differing_only_in_trailing_spaces_are_distinct() {
    let f = fixture().await;
    let plain = f.write("a", 1).await;
    let spaced = f.write("a ", 2).await;
    let twice = f.write("a  ", 3).await;
    assert!(plain != spaced && spaced != twice && plain != twice);
    for (path, id, size) in [("a", plain, 1), ("a ", spaced, 2), ("a  ", twice, 3)] {
        let row = f.store.get(f.owner, &p(path)).await.unwrap().unwrap();
        assert_eq!((row.id, row.size, row.rel_path.as_str()), (id, size, path));
    }
    f.mkdir("d ").await;
    f.write("d /x", 4).await;
    f.mkdir("d").await;
    assert!(f.exists("d /x").await, "creating `d` left `d ` alone");
    f.store.record_delete(f.owner, &p("a ")).await.unwrap();
    assert!(f.exists("a").await && f.exists("a  ").await);
    assert!(!f.exists("a ").await);
    assert_eq!(
        f.store
            .get(f.owner, &RelPath::root())
            .await
            .unwrap()
            .unwrap()
            .size,
        8
    );
}

/// Paths of up to 4096 bytes are stored on every backend; longer ones on none, also when a
/// move or a copy would make them.
#[tokio::test]
async fn paths_longer_than_4096_bytes_are_refused() {
    let f = fixture().await;
    let segment = "s".repeat(255);
    // 15 folders of 255 bytes and one of 200: 4040 bytes with the slashes.
    let mut deep = RelPath::root();
    for index in 0..16 {
        let name = if index < 15 {
            segment.clone()
        } else {
            "t".repeat(200)
        };
        deep = deep.join(&name);
        f.store.record_mkdir(f.owner, &deep, 5).await.unwrap();
    }
    assert_eq!(deep.as_str().len(), 4040);
    let longest = deep.join(&"f".repeat(4096 - deep.as_str().len() - 1));
    assert_eq!(longest.as_str().len(), 4096);
    f.store
        .record_write(f.owner, &longest, file_stat(1), None)
        .await
        .unwrap();
    let row = f.store.get(f.owner, &longest).await.unwrap().unwrap();
    assert_eq!(row.rel_path, longest);

    let too_long = deep.join(&"g".repeat(4096 - deep.as_str().len()));
    assert!(too_long.check_length().is_err());
    assert_eq!(too_long.as_str().len(), 4097);
    let err = f
        .store
        .record_write(f.owner, &too_long, file_stat(1), None)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            gono_server_core::Error::InvalidPath {
                source: gono_server_core::path::PathError::PathTooLong,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(f.store.get(f.owner, &too_long).await.unwrap().is_none());

    // Moving the tree one level deeper would make its file 4098 bytes long: refused, and
    // nothing moves.
    f.mkdir("x").await;
    let top = p(&segment);
    let err = f
        .store
        .record_move(f.owner, &top, &p(&format!("x/{segment}")), dir_stat())
        .await
        .unwrap_err();
    assert!(
        matches!(err, gono_server_core::Error::InvalidPath { .. }),
        "{err:?}"
    );
    assert!(f.exists(longest.as_str()).await);
    // A copy that would be too long fails as a whole.
    let err = f
        .store
        .record_copy(
            f.owner,
            &longest,
            &deep.join(&"h".repeat(4096 - deep.as_str().len())),
            &[(RelPath::root(), file_stat(1))],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, gono_server_core::Error::InvalidPath { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn dead_props_follow_moves_and_copies_and_die_with_deletes() {
    let f = fixture().await;
    f.mkdir("dir").await;
    f.write("dir/file.txt", 1).await;
    let original = f.tag("dir/file.txt").await;
    let row = f
        .store
        .get(f.owner, &p("dir/file.txt"))
        .await
        .unwrap()
        .unwrap();
    f.store.set_favorite(row.id, true).await.unwrap();

    let copied = f
        .store
        .record_copy(
            f.owner,
            &p("dir"),
            &p("copied"),
            &[(RelPath::root(), dir_stat()), (p("file.txt"), file_stat(1))],
        )
        .await
        .unwrap();
    let copied_file = f
        .store
        .get(f.owner, &p("copied/file.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(copied.id, original);
    assert!(
        f.marker(copied_file.id).await.is_some(),
        "copied dead property"
    );
    assert!(!copied_file.favorite, "favorites are not copied");

    f.store
        .record_move(f.owner, &p("dir"), &p("moved"), dir_stat())
        .await
        .unwrap();
    let moved = f
        .store
        .get(f.owner, &p("moved/file.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(moved.id, original);
    assert!(moved.favorite, "favorites move along");
    assert!(f.marker(original).await.is_some());

    f.store
        .record_delete(f.owner, &p("moved/file.txt"))
        .await
        .unwrap();
    assert!(f.marker(original).await.is_none());
    let reborn = f.write("moved/file.txt", 1).await;
    assert!(
        f.marker(reborn).await.is_none(),
        "delete and re-create starts clean"
    );
}

#[tokio::test]
async fn dead_props_of_many_entries_are_loaded_together() {
    let f = fixture().await;
    let a = f.write("a.txt", 1).await;
    let b = f.write("b.txt", 1).await;
    let c = f.write("c.txt", 1).await;
    for (id, name) in [(a, "x"), (a, "y"), (c, "z")] {
        f.store
            .patch_dead_props(id, &[PropChange::Set(dead(name, "1"))])
            .await
            .unwrap();
    }
    // More ids than one batch holds.
    let mut ids: Vec<i64> = (100_000..100_900).collect();
    ids.extend([a, b, c]);
    let found = f.store.dead_props_many(&ids).await.unwrap();
    let names = |id: i64| -> Vec<String> {
        found
            .get(&id)
            .map(|props| props.iter().map(|prop| prop.name.clone()).collect())
            .unwrap_or_default()
    };
    assert_eq!(names(a), ["x", "y"]);
    assert!(!found.contains_key(&b), "entries without any are absent");
    assert_eq!(names(c), ["z"]);
    assert_eq!(found.len(), 2);
}

#[tokio::test]
async fn creation_times_survive_writes_and_moves_and_are_copied() {
    let f = fixture().await;
    let id = f.write("a.txt", 1).await;
    let row = |path: &'static str| {
        let store = f.store.clone();
        let owner = f.owner;
        async move { store.get(owner, &p(path)).await.unwrap().unwrap() }
    };
    assert_eq!(
        row("a.txt").await.creation_time,
        0,
        "unknown until reported"
    );
    let etag = f.etag("a.txt").await;
    f.store.set_creation_time(id, 1_600_000_000).await.unwrap();
    assert_eq!(row("a.txt").await.creation_time, 1_600_000_000);
    assert_eq!(f.etag("a.txt").await, etag, "not content");

    f.write("a.txt", 2).await;
    assert_eq!(row("a.txt").await.creation_time, 1_600_000_000, "overwrite");
    f.store
        .record_move(f.owner, &p("a.txt"), &p("b.txt"), file_stat(2))
        .await
        .unwrap();
    assert_eq!(row("b.txt").await.creation_time, 1_600_000_000, "move");
    let copy = f
        .store
        .record_copy(
            f.owner,
            &p("b.txt"),
            &p("c.txt"),
            &[(RelPath::root(), file_stat(2))],
        )
        .await
        .unwrap();
    assert_eq!(copy.creation_time, 1_600_000_000, "copy");
    assert_eq!(row("c.txt").await.creation_time, 1_600_000_000);
}

#[tokio::test]
async fn dead_props_can_be_set_replaced_and_removed() {
    let f = fixture().await;
    let id = f.write("props.txt", 1).await;
    let remove = |name: &str| PropChange::Remove("urn:test".into(), name.into());
    f.store
        .patch_dead_props(
            id,
            &[
                PropChange::Set(dead("color", "blue")),
                PropChange::Set(dead("size", "large")),
            ],
        )
        .await
        .unwrap();
    f.store
        .patch_dead_props(id, &[PropChange::Set(dead("color", "red")), remove("size")])
        .await
        .unwrap();
    assert_eq!(
        f.store.dead_props(id).await.unwrap(),
        [dead("color", "red")]
    );

    // Changes apply in request order.
    f.store
        .patch_dead_props(
            id,
            &[remove("shape"), PropChange::Set(dead("shape", "round"))],
        )
        .await
        .unwrap();
    f.store
        .patch_dead_props(id, &[PropChange::Set(dead("color", "x")), remove("color")])
        .await
        .unwrap();
    assert_eq!(
        f.store.dead_props(id).await.unwrap(),
        [dead("shape", "round")]
    );
}

#[tokio::test]
async fn moves_replace_the_destination() {
    let f = fixture().await;
    f.write("source.txt", 3).await;
    let target = f.write("target.txt", 10).await;
    f.tag("target.txt").await;
    assert_eq!(f.size("").await, 13);

    let moved = f
        .store
        .record_move(f.owner, &p("source.txt"), &p("target.txt"), file_stat(3))
        .await
        .unwrap();
    assert_ne!(moved.id, target);
    assert!(
        f.marker(target).await.is_none(),
        "replaced entry's metadata is gone"
    );
    assert_eq!(f.size("").await, 3);
}

#[tokio::test]
async fn adoption_creates_rows_without_signalling_a_change() {
    let f = fixture().await;
    let root_etag = f.etag("").await;
    let rows = f
        .store
        .adopt(
            f.owner,
            &[(p("found.txt"), file_stat(4)), (p("found-dir"), dir_stat())],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].etag,
        gono_server_core::meta::derived_file_etag(rows[0].id, 1_000, 4)
    );
    assert_eq!(f.etag("").await, root_etag);
    let again = f
        .store
        .adopt(f.owner, &[(p("found.txt"), file_stat(9))])
        .await
        .unwrap();
    assert_eq!(again[0], rows[0], "existing rows are kept as they are");
    assert!(f.changes().await.is_empty());

    let many = f
        .store
        .get_many(f.owner, &[p("found.txt"), p("found-dir"), p("missing")])
        .await
        .unwrap();
    assert_eq!(many.len(), 2);
}

#[tokio::test]
async fn changes_are_logged_in_the_same_transaction() {
    let f = fixture().await;
    f.mkdir("d").await;
    f.write("d/a.txt", 1).await;
    f.write("d/a.txt", 2).await;
    f.store
        .record_move(f.owner, &p("d/a.txt"), &p("d/b.txt"), file_stat(2))
        .await
        .unwrap();
    f.store.record_delete(f.owner, &p("d")).await.unwrap();
    let ops = |op: &str, path: &str, old: Option<&str>| {
        (op.to_owned(), path.to_owned(), old.map(str::to_owned))
    };
    assert_eq!(
        f.changes().await,
        [
            ops("create", "d", None),
            ops("create", "d/a.txt", None),
            ops("modify", "d/a.txt", None),
            ops("move", "d/b.txt", Some("d/a.txt")),
            ops("delete", "d", None),
        ]
    );
    assert!(f.store.subtree(f.owner, &p("d")).await.unwrap().is_empty());
}

#[tokio::test]
async fn favorites_are_listed_by_subtree() {
    let f = fixture().await;
    f.mkdir("a").await;
    f.mkdir("a/b").await;
    f.mkdir("a_").await;
    for path in ["a/x.txt", "a/b/y.txt", "a_/z.txt", "top.txt"] {
        f.write(path, 1).await;
    }
    for path in ["a", "a/b/y.txt", "a_/z.txt", "top.txt"] {
        let id = f.store.get(f.owner, &p(path)).await.unwrap().unwrap().id;
        f.store.set_favorite(id, true).await.unwrap();
    }
    let paths = |rows: Vec<gono_server_core::meta::FileRow>| -> Vec<String> {
        rows.into_iter()
            .map(|row| row.rel_path.as_str().to_owned())
            .collect()
    };

    let below_a = f.store.favorites(f.owner, &p("a"), false).await.unwrap();
    assert_eq!(paths(below_a), ["a/b/y.txt"], "no wildcard sibling a_");
    let with_a = f.store.favorites(f.owner, &p("a"), true).await.unwrap();
    assert_eq!(paths(with_a), ["a", "a/b/y.txt"]);
    let everything = f
        .store
        .favorites(f.owner, &RelPath::root(), false)
        .await
        .unwrap();
    assert_eq!(paths(everything), ["a", "a/b/y.txt", "a_/z.txt", "top.txt"]);

    let root = f
        .store
        .get(f.owner, &RelPath::root())
        .await
        .unwrap()
        .unwrap();
    f.store.set_favorite(root.id, true).await.unwrap();
    let root_only =
        |rows: Vec<gono_server_core::meta::FileRow>| rows.iter().any(|r| r.rel_path.is_root());
    assert!(!root_only(
        f.store
            .favorites(f.owner, &RelPath::root(), false)
            .await
            .unwrap()
    ));
    assert!(root_only(
        f.store
            .favorites(f.owner, &RelPath::root(), true)
            .await
            .unwrap()
    ));
}

/// Records the published events.
#[derive(Debug, Default)]
struct Recorder(std::sync::Mutex<Vec<gono_server_core::meta::ChangeEvent>>);

impl gono_server_core::meta::ChangeSink for Recorder {
    fn publish(&self, event: &gono_server_core::meta::ChangeEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[tokio::test]
async fn every_logged_change_is_published_after_the_commit() {
    use gono_server_core::meta::ChangeOperation;

    let fixture = fixture().await;
    let recorder = std::sync::Arc::new(Recorder::default());
    let store = fixture.store.clone().with_sink(recorder.clone());
    let owner = fixture.owner;
    let before = store.latest_change_id().await.unwrap();

    let dir = store.record_mkdir(owner, &p("d"), 1).await.unwrap();
    let file = store
        .record_write(owner, &p("d/f.txt"), file_stat(3), None)
        .await
        .unwrap();
    store
        .record_write(owner, &p("d/f.txt"), file_stat(4), None)
        .await
        .unwrap();
    store
        .record_copy(owner, &p("d"), &p("e"), &[(RelPath::root(), dir_stat())])
        .await
        .unwrap();
    store
        .record_move(owner, &p("e"), &p("g"), dir_stat())
        .await
        .unwrap();
    store.record_delete(owner, &p("d")).await.unwrap();
    // Not content changes: nothing is published.
    store.set_favorite(file.id, true).await.unwrap();

    let published = recorder.0.lock().unwrap().clone();
    let summary: Vec<(ChangeOperation, &str, Option<&str>)> = published
        .iter()
        .map(|event| {
            (
                event.operation,
                event.rel_path.as_str(),
                event.old_rel_path.as_ref().map(RelPath::as_str),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (ChangeOperation::Create, "d", None),
            (ChangeOperation::Create, "d/f.txt", None),
            (ChangeOperation::Modify, "d/f.txt", None),
            (ChangeOperation::Create, "e", None),
            (ChangeOperation::Move, "g", Some("e")),
            (ChangeOperation::Delete, "d", None),
        ]
    );
    // The delete carries the id the directory had: its row is gone by now.
    assert_eq!(published[5].file_id, dir.id);
    assert!(store.get(owner, &p("d")).await.unwrap().is_none());
    assert!(published.iter().all(|event| event.owner_id == owner));

    // The change log holds the same events, in the same order, with the same ids.
    let logged = store.changes_since(before, 100).await.unwrap();
    assert_eq!(logged, published);
    assert_eq!(
        store.latest_change_id().await.unwrap(),
        published.last().unwrap().id
    );
    assert_eq!(
        store.changes_since(before, 2).await.unwrap(),
        published[..2]
    );
}

fn entries(list: &[(&str, Option<u64>)]) -> Vec<(RelPath, DiskStat)> {
    list.iter()
        .map(|(path, size)| {
            let stat = match size {
                Some(size) => file_stat(*size),
                None => dir_stat(),
            };
            (p(path), stat)
        })
        .collect()
}

#[tokio::test]
async fn reconcile_adds_removes_and_updates_what_changed_on_disk() {
    use gono_server_core::meta::ChangeOperation;

    let fixture = fixture().await;
    let recorder = std::sync::Arc::new(Recorder::default());
    let store = fixture.store.clone().with_sink(recorder.clone());
    let owner = fixture.owner;
    store.record_mkdir(owner, &p("docs"), 1).await.unwrap();
    let kept = store
        .record_write(owner, &p("docs/kept.txt"), file_stat(10), None)
        .await
        .unwrap();
    let changed = store
        .record_write(owner, &p("docs/changed.txt"), file_stat(20), None)
        .await
        .unwrap();
    store.record_mkdir(owner, &p("old"), 1).await.unwrap();
    store
        .record_write(owner, &p("old/gone.txt"), file_stat(5), None)
        .await
        .unwrap();
    let root_before = store.get(owner, &RelPath::root()).await.unwrap().unwrap();
    assert_eq!(root_before.size, 35);
    recorder.0.lock().unwrap().clear();

    // On disk: `old` is gone, `changed.txt` grew, `new/a/b.txt` appeared.
    let disk = entries(&[
        ("", None),
        ("docs", None),
        ("docs/changed.txt", Some(25)),
        ("docs/kept.txt", Some(10)),
        ("new", None),
        ("new/a", None),
        ("new/a/b.txt", Some(7)),
    ]);
    let dry = store
        .reconcile(owner, &RelPath::root(), &[], &disk, true)
        .await
        .unwrap();
    assert_eq!(dry.added, [p("new")]);
    assert!(
        recorder.0.lock().unwrap().is_empty(),
        "a dry run publishes nothing"
    );
    assert!(
        store.get(owner, &p("old")).await.unwrap().is_some(),
        "and changes nothing"
    );

    let report = store
        .reconcile(owner, &RelPath::root(), &[], &disk, false)
        .await
        .unwrap();
    assert_eq!(report, dry, "the dry run predicts the real run");
    assert_eq!(report.added, [p("new")]);
    assert_eq!(report.added_rows, 3);
    assert_eq!(report.removed, [p("old")]);
    assert_eq!(report.removed_rows, 2);
    assert_eq!(report.modified, [p("docs/changed.txt")]);

    // Rows, sizes and ETags.
    assert!(
        store
            .get(owner, &p("old/gone.txt"))
            .await
            .unwrap()
            .is_none()
    );
    let file = store
        .get(owner, &p("docs/changed.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file.id, changed.id, "the file id is kept");
    assert_eq!(
        file.etag,
        gono_server_core::meta::derived_file_etag(file.id, 1_000, 25)
    );
    let unchanged = store
        .get(owner, &p("docs/kept.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.etag, kept.etag);
    let root = store.get(owner, &RelPath::root()).await.unwrap().unwrap();
    assert_eq!(root.size, 42);
    assert_ne!(root.etag, root_before.etag);
    assert_eq!(
        store.get(owner, &p("new/a")).await.unwrap().unwrap().size,
        7
    );

    // The change log names every top-most change, in order.
    let published: Vec<(ChangeOperation, String)> = recorder
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|event| (event.operation, event.rel_path.as_str().to_owned()))
        .collect();
    assert_eq!(
        published,
        [
            (ChangeOperation::Delete, "old".to_owned()),
            (ChangeOperation::Create, "new".to_owned()),
            (ChangeOperation::Modify, "docs/changed.txt".to_owned()),
        ]
    );

    // A second run finds nothing to do.
    let again = store
        .reconcile(owner, &RelPath::root(), &[], &disk, false)
        .await
        .unwrap();
    assert!(again.is_empty(), "{again:?}");
}

#[tokio::test]
async fn reconcile_of_a_subtree_corrects_sizes_and_leaves_the_rest_alone() {
    let fixture = fixture().await;
    let store = &fixture.store;
    let owner = fixture.owner;
    store.record_mkdir(owner, &p("a"), 1).await.unwrap();
    store.record_mkdir(owner, &p("a/b"), 1).await.unwrap();
    store
        .record_write(owner, &p("a/b/f.txt"), file_stat(10), None)
        .await
        .unwrap();
    store
        .record_write(owner, &p("other.txt"), file_stat(100), None)
        .await
        .unwrap();
    let a_before = store.get(owner, &p("a")).await.unwrap().unwrap();

    // `a/b` lost its file and got a bigger one; the rest of the tree is not looked at.
    let ancestors = entries(&[("", None), ("a", None)]);
    let disk = entries(&[("a/b", None), ("a/b/g.txt", Some(30))]);
    let report = store
        .reconcile(owner, &p("a/b"), &ancestors, &disk, false)
        .await
        .unwrap();
    assert_eq!(report.added, [p("a/b/g.txt")]);
    assert_eq!(report.removed, [p("a/b/f.txt")]);
    assert!(store.get(owner, &p("other.txt")).await.unwrap().is_some());
    assert_eq!(store.get(owner, &p("a/b")).await.unwrap().unwrap().size, 30);
    let a = store.get(owner, &p("a")).await.unwrap().unwrap();
    assert_eq!(a.size, 30);
    assert_ne!(a.etag, a_before.etag);
    assert_eq!(
        store
            .get(owner, &RelPath::root())
            .await
            .unwrap()
            .unwrap()
            .size,
        130
    );

    // A scope that disappeared takes its rows along; its ancestors shrink.
    let report = store
        .reconcile(owner, &p("a/b"), &ancestors, &[], false)
        .await
        .unwrap();
    assert_eq!(report.removed, [p("a/b")]);
    assert_eq!(report.removed_rows, 2);
    assert_eq!(store.get(owner, &p("a")).await.unwrap().unwrap().size, 0);
    assert_eq!(
        store
            .get(owner, &RelPath::root())
            .await
            .unwrap()
            .unwrap()
            .size,
        100
    );
}

#[tokio::test]
async fn reconcile_fixes_drifted_directory_sizes() {
    let fixture = fixture().await;
    let store = &fixture.store;
    let owner = fixture.owner;
    store.record_mkdir(owner, &p("d"), 1).await.unwrap();
    store
        .record_write(owner, &p("d/f"), file_stat(8), None)
        .await
        .unwrap();
    sqlx::query("UPDATE files SET size = 999 WHERE rel_path = 'd'")
        .execute(store.pool())
        .await
        .unwrap();
    let disk = entries(&[("", None), ("d", None), ("d/f", Some(8))]);
    let report = store
        .reconcile(owner, &RelPath::root(), &[], &disk, false)
        .await
        .unwrap();
    assert_eq!(report.resized, 1);
    assert!(report.added.is_empty() && report.removed.is_empty());
    assert_eq!(store.get(owner, &p("d")).await.unwrap().unwrap().size, 8);
}

#[tokio::test]
async fn names_are_searched_by_subtree_ignoring_case() {
    let f = fixture().await;
    f.mkdir("Photos").await;
    f.mkdir("Photos/2026").await;
    f.mkdir("photo_").await;
    for path in [
        "Photos/2026/Beach.JPG",
        "Photos/notes.txt",
        "photo_/x.txt",
        "Über.txt",
        "50%_off.txt",
        "500_off.txt",
    ] {
        f.write(path, 1).await;
    }
    let search = |dir: &'static str, needle: &'static str, limit: usize| {
        let store = f.store.clone();
        let owner = f.owner;
        async move {
            store
                .search_names(owner, &p(dir), needle, limit)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.rel_path.as_str().to_owned())
                .collect::<Vec<_>>()
        }
    };

    // Names only: "Photos/notes.txt" matches "photo" through its folder, not its name.
    assert_eq!(search("", "PHOTO", 10).await, ["Photos", "photo_"]);
    assert_eq!(search("", "beach", 10).await, ["Photos/2026/Beach.JPG"]);
    assert_eq!(search("Photos", "2026", 10).await, ["Photos/2026"]);
    assert!(search("photo_", "beach", 10).await.is_empty(), "no sibling");
    // Unicode case and LIKE wildcards are literal.
    assert_eq!(search("", "über", 10).await, ["Über.txt"]);
    assert_eq!(search("", "%_", 10).await, ["50%_off.txt"]);
    assert_eq!(search("", "txt", 2).await.len(), 2, "limit");
    assert!(search("", "", 10).await.is_empty());
}

/// The narrowing `LIKE` of an ASCII needle ignores ASCII case only, on every backend: `İ`
/// (U+0130) lowercases to `i` and a combining dot in Unicode, but SQLite's `LIKE` (and MySQL's
/// emulation of it) sees no `i` in it, so `İpek` is not found for `i`. Every backend returns
/// these exact rows.
#[tokio::test]
async fn name_search_matches_on_every_backend() {
    let f = fixture().await;
    for path in [
        "\u{130}pek",
        "KELVIN.md",
        "kelvin_",
        "Ünïcode.TXT",
        "back\\slash",
        "trailing ",
        "MiXeD",
        "naïve",
    ] {
        f.write(path, 1).await;
    }
    let search = |needle: &'static str| {
        let store = f.store.clone();
        let owner = f.owner;
        async move {
            store
                .search_names(owner, &RelPath::root(), needle, 10)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.rel_path.as_str().to_owned())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(search("kelvin").await, ["KELVIN.md", "kelvin_"]);
    assert_eq!(
        search("i").await,
        ["KELVIN.md", "MiXeD", "kelvin_", "trailing "]
    );
    // A needle that is not ASCII skips the narrowing: Unicode lowercasing alone decides.
    assert_eq!(search("i\u{307}").await, ["\u{130}pek"]);
    assert_eq!(search("ünï").await, ["Ünïcode.TXT"]);
    assert_eq!(search(".txt").await, ["Ünïcode.TXT"]);
    assert_eq!(search("\\").await, ["back\\slash"]);
    assert_eq!(search("g ").await, ["trailing "]);
    assert_eq!(search("XED").await, ["MiXeD"]);
    assert_eq!(search("NAÏ").await, ["naïve"]);
    assert_eq!(search("_").await, ["kelvin_"]);
}

fn object(etag: &str) -> ObjectMeta {
    ObjectMeta {
        s3_etag: Some(etag.to_owned()),
        content_type: Some("image/png".to_owned()),
        cache_control: Some("max-age=60".to_owned()),
        user_meta: [("mtime".to_owned(), "1700000000.5".to_owned())].into(),
        checksum: Some(Checksum {
            algorithm: "CRC32".to_owned(),
            value: "AAAAAA==".to_owned(),
            composite: false,
        }),
        ..ObjectMeta::default()
    }
}

impl Fixture {
    async fn put_object(&self, path: &str, size: u64, meta: &ObjectMeta) -> i64 {
        self.store
            .record_object_write(self.owner, &p(path), file_stat(size), None, meta, None)
            .await
            .unwrap()
            .id
    }

    async fn object_meta(&self, path: &str) -> Option<ObjectMeta> {
        let row = self.store.get(self.owner, &p(path)).await.unwrap()?;
        self.store.object_meta(row.id).await.unwrap()
    }

    async fn list(
        &self,
        root: &str,
        prefix: &str,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_entries: usize,
    ) -> ObjectListing {
        self.store
            .list_objects(
                self.owner,
                ObjectQuery {
                    root: &p(root),
                    prefix,
                    delimiter,
                    start_after,
                    max_entries,
                },
            )
            .await
            .unwrap()
    }
}

/// Objects as `key`, common prefixes as `key/` marked with a trailing `*`.
fn names(listing: &ObjectListing) -> Vec<String> {
    listing
        .entries
        .iter()
        .map(|entry| match entry {
            ListEntry::Object(object) => object.key.clone(),
            ListEntry::CommonPrefix(prefix) => format!("{prefix}*"),
        })
        .collect()
}

#[tokio::test]
async fn object_meta_belongs_to_one_version() {
    let f = fixture().await;
    f.mkdir("b").await;
    let id = f.put_object("b/a.png", 3, &object("md5-one")).await;
    let stored = f.object_meta("b/a.png").await.unwrap();
    assert_eq!(stored, object("md5-one"));
    assert_eq!(stored.etag_or("dav"), "md5-one");

    // Another S3 write replaces it; the file keeps its id.
    let mut second = object("md5-two");
    second.content_type = None;
    second.checksum = None;
    second.user_meta.clear();
    assert_eq!(f.put_object("b/a.png", 4, &second).await, id);
    assert_eq!(f.object_meta("b/a.png").await.unwrap(), second);

    // A write that is not an S3 write removes it.
    assert_eq!(f.write("b/a.png", 5).await, id);
    assert_eq!(f.object_meta("b/a.png").await, None);

    // A MOVE keeps it, a COPY does not copy it, a DELETE removes it.
    f.put_object("b/a.png", 6, &object("md5-three")).await;
    f.store
        .record_move(f.owner, &p("b/a.png"), &p("b/moved.png"), file_stat(6))
        .await
        .unwrap();
    assert_eq!(
        f.object_meta("b/moved.png")
            .await
            .unwrap()
            .s3_etag
            .as_deref(),
        Some("md5-three")
    );
    f.store
        .record_copy(
            f.owner,
            &p("b/moved.png"),
            &p("b/copy.png"),
            &[(RelPath::root(), file_stat(6))],
        )
        .await
        .unwrap();
    assert_eq!(f.object_meta("b/copy.png").await, None);
    f.store
        .record_delete(f.owner, &p("b/moved.png"))
        .await
        .unwrap();
    let orphans: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM object_meta WHERE file_id = ?")
        .bind(id)
        .fetch_one(f.store.pool())
        .await
        .unwrap();
    assert_eq!(orphans, 0);
}

/// The MD5 of a file's content is recorded with the version, carried by COPY and MOVE, dropped
/// by a write without one and by content that changed on disk, and filled in for the version
/// it was computed for only.
#[tokio::test]
async fn md5s_belong_to_one_version() {
    let f = fixture().await;
    f.mkdir("d").await;
    let md5 = |byte: u8| [byte; 16];
    let row = |path: &'static str| {
        let f = &f;
        async move { f.store.get(f.owner, &p(path)).await.unwrap().unwrap() }
    };
    let written = f
        .store
        .record_write(f.owner, &p("d/a"), file_stat(3), Some(md5(1)))
        .await
        .unwrap();
    assert_eq!(written.md5, Some(md5(1)));
    assert_eq!(row("d/a").await.md5_hex().unwrap(), "01".repeat(16));

    f.store
        .record_copy(
            f.owner,
            &p("d"),
            &p("copy"),
            &[(RelPath::root(), dir_stat()), (p("a"), file_stat(3))],
        )
        .await
        .unwrap();
    assert_eq!(
        row("copy/a").await.md5,
        Some(md5(1)),
        "a copy has the same content"
    );
    f.store
        .record_move(f.owner, &p("copy/a"), &p("copy/b"), file_stat(3))
        .await
        .unwrap();
    assert_eq!(row("copy/b").await.md5, Some(md5(1)));

    // Changed behind the server's back: unknown again, and listed for `rescan --checksums`.
    let changed = DiskStat {
        mtime_ns: 2_000,
        ..file_stat(4)
    };
    f.store
        .reconcile(
            f.owner,
            &p("copy"),
            &[],
            &[(p("copy"), dir_stat()), (p("copy/b"), changed)],
            false,
        )
        .await
        .unwrap();
    let stale = row("copy/b").await;
    assert_eq!(stale.md5, None);
    let missing = f.store.files_without_md5(None, 0, 10).await.unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0], (f.owner, stale.clone()));
    assert!(
        f.store
            .files_without_md5(Some(f.owner + 1), 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!f.store.set_md5(stale.id, "old", md5(2)).await.unwrap());
    assert!(
        f.store
            .set_md5(stale.id, &stale.etag, md5(2))
            .await
            .unwrap()
    );
    assert_eq!(row("copy/b").await.md5, Some(md5(2)));
    assert_eq!(row("copy/b").await.etag, stale.etag, "the ETag stays");

    // A write that computed none leaves none.
    f.write("d/a", 5).await;
    assert_eq!(row("d/a").await.md5, None);
}

/// Tags are S3 metadata of one version: set for the version they name, kept by an ACL change,
/// dropped by a write that is not an S3 write.
#[tokio::test]
async fn object_tags_belong_to_one_version() {
    let f = fixture().await;
    f.mkdir("b").await;
    let tags: std::collections::BTreeMap<String, String> =
        [("project".to_owned(), "blue".to_owned())].into();
    let tagged = ObjectMeta {
        tags: tags.clone(),
        ..object("md5-1")
    };
    let id = f.put_object("b/a", 3, &tagged).await;
    assert_eq!(f.object_meta("b/a").await.unwrap().tags, tags);

    let etag = f.store.get(f.owner, &p("b/a")).await.unwrap().unwrap().etag;
    let other: std::collections::BTreeMap<String, String> =
        [("project".to_owned(), "red".to_owned())].into();
    assert!(!f.store.set_object_tags(id, "old", &other).await.unwrap());
    assert!(f.store.set_object_tags(id, &etag, &other).await.unwrap());
    assert!(f.store.set_object_public(id, &etag, true).await.unwrap());
    let stored = f.object_meta("b/a").await.unwrap();
    assert_eq!(stored.tags, other);
    assert_eq!(
        stored.s3_etag.as_deref(),
        Some("md5-1"),
        "only the tags changed"
    );

    // A file without S3 metadata gets a row for its version.
    f.write("b/a", 4).await;
    assert_eq!(f.object_meta("b/a").await, None);
    let etag = f.store.get(f.owner, &p("b/a")).await.unwrap().unwrap().etag;
    assert!(f.store.set_object_tags(id, &etag, &tags).await.unwrap());
    let stored = f.object_meta("b/a").await.unwrap();
    assert_eq!((stored.tags, stored.s3_etag), (tags, None));
}

/// The parts of a multipart object are stored with its metadata, in order, and go with it.
#[tokio::test]
async fn object_parts_belong_to_one_version() {
    let f = fixture().await;
    f.mkdir("b").await;
    let parts = vec![
        ObjectPart {
            size: 5,
            checksum: Some("one".to_owned()),
        },
        ObjectPart {
            size: 2,
            checksum: Some("two".to_owned()),
        },
    ];
    let multipart = ObjectMeta {
        checksum: Some(Checksum {
            algorithm: "SHA256".to_owned(),
            value: "sum-2".to_owned(),
            composite: true,
        }),
        parts: parts.clone(),
        ..object("md5-2")
    };
    let id = f.put_object("b/big", 7, &multipart).await;
    let stored = f.object_meta("b/big").await.unwrap();
    assert_eq!(stored.checksum, multipart.checksum, "composite survives");
    assert!(stored.parts.is_empty(), "read on their own");
    assert_eq!(f.store.object_parts(id).await.unwrap(), parts);

    // An ACL change keeps them, another S3 write replaces them, a WebDAV write removes them.
    let etag = f
        .store
        .get(f.owner, &p("b/big"))
        .await
        .unwrap()
        .unwrap()
        .etag;
    assert!(f.store.set_object_public(id, &etag, true).await.unwrap());
    assert_eq!(f.store.object_parts(id).await.unwrap(), parts);
    let single = object("md5-single");
    f.put_object("b/big", 3, &single).await;
    assert!(f.store.object_parts(id).await.unwrap().is_empty());
    f.put_object("b/big", 7, &multipart).await;
    assert_eq!(f.write("b/big", 9).await, id);
    assert!(f.store.object_parts(id).await.unwrap().is_empty());
}

#[tokio::test]
async fn object_writes_propagate_and_log_like_any_write() {
    let f = fixture().await;
    f.mkdir("b").await;
    let before = f.etags(&["", "b"]).await;
    f.put_object("b/a.png", 7, &object("md5")).await;
    assert!(all_changed(&before, &f.etags(&["", "b"]).await));
    assert_eq!(f.size("").await, 7);
    assert_eq!(
        f.changes().await.last().unwrap(),
        &("create".to_owned(), "b/a.png".to_owned(), None)
    );
}

#[tokio::test]
async fn rescanned_content_drops_object_meta() {
    let f = fixture().await;
    f.mkdir("b").await;
    f.put_object("b/same.png", 1, &object("md5-same")).await;
    f.put_object("b/changed.png", 2, &object("md5-changed"))
        .await;
    let disk = entries(&[
        ("", None),
        ("b", None),
        ("b/same.png", Some(1)),
        ("b/changed.png", Some(3)),
    ]);
    f.store
        .reconcile(f.owner, &RelPath::root(), &[], &disk, false)
        .await
        .unwrap();
    assert!(f.object_meta("b/same.png").await.is_some());
    assert_eq!(f.object_meta("b/changed.png").await, None);
}

#[tokio::test]
async fn object_acls_apply_to_the_version_they_were_set_for() {
    let f = fixture().await;
    f.mkdir("b").await;
    // A file written through WebDAV gets a row that holds only the ACL.
    let id = f.write("b/dav.txt", 1).await;
    let etag = f.etag("b/dav.txt").await;
    assert!(f.store.set_object_public(id, &etag, true).await.unwrap());
    let meta = f.object_meta("b/dav.txt").await.unwrap();
    assert!(meta.public_read);
    assert_eq!(meta.s3_etag, None);
    assert_eq!(meta.etag_or(&etag), etag);

    // Setting it again, and clearing it, keeps the S3 metadata of an S3 write.
    let id = f.put_object("b/s3.png", 1, &object("md5")).await;
    let etag = f.etag("b/s3.png").await;
    assert!(f.store.set_object_public(id, &etag, true).await.unwrap());
    assert!(f.store.set_object_public(id, &etag, true).await.unwrap());
    let meta = f.object_meta("b/s3.png").await.unwrap();
    assert!(meta.public_read);
    assert_eq!(meta.s3_etag.as_deref(), Some("md5"));
    // The file UI asks for the public files of a listing at once.
    let dav = f
        .store
        .get(f.owner, &p("b/dav.txt"))
        .await
        .unwrap()
        .unwrap();
    let public = f
        .store
        .public_objects(f.owner, &[dav.id, id, i64::MAX])
        .await
        .unwrap();
    assert_eq!(public.len(), 2);
    assert_eq!(public[&id], etag);
    assert_eq!(public[&dav.id], dav.etag);
    assert!(
        f.store
            .public_objects(f.owner + 1, &[dav.id, id])
            .await
            .unwrap()
            .is_empty(),
        "another account's files"
    );
    assert!(
        f.store
            .public_objects(f.owner, &[])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(f.store.set_object_public(id, &etag, false).await.unwrap());
    assert!(!f.object_meta("b/s3.png").await.unwrap().public_read);
    assert!(
        !f.store
            .public_objects(f.owner, &[id])
            .await
            .unwrap()
            .contains_key(&id)
    );

    // A stale version, a directory and a missing file are refused.
    f.write("b/s3.png", 2).await;
    assert!(!f.store.set_object_public(id, &etag, true).await.unwrap());
    assert_eq!(f.object_meta("b/s3.png").await, None);
    let dir = f.store.get(f.owner, &p("b")).await.unwrap().unwrap();
    assert!(
        !f.store
            .set_object_public(dir.id, &dir.etag, true)
            .await
            .unwrap()
    );
    assert!(
        !f.store
            .set_object_public(i64::MAX, "x", true)
            .await
            .unwrap()
    );

    // Overwriting a public object makes it private again.
    let id = f.write("b/public.txt", 1).await;
    let etag = f.etag("b/public.txt").await;
    f.store.set_object_public(id, &etag, true).await.unwrap();
    f.write("b/public.txt", 2).await;
    assert_eq!(f.object_meta("b/public.txt").await, None);
}

#[tokio::test]
async fn listings_follow_s3_key_order() {
    let f = fixture().await;
    f.mkdir("b").await;
    f.mkdir("b/a").await;
    f.mkdir("b/empty").await;
    f.mkdir("b/a/deep").await;
    for path in ["b/a-b", "b/a/x", "b/a/deep/y", "b/a0", "b/é", "b/z"] {
        f.write(path, 1).await;
    }
    // Next to the bucket: never listed.
    f.mkdir("b0").await;
    f.write("b0/outside", 1).await;
    f.write("b-outside", 1).await;

    let flat = f.list("b", "", None, None, 100).await;
    assert_eq!(names(&flat), ["a-b", "a/deep/y", "a/x", "a0", "z", "é"]);
    assert!(!flat.truncated);

    // `a/` sorts after `a-b` although the folder `a` sorts before it; the empty folder and
    // the bucket's neighbours never appear.
    let rolled = f.list("b", "", Some("/"), None, 100).await;
    assert_eq!(names(&rolled), ["a-b", "a/*", "a0", "z", "é"]);

    assert_eq!(
        names(&f.list("b", "a/", Some("/"), None, 100).await),
        ["a/deep/*", "a/x"]
    );
    assert_eq!(
        names(&f.list("b", "a", Some("/"), None, 100).await),
        ["a-b", "a/*", "a0"]
    );
    assert_eq!(
        names(&f.list("b", "a/d", None, None, 100).await),
        ["a/deep/y"]
    );
    assert!(
        f.list("b", "nothing", None, None, 100)
            .await
            .entries
            .is_empty()
    );

    // Delimiters other than `/`.
    assert_eq!(
        names(&f.list("b", "", Some("-"), None, 100).await),
        ["a-*", "a/deep/y", "a/x", "a0", "z", "é"]
    );
    assert_eq!(
        names(&f.list("b", "", Some("ee"), None, 100).await),
        ["a-b", "a/dee*", "a/x", "a0", "z", "é"]
    );

    // The root of the tree as the folder.
    assert_eq!(
        names(&f.list("", "", Some("/"), None, 100).await),
        ["b-outside", "b/*", "b0/*"]
    );
}

#[tokio::test]
async fn listings_page_without_losing_or_repeating_entries() {
    let f = fixture().await;
    f.mkdir("b").await;
    f.mkdir("b/a").await;
    for path in ["b/a-b", "b/a/1", "b/a/2", "b/a/3", "b/a0", "b/c"] {
        f.write(path, 1).await;
    }
    for delimiter in [None, Some("/")] {
        let complete = names(&f.list("b", "", delimiter, None, 100).await);
        for page_size in 1..=complete.len() {
            let mut seen = Vec::new();
            let mut after: Option<String> = None;
            loop {
                let page = f
                    .list("b", "", delimiter, after.as_deref(), page_size)
                    .await;
                assert!(page.entries.len() <= page_size);
                seen.extend(names(&page));
                if !page.truncated {
                    break;
                }
                after = Some(page.entries.last().unwrap().marker().to_owned());
            }
            assert_eq!(
                seen, complete,
                "pages of {page_size}, delimiter {delimiter:?}"
            );
        }
    }
    // Truncation is reported exactly.
    let page = f.list("b", "", Some("/"), None, 4).await;
    assert_eq!(names(&page), ["a-b", "a/*", "a0", "c"]);
    assert!(!page.truncated);
    assert!(f.list("b", "", Some("/"), None, 3).await.truncated);
    let none = f.list("b", "", None, None, 0).await;
    assert!(none.entries.is_empty() && none.truncated);
}

#[tokio::test]
async fn listings_start_after_any_key() {
    let f = fixture().await;
    f.mkdir("b").await;
    f.mkdir("b/a").await;
    for path in ["b/a-b", "b/a/1", "b/a/2", "b/c"] {
        f.write(path, 1).await;
    }
    // Before the prefix, inside it, after it.
    assert_eq!(
        names(&f.list("b", "a/", None, Some("0"), 10).await),
        ["a/1", "a/2"]
    );
    assert_eq!(
        names(&f.list("b", "a/", None, Some("a/1"), 10).await),
        ["a/2"]
    );
    assert!(
        f.list("b", "a/", None, Some("b"), 10)
            .await
            .entries
            .is_empty()
    );
    // Inside a common prefix: the whole group is skipped.
    assert_eq!(
        names(&f.list("b", "", Some("/"), Some("a/1"), 10).await),
        ["c"]
    );
    assert_eq!(
        names(&f.list("b", "", Some("/"), Some("a/"), 10).await),
        ["c"]
    );
    assert_eq!(
        names(&f.list("b", "", Some("/"), Some("a"), 10).await),
        ["a-b", "a/*", "c"]
    );
}

#[tokio::test]
async fn listings_report_s3_etags_and_fall_back_to_webdav_ones() {
    let f = fixture().await;
    f.mkdir("b").await;
    f.put_object("b/s3", 1, &object("md5")).await;
    f.write("b/dav", 1).await;
    let dav_etag = f.etag("b/dav").await;
    let listing = f.list("b", "", None, None, 10).await;
    let etags: Vec<(&str, String)> = listing
        .entries
        .iter()
        .map(|entry| match entry {
            ListEntry::Object(object) => (object.key.as_str(), object.etag()),
            ListEntry::CommonPrefix(_) => unreachable!(),
        })
        .collect();
    assert_eq!(etags, [("dav", dav_etag.clone()), ("s3", "md5".to_owned())]);
}

/// S3 keys need not be in NFC, the tree's names are: rows record how S3 spelled them, rows
/// below a spelled folder inherit the spelling, moves carry it, and listings return and order
/// the spelled keys.
#[tokio::test]
async fn s3_spellings_follow_their_entries() {
    let f = fixture().await;
    let nfc = "Caf\u{e9}";
    let nfd = "Cafe\u{301}";
    let spelling = |path: &str| {
        let store = f.store.clone();
        let owner = f.owner;
        let path = p(path);
        async move { store.get(owner, &path).await.unwrap().unwrap().s3_path }
    };
    f.mkdir("b").await;
    // A folder S3 created with an NFD name, and a file S3 wrote below it.
    f.store
        .record_spelled_mkdir(
            f.owner,
            &p(&format!("b/{nfc}")),
            5,
            Some(&format!("b/{nfd}")),
        )
        .await
        .unwrap();
    f.store
        .record_object_write(
            f.owner,
            &p(&format!("b/{nfc}/s3.txt")),
            file_stat(1),
            None,
            &object("md5"),
            Some(&format!("b/{nfd}/s3.txt")),
        )
        .await
        .unwrap();
    // A write spelled as the tree keeps no spelling of its own.
    f.store
        .record_object_write(
            f.owner,
            &p("b/plain.txt"),
            file_stat(1),
            None,
            &object("md5"),
            Some("b/plain.txt"),
        )
        .await
        .unwrap();
    assert_eq!(spelling("b/plain.txt").await, None);
    // WebDAV writes below the folder inherit its spelling.
    f.write(&format!("b/{nfc}/dav.txt"), 1).await;
    assert_eq!(
        spelling(&format!("b/{nfc}/dav.txt")).await.as_deref(),
        Some(format!("b/{nfd}/dav.txt").as_str())
    );

    // Listings return the spelled keys in the byte order of the spelling: NFD's "e" + U+0301
    // sorts before "plain", NFC's U+00E9 would sort after it.
    let listing = f.list("b", "", None, None, 10).await;
    assert_eq!(
        names(&listing),
        [
            format!("{nfd}/dav.txt"),
            format!("{nfd}/s3.txt"),
            "plain.txt".to_owned()
        ]
    );
    let page = f
        .list("b", "", Some("/"), Some(&format!("{nfd}/")), 10)
        .await;
    assert_eq!(names(&page), ["plain.txt"]);
    // The listing uses its index (`files_s3_listing`), on MySQL through the generated column
    // `s3_key` that its queries name.
    match Backend::of(f.store.pool()) {
        Backend::Sqlite => {
            let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
                "EXPLAIN QUERY PLAN SELECT id FROM files WHERE owner_id = 1 \
                 AND COALESCE(s3_path, rel_path) >= 'b/' AND COALESCE(s3_path, rel_path) < 'b0' \
                 AND is_dir = 0 ORDER BY COALESCE(s3_path, rel_path) LIMIT 5",
            )
            .fetch_all(f.store.pool())
            .await
            .unwrap();
            assert!(
                plan.iter()
                    .any(|(_, _, _, detail)| detail.contains("files_s3_listing")),
                "{plan:?}"
            );
        }
        Backend::MySql => {
            let plan = sqlx::query(
                "EXPLAIN SELECT f.id FROM files f WHERE f.owner_id = 1 AND f.is_dir = 0 \
                 AND f.s3_key >= 'b/' AND f.s3_key < 'b0' ORDER BY f.s3_key LIMIT 5",
            )
            .fetch_one(f.store.pool())
            .await
            .unwrap();
            let keys: Option<Text> = plan.try_get("possible_keys").unwrap();
            assert!(
                keys.as_deref()
                    .is_some_and(|keys| keys.split(',').any(|key| key == "files_s3_listing")),
                "{keys:?}"
            );
        }
    }

    // A move that keeps the name keeps the folder's spelling, and its files' with it.
    f.mkdir("c").await;
    f.store
        .record_move(
            f.owner,
            &p(&format!("b/{nfc}")),
            &p(&format!("c/{nfc}")),
            dir_stat(),
        )
        .await
        .unwrap();
    assert_eq!(
        spelling(&format!("c/{nfc}")).await.as_deref(),
        Some(format!("c/{nfd}").as_str())
    );
    assert_eq!(
        spelling(&format!("c/{nfc}/s3.txt")).await.as_deref(),
        Some(format!("c/{nfd}/s3.txt").as_str())
    );
    // A rename gives the folder the new (NFC) name, and its files lose the spelling.
    f.store
        .record_move(
            f.owner,
            &p(&format!("c/{nfc}")),
            &p("c/renamed"),
            dir_stat(),
        )
        .await
        .unwrap();
    assert_eq!(spelling("c/renamed").await, None);
    assert_eq!(spelling("c/renamed/s3.txt").await, None);
    // A file moved into a spelled folder takes the folder's spelling.
    f.store
        .record_spelled_mkdir(
            f.owner,
            &p(&format!("c/{nfc}")),
            5,
            Some(&format!("c/{nfd}")),
        )
        .await
        .unwrap();
    f.store
        .record_move(
            f.owner,
            &p("b/plain.txt"),
            &p(&format!("c/{nfc}/plain.txt")),
            file_stat(1),
        )
        .await
        .unwrap();
    assert_eq!(
        spelling(&format!("c/{nfc}/plain.txt")).await.as_deref(),
        Some(format!("c/{nfd}/plain.txt").as_str())
    );
}
