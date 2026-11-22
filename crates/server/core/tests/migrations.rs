//! Schema migration tests: the migrations apply to an empty database, the resulting schema
//! enforces its constraints, and released migrations stay byte-for-byte unchanged.
//!
//! The tests run on the backend `GONO_TEST_MYSQL_URL` chooses (see `db::testing`); the ones
//! about SQLite's file, pragmas and CHECK constraints (which MySQL 5.7 does not enforce) run on
//! SQLite only, and the ones about MySQL's session and databases on MySQL only.

use std::path::Path;

use gono_server_core::{
    Error, Username,
    config::DbConfig,
    db::{self, Backend, Flag, MYSQL_MIGRATOR, OpenMode, Pool, SQLITE_MIGRATOR, Text},
    meta, password, users,
};
use secrecy::SecretString;
use sqlx::Row as _;

/// SHA-384 checksums (as computed by sqlx, equal to `shasum -a 384 <file>`) of the migrations,
/// per backend.
///
/// Until the next release the schema is edited in place (see the header of
/// `migrations/sqlite/0001_initial.sql`): update the checksums here with it. Once a migration
/// is released (merged into `main` with a release), sqlx refuses to open databases whose
/// applied migrations changed; if this test fails because you edited a released one, revert
/// the edit and add a new migration instead.
const SQLITE_MIGRATIONS: &[(i64, &str)] = &[(
    1,
    "4d7994e283b6cf7ab7e872132dbe0488efbc6d49baf4375fa43004bde06d00ac9e3001d8075e9e124ddc4d2489f4886e",
)];
const MYSQL_MIGRATIONS: &[(i64, &str)] = &[(
    1,
    "b3333b4d503577a9386b6cff9fc7e0c0f57b8e4c19a6b4f891980dae695eaf80014f096f44a196932fb88cc9be5ff021",
)];

/// The tables of the schema on both backends.
const TABLES: &[&str] = &[
    "app_password_scopes",
    "app_passwords",
    "audit_log",
    "change_log",
    "dead_props",
    "device_approvals",
    "device_events",
    "devices",
    "direct_downloads",
    "email_codes",
    "files",
    "id_sequences",
    "locks",
    "login_flows",
    "mp_sessions",
    "object_meta",
    "object_parts",
    "recovery_codes",
    "retired_usernames",
    "revocations_applied",
    "revoked_keys",
    "s3_buckets",
    "s3_key_grants",
    "s3_upload_parts",
    "s3_uploads",
    "settings",
    "two_factor",
    "upload_sessions",
    "users",
    "web_sessions",
    "wechat_bind_tickets",
    "wechat_identities",
    "wechat_signup_tokens",
];

fn sqlite_config(dir: &Path) -> DbConfig {
    let mut config = DbConfig::sqlite(dir.join("nested").join("gono-cloud.db"));
    config.max_connections = 4;
    config
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_sqlite() -> bool {
    db::testing::backend() == Backend::Sqlite
}

/// Inserts a user directly, with an id from `id_sequences` as the code allocates them.
async fn insert_user(pool: &Pool, username: &str) -> i64 {
    let mut tx = db::begin_immediate(pool).await.unwrap();
    let id = db::next_id(&mut tx, "users").await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, username, display_name, password_hash, created_at, updated_at) \
         VALUES (?, ?, ?, 'x', 0, 0)",
    )
    .bind(id)
    .bind(username)
    .bind(username)
    .execute(&mut *tx)
    .await
    .expect("insert user");
    tx.commit().await.unwrap();
    id
}

/// Inserts a file row of `owner` directly, with a new id.
async fn insert_file(pool: &Pool, owner: i64, path: &str, is_dir: bool) -> i64 {
    let mut tx = db::begin_immediate(pool).await.unwrap();
    let id = db::next_id(&mut tx, "files").await.unwrap();
    sqlx::query(
        "INSERT INTO files (id, owner_id, rel_path, is_dir, etag, mtime_ns) \
         VALUES (?, ?, ?, ?, 'e', 0)",
    )
    .bind(id)
    .bind(owner)
    .bind(path)
    .bind(is_dir)
    .execute(&mut *tx)
    .await
    .expect("insert file");
    tx.commit().await.unwrap();
    id
}

#[tokio::test]
async fn migrations_apply_to_an_empty_database() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;

    let backend = Backend::of(&pool);
    let tables: Vec<Text> = sqlx::query_scalar(backend.pick(
        "SELECT name FROM sqlite_schema WHERE type = 'table' \
         AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name <> '_sqlx_migrations' ORDER BY name",
        "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() \
         AND TABLE_NAME <> '_sqlx_migrations' ORDER BY TABLE_NAME",
    ))
    .fetch_all(&pool)
    .await
    .unwrap();
    // information_schema orders by a case-insensitive collation; compare in byte order.
    let mut tables: Vec<&str> = tables.iter().map(|table| &**table).collect();
    tables.sort_unstable();
    let mut expected = TABLES.to_vec();
    if backend == Backend::MySql {
        // MySQL's stand-in for SQLite's single writer (`db::begin_immediate`).
        expected.push("write_lock");
        expected.sort_unstable();
    }
    assert_eq!(tables, expected);

    // `success` is a BOOLEAN, which MySQL stores as TINYINT (unreadable through `Any`).
    let applied: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT version, CAST(success AS SIGNED) FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let expected: Vec<(i64, i64)> = db::migrator(backend)
        .iter()
        .map(|m| (m.version, 1))
        .collect();
    assert_eq!(applied, expected);
}

#[tokio::test]
async fn sqlite_connections_use_wal_and_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::open(&sqlite_config(dir.path())).await;

    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(journal_mode, "wal");

    for (pragma, value) in [
        ("PRAGMA foreign_keys", 1),
        // FULL
        ("PRAGMA synchronous", 2),
        ("PRAGMA busy_timeout", 5000),
    ] {
        let found: i64 = sqlx::query_scalar(pragma).fetch_one(&pool).await.unwrap();
        assert_eq!(found, value, "{pragma}");
    }
}

#[tokio::test]
async fn mysql_sessions_are_strict_utc_and_read_committed() {
    if is_sqlite() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let (mode, zone, isolation, charset, collation, wait): (Text, Text, Text, Text, Text, i64) =
        sqlx::query_as(
            "SELECT @@SESSION.sql_mode, @@SESSION.time_zone, @@SESSION.transaction_isolation, \
             @@SESSION.character_set_connection, @@SESSION.collation_connection, \
             @@SESSION.innodb_lock_wait_timeout",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
    for flag in [
        "STRICT_TRANS_TABLES",
        "ONLY_FULL_GROUP_BY",
        "NO_ENGINE_SUBSTITUTION",
        "PIPES_AS_CONCAT",
        "NO_BACKSLASH_ESCAPES",
    ] {
        assert!(mode.split(',').any(|m| m == flag), "{flag} in {}", &*mode);
    }
    assert_eq!(&*zone, "+00:00");
    assert_eq!(&*isolation, "READ-COMMITTED");
    assert_eq!(&*charset, "utf8mb4");
    assert_eq!(&*collation, "utf8mb4_bin");
    assert_eq!(wait, 5);

    // Every table is InnoDB with the DYNAMIC row format and utf8mb4.
    let odd: Vec<Text> = sqlx::query_scalar(
        "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() \
         AND TABLE_NAME <> '_sqlx_migrations' AND (ENGINE <> 'InnoDB' \
         OR ROW_FORMAT <> 'Dynamic' OR TABLE_COLLATION <> 'utf8mb4_bin')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(odd.is_empty(), "{odd:?}");
}

#[tokio::test]
async fn migrating_twice_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let config = db::testing::config(dir.path()).await;
    let pool = db::testing::open(&config).await;
    db::migrate(&pool).await.expect("second run");
    pool.close().await;

    let reopened = db::connect(&config, OpenMode::MustExist)
        .await
        .expect("reopen");
    db::migrate(&reopened).await.expect("run after reopen");
}

#[tokio::test]
async fn sqlite_must_exist_never_creates_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let config = sqlite_config(dir.path());
    let err = db::connect(&config, OpenMode::MustExist).await.unwrap_err();
    assert!(matches!(err, Error::DatabaseMissing { .. }), "{err:?}");
    assert!(!config.path.exists());
}

/// MySQL databases are never created: `init` needs an empty one (or one with the schema), and
/// `serve` one with the schema.
#[tokio::test]
async fn mysql_databases_must_be_empty_or_ours() {
    if is_sqlite() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = db::testing::config(dir.path()).await;
    let err = db::connect(&config, OpenMode::MustExist).await.unwrap_err();
    assert!(
        matches!(err, Error::DatabaseUninitialized { .. }),
        "{err:?}"
    );

    // A table of something else: not a database for `init`.
    let pool = db::connect(&config, OpenMode::CreateIfMissing)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE wp_posts (id BIGINT PRIMARY KEY) ENGINE=InnoDB")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let err = db::connect(&config, OpenMode::CreateIfMissing)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::DatabaseForeign { .. }), "{err:?}");

    // A database that does not exist at all.
    let mut missing = config.clone();
    let mut url = missing.url.clone().unwrap();
    url.set_path("/gono_test_does_not_exist");
    missing.url = Some(url);
    assert!(
        db::connect(&missing, OpenMode::CreateIfMissing)
            .await
            .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn sqlite_database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let config = sqlite_config(dir.path());
    let _pool = db::testing::open(&config).await;
    let mode = std::fs::metadata(&config.path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");
}

#[test]
fn released_migrations_are_unchanged() {
    for (migrator, released) in [
        (&SQLITE_MIGRATOR, SQLITE_MIGRATIONS),
        (&MYSQL_MIGRATOR, MYSQL_MIGRATIONS),
    ] {
        for &(version, checksum) in released {
            let migration = migrator
                .iter()
                .find(|m| m.version == version)
                .unwrap_or_else(|| panic!("released migration {version} was removed"));
            assert_eq!(
                hex(&migration.checksum),
                checksum,
                "released migration {version} ({}) was modified; add a new migration instead",
                migration.description
            );
        }
    }
}

#[test]
fn migration_versions_are_contiguous_and_alike() {
    let sqlite: Vec<i64> = SQLITE_MIGRATOR.iter().map(|m| m.version).collect();
    let expected: Vec<i64> = (1..=i64::try_from(sqlite.len()).unwrap()).collect();
    assert_eq!(sqlite, expected);
    // Every migration exists for both backends, with the same name.
    let describe = |migrator: &sqlx::migrate::Migrator| -> Vec<(i64, String)> {
        migrator
            .iter()
            .map(|m| (m.version, m.description.to_string()))
            .collect()
    };
    assert_eq!(describe(&SQLITE_MIGRATOR), describe(&MYSQL_MIGRATOR));
}

#[tokio::test]
async fn schema_enforces_constraints() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let alice = insert_user(&pool, "alice").await;
    let sqlite = is_sqlite();

    let rejects = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            let result = sqlx::query(sql).bind(alice).execute(&pool).await;
            assert!(result.is_err(), "should be rejected: {sql}");
        }
    };

    // Usernames are unique.
    rejects(
        "INSERT INTO users (id, username, display_name, password_hash, created_at, updated_at) \
         SELECT id + 1000, username, 'x', 'x', 0, 0 FROM users WHERE id = ?",
    )
    .await;
    // Foreign keys are enforced.
    rejects(
        "INSERT INTO app_passwords (id, user_id, token_hash, label, created_at) \
         VALUES (1000, ? + 100, x'0000000000000000000000000000000000000000000000000000000000000000', \
         'orphan', 0)",
    )
    .await;
    // Locks always expire.
    rejects(
        "INSERT INTO locks (token, owner_id, rel_path, shared, deep, created_at, timeout_at) \
         VALUES ('t', ?, 'a', 0, 0, 0, NULL)",
    )
    .await;
    // Ids are named by the code: there is no AUTOINCREMENT to fall back on in MySQL. (SQLite
    // assigns a rowid, which the code never relies on.)
    if !sqlite {
        rejects(
            "INSERT INTO files (owner_id, rel_path, is_dir, etag, mtime_ns) \
             VALUES (?, 'no-id', 0, 'e', 0)",
        )
        .await;
    }

    if sqlite {
        // CHECK constraints and STRICT tables; MySQL 5.7 parses CHECK but does not enforce it,
        // and the code keeps these invariants on every backend.
        // Token hashes are 32-byte SHA-256 digests.
        rejects(
            "INSERT INTO app_passwords (id, user_id, token_hash, label, created_at) \
             VALUES (1000, ?, x'00', 'short', 0)",
        )
        .await;
        // An app password has a token hash, an S3 key an access key id and a sealed secret,
        // never the other's.
        rejects(
            "INSERT INTO app_passwords (id, user_id, kind, label, created_at) \
             VALUES (1000, ?, 'dav', 'x', 0)",
        )
        .await;
        rejects(
            "INSERT INTO app_passwords (id, user_id, kind, token_hash, access_key_id, \
             secret_sealed, label, created_at) \
             VALUES (1000, ?, 's3', zeroblob(32), 'GONOX', x'00', 'x', 0)",
        )
        .await;
        rejects(
            "INSERT INTO app_passwords (id, user_id, kind, access_key_id, label, created_at) \
             VALUES (1000, ?, 's3', 'GONOX', 'x', 0)",
        )
        .await;
        rejects(
            "INSERT INTO app_passwords (id, user_id, kind, token_hash, label, created_at) \
             VALUES (1000, ?, 'ftp', zeroblob(32), 'x', 0)",
        )
        .await;
        // STRICT tables reject values of the wrong type.
        rejects(
            "INSERT INTO files (id, owner_id, rel_path, is_dir, etag, mtime_ns) \
             VALUES (1000, ?, 'a', 0, 'e', 'yesterday')",
        )
        .await;
    } else {
        // Strict mode rejects values of the wrong type and values too long for their column.
        rejects(
            "INSERT INTO files (id, owner_id, rel_path, is_dir, etag, mtime_ns) \
             VALUES (1000, ?, 'a', 0, 'e', 'yesterday')",
        )
        .await;
        rejects(
            "INSERT INTO users (id, username, display_name, password_hash, created_at, \
             updated_at) VALUES (1000 + ?, REPEAT('a', 65), 'x', 'x', 0, 0)",
        )
        .await;
    }

    // S3 metadata belongs to an existing file.
    let object = insert_file(&pool, alice, "object.bin", false).await;
    rejects("INSERT INTO object_meta (file_id, user_meta, tags) VALUES (? + 100, '{}', '{}')")
        .await;
    if sqlite {
        // A checksum has an algorithm and a value.
        rejects(
            "INSERT INTO object_meta (file_id, checksum_algorithm) \
             SELECT id, 'CRC32' FROM files WHERE owner_id = ?",
        )
        .await;
    }
    sqlx::query(
        "INSERT INTO object_meta (file_id, public_read, user_meta, tags) VALUES (?, 1, '{}', '{}')",
    )
    .bind(object)
    .execute(&pool)
    .await
    .unwrap();

    let mut tx = db::begin_immediate(&pool).await.unwrap();
    let app_password = db::next_id(&mut tx, "app_passwords").await.unwrap();
    sqlx::query(
        "INSERT INTO app_passwords (id, user_id, token_hash, label, created_at) \
         VALUES (?, ?, ?, 'laptop', 0)",
    )
    .bind(app_password)
    .bind(alice)
    .bind(vec![0u8; 32])
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Scope permissions are limited to 'view' and 'full' (by CHECK in SQLite, by the code's
    // `Permission` everywhere).
    let permissions: &[(&str, bool)] = if sqlite {
        &[
            ("view", true),
            ("full", true),
            ("admin", false),
            ("VIEW", false),
        ]
    } else {
        &[("view", true), ("full", true)]
    };
    for &(permission, ok) in permissions {
        let result = sqlx::query(
            "INSERT INTO app_password_scopes (app_password_id, mount_path, storage_path, \
             permission) VALUES (?, ?, '', ?)",
        )
        .bind(app_password)
        .bind(permission)
        .bind(permission)
        .execute(&pool)
        .await;
        assert_eq!(result.is_ok(), ok, "permission {permission:?}");
    }
    // Mount paths are unique per app password, also on MySQL, which keys them by digest.
    let duplicate = sqlx::query(
        "INSERT INTO app_password_scopes (app_password_id, mount_path, storage_path, permission) \
         VALUES (?, 'view', 'x', 'full')",
    )
    .bind(app_password)
    .execute(&pool)
    .await;
    assert!(duplicate.is_err());

    // Deleting a user removes everything that belongs to them.
    insert_file(&pool, alice, "", true).await;
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    for table in [
        "app_passwords",
        "app_password_scopes",
        "files",
        "object_meta",
    ] {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let remaining: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining, 0,
            "{table} should be empty after deleting the user"
        );
    }
}

#[tokio::test]
async fn rel_path_ranges_select_exactly_the_subtree() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let alice = insert_user(&pool, "alice").await;

    let paths = [
        "", "a", "a/b", "a/b/c", "a/_", "a/%", "A", "A/b", "a_b", "a%", "a.b", "ab", "a0", "b",
        // Differ from "a" only by trailing spaces: MySQL's utf8mb4_bin would call them equal.
        "a ", "a  ", "a /b",
    ];
    for path in paths {
        insert_file(&pool, alice, path, false).await;
    }

    // Paths that differ only in case or trailing spaces are distinct rows (BINARY collation,
    // VARBINARY in MySQL).
    for (path, matches) in [("A", 1), ("a", 1), ("a ", 1), ("a  ", 1)] {
        let found: Vec<Text> =
            sqlx::query_scalar("SELECT rel_path FROM files WHERE owner_id = ? AND rel_path = ?")
                .bind(alice)
                .bind(path)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(found.len(), matches, "{path:?}");
        assert_eq!(&*found[0], path);
    }

    let (lower, upper) = meta::descendant_bounds("a").unwrap();
    let subtree: Vec<Text> = sqlx::query_scalar(
        "SELECT rel_path FROM files WHERE owner_id = ? AND rel_path >= ? AND rel_path < ? \
         ORDER BY rel_path",
    )
    .bind(alice)
    .bind(&lower)
    .bind(&upper)
    .fetch_all(&pool)
    .await
    .unwrap();
    let subtree: Vec<&str> = subtree.iter().map(|path| &**path).collect();
    assert_eq!(subtree, ["a/%", "a/_", "a/b", "a/b/c"]);

    // The range scan is served by the (owner_id, rel_path) index.
    match Backend::of(&pool) {
        Backend::Sqlite => {
            let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
                "EXPLAIN QUERY PLAN SELECT rel_path FROM files \
                 WHERE owner_id = ? AND rel_path >= ? AND rel_path < ?",
            )
            .bind(alice)
            .bind(&lower)
            .bind(&upper)
            .fetch_all(&pool)
            .await
            .unwrap();
            assert!(
                plan.iter()
                    .any(|(_, _, _, detail)| detail.contains("USING COVERING INDEX")
                        || detail.contains("USING INDEX")),
                "{plan:?}"
            );
        }
        Backend::MySql => {
            // With so few rows MySQL might prefer a scan; ask for the index's use.
            let plan = sqlx::query(
                "EXPLAIN SELECT rel_path FROM files FORCE INDEX (files_owner_rel_path) \
                 WHERE owner_id = ? AND rel_path >= ? AND rel_path < ?",
            )
            .bind(alice)
            .bind(&lower)
            .bind(&upper)
            .fetch_one(&pool)
            .await
            .unwrap();
            let kind: Text = plan.try_get("type").unwrap();
            let key: Option<Text> = plan.try_get("key").unwrap();
            assert_eq!(&*kind, "range");
            assert_eq!(key.as_deref(), Some("files_owner_rel_path"));
        }
    }
}

#[tokio::test]
async fn instance_id_is_generated_once() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let id = gono_server_core::settings::instance_id(&pool)
        .await
        .unwrap();
    assert_eq!(id.len(), 12, "{id}");
    assert!(id.starts_with("oc"), "{id}");
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    );
    db::migrate(&pool).await.unwrap();
    assert_eq!(
        gono_server_core::settings::instance_id(&pool)
            .await
            .unwrap(),
        id
    );
}

#[tokio::test]
async fn initial_admin_is_created_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;

    let username = Username::new("admin").unwrap();
    let phc = password::hash(&SecretString::from("correct horse".to_owned())).unwrap();
    users::create_initial_admin(&pool, &username, "Admin", &phc)
        .await
        .expect("first admin");

    let (Flag(is_admin), Flag(enabled), stored_hash): (Flag, Flag, String) =
        sqlx::query_as("SELECT is_admin, enabled, password_hash FROM users WHERE username = ?")
            .bind("admin")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_admin && enabled);
    assert_eq!(stored_hash, phc);

    let other = Username::new("mallory").unwrap();
    let err = users::create_initial_admin(&pool, &other, "Mallory", &phc)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AlreadyInitialized), "{err:?}");
    assert_eq!(users::count(&pool).await.unwrap(), 1);
}

/// Ids come from `id_sequences`: deleting the newest rows and reopening the database (MySQL
/// 5.7 forgets an AUTO_INCREMENT counter on restart) never hands their ids out again.
#[tokio::test]
async fn ids_are_never_reused() {
    let dir = tempfile::tempdir().unwrap();
    let config = db::testing::config(dir.path()).await;
    let pool = db::testing::open(&config).await;
    let first = insert_user(&pool, "first").await;
    let second = insert_user(&pool, "second").await;
    let file = insert_file(&pool, first, "", true).await;
    assert!(second > first);
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(second)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM files WHERE id = ?")
        .bind(file)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let reopened = db::connect(&config, OpenMode::MustExist).await.unwrap();
    let third = insert_user(&reopened, "third").await;
    assert_eq!(third, second + 1);
    assert_eq!(insert_file(&reopened, first, "", true).await, file + 1);

    // A rolled back transaction gives its ids back: nobody saw them.
    let mut tx = db::begin_immediate(&reopened).await.unwrap();
    let unused = db::next_id(&mut tx, "users").await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(insert_user(&reopened, "fourth").await, unused);
}
