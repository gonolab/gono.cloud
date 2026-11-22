//! Fresh databases for tests, on the backend the environment chooses (feature `testing`).
//!
//! Without `GONO_TEST_MYSQL_URL`, a test gets a SQLite database in its temporary directory.
//! With it, for example `GONO_TEST_MYSQL_URL=mysql://root@127.0.0.1:3317` (the server of
//! `acceptance/scripts/mysql-instance.sh`), every test gets a new MySQL database with a random
//! name on that server. Test databases are not dropped when a test ends; instead every test
//! process first drops those left behind more than an hour ago, so runs do not accumulate them.

use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use rand::RngExt as _;
use sqlx::Connection as _;
use url::Url;

use super::{Backend, OpenMode, Pool, Text};
use crate::config::DbConfig;

/// The environment variable that names the MySQL server tests run against.
pub const MYSQL_URL_VAR: &str = "GONO_TEST_MYSQL_URL";

/// Prefix of the names of test databases on the MySQL server.
const PREFIX: &str = "gono_test_";

/// Age after which a test database counts as left behind, in seconds.
const LEFTOVER_SECS: i64 = 60 * 60;

/// The MySQL server tests run against, if `GONO_TEST_MYSQL_URL` names one.
pub fn mysql_server() -> Option<Url> {
    let value = std::env::var(MYSQL_URL_VAR).ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(Url::parse(value).unwrap_or_else(|err| panic!("{MYSQL_URL_VAR} {value:?}: {err}")))
}

/// The backend tests run against.
pub fn backend() -> Backend {
    if mysql_server().is_some() {
        Backend::MySql
    } else {
        Backend::Sqlite
    }
}

/// The configuration of a new, empty database: SQLite at `dir/gono-cloud.db`, or a new database
/// on the MySQL server of `GONO_TEST_MYSQL_URL`.
pub async fn config(dir: &Path) -> DbConfig {
    let mut config = match mysql_server() {
        None => DbConfig::sqlite(dir.join("gono-cloud.db")),
        Some(server) => DbConfig::mysql(create_mysql_database(&server).await),
    };
    config.max_connections = 4;
    config
}

/// A new database, migrated (see [`config`]).
pub async fn database(dir: &Path) -> Pool {
    open(&config(dir).await).await
}

/// Opens the database of `config` (from [`config`]) and applies the migrations.
pub async fn open(config: &DbConfig) -> Pool {
    let pool = super::connect(config, OpenMode::CreateIfMissing)
        .await
        .expect("connect to the test database");
    super::migrate(&pool)
        .await
        .expect("migrate the test database");
    pool
}

/// Creates a database with a random name on `server` and returns its URL.
async fn create_mysql_database(server: &Url) -> Url {
    sqlx::any::install_default_drivers();
    let mut conn = sqlx::AnyConnection::connect(server.as_str())
        .await
        .unwrap_or_else(|err| panic!("connect to {MYSQL_URL_VAR} {server}: {err}"));
    let now = super::unix_now();

    static CLEANED: AtomicBool = AtomicBool::new(false);
    if !CLEANED.swap(true, Ordering::SeqCst) {
        let names: Vec<Text> = sqlx::query_scalar(
            "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'gono_test%'",
        )
        .fetch_all(&mut conn)
        .await
        .expect("list test databases");
        for name in names {
            let created: Option<i64> = name
                .strip_prefix(PREFIX)
                .and_then(|rest| rest.split('_').next())
                .and_then(|secs| secs.parse().ok());
            if created.is_some_and(|created| created < now - LEFTOVER_SECS) {
                // Another process may drop it at the same time.
                let drop = format!("DROP DATABASE IF EXISTS `{}`", &*name);
                let _ = sqlx::query(sqlx::AssertSqlSafe(drop))
                    .execute(&mut conn)
                    .await;
            }
        }
    }

    let suffix: u64 = rand::rng().random();
    let name = format!("{PREFIX}{now}_{suffix:016x}");
    let create = format!("CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin");
    sqlx::query(sqlx::AssertSqlSafe(create))
        .execute(&mut conn)
        .await
        .expect("create a test database");
    let _ = conn.close().await;

    let mut url = server.clone();
    url.set_path(&format!("/{name}"));
    url
}
