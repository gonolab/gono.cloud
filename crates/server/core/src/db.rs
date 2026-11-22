//! Database connection setup, schema migrations and the helpers that keep queries portable.
//!
//! The metadata lives in **SQLite** (compiled in, the default) or in **MySQL 5.7.44 or later**
//! (InnoDB, utf8mb4), chosen by `db.backend`. Both are reached through sqlx's `Any` driver, so
//! the rest of the crate works with one [`Pool`] type and writes one query for both wherever the
//! dialects agree. Where they do not, [`Backend::pick`] chooses between two static SQL texts.
//!
//! # Rules every query follows
//!
//! - Placeholders are plain `?`, bound in order of appearance (MySQL knows no `?1`).
//! - Booleans and 0/1 columns are read through [`Flag`], and text columns that MySQL stores as
//!   `VARBINARY` (paths, usernames, keys: everything SQLite declares `COLLATE BINARY`) through
//!   [`Text`]: the `Any` driver decodes neither on its own.
//! - Ids of tables whose ids must never be reused come from [`next_id`], never from
//!   `AUTOINCREMENT`/`AUTO_INCREMENT` (MySQL 5.7 forgets its counter on restart), and there is no
//!   `RETURNING` (MySQL has none): a statement that needs the rows it deletes selects them first,
//!   inside the same write transaction.
//! - Sums are wrapped in `CAST(... AS SIGNED)`: MySQL returns `SUM()` as `DECIMAL`, which the
//!   `Any` driver cannot decode. SQLite reads `SIGNED` as NUMERIC affinity, which keeps integers.
//! - MySQL sessions run with `PIPES_AS_CONCAT` and `NO_BACKSLASH_ESCAPES` (see
//!   `configure_mysql`), so `||` concatenates and `'\'` is a one-character literal, as in
//!   SQLite.
//!
//! # Writes
//!
//! Writes go through [`begin_immediate`]: one write transaction per operation, which takes the
//! database's write lock up front, so concurrent writers wait instead of failing halfway
//! through a transaction. They first wait at the database's **write gate**, an in-process FIFO
//! lock taken before a connection: writers queued at the gate neither hold pool connections
//! (which readers need meanwhile) nor sleep in SQLite's busy handler (which wakes them late, in
//! steps of up to 100 ms, and gives up after `busy_timeout`). Other processes (the CLI) are
//! held off by the database itself: SQLite's single writer (`BEGIN IMMEDIATE`, waiting up to
//! `db.busy_timeout_secs`), and on MySQL the row lock on `write_lock` that every write
//! transaction takes first (waiting up to `innodb_lock_wait_timeout`, set to the same value).
//! Both backends therefore see exactly one writer at a time.
//!
//! # Migrations
//!
//! The schema lives in `crates/server/core/migrations/sqlite/` and `.../mysql/`, one file per
//! version in each, with the same tables, keys and cascades; both are embedded into the binary.
//! See the header of `migrations/sqlite/0001_initial.sql`, and [`crate::meta`] for the path
//! comparison rules every query must follow.

use std::{
    collections::HashMap,
    fs,
    ops::{Deref, DerefMut},
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use sqlx::{
    Any, AnyConnection, ConnectOptions as _, Decode, Transaction, Type,
    any::{AnyConnectOptions, AnyPoolOptions, AnyTypeInfo, AnyTypeInfoKind, AnyValueRef},
    error::BoxDynError,
    migrate::Migrator,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use url::Url;

use crate::{
    config::DbConfig,
    error::{Error, Result},
};

/// Connection pool type used throughout Gono Cloud.
pub type Pool = sqlx::AnyPool;

/// The database systems Gono Cloud runs on (`db.backend`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// SQLite, compiled into the binary: one database file next to the data.
    #[default]
    Sqlite,
    /// MySQL 5.7.44 or later, InnoDB with utf8mb4.
    MySql,
}

impl Backend {
    /// The backend `pool` connects to.
    pub fn of(pool: &Pool) -> Self {
        Self::of_url(&pool.connect_options().database_url)
    }

    /// The backend of an open connection.
    pub fn of_connection(conn: &AnyConnection) -> Self {
        if conn.backend_name().eq_ignore_ascii_case("mysql") {
            Self::MySql
        } else {
            Self::Sqlite
        }
    }

    fn of_url(url: &Url) -> Self {
        if url.scheme() == "mysql" {
            Self::MySql
        } else {
            Self::Sqlite
        }
    }

    /// One of two SQL texts: the dialects differ, but each text stays a static string.
    pub const fn pick(self, sqlite: &'static str, mysql: &'static str) -> &'static str {
        match self {
            Self::Sqlite => sqlite,
            Self::MySql => mysql,
        }
    }

    /// `sqlite` or `mysql`, as `db.backend` spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::MySql => "mysql",
        }
    }
}

/// An integer column or expression read as a boolean: nonzero is `true`.
///
/// Both backends return integers for the 0/1 columns and for boolean expressions (`EXISTS`,
/// comparisons), and sqlx's `Any` driver decodes `bool` only from a value that the backend
/// typed as a boolean. Use it as `#[sqlx(try_from = "Flag")]` on `bool` fields and as
/// `query_scalar::<_, Flag>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flag(pub bool);

impl From<Flag> for bool {
    fn from(flag: Flag) -> Self {
        flag.0
    }
}

impl Type<Any> for Flag {
    fn type_info() -> AnyTypeInfo {
        <i64 as Type<Any>>::type_info()
    }

    fn compatible(ty: &AnyTypeInfo) -> bool {
        ty.kind().is_integer() || ty.kind() == AnyTypeInfoKind::Bool
    }
}

impl<'r> Decode<'r, Any> for Flag {
    fn decode(value: AnyValueRef<'r>) -> std::result::Result<Self, BoxDynError> {
        // The value's kind is private to sqlx: delegate to the decoders it has.
        if sqlx::ValueRef::type_info(&value).kind() == AnyTypeInfoKind::Bool {
            return Ok(Self(<bool as Decode<Any>>::decode(value)?));
        }
        Ok(Self(<i64 as Decode<Any>>::decode(value)? != 0))
    }
}

/// A text column read as a string, also where MySQL stores it as `VARBINARY`.
///
/// Columns compared byte for byte (paths, usernames, keys) are `COLLATE BINARY` in SQLite and
/// `VARBINARY` in MySQL, whose `utf8mb4_bin` collation ignores trailing spaces. MySQL returns
/// them as bytes, which sqlx's `Any` driver does not decode as `String`. Every value written to
/// them is valid UTF-8, so invalid UTF-8 is a decoding error. Use it as
/// `#[sqlx(try_from = "Text")]` and as `query_scalar::<_, Text>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Text(pub String);

impl From<Text> for String {
    fn from(text: Text) -> Self {
        text.0
    }
}

impl Deref for Text {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl Type<Any> for Text {
    fn type_info() -> AnyTypeInfo {
        <String as Type<Any>>::type_info()
    }

    fn compatible(ty: &AnyTypeInfo) -> bool {
        matches!(ty.kind(), AnyTypeInfoKind::Text | AnyTypeInfoKind::Blob)
    }
}

impl<'r> Decode<'r, Any> for Text {
    fn decode(value: AnyValueRef<'r>) -> std::result::Result<Self, BoxDynError> {
        if sqlx::ValueRef::type_info(&value).kind() == AnyTypeInfoKind::Blob {
            let bytes = <Vec<u8> as Decode<Any>>::decode(value)?;
            return Ok(Self(String::from_utf8(bytes)?));
        }
        Ok(Self(<String as Decode<Any>>::decode(value)?))
    }
}

/// `n` placeholders separated by commas, for `IN (...)` lists built at run time.
///
/// Keep lists below [`MAX_LIST`] values: SQLite accepts at most 32766 bound values per
/// statement.
pub fn placeholders(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// Most values callers put into one `IN (...)` list; longer lists are split into chunks.
pub const MAX_LIST: usize = 400;

/// A write transaction started by [`begin_immediate`]. It holds the database's write gate (and
/// on MySQL the row lock of `write_lock`) until it is committed, rolled back or dropped, and is
/// used like the connection it runs on (`&mut *tx` as an executor).
pub struct Tx {
    // Dropped first: a transaction that was neither committed nor rolled back is rolled back
    // before the next writer passes the gate (the database's own lock covers the rest).
    inner: Transaction<'static, Any>,
    backend: Backend,
    _gate: OwnedMutexGuard<()>,
}

impl Tx {
    /// Commits the transaction and opens the gate.
    pub async fn commit(self) -> std::result::Result<(), sqlx::Error> {
        self.inner.commit().await
    }

    /// Rolls the transaction back and opens the gate.
    pub async fn rollback(self) -> std::result::Result<(), sqlx::Error> {
        self.inner.rollback().await
    }

    /// The backend the transaction runs on.
    pub fn backend(&self) -> Backend {
        self.backend
    }
}

impl Deref for Tx {
    type Target = AnyConnection;

    fn deref(&self) -> &AnyConnection {
        &self.inner
    }
}

impl DerefMut for Tx {
    fn deref_mut(&mut self) -> &mut AnyConnection {
        &mut self.inner
    }
}

impl std::fmt::Debug for Tx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tx")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

/// The write gate of the database `pool` opens, one per database in this process. Databases
/// are told apart by their URL without the password: for SQLite the canonical path of the
/// file, for MySQL the server and the database name.
fn write_gate(pool: &Pool) -> Arc<AsyncMutex<()>> {
    static GATES: OnceLock<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>> = OnceLock::new();
    let mut url = pool.connect_options().database_url.clone();
    // Fails only for URLs that cannot have a password, which then carry none.
    let _ = url.set_password(None);
    GATES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(url.into())
        .or_default()
        .clone()
}

/// The embedded SQLite schema migrations.
pub static SQLITE_MIGRATOR: Migrator = sqlx::migrate!("./migrations/sqlite");

/// The embedded MySQL schema migrations, one for every SQLite migration.
pub static MYSQL_MIGRATOR: Migrator = sqlx::migrate!("./migrations/mysql");

/// The migrations of `backend`.
pub fn migrator(backend: Backend) -> &'static Migrator {
    match backend {
        Backend::Sqlite => &SQLITE_MIGRATOR,
        Backend::MySql => &MYSQL_MIGRATOR,
    }
}

/// Whether [`connect`] may start from a database without the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// SQLite: create the file (and its parent directories) if needed. MySQL: the database
    /// must exist (Gono Cloud never creates one) and be empty or hold Gono Cloud's schema.
    /// Used by `init`.
    CreateIfMissing,
    /// The database must exist and hold Gono Cloud's schema: SQLite fails with
    /// [`Error::DatabaseMissing`] if the file does not exist, MySQL with
    /// [`Error::DatabaseUninitialized`] for a database without the schema. Used by `serve` and
    /// the management commands, so that a typo in `db.path` or `db.url` cannot silently start
    /// from an empty database.
    MustExist,
}

/// Opens a connection pool to the configured database.
///
/// This does not run migrations; call [`migrate`] afterwards. A MySQL server that is older
/// than 5.7.44, or a database whose character set, row format or storage engine Gono Cloud
/// does not support, is refused with [`Error::DatabaseUnsupported`].
pub async fn connect(config: &DbConfig, mode: OpenMode) -> Result<Pool> {
    sqlx::any::install_default_drivers();
    match config.backend {
        Backend::Sqlite => connect_sqlite(config, mode).await,
        Backend::MySql => connect_mysql(config, mode).await,
    }
}

async fn connect_sqlite(config: &DbConfig, mode: OpenMode) -> Result<Pool> {
    let path = &config.path;
    match mode {
        OpenMode::CreateIfMissing => create_database_file(path)?,
        OpenMode::MustExist => {
            if !path.exists() {
                return Err(Error::DatabaseMissing { path: path.clone() });
            }
        }
    }
    // The `Any` driver configures SQLite from a URL only. The canonical path has no `.` or `..`
    // segments (which URL parsing would remove) and names the file the same way whichever
    // path the configuration used, which the write gate relies on.
    let canonical = fs::canonicalize(path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    let options = AnyConnectOptions::from_str(&sqlite_url(&canonical)?)?;
    let busy_timeout_ms = config.busy_timeout_secs.saturating_mul(1000);
    let pool = AnyPoolOptions::new()
        .max_connections(config.max_connections)
        .after_connect(move |conn, _| Box::pin(configure_sqlite(conn, busy_timeout_ms)))
        .connect_with(options)
        .await?;
    Ok(pool)
}

/// The URL that opens the existing SQLite file `path` (absolute) for reading and writing.
fn sqlite_url(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or_else(|| {
        Error::DatabaseUnsupported(format!(
            "the database path {} is not valid UTF-8",
            path.display()
        ))
    })?;
    // sqlx percent-decodes the path; everything but unreserved characters and `/` is encoded,
    // so `?`, `#` and `%` in a file name survive.
    let mut url = String::from("sqlite://");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            url.push(char::from(byte));
        } else {
            url.push_str(&format!("%{byte:02X}"));
        }
    }
    // `rw`: the file must exist; `create_database_file` creates it with mode 0600.
    url.push_str("?mode=rw");
    Ok(url)
}

/// Session settings of every SQLite connection: WAL, enforced foreign keys, and
/// `synchronous = FULL` so that metadata never lags behind file contents after a power loss.
/// The busy timeout comes first, so that switching to WAL waits for other processes.
async fn configure_sqlite(
    conn: &mut AnyConnection,
    busy_timeout_ms: u64,
) -> std::result::Result<(), sqlx::Error> {
    let busy = format!("PRAGMA busy_timeout = {busy_timeout_ms}");
    sqlx::query(sqlx::AssertSqlSafe(busy))
        .execute(&mut *conn)
        .await?;
    for pragma in [
        "PRAGMA journal_mode = WAL",
        "PRAGMA foreign_keys = ON",
        "PRAGMA synchronous = FULL",
    ] {
        sqlx::query(pragma).execute(&mut *conn).await?;
    }
    Ok(())
}

/// The `sql_mode` of every MySQL session. Strict, so that a value that does not fit its column
/// is an error instead of being truncated; `ONLY_FULL_GROUP_BY` as MySQL's default;
/// `PIPES_AS_CONCAT` and `NO_BACKSLASH_ESCAPES` make `||` and string literals behave as in
/// SQLite (with the latter, `LIKE` has no escape character but the one an `ESCAPE` clause names,
/// as in SQLite).
const MYSQL_SQL_MODE: &str = "STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,\
     ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY,PIPES_AS_CONCAT,\
     NO_BACKSLASH_ESCAPES";

/// The oldest MySQL release Gono Cloud runs on.
const MYSQL_MIN_VERSION: (u32, u32, u32) = (5, 7, 44);

async fn connect_mysql(config: &DbConfig, mode: OpenMode) -> Result<Pool> {
    let mut url = config.url.clone().ok_or_else(|| {
        Error::DatabaseUnsupported("db.url is required with backend = \"mysql\"".to_owned())
    })?;
    // Messages name the URL as configured, never with the password.
    let database = mysql_database(&url)?;
    if let Some(file) = &config.password_file {
        let password = read_password_file(file)?;
        url.set_password(Some(&password)).map_err(|()| {
            Error::DatabaseUnsupported(format!("db.url {url} cannot carry a password"))
        })?;
    }
    let options = AnyConnectOptions::from_url(&url)?;
    let busy_timeout_secs = config.busy_timeout_secs;
    let pool = AnyPoolOptions::new()
        .max_connections(config.max_connections)
        .after_connect(move |conn, _| Box::pin(configure_mysql(conn, busy_timeout_secs)))
        .connect_with(options)
        .await?;
    if let Err(err) = check_mysql(&pool, &database, mode).await {
        pool.close().await;
        return Err(err);
    }
    Ok(pool)
}

/// The database name of a MySQL URL (`mysql://user@host:port/<database>`).
fn mysql_database(url: &Url) -> Result<String> {
    let name = url.path().trim_start_matches('/');
    let name = percent_decode(name);
    if name.is_empty() || name.contains('/') {
        return Err(Error::DatabaseUnsupported(format!(
            "db.url {url} must name exactly one database, as in mysql://gono@127.0.0.1:3306/gono_cloud"
        )));
    }
    Ok(name)
}

/// Decodes `%XX` escapes (the database name of a URL).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[index], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                index += 3;
            }
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads the MySQL password from `db.password_file`: the first line, without the line break.
fn read_password_file(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(content.lines().next().unwrap_or_default().to_owned())
}

/// Session settings of every MySQL connection: the SQL mode (see [`MYSQL_SQL_MODE`]), UTC,
/// `READ COMMITTED` (writers are serialized by `write_lock`, so readers need no more than the
/// latest committed state, as with SQLite in WAL mode), utf8mb4 with a binary collation for
/// literals and parameters, the lock wait of `db.busy_timeout_secs`, and InnoDB for tables
/// created without an engine (sqlx's `_sqlx_migrations`).
async fn configure_mysql(
    conn: &mut AnyConnection,
    busy_timeout_secs: u64,
) -> std::result::Result<(), sqlx::Error> {
    let set = format!(
        "SET SESSION sql_mode = '{MYSQL_SQL_MODE}', time_zone = '+00:00', \
         transaction_isolation = 'READ-COMMITTED', innodb_lock_wait_timeout = {busy_timeout_secs}, \
         default_storage_engine = 'InnoDB', NAMES utf8mb4 COLLATE utf8mb4_bin"
    );
    sqlx::query(sqlx::AssertSqlSafe(set))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Refuses a MySQL server or database Gono Cloud does not support, and a database that does not
/// fit `mode`.
async fn check_mysql(pool: &Pool, database: &str, mode: OpenMode) -> Result<()> {
    let version: Text = sqlx::query_scalar("SELECT VERSION()")
        .fetch_one(pool)
        .await?;
    check_mysql_version(&version)?;

    let charset: Option<Text> = sqlx::query_scalar(
        "SELECT DEFAULT_CHARACTER_SET_NAME FROM information_schema.SCHEMATA \
         WHERE SCHEMA_NAME = DATABASE()",
    )
    .fetch_optional(pool)
    .await?;
    if charset.as_deref() != Some("utf8mb4") {
        return Err(Error::DatabaseUnsupported(format!(
            "the default character set of MySQL database {database} is {}, not utf8mb4; \
             create it with `CREATE DATABASE {database} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin` \
             or change it with `ALTER DATABASE {database} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`",
            charset.as_deref().unwrap_or("unknown")
        )));
    }

    // Indexes on paths need keys of up to 3072 bytes: the DYNAMIC row format (every table
    // asks for it) with large index prefixes, which MySQL 5.7 has unless turned off.
    let row_format: Text = sqlx::query_scalar("SELECT @@innodb_default_row_format")
        .fetch_one(pool)
        .await?;
    if !row_format.eq_ignore_ascii_case("dynamic") {
        let large_prefix: i64 = sqlx::query_scalar("SELECT @@innodb_large_prefix + 0")
            .fetch_one(pool)
            .await
            .unwrap_or(1);
        if large_prefix == 0 {
            return Err(Error::DatabaseUnsupported(format!(
                "innodb_default_row_format is {} and innodb_large_prefix is off; set \
                 innodb_default_row_format = DYNAMIC (the default)",
                &*row_format
            )));
        }
    }

    // InnoDB refuses to log READ COMMITTED transactions statement by statement.
    let (log_bin, binlog_format): (i64, Text) =
        sqlx::query_as("SELECT @@log_bin + 0, @@binlog_format")
            .fetch_one(pool)
            .await?;
    if log_bin != 0 && binlog_format.eq_ignore_ascii_case("statement") {
        return Err(Error::DatabaseUnsupported(
            "the binary log of the MySQL server uses binlog_format = STATEMENT, which cannot log \
             the READ COMMITTED transactions of Gono Cloud; set binlog_format = ROW (the default) \
             or MIXED"
                .to_owned(),
        ));
    }

    let tables: Vec<(Text, Option<Text>)> = sqlx::query_as(
        "SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'",
    )
    .fetch_all(pool)
    .await?;
    if let Some((table, engine)) = tables.iter().find(|(_, engine)| {
        !engine
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case("InnoDB"))
    }) {
        return Err(Error::DatabaseUnsupported(format!(
            "table {} of MySQL database {database} uses the {} storage engine; Gono Cloud needs \
             InnoDB (ALTER TABLE {} ENGINE = InnoDB)",
            &**table,
            engine.as_deref().unwrap_or("unknown"),
            &**table
        )));
    }
    let migrated = tables
        .iter()
        .any(|(table, _)| &**table == "_sqlx_migrations");
    match mode {
        OpenMode::MustExist if !migrated => Err(Error::DatabaseUninitialized {
            database: database.to_owned(),
        }),
        OpenMode::CreateIfMissing if !migrated && !tables.is_empty() => {
            Err(Error::DatabaseForeign {
                database: database.to_owned(),
            })
        }
        _ => Ok(()),
    }
}

/// Refuses MySQL releases before 5.7.44 and MariaDB, which Gono Cloud is not tested with.
fn check_mysql_version(version: &str) -> Result<()> {
    if version.contains("MariaDB") {
        return Err(Error::DatabaseUnsupported(format!(
            "the server is MariaDB {version}; Gono Cloud supports MySQL 5.7.44 or later"
        )));
    }
    let mut numbers = version
        .split(|c: char| !c.is_ascii_digit())
        .take(3)
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let found = (
        numbers.next().unwrap_or(0),
        numbers.next().unwrap_or(0),
        numbers.next().unwrap_or(0),
    );
    if found < MYSQL_MIN_VERSION {
        return Err(Error::DatabaseUnsupported(format!(
            "MySQL {version} is too old; Gono Cloud needs MySQL 5.7.44 or later"
        )));
    }
    Ok(())
}

/// Applies all pending migrations of the pool's backend.
///
/// Fails if an already applied migration was modified (checksum mismatch) or if the database
/// was migrated by a newer version of Gono Cloud.
pub async fn migrate(pool: &Pool) -> Result<()> {
    migrator(Backend::of(pool)).run(pool).await?;
    Ok(())
}

/// Starts a write transaction, after the database's write gate.
///
/// SQLite: `BEGIN IMMEDIATE`. MySQL: `BEGIN` and a locking read of the one row of
/// `write_lock`, which plays the part of SQLite's write lock across processes and is released
/// with the transaction.
///
/// Every operation that writes uses exactly one such transaction. Taking the write lock at
/// `BEGIN` means a transaction never has to be retried after it has already read data. A
/// transaction must not start another one on the same database: the second would wait for the
/// first forever.
pub async fn begin_immediate(pool: &Pool) -> Result<Tx> {
    let gate = write_gate(pool).lock_owned().await;
    let backend = Backend::of(pool);
    let inner = match backend {
        Backend::Sqlite => pool.begin_with("BEGIN IMMEDIATE").await?,
        Backend::MySql => {
            let mut inner = pool.begin().await?;
            sqlx::query("SELECT id FROM write_lock WHERE id = 1 FOR UPDATE")
                .execute(&mut *inner)
                .await?;
            inner
        }
    };
    Ok(Tx {
        inner,
        backend,
        _gate: gate,
    })
}

/// Allocates the next id of `table` from `id_sequences`, inside the write transaction `tx`.
///
/// Ids allocated this way are never handed out again, also after the rows are deleted, the
/// transaction is rolled back (the counter rolls back with it, so nobody saw the id) or the
/// server restarts. The INSERT then names the id explicitly.
pub async fn next_id(tx: &mut Tx, table: &'static str) -> Result<i64> {
    next_ids(tx, table, 1).await
}

/// Allocates `count` (at least 1) consecutive ids of `table` and returns the first; the others
/// follow it. See [`next_id`].
pub async fn next_ids(tx: &mut Tx, table: &'static str, count: u32) -> Result<i64> {
    let count = i64::from(count.max(1));
    let updated = sqlx::query("UPDATE id_sequences SET last_id = last_id + ? WHERE name = ?")
        .bind(count)
        .bind(table)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    debug_assert_eq!(updated, 1, "id_sequences has no row for {table}");
    let last: i64 = sqlx::query_scalar("SELECT last_id FROM id_sequences WHERE name = ?")
        .bind(table)
        .fetch_one(&mut **tx)
        .await?;
    Ok(last - count + 1)
}

/// The bytes MySQL holds for the tables and indexes of the database, or `None` for SQLite, whose
/// size is that of its files.
pub async fn size_on_server(pool: &Pool) -> Result<Option<u64>> {
    if Backend::of(pool) == Backend::Sqlite {
        return Ok(None);
    }
    let bytes: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) AS SIGNED) \
         FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()",
    )
    .fetch_one(pool)
    .await?;
    Ok(Some(u64::try_from(bytes).unwrap_or(0)))
}

/// Runs a trivial query to check that the database is reachable.
pub async fn ping(pool: &Pool) -> Result<()> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}

/// Current time as UNIX seconds, the unit of every `*_at` column.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Creates the database file and its parent directory if they do not exist yet.
///
/// On Unix the file is created with mode `0600` and new directories with `0700`: the database
/// holds password hashes. SQLite creates its `-wal` and `-shm` files with the permissions of
/// the main file.
fn create_database_file(path: &Path) -> Result<()> {
    let io_error = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(parent).map_err(|source| Error::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        // An empty file is a valid, empty SQLite database.
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(io_error(err)),
    }
}

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_versions_are_checked() {
        for ok in [
            "5.7.44",
            "5.7.44-log",
            "5.7.50",
            "8.0.36",
            "8.4.3-commercial",
            "9.1.0",
        ] {
            assert!(check_mysql_version(ok).is_ok(), "{ok}");
        }
        for old in ["5.7.43", "5.6.51", "5.7.9-log", "4.1"] {
            assert!(check_mysql_version(old).is_err(), "{old}");
        }
        assert!(check_mysql_version("10.11.6-MariaDB").is_err());
        assert!(check_mysql_version("5.5.5-10.11.6-MariaDB-log").is_err());
    }

    #[test]
    fn sqlite_urls_encode_the_path() {
        assert_eq!(
            sqlite_url(Path::new("/var/lib/gono-cloud/gono-cloud.db")).unwrap(),
            "sqlite:///var/lib/gono-cloud/gono-cloud.db?mode=rw"
        );
        assert_eq!(
            sqlite_url(Path::new("/tmp/a b/c?d#e%f.db")).unwrap(),
            "sqlite:///tmp/a%20b/c%3Fd%23e%25f.db?mode=rw"
        );
    }

    #[test]
    fn database_names_come_from_the_url_path() {
        let url = Url::parse("mysql://gono@127.0.0.1:3306/gono_cloud").unwrap();
        assert_eq!(mysql_database(&url).unwrap(), "gono_cloud");
        let url = Url::parse("mysql://gono@127.0.0.1:3306/gono%2Dcloud").unwrap();
        assert_eq!(mysql_database(&url).unwrap(), "gono-cloud");
        for bad in [
            "mysql://gono@127.0.0.1:3306",
            "mysql://gono@127.0.0.1:3306/a/b",
        ] {
            assert!(mysql_database(&Url::parse(bad).unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn backends_parse_from_their_names() {
        #[derive(Deserialize)]
        struct Wrapper {
            backend: Backend,
        }
        let parse = |raw: &str| toml::from_str::<Wrapper>(raw).map(|w| w.backend);
        assert_eq!(parse("backend = \"sqlite\"").unwrap(), Backend::Sqlite);
        assert_eq!(parse("backend = \"mysql\"").unwrap(), Backend::MySql);
        assert!(parse("backend = \"MySQL\"").is_err());
        assert!(parse("backend = \"postgres\"").is_err());
    }
}
