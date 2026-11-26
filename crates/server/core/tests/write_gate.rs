//! The database's write gate (`db::begin_immediate`): writers queue in this process instead of
//! in the database's lock wait, one at a time, and readers are never held up by them. On MySQL
//! the row lock of `write_lock` also serializes writers of different processes. The tests run on
//! the backend `GONO_TEST_MYSQL_URL` chooses (see `db::testing`).

use std::time::Duration;

use gono_server_core::db::{self, Backend, OpenMode, Pool};

async fn database(dir: &std::path::Path) -> Pool {
    let pool = db::testing::database(dir).await;
    sqlx::query("CREATE TABLE counter (n INTEGER NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO counter (n) VALUES (0)")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

#[tokio::test]
async fn writers_wait_at_the_gate_and_readers_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;

    let mut first = db::begin_immediate(&pool).await.unwrap();
    sqlx::query("UPDATE counter SET n = n + 1")
        .execute(&mut *first)
        .await
        .unwrap();

    // A second writer waits for the first one to end...
    let second = tokio::spawn({
        let pool = pool.clone();
        async move {
            let mut tx = db::begin_immediate(&pool).await.unwrap();
            sqlx::query("UPDATE counter SET n = n * 10")
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!second.is_finished(), "the second writer passed the gate");

    // ...while readers get a connection and see the last committed state.
    let seen: i64 = tokio::time::timeout(
        Duration::from_secs(1),
        sqlx::query_scalar("SELECT n FROM counter").fetch_one(&pool),
    )
    .await
    .expect("a reader waited for a writer")
    .unwrap();
    assert_eq!(seen, 0);

    first.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .expect("the second writer never passed the gate")
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT n FROM counter")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 10, "the writers ran one after the other, in order");
}

#[tokio::test]
async fn a_dropped_transaction_opens_the_gate_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;

    {
        let mut tx = db::begin_immediate(&pool).await.unwrap();
        sqlx::query("UPDATE counter SET n = 99")
            .execute(&mut *tx)
            .await
            .unwrap();
        // Dropped without commit, as when a request fails halfway.
    }
    let mut tx = tokio::time::timeout(Duration::from_secs(5), db::begin_immediate(&pool))
        .await
        .expect("the gate stayed closed")
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT n FROM counter")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 0);
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn databases_have_gates_of_their_own() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    let first = database(one.path()).await;
    let second = database(two.path()).await;

    let held = db::begin_immediate(&first).await.unwrap();
    let other = tokio::time::timeout(Duration::from_secs(1), db::begin_immediate(&second))
        .await
        .expect("another database's writer waited")
        .unwrap();
    other.commit().await.unwrap();
    held.commit().await.unwrap();
}

/// Two pools on one MySQL database stand for two processes (the server and the CLI): they
/// have gates of their own, and the row lock of `write_lock` still lets one writer at a time
/// through.
#[tokio::test]
async fn mysql_writers_of_different_processes_take_turns() {
    if db::testing::backend() != Backend::MySql {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = db::testing::config(dir.path()).await;
    let first = db::testing::open(&config).await;
    sqlx::query("CREATE TABLE counter (n INTEGER NOT NULL)")
        .execute(&first)
        .await
        .unwrap();
    sqlx::query("INSERT INTO counter (n) VALUES (0)")
        .execute(&first)
        .await
        .unwrap();
    // Another URL for the same database: another gate, as in another process. The parameter is
    // added to the URL's own ones, such as the ssl-mode of GONO_TEST_MYSQL_URL.
    let mut other = config.clone();
    let mut url = other.url.clone().unwrap();
    url.query_pairs_mut()
        .append_pair("statement-cache-capacity", "99");
    other.url = Some(url);
    let second = db::connect(&other, OpenMode::MustExist).await.unwrap();

    let mut held = db::begin_immediate(&first).await.unwrap();
    sqlx::query("UPDATE counter SET n = n + 1")
        .execute(&mut *held)
        .await
        .unwrap();
    let waiting = tokio::spawn(async move {
        let mut tx = db::begin_immediate(&second).await.unwrap();
        let seen: i64 = sqlx::query_scalar("SELECT n FROM counter")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE counter SET n = n * 10")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        seen
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !waiting.is_finished(),
        "the other process's writer did not wait"
    );
    held.commit().await.unwrap();
    let seen = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the other process's writer never got the lock")
        .unwrap();
    assert_eq!(
        seen, 1,
        "the second writer read after the first one committed"
    );
    let n: i64 = sqlx::query_scalar("SELECT n FROM counter")
        .fetch_one(&first)
        .await
        .unwrap();
    assert_eq!(n, 10);
}
