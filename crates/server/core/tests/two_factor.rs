//! Two-step verification against a real database: enrolment, codes and recovery codes that
//! work once, the lock after failures, and turning it off.

use gono_server_core::{
    Error, Username,
    config::DbConfig,
    db::{self, OpenMode, Pool},
    devices,
    sealing::Purpose,
    two_factor::{self, Key, TurnedOff, Verification},
    users::{self, NewUser},
    web_sessions,
};
use secrecy::ExposeSecret as _;

async fn fixture() -> (tempfile::TempDir, Pool, i64) {
    let dir = tempfile::tempdir().unwrap();
    let config = DbConfig {
        path: dir.path().join("gono-cloud.db"),
        max_connections: 4,
        busy_timeout_secs: 5,
    };
    let pool = db::connect(&config, OpenMode::CreateIfMissing)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let username = Username::new("alice").unwrap();
    let alice = users::create(
        &pool,
        &NewUser {
            username: &username,
            display_name: "Alice",
            password_hash: "x",
            is_admin: false,
        },
        |_| Ok(()),
    )
    .await
    .unwrap();
    (dir, pool, alice)
}

const NOW: i64 = 1_763_200_000;

#[tokio::test]
async fn codes_and_recovery_codes_work_once() {
    let (_dir, pool, alice) = fixture().await;
    let key = Key::from_bytes(&[5; 32]);
    let secret = two_factor::new_secret();
    let step = two_factor::step_of(NOW);
    assert!(!two_factor::is_enrolled(&pool, alice).await.unwrap());
    let codes = two_factor::enable(&pool, &key, alice, &secret, step, None, None, NOW)
        .await
        .unwrap();
    assert_eq!(codes.len(), two_factor::RECOVERY_CODES);
    assert!(devices::remote_access(&pool, alice).await.unwrap());
    assert!(matches!(
        two_factor::enable(&pool, &key, alice, &secret, step, None, None, NOW).await,
        Err(Error::TwoFactorEnrolled)
    ));

    // The code of the enrolment step is used up; the next step's works once.
    let current = format!("{:06}", two_factor::code_at(&secret, step));
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &current, None, NOW)
            .await
            .unwrap(),
        Verification::Wrong
    );
    let next = format!("{:06}", two_factor::code_at(&secret, step + 1));
    let later = NOW + two_factor::STEP_SECS;
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &next, None, later)
            .await
            .unwrap(),
        Verification::Code
    );
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &next, None, later)
            .await
            .unwrap(),
        Verification::Wrong,
        "replayed"
    );

    // Another key cannot open the secret.
    let other = Key::from_bytes(&[6; 32]);
    let fresh = format!("{:06}", two_factor::code_at(&secret, step + 3));
    assert_eq!(
        two_factor::verify(
            &pool,
            &other,
            alice,
            &fresh,
            None,
            NOW + 3 * two_factor::STEP_SECS
        )
        .await
        .unwrap(),
        Verification::WrongKey
    );

    let recovery = codes[0].to_ascii_lowercase().replace('-', " ");
    let client = "198.51.100.4".parse().ok();
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &recovery, client, later)
            .await
            .unwrap(),
        Verification::RecoveryCode { left: 9 }
    );
    // The use is recorded with the client's address, for the account page.
    assert_eq!(
        two_factor::recovery_code_uses(&pool, alice, NOW - 1, 5)
            .await
            .unwrap(),
        [(later, Some("198.51.100.4".to_owned()))]
    );
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &recovery, None, later)
            .await
            .unwrap(),
        Verification::Wrong
    );
    let status = two_factor::status(&pool, alice).await.unwrap().unwrap();
    assert_eq!(status.recovery_codes_left, 9);

    let renewed = two_factor::renew_recovery_codes(&pool, alice, None, later)
        .await
        .unwrap();
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &codes[1], None, later)
            .await
            .unwrap(),
        Verification::Wrong,
        "old codes are gone"
    );
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &renewed[1], None, later)
            .await
            .unwrap(),
        Verification::RecoveryCode { left: 9 }
    );

    assert!(
        two_factor::disable(&pool, alice, TurnedOff::Admin, None, later)
            .await
            .unwrap()
    );
    assert!(!devices::remote_access(&pool, alice).await.unwrap());
    assert_eq!(
        two_factor::verify(&pool, &key, alice, &next, None, later)
            .await
            .unwrap(),
        Verification::NotEnrolled
    );
    let kinds: Vec<String> = gono_server_core::audit::list(&pool, Some(alice), None, 20)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            "two_factor.reset",
            "recovery_code.used",
            "recovery_codes.renewed",
            "recovery_code.used",
            "two_factor.enabled",
        ]
    );
}

#[tokio::test]
async fn enrolment_ends_the_other_browser_sessions() {
    let (_dir, pool, alice) = fixture().await;
    let enrolling = web_sessions::create(&pool, alice, NOW).await.unwrap();
    // A session opened with the password alone, before two-step verification was on.
    let earlier = web_sessions::create(&pool, alice, NOW).await.unwrap();
    let current = web_sessions::lookup(&pool, enrolling.expose_secret(), NOW)
        .await
        .unwrap()
        .unwrap();
    let key = Key::from_bytes(&[5; 32]);
    let secret = two_factor::new_secret();
    two_factor::enable(
        &pool,
        &key,
        alice,
        &secret,
        two_factor::step_of(NOW),
        Some(current.session_id),
        None,
        NOW,
    )
    .await
    .unwrap();
    assert!(
        web_sessions::lookup(&pool, earlier.expose_secret(), NOW)
            .await
            .unwrap()
            .is_none(),
        "the earlier session ended"
    );
    assert!(
        web_sessions::lookup(&pool, enrolling.expose_secret(), NOW)
            .await
            .unwrap()
            .is_some(),
        "the enrolling session stays"
    );
}

#[tokio::test]
async fn sign_ins_continue_with_the_account_of_their_id() {
    let (_dir, pool, alice) = fixture().await;
    let account = two_factor::sign_in_account(&pool, alice)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.username.as_str(), "alice");
    let name = Username::new("alice").unwrap();
    users::delete(&pool, &name).await.unwrap();
    assert!(
        two_factor::sign_in_account(&pool, alice)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn failures_lock_the_second_step_for_a_while() {
    let (_dir, pool, alice) = fixture().await;
    for _ in 0..two_factor::FAILURES_PER_WINDOW - 1 {
        two_factor::record_failure(&pool, alice, Some("192.0.2.1".parse().unwrap()), NOW)
            .await
            .unwrap();
    }
    assert!(!two_factor::locked(&pool, alice, NOW).await.unwrap());
    two_factor::record_failure(&pool, alice, None, NOW)
        .await
        .unwrap();
    assert!(two_factor::locked(&pool, alice, NOW).await.unwrap());
    assert!(
        !two_factor::locked(&pool, alice, NOW + two_factor::FAILURE_WINDOW_SECS + 1)
            .await
            .unwrap(),
        "the short window passed"
    );
    let entries = gono_server_core::audit::list(&pool, Some(alice), None, 1)
        .await
        .unwrap();
    assert_eq!(entries[0].kind, "two_factor.locked");
}

#[test]
fn the_key_file_is_created_once_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two-factor.key");
    assert!(Key::load(&path).unwrap().is_none());
    assert!(Key::create(&path).unwrap());
    assert!(!Key::create(&path).unwrap(), "never overwritten");
    let key = Key::load(&path).unwrap().unwrap();
    let sealed = key.seal(Purpose::Totp, 1, b"x");
    assert_eq!(
        Key::load(&path)
            .unwrap()
            .unwrap()
            .open(Purpose::Totp, 1, &sealed)
            .as_deref(),
        Some(&b"x"[..])
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640, "{mode:o}");
    }
    std::fs::write(&path, "too short").unwrap();
    assert!(Key::load(&path).is_err());
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["two-factor.key"], "no temporary file is left");
}

#[test]
fn concurrent_creations_of_the_key_file_agree_on_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two-factor.key");
    let created: Vec<bool> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| Key::create(&path).unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(created.iter().filter(|c| **c).count(), 1, "{created:?}");
    assert_eq!(std::fs::read(&path).unwrap().len(), 32);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn a_dangling_link_is_not_replaced_by_a_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two-factor.key");
    let target = dir.path().join("elsewhere.key");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(!Key::create(&path).unwrap(), "the link counts as existing");
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!target.exists());
    assert!(Key::load(&path).unwrap().is_none());
}
