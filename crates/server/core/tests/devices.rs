//! The device directory against a real SQLite database: registration through a device flow,
//! revocation, signing out, the event log and relay admission.

use gono_server_core::{
    Username, app_passwords, audit,
    config::DbConfig,
    db::{self, OpenMode, Pool},
    devices::{self, EndpointId, NewDevice, Registration, RevokedBy, Settings},
    login_flows::{self, DevicePoll},
    two_factor,
    users::{self, NewUser},
};
use secrecy::ExposeSecret as _;

async fn fixture() -> (tempfile::TempDir, Pool) {
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
    (dir, pool)
}

async fn user(pool: &Pool, name: &str) -> i64 {
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

/// Two-step verification as part 2c will store it; the secret does not matter here.
async fn enroll(pool: &Pool, user_id: i64) {
    sqlx::query("INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (?1, x'00', 0)")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
}

fn key(seed: u8) -> EndpointId {
    EndpointId([seed; 32])
}

fn new_device(seed: u8, name: &str) -> NewDevice {
    NewDevice {
        endpoint_id: key(seed),
        product: "input-show".to_owned(),
        platform: "windows".to_owned(),
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
    }
}

/// Runs a device flow for `device` to completion as `user_id`.
async fn register(pool: &Pool, user_id: i64, device: &NewDevice, now: i64) -> Registration {
    let (flow, challenge) = login_flows::create_device(pool, device, now)
        .await
        .unwrap()
        .unwrap();
    let poll = flow.poll_token.expose_secret();
    assert_eq!(
        login_flows::device_poll(pool, poll, now).await.unwrap(),
        DevicePoll::Pending
    );
    let found = login_flows::find(pool, flow.login_token.expose_secret(), now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        found.device.as_ref().unwrap().endpoint_id,
        device.endpoint_id
    );
    assert!(
        login_flows::grant(
            pool,
            found.id,
            user_id,
            Some("192.0.2.1".parse().unwrap()),
            now
        )
        .await
        .unwrap()
    );
    assert_eq!(
        login_flows::device_poll(pool, poll, now).await.unwrap(),
        DevicePoll::Granted {
            endpoint_id: device.endpoint_id,
            challenge
        }
    );
    // A Nextcloud poll never consumes a device flow.
    assert!(
        login_flows::complete(pool, poll, now)
            .await
            .unwrap()
            .is_none()
    );
    let (_, registration) = login_flows::complete_device(pool, poll, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        login_flows::device_poll(pool, poll, now).await.unwrap(),
        DevicePoll::Gone,
        "used once"
    );
    registration
}

#[tokio::test]
async fn a_device_flow_registers_the_device_with_an_app_password_without_files() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let Registration::Registered {
        device,
        app_password,
        new: true,
    } = register(&pool, alice, &new_device(1, "Home PC"), 100).await
    else {
        panic!("expected a new registration");
    };
    assert_eq!(device.name, "Home PC");
    assert_eq!(
        device.pairing_open_until,
        Some(100 + devices::PAIRING_WINDOW_SECS)
    );
    assert!(device.pairing_open(100));

    let authenticated = app_passwords::authenticate(&pool, "alice", &app_password, 100)
        .await
        .unwrap()
        .unwrap();
    assert!(authenticated.scopes.is_empty(), "no file access");
    assert_eq!(
        devices::find_by_app_password(&pool, authenticated.app_password_id)
            .await
            .unwrap()
            .unwrap()
            .id,
        device.id
    );
    // The credential is the device's, not an app password of the account.
    assert!(app_passwords::list(&pool, alice).await.unwrap().is_empty());
    assert!(
        !app_passwords::delete(&pool, alice, authenticated.app_password_id)
            .await
            .unwrap()
    );

    let (events, truncated) = devices::events_since(&pool, alice, 0, 100).await.unwrap();
    assert!(!truncated);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "device.added");
    let audit = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    assert_eq!(audit[0].kind, "device.registered");
    assert_eq!(audit[0].client_ip.as_deref(), Some("192.0.2.1"));
}

#[tokio::test]
async fn registering_again_replaces_the_credential_and_keys_stay_with_their_account() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let Registration::Registered {
        device: first,
        app_password: old,
        ..
    } = register(&pool, alice, &new_device(1, "Home PC"), 100).await
    else {
        panic!()
    };
    let Registration::Registered {
        device: again,
        app_password: new,
        new: false,
    } = register(&pool, alice, &new_device(1, "Study PC"), 200).await
    else {
        panic!("expected a registration of the same entry")
    };
    assert_eq!(again.id, first.id);
    assert_eq!(again.name, "Study PC");
    assert!(
        app_passwords::authenticate(&pool, "alice", &old, 200)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        app_passwords::authenticate(&pool, "alice", &new, 200)
            .await
            .unwrap()
            .is_some()
    );
    let (events, _) = devices::events_since(&pool, alice, 0, 100).await.unwrap();
    assert_eq!(events.len(), 1, "no second device.added");

    assert!(matches!(
        register(&pool, bob, &new_device(1, "Bob's"), 300).await,
        Registration::Taken
    ));
}

#[tokio::test]
async fn revocation_is_final_and_keeps_a_tombstone() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let Registration::Registered {
        device,
        app_password,
        ..
    } = register(&pool, alice, &new_device(1, "Laptop"), 100).await
    else {
        panic!()
    };
    let revoked = devices::revoke(
        &pool,
        alice,
        &[key(1), key(9)],
        RevokedBy::AccountPage,
        None,
        150,
    )
    .await
    .unwrap();
    assert_eq!(revoked.len(), 1, "unknown keys are skipped");
    assert_eq!(revoked[0].revoked_at, Some(150));
    assert_eq!(revoked[0].app_password_id, None);
    assert!(
        app_passwords::authenticate(&pool, "alice", &app_password, 150)
            .await
            .unwrap()
            .is_none()
    );
    // Revoking again changes nothing.
    assert!(
        devices::revoke(&pool, alice, &[key(1)], RevokedBy::Cli, None, 160)
            .await
            .unwrap()
            .is_empty()
    );
    let listed = devices::list(&pool, alice).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].is_revoked());
    assert!(matches!(
        register(&pool, alice, &new_device(1, "Laptop"), 200).await,
        Registration::Revoked
    ));
    let (events, _) = devices::events_since(&pool, alice, 0, 100).await.unwrap();
    assert_eq!(
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        ["device.added", "device.revoked"]
    );
    assert!(events[1].body.contains("\"by\":\"account_page\""));
    assert_eq!(
        devices::get(&pool, device.id)
            .await
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(150)
    );
}

#[tokio::test]
async fn signing_out_leaves_no_tombstone() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let Registration::Registered { device, .. } =
        register(&pool, alice, &new_device(1, "Phone"), 100).await
    else {
        panic!()
    };
    assert!(
        devices::leave(&pool, device.id, 110)
            .await
            .unwrap()
            .is_some()
    );
    assert!(devices::list(&pool, alice).await.unwrap().is_empty());
    assert!(matches!(
        register(&pool, alice, &new_device(1, "Phone"), 120).await,
        Registration::Registered { new: true, .. }
    ));
}

#[tokio::test]
async fn deleting_an_account_removes_its_devices() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    register(&pool, alice, &new_device(1, "Home PC"), 100).await;
    register(&pool, alice, &new_device(2, "Laptop"), 100).await;
    devices::revoke(&pool, alice, &[key(2)], RevokedBy::Admin, None, 110)
        .await
        .unwrap();
    users::delete(&pool, &Username::new("alice").unwrap())
        .await
        .unwrap();
    for table in ["devices", "app_passwords", "device_events", "audit_log"] {
        let remaining: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0, "{table}");
    }
}

#[tokio::test]
async fn an_app_password_in_use_by_a_device_cannot_be_deleted_directly() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let Registration::Registered { device, .. } =
        register(&pool, alice, &new_device(1, "Home PC"), 100).await
    else {
        panic!()
    };
    let result = sqlx::query("DELETE FROM app_passwords WHERE id = ?1")
        .bind(device.app_password_id)
        .execute(&pool)
        .await;
    assert!(result.is_err(), "the foreign key keeps the credential");
}

#[tokio::test]
async fn an_account_holds_a_limited_number_of_devices() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    for seed in 0..devices::MAX_DEVICES_PER_ACCOUNT {
        let seed = u8::try_from(seed).unwrap();
        register(&pool, alice, &new_device(seed, "d"), 100).await;
    }
    assert!(matches!(
        register(&pool, alice, &new_device(200, "one more"), 100).await,
        Registration::TooMany
    ));
    devices::revoke(&pool, alice, &[key(0)], RevokedBy::Cli, None, 110)
        .await
        .unwrap();
    assert!(matches!(
        register(&pool, alice, &new_device(200, "one more"), 120).await,
        Registration::Registered { new: true, .. }
    ));
}

#[tokio::test]
async fn settings_change_the_entry() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let Registration::Registered { device, .. } =
        register(&pool, alice, &new_device(1, "Home PC"), 100).await
    else {
        panic!()
    };
    let updated = devices::update_settings(
        &pool,
        device.id,
        &Settings {
            name: Some(" Study ".to_owned()),
            accept_remote: Some(true),
            services: Some(vec!["inputshow/1".to_owned()]),
            ..Settings::default()
        },
        audit::Actor::Device,
        110,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(updated.name, "Study");
    assert!(updated.accept_remote && !updated.unattended);
    assert_eq!(updated.services, ["inputshow/1"]);
    assert!(
        devices::update_settings(
            &pool,
            device.id,
            &Settings {
                name: Some(String::new()),
                ..Settings::default()
            },
            audit::Actor::Device,
            120,
        )
        .await
        .is_err()
    );
    let kinds: Vec<String> = audit::list(&pool, Some(alice), None, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.kind)
        .collect();
    assert_eq!(
        kinds,
        ["device.settings", "device.renamed", "device.registered"]
    );
}

#[tokio::test]
async fn the_relay_admits_active_devices_of_accounts_with_two_step_verification() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    register(&pool, alice, &new_device(1, "a1"), 100).await;
    register(&pool, alice, &new_device(2, "a2"), 100).await;
    register(&pool, bob, &new_device(3, "b1"), 100).await;
    assert!(devices::admissible(&pool).await.unwrap().is_empty());
    assert!(!devices::remote_access(&pool, alice).await.unwrap());

    enroll(&pool, alice).await;
    assert!(two_factor::is_enrolled(&pool, alice).await.unwrap());
    assert!(devices::remote_access(&pool, alice).await.unwrap());
    let mut admitted = devices::admissible(&pool).await.unwrap();
    admitted.sort();
    assert_eq!(admitted, [key(1), key(2)]);

    devices::revoke(&pool, alice, &[key(2)], RevokedBy::Cli, None, 110)
        .await
        .unwrap();
    assert_eq!(devices::admissible(&pool).await.unwrap(), [key(1)]);
    users::set_enabled(&pool, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    assert!(devices::admissible(&pool).await.unwrap().is_empty());
    assert!(!devices::remote_access(&pool, alice).await.unwrap());
}

#[tokio::test]
async fn approvals_and_applied_revocations_are_recorded() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let mut ids = Vec::new();
    for seed in 1..=3 {
        let Registration::Registered { device, .. } =
            register(&pool, alice, &new_device(seed, "d"), 100).await
        else {
            panic!()
        };
        ids.push(device.id);
    }
    let Registration::Registered { device: bobs, .. } =
        register(&pool, bob, &new_device(9, "b"), 100).await
    else {
        panic!()
    };
    let seq = devices::record_approval(
        &pool,
        alice,
        ids[0],
        ids[1],
        &serde_json::json!({ "request_id": "r" }),
        120,
    )
    .await
    .unwrap();
    assert!(seq > 0);
    let introduced = devices::introduced_by(&pool, ids[0]).await.unwrap();
    assert_eq!(
        introduced.iter().map(|d| d.id).collect::<Vec<_>>(),
        [ids[1]]
    );

    devices::revoke(&pool, alice, &[key(1)], RevokedBy::AccountPage, None, 130)
        .await
        .unwrap();
    // Only revoked devices of the same account count, and each only once.
    let recorded = devices::record_applied(&pool, ids[2], &[key(1), key(2), key(9)], 140)
        .await
        .unwrap();
    assert_eq!(recorded, [key(1)]);
    assert!(
        devices::record_applied(&pool, ids[2], &[key(1)], 150)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        devices::record_applied(&pool, bobs.id, &[key(1)], 150)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        devices::applied(&pool, alice).await.unwrap(),
        [(ids[0], ids[2])]
    );
}

#[tokio::test]
async fn the_event_log_tells_a_device_when_it_fell_behind() {
    let (_dir, pool) = fixture().await;
    let alice = user(&pool, "alice").await;
    register(&pool, alice, &new_device(1, "a"), 100).await;
    register(&pool, alice, &new_device(2, "b"), 200).await;
    let (events, truncated) = devices::events_since(&pool, alice, 0, 100).await.unwrap();
    assert_eq!(events.len(), 2);
    assert!(!truncated);
    let first = events[0].seq;

    let (after, truncated) = devices::events_since(&pool, alice, first, 100)
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    assert!(!truncated);
    let (limited, truncated) = devices::events_since(&pool, alice, 0, 1).await.unwrap();
    assert_eq!(limited.len(), 1);
    assert!(truncated, "more than the limit");

    assert_eq!(devices::purge_events(&pool, 150).await.unwrap(), 1);
    let (after, truncated) = devices::events_since(&pool, alice, first, 100)
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    assert!(truncated, "the event the device saw last was purged");
    assert!(devices::last_seq(&pool).await.unwrap() > first);
    assert_eq!(
        devices::events_after(&pool, first, 10).await.unwrap().len(),
        1
    );
}
