//! Email addresses and their one-time codes (`gono_server_core::email`) on the backend the
//! environment chooses (`db::testing`): binding, removing, password resets, the keyed digests,
//! the binding of reset codes to a browser, the limits on codes and their tries, unique
//! addresses and the cleanup.

use std::sync::LazyLock;

use gono_server_core::{
    Username, audit,
    db::{self, Pool},
    email::{
        self, BIND_SENDS_PER_DAY, Bind, Binding, CODE_TTL_SECS, CodeFor, DAY_SECS, Key,
        MAX_ATTEMPTS, NewCode, Purpose, RESET_SENDS_PER_DAY, RESET_SENDS_PER_NET_PER_DAY, Reset,
        ResetClient, SEND_INTERVAL_SECS,
    },
    two_factor, users,
    users::NewUser,
    web_sessions,
};

/// A fixed "now" far from the real clock, so that the tests choose every time themselves.
const NOW: i64 = 1_800_000_000;

/// The server's key file.
static KEY: LazyLock<Key> = LazyLock::new(|| Key::from_bytes(&[7; 32]));

/// The owner's browser, which asks for reset codes from 192.0.2.7.
static OWNER: LazyLock<ResetClient> =
    LazyLock::new(|| ResetClient::new(&KEY, "owner cookie", "192.0.2.7".parse().unwrap()));

/// A browser at address `ip` with reset cookie `cookie`.
fn browser(cookie: &str, ip: &str) -> ResetClient {
    ResetClient::new(&KEY, cookie, ip.parse().unwrap())
}

async fn fixture() -> (tempfile::TempDir, Pool, i64, i64) {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let mut ids = Vec::new();
    for name in ["alice", "bob"] {
        let username = Username::new(name).unwrap();
        let id = users::create(
            &pool,
            &NewUser {
                username: &username,
                display_name: name,
                password_hash: "old hash",
                is_admin: false,
                services: gono_server_core::services::Services::NONE,
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        ids.push(id);
    }
    (dir, pool, ids[0], ids[1])
}

/// A new code of `purpose` for `address` (a reset code asked for by [`OWNER`]); panics on a
/// refusal.
async fn code(pool: &Pool, user: i64, purpose: Purpose, address: &str, now: i64) -> email::Code {
    let request = match purpose {
        Purpose::Bind => CodeFor::Bind,
        Purpose::Reset => CodeFor::Reset(&OWNER),
    };
    sent(pool, user, request, address, now).await
}

/// A new code for `request` to `address`; panics on a refusal.
async fn sent(
    pool: &Pool,
    user: i64,
    request: CodeFor<'_>,
    address: &str,
    now: i64,
) -> email::Code {
    match email::send_code(pool, &KEY, user, request, address, now)
        .await
        .unwrap()
    {
        NewCode::Code(code) => code,
        other => panic!("no code: {other:?}"),
    }
}

/// Binds `address` to `user` with a code sent at `now`.
async fn bind(pool: &Pool, user: i64, address: &str, now: i64) -> Bind {
    let sent = code(pool, user, Purpose::Bind, address, now).await;
    email::bind(pool, &KEY, user, &sent.code, None, now + 1)
        .await
        .unwrap()
}

/// Tries to reset the password of `user` with `code` from the browser of `binding`.
async fn try_reset(
    pool: &Pool,
    user: Option<i64>,
    binding: Option<&Binding>,
    code: &str,
    now: i64,
) -> Reset {
    email::reset_password(pool, &KEY, user, binding, code, "new hash", None, now)
        .await
        .unwrap()
}

/// The tries counted on the code of row `id`.
async fn attempts(pool: &Pool, id: i64) -> i64 {
    sqlx::query_scalar("SELECT attempts FROM email_codes WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A code that is not `code`.
fn other_than(code: &str) -> String {
    let value: u32 = code.parse().unwrap();
    format!("{:06}", (value + 1) % 1_000_000)
}

async fn updated_at(pool: &Pool, user: i64) -> i64 {
    users::by_id(pool, user).await.unwrap().unwrap().updated_at
}

async fn kinds(pool: &Pool, user: i64) -> Vec<String> {
    audit::list(pool, Some(user), None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.kind)
        .collect()
}

#[tokio::test]
async fn a_code_binds_the_address_it_was_sent_to() {
    let (_dir, pool, alice, _) = fixture().await;
    assert_eq!(email::address(&pool, alice).await.unwrap(), None);

    let sent = code(&pool, alice, Purpose::Bind, "alice@example.com", NOW).await;
    assert_eq!(sent.code.len(), 6);
    assert_eq!(sent.expires_at, NOW + CODE_TTL_SECS);
    assert!(!format!("{sent:?}").contains(&sent.code));
    assert_eq!(
        email::pending(&pool, alice, Purpose::Bind, NOW)
            .await
            .unwrap(),
        Some(("alice@example.com".to_owned(), NOW + CODE_TTL_SECS))
    );
    // Codes are stored as digests only.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT code_hash FROM email_codes WHERE id = ?")
        .bind(sent.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 32);
    assert!(!stored.windows(6).any(|w| w == sent.code.as_bytes()));

    let wrong = email::bind(&pool, &KEY, alice, &other_than(&sent.code), None, NOW + 1)
        .await
        .unwrap();
    assert_eq!(wrong, Bind::Wrong(MAX_ATTEMPTS - 1));
    assert_eq!(email::address(&pool, alice).await.unwrap(), None);

    let bound = email::bind(&pool, &KEY, alice, &sent.code, None, NOW + 2)
        .await
        .unwrap();
    assert_eq!(
        bound,
        Bind::Bound {
            email: "alice@example.com".to_owned(),
            previous: None
        }
    );
    assert_eq!(
        email::address(&pool, alice).await.unwrap().as_deref(),
        Some("alice@example.com")
    );
    // A recovery credential changed: sign-ins waiting for their second step end with it.
    assert_eq!(updated_at(&pool, alice).await, NOW + 2);
    assert!(
        kinds(&pool, alice)
            .await
            .contains(&"email.bound".to_owned())
    );

    // Used once.
    assert_eq!(
        email::bind(&pool, &KEY, alice, &sent.code, None, NOW + 3)
            .await
            .unwrap(),
        Bind::Expired
    );
    assert_eq!(
        email::pending(&pool, alice, Purpose::Bind, NOW + 3)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn codes_expire_and_take_five_tries() {
    let (_dir, pool, alice, _) = fixture().await;
    let sent = code(&pool, alice, Purpose::Bind, "alice@example.com", NOW).await;
    assert_eq!(
        email::bind(&pool, &KEY, alice, &sent.code, None, NOW + CODE_TTL_SECS)
            .await
            .unwrap(),
        Bind::Expired,
        "ten minutes"
    );

    let sent = code(
        &pool,
        alice,
        Purpose::Bind,
        "alice@example.com",
        NOW + SEND_INTERVAL_SECS,
    )
    .await;
    let wrong = other_than(&sent.code);
    for left in (0..MAX_ATTEMPTS).rev() {
        assert_eq!(
            email::bind(&pool, &KEY, alice, &wrong, None, NOW + 61)
                .await
                .unwrap(),
            Bind::Wrong(left)
        );
    }
    // The fifth wrong try ended it: the right code no longer works.
    assert_eq!(
        email::bind(&pool, &KEY, alice, &sent.code, None, NOW + 62)
            .await
            .unwrap(),
        Bind::Expired
    );
    assert_eq!(email::address(&pool, alice).await.unwrap(), None);
}

#[tokio::test]
async fn one_code_a_minute_and_ten_a_day() {
    let (_dir, pool, alice, _) = fixture().await;
    let first = code(&pool, alice, Purpose::Bind, "alice@example.com", NOW).await;
    match email::send_code(
        &pool,
        &KEY,
        alice,
        CodeFor::Bind,
        "alice@example.com",
        NOW + 20,
    )
    .await
    .unwrap()
    {
        NewCode::TooSoon(wait) => assert_eq!(wait, SEND_INTERVAL_SECS - 20),
        other => panic!("{other:?}"),
    }
    // Another purpose has limits of its own.
    code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 20).await;

    // A new code ends the earlier one.
    let second = code(
        &pool,
        alice,
        Purpose::Bind,
        "alice@example.org",
        NOW + SEND_INTERVAL_SECS,
    )
    .await;
    assert_ne!(first.id, second.id);
    if first.code != second.code {
        assert!(matches!(
            email::bind(&pool, &KEY, alice, &first.code, None, NOW + 61)
                .await
                .unwrap(),
            Bind::Wrong(_)
        ));
    }
    assert_eq!(
        email::pending(&pool, alice, Purpose::Bind, NOW + 61)
            .await
            .unwrap()
            .map(|(address, _)| address)
            .as_deref(),
        Some("alice@example.org")
    );

    // Ten in a day, also when the earlier ones were used up.
    for index in 2..BIND_SENDS_PER_DAY {
        code(
            &pool,
            alice,
            Purpose::Bind,
            "alice@example.com",
            NOW + index * SEND_INTERVAL_SECS,
        )
        .await;
    }
    let later = NOW + BIND_SENDS_PER_DAY * SEND_INTERVAL_SECS;
    assert!(matches!(
        email::send_code(
            &pool,
            &KEY,
            alice,
            CodeFor::Bind,
            "alice@example.com",
            later
        )
        .await
        .unwrap(),
        NewCode::DailyLimit
    ));
    // A day after the first, one more.
    code(
        &pool,
        alice,
        Purpose::Bind,
        "alice@example.com",
        NOW + DAY_SECS,
    )
    .await;
}

#[tokio::test]
async fn an_address_belongs_to_one_account() {
    let (_dir, pool, alice, bob) = fixture().await;
    assert!(matches!(
        bind(&pool, alice, "shared@example.com", NOW).await,
        Bind::Bound { .. }
    ));
    // Bob gets a code (only its recipient may learn that the address is taken), but it does
    // not bind the address.
    assert_eq!(
        bind(&pool, bob, "shared@example.com", NOW).await,
        Bind::Taken
    );
    assert_eq!(email::address(&pool, bob).await.unwrap(), None);
    assert_eq!(
        email::pending(&pool, bob, Purpose::Bind, NOW + 2)
            .await
            .unwrap(),
        None
    );

    // The key holds also for writes that skip the checks.
    let duplicate = sqlx::query("UPDATE users SET email = 'shared@example.com' WHERE id = ?")
        .bind(bob)
        .execute(&pool)
        .await;
    assert!(duplicate.is_err());
}

#[tokio::test]
async fn replacing_and_removing_report_the_previous_address() {
    let (_dir, pool, alice, _) = fixture().await;
    bind(&pool, alice, "first@example.com", NOW).await;
    let reset = code(&pool, alice, Purpose::Reset, "first@example.com", NOW + 10).await;
    assert_eq!(
        bind(&pool, alice, "second@example.com", NOW + SEND_INTERVAL_SECS).await,
        Bind::Bound {
            email: "second@example.com".to_owned(),
            previous: Some("first@example.com".to_owned()),
        }
    );
    // The reset code went to the address the account no longer has.
    assert_eq!(
        try_reset(
            &pool,
            Some(alice),
            Some(&OWNER.binding),
            &reset.code,
            NOW + 70
        )
        .await,
        Reset::Refused
    );

    let before = updated_at(&pool, alice).await;
    assert_eq!(
        email::remove(&pool, alice, None, before + 5).await.unwrap(),
        Some("second@example.com".to_owned())
    );
    assert_eq!(email::address(&pool, alice).await.unwrap(), None);
    assert_eq!(updated_at(&pool, alice).await, before + 5);
    assert!(
        kinds(&pool, alice)
            .await
            .contains(&"email.removed".to_owned())
    );
    assert_eq!(
        email::remove(&pool, alice, None, before + 6).await.unwrap(),
        None,
        "nothing to remove"
    );
    assert_eq!(updated_at(&pool, alice).await, before + 5);
}

#[tokio::test]
async fn a_reset_code_sets_the_password_and_ends_the_sessions() {
    let (_dir, pool, alice, bob) = fixture().await;
    bind(&pool, alice, "alice@example.com", NOW).await;
    let key = Key::from_bytes(&[7; 32]);
    two_factor::enable(&pool, &key, alice, &[1; 20], 0, None, None, NOW)
        .await
        .unwrap();
    web_sessions::create(&pool, alice, NOW).await.unwrap();
    web_sessions::create(&pool, bob, NOW).await.unwrap();

    let sent = code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 10).await;
    let refused = try_reset(
        &pool,
        Some(alice),
        Some(&OWNER.binding),
        &other_than(&sent.code),
        NOW + 11,
    )
    .await;
    assert_eq!(refused, Reset::Refused);
    // A code of the wrong purpose does not reset either.
    let later = NOW + SEND_INTERVAL_SECS;
    let bind_code = code(&pool, alice, Purpose::Bind, "other@example.com", later).await;
    if bind_code.code != sent.code {
        assert_eq!(
            try_reset(
                &pool,
                Some(alice),
                Some(&OWNER.binding),
                &bind_code.code,
                later
            )
            .await,
            Reset::Refused
        );
    }
    // Nor does a form that names no account.
    assert_eq!(
        try_reset(&pool, None, Some(&OWNER.binding), &sent.code, later).await,
        Reset::Refused
    );

    let done = email::reset_password(
        &pool,
        &KEY,
        Some(alice),
        Some(&OWNER.binding),
        &sent.code,
        "new hash",
        Some("192.0.2.1".parse().unwrap()),
        later + 1,
    )
    .await
    .unwrap();
    assert_eq!(
        done,
        Reset::Done {
            username: "alice".to_owned(),
            email: "alice@example.com".to_owned()
        }
    );
    let username = Username::new("alice").unwrap();
    let (account, hash) = users::credentials(&pool, &username).await.unwrap().unwrap();
    assert_eq!(hash.as_deref(), Some("new hash"));
    assert_eq!(account.updated_at, later + 1);
    let sessions: Vec<i64> = sqlx::query_scalar("SELECT user_id FROM web_sessions")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(sessions, [bob], "alice's sessions ended, bob's stayed");
    // Two-step verification is untouched: the next sign-in still asks for a code.
    assert!(two_factor::is_enrolled(&pool, alice).await.unwrap());
    let entries = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    let reset = entries
        .iter()
        .find(|entry| entry.kind == "password.reset")
        .expect("recorded");
    assert_eq!(reset.client_ip.as_deref(), Some("192.0.2.1"));
    // Every code ended with it, the reset code and the pending bind code.
    assert_eq!(
        try_reset(
            &pool,
            Some(alice),
            Some(&OWNER.binding),
            &sent.code,
            later + 2
        )
        .await,
        Reset::Refused
    );
    assert_eq!(
        email::pending(&pool, alice, Purpose::Bind, later + 2)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn disabled_accounts_cannot_reset() {
    let (_dir, pool, alice, _) = fixture().await;
    bind(&pool, alice, "alice@example.com", NOW).await;
    let sent = code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 10).await;
    let username = Username::new("alice").unwrap();
    users::set_enabled(&pool, &username, false).await.unwrap();
    assert_eq!(
        try_reset(
            &pool,
            Some(alice),
            Some(&OWNER.binding),
            &sent.code,
            NOW + 11
        )
        .await,
        Reset::Refused
    );
    let (_, hash) = users::credentials(&pool, &username).await.unwrap().unwrap();
    assert_eq!(hash.as_deref(), Some("old hash"));
}

#[tokio::test]
async fn accounts_are_found_by_name_or_address() {
    let (_dir, pool, alice, bob) = fixture().await;
    bind(&pool, alice, "alice@example.com", NOW).await;
    let found = |login: &'static str| {
        let pool = pool.clone();
        async move {
            email::find_account(&pool, login)
                .await
                .unwrap()
                .map(|(user, address)| (user.id, address))
        }
    };
    assert_eq!(
        found("alice").await,
        Some((alice, Some("alice@example.com".to_owned())))
    );
    assert_eq!(
        found(" Alice@Example.COM ").await,
        Some((alice, Some("alice@example.com".to_owned())))
    );
    assert_eq!(found("bob").await, Some((bob, None)));
    for unknown in ["carol", "carol@example.com", "", "Bob", "a b"] {
        assert_eq!(found(unknown).await, None, "{unknown:?}");
    }

    // Usernames may look like addresses: a username wins over another account's address.
    let username = Username::new("bob@example.com").unwrap();
    let named = users::create(
        &pool,
        &NewUser {
            username: &username,
            display_name: "Bob's other account",
            password_hash: "x",
            is_admin: false,
            services: gono_server_core::services::Services::NONE,
        },
        |_| Ok(()),
    )
    .await
    .unwrap();
    bind(&pool, bob, "bob@example.com", NOW).await;
    assert_eq!(
        found("bob@example.com").await.map(|(id, _)| id),
        Some(named)
    );
}

#[tokio::test]
async fn deleting_an_account_removes_its_codes_and_frees_its_address() {
    let (_dir, pool, alice, bob) = fixture().await;
    bind(&pool, alice, "alice@example.com", NOW).await;
    code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 10).await;
    users::delete(&pool, &Username::new("alice").unwrap())
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_codes WHERE user_id = ?")
        .bind(alice)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert!(matches!(
        bind(&pool, bob, "alice@example.com", NOW + 20).await,
        Bind::Bound { .. }
    ));
}

#[tokio::test]
async fn ended_codes_stay_a_day_for_the_daily_limit() {
    let (_dir, pool, alice, _) = fixture().await;
    let used = code(&pool, alice, Purpose::Bind, "alice@example.com", NOW).await;
    email::bind(&pool, &KEY, alice, &used.code, None, NOW + 1)
        .await
        .unwrap();
    code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 100).await;
    let count = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM email_codes")
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    // Used or expired, they still count until they are a day old.
    assert_eq!(email::purge(&pool, NOW + 1000).await.unwrap(), 0);
    assert_eq!(count().await, 2);
    assert_eq!(email::purge(&pool, NOW + DAY_SECS).await.unwrap(), 1);
    assert_eq!(count().await, 1);
    assert_eq!(email::purge(&pool, NOW + 100 + DAY_SECS).await.unwrap(), 1);
    assert_eq!(count().await, 0);
}

#[tokio::test]
async fn codes_are_keyed_with_the_key_file() {
    let (_dir, pool, alice, _) = fixture().await;
    let other = Key::from_bytes(&[8; 32]);
    let sent = code(&pool, alice, Purpose::Bind, "alice@example.com", NOW).await;
    // Under another key the right code is a wrong one: its digest cannot be computed without
    // the key the code was made with.
    assert_eq!(
        email::bind(&pool, &other, alice, &sent.code, None, NOW + 1)
            .await
            .unwrap(),
        Bind::Wrong(MAX_ATTEMPTS - 1)
    );
    assert!(matches!(
        email::bind(&pool, &KEY, alice, &sent.code, None, NOW + 2)
            .await
            .unwrap(),
        Bind::Bound { .. }
    ));

    // Reset codes too: the binding and the code are both keyed digests.
    let reset_code = code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 10).await;
    let stored: (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT code_hash, client_binding FROM email_codes WHERE id = ?")
            .bind(reset_code.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored.1.len(), 32);
    assert_ne!(
        stored.1,
        gono_server_core::secret::digest("owner cookie"),
        "not an unkeyed digest of the cookie"
    );
    let elsewhere = Binding::new(&other, "owner cookie");
    let refused = email::reset_password(
        &pool,
        &other,
        Some(alice),
        Some(&elsewhere),
        &reset_code.code,
        "new hash",
        None,
        NOW + 11,
    )
    .await
    .unwrap();
    assert_eq!(refused, Reset::Refused);
    assert!(matches!(
        try_reset(
            &pool,
            Some(alice),
            Some(&OWNER.binding),
            &reset_code.code,
            NOW + 12
        )
        .await,
        Reset::Done { .. }
    ));
}

#[tokio::test]
async fn a_reset_code_works_only_in_the_browser_that_asked_for_it() {
    let (_dir, pool, alice, _) = fixture().await;
    bind(&pool, alice, "alice@example.com", NOW).await;
    let sent = code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 10).await;
    let stranger = browser("stranger cookie", "198.51.100.9");
    let neighbour = browser("neighbour cookie", "192.0.2.8");

    // Other browsers, and a form without a reset cookie, never reach the code, not even with
    // the right digits; their tries are not counted on it.
    for _ in 0..=MAX_ATTEMPTS {
        for binding in [Some(&stranger.binding), Some(&neighbour.binding), None] {
            assert_eq!(
                try_reset(&pool, Some(alice), binding, &sent.code, NOW + 11).await,
                Reset::Refused
            );
        }
    }
    assert_eq!(attempts(&pool, sent.id).await, 0);
    let stored: (Option<Vec<u8>>, Option<String>) =
        sqlx::query_as("SELECT client_binding, client_net FROM email_codes WHERE id = ?")
            .bind(sent.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(stored.0.is_some());
    assert_eq!(stored.1.as_deref(), Some("192.0.2.0/24"));

    // The browser that asked has its tries, MAX_ATTEMPTS of them.
    assert_eq!(
        try_reset(
            &pool,
            Some(alice),
            Some(&OWNER.binding),
            &other_than(&sent.code),
            NOW + 12
        )
        .await,
        Reset::Refused
    );
    assert_eq!(attempts(&pool, sent.id).await, 1);
    assert!(matches!(
        try_reset(
            &pool,
            Some(alice),
            Some(&OWNER.binding),
            &sent.code,
            NOW + 13
        )
        .await,
        Reset::Done { .. }
    ));
}

#[tokio::test]
async fn a_request_from_another_browser_leaves_the_first_code_live() {
    let (_dir, pool, alice, _) = fixture().await;
    bind(&pool, alice, "alice@example.com", NOW).await;
    let first = code(&pool, alice, Purpose::Reset, "alice@example.com", NOW + 10).await;
    // A stranger asks for codes for the same account, from another network and from the
    // owner's: neither ends the owner's code.
    let stranger = browser("stranger cookie", "198.51.100.9");
    let theirs = sent(
        &pool,
        alice,
        CodeFor::Reset(&stranger),
        "alice@example.com",
        NOW + 11,
    )
    .await;
    let neighbour = browser("neighbour cookie", "192.0.2.8");
    sent(
        &pool,
        alice,
        CodeFor::Reset(&neighbour),
        "alice@example.com",
        NOW + 10 + SEND_INTERVAL_SECS,
    )
    .await;
    // The stranger's own code is theirs to try, but it was mailed to the owner.
    if theirs.code != first.code {
        assert_eq!(
            try_reset(
                &pool,
                Some(alice),
                Some(&stranger.binding),
                &first.code,
                NOW + 80
            )
            .await,
            Reset::Refused
        );
    }

    // A new code for the same browser (also from another network) ends its earlier one.
    let moved = browser("owner cookie", "203.0.113.5");
    let second = sent(
        &pool,
        alice,
        CodeFor::Reset(&moved),
        "alice@example.com",
        NOW + 81,
    )
    .await;
    if first.code != second.code {
        assert_eq!(
            try_reset(
                &pool,
                Some(alice),
                Some(&OWNER.binding),
                &first.code,
                NOW + 82
            )
            .await,
            Reset::Refused
        );
        assert_eq!(attempts(&pool, first.id).await, 0, "ended, not tried");
    }
    assert!(matches!(
        try_reset(
            &pool,
            Some(alice),
            Some(&OWNER.binding),
            &second.code,
            NOW + 83
        )
        .await,
        Reset::Done { .. }
    ));
    // A reset ends every code of the account, those of other browsers too.
    let live: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_codes WHERE user_id = ? AND expires_at > ?")
            .bind(alice)
            .bind(NOW + 83)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(live, 0);
}

#[tokio::test]
async fn reset_codes_are_limited_per_network_and_per_account() {
    let (_dir, pool, alice, _) = fixture().await;
    bind(&pool, alice, "alice@example.com", NOW).await;
    let reset_code = |client: ResetClient, now: i64| {
        let pool = pool.clone();
        async move {
            email::send_code(
                &pool,
                &KEY,
                alice,
                CodeFor::Reset(&client),
                "alice@example.com",
                now,
            )
            .await
            .unwrap()
        }
    };
    let start = NOW + 100;
    assert!(matches!(
        reset_code(OWNER.clone(), start).await,
        NewCode::Code(_)
    ));
    // One a minute per network, whichever browser of it asks.
    match reset_code(browser("neighbour cookie", "192.0.2.200"), start + 20).await {
        NewCode::TooSoon(wait) => assert_eq!(wait, SEND_INTERVAL_SECS - 20),
        other => panic!("{other:?}"),
    }
    // Another network has a minute of its own; IPv6 clients count per /64.
    assert!(matches!(
        reset_code(browser("phone", "2001:db8:1:2::7"), start + 20).await,
        NewCode::Code(_)
    ));
    assert!(matches!(
        reset_code(browser("phone, new address", "2001:db8:1:2::8"), start + 40).await,
        NewCode::TooSoon(_)
    ));
    // Three a day per network.
    for index in 1..RESET_SENDS_PER_NET_PER_DAY {
        assert!(matches!(
            reset_code(OWNER.clone(), start + index * SEND_INTERVAL_SECS).await,
            NewCode::Code(_)
        ));
    }
    let later = start + RESET_SENDS_PER_NET_PER_DAY * SEND_INTERVAL_SECS;
    assert!(matches!(
        reset_code(browser("neighbour cookie", "192.0.2.200"), later).await,
        NewCode::DailyLimit
    ));
    // Bind codes keep their own limits.
    code(&pool, alice, Purpose::Bind, "new@example.com", later).await;

    // Twenty a day per account in all, from however many networks.
    let made = RESET_SENDS_PER_NET_PER_DAY + 1;
    for index in made..RESET_SENDS_PER_DAY {
        let client = browser(&format!("cookie {index}"), &format!("10.0.{index}.1"));
        assert!(
            matches!(reset_code(client, later + index).await, NewCode::Code(_)),
            "{index}"
        );
    }
    assert!(matches!(
        reset_code(browser("one more", "10.1.0.1"), later + 100).await,
        NewCode::DailyLimit
    ));
    // A day after the first, the account may get one again.
    assert!(matches!(
        reset_code(browser("one more", "10.1.0.1"), start + DAY_SECS).await,
        NewCode::Code(_)
    ));
}
