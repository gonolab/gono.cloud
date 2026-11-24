//! Third-party identities, pending identities and accounts without a web login password
//! (`gono_server_core::identities`, `gono_server_core::users`) on the backend the environment
//! chooses (`db::testing`).

use gono_server_core::{
    Username,
    audit::{self, Actor},
    db::{self, Pool},
    identities::{
        self, Bound, BoundPending, Claims, GITHUB_REALM, GOOGLE_REALM, Holder, How,
        PENDING_TTL_SECS, Provider, Unbound, Which,
    },
    services::Services,
    users::{self, CreatedVia, NewUser},
};
use secrecy::ExposeSecret as _;

/// A fixed "now" far from the real clock.
const NOW: i64 = 1_800_000_000;

const APP: &str = "wxd930ea5d5a258f4f";

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
                password_hash: "x",
                is_admin: false,
                services: Services::NONE,
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        ids.push(id);
    }
    (dir, pool, ids[0], ids[1])
}

fn google(subject: &str, email: &str) -> Claims {
    Claims {
        provider: Provider::Google,
        realm: GOOGLE_REALM.to_owned(),
        subject: subject.to_owned(),
        unionid: None,
        label: email.to_owned(),
        email: Some(email.to_owned()),
        email_verified: true,
        name: Some("Alice Example".to_owned()),
    }
}

fn github(subject: &str, login: &str) -> Claims {
    Claims {
        provider: Provider::GitHub,
        realm: GITHUB_REALM.to_owned(),
        subject: subject.to_owned(),
        unionid: None,
        label: format!("@{login}"),
        email: None,
        email_verified: false,
        name: None,
    }
}

async fn bind(pool: &Pool, user: i64, claims: &Claims) -> Bound {
    identities::bind(pool, user, claims, How::AccountPage, Actor::User, None, NOW)
        .await
        .unwrap()
}

async fn unbind(pool: &Pool, user: i64, provider: Provider, realm: &str) -> Unbound {
    identities::unbind(
        pool,
        user,
        Which::Realm(provider, realm),
        How::AccountPage,
        Actor::User,
        Some("192.0.2.5".parse().unwrap()),
        NOW + 1,
    )
    .await
    .unwrap()
}

async fn without_password(pool: &Pool, user: i64) {
    sqlx::query("UPDATE users SET password_hash = NULL WHERE id = ?")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn accounts_say_how_they_were_made_and_whether_they_have_a_password() {
    let (_dir, pool, alice, _) = fixture().await;
    let carol = Username::new("carol").unwrap();
    users::create_via(
        &pool,
        &NewUser {
            username: &carol,
            display_name: "Carol",
            password_hash: "x",
            is_admin: false,
            services: Services::NONE,
        },
        CreatedVia::Cli,
        |_| Ok(()),
    )
    .await
    .unwrap();
    let listed: Vec<(String, CreatedVia, bool, Option<i64>)> = users::list(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|user| {
            (
                user.username.to_string(),
                user.created_via,
                user.has_password,
                user.deleting_at,
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("alice".to_owned(), CreatedVia::Admin, true, None),
            ("bob".to_owned(), CreatedVia::Admin, true, None),
            ("carol".to_owned(), CreatedVia::Cli, true, None),
        ]
    );
    for via in [
        CreatedVia::Admin,
        CreatedVia::Cli,
        CreatedVia::WeChat,
        CreatedVia::Google,
        CreatedVia::GitHub,
    ] {
        assert_eq!(CreatedVia::parse(via.as_str()), Some(via));
        assert_eq!(
            via.is_self_service(),
            !matches!(via, CreatedVia::Admin | CreatedVia::Cli)
        );
    }

    // Without a password, the credentials have no hash.
    without_password(&pool, alice).await;
    let username = Username::new("alice").unwrap();
    let (user, hash) = users::credentials(&pool, &username).await.unwrap().unwrap();
    assert!(!user.has_password && hash.is_none());

    // The first password is recorded as `password.set`, by whoever set it; a later one is not.
    users::set_password_hash(&pool, &username, "first", Actor::Admin)
        .await
        .unwrap();
    users::set_password_hash(&pool, &username, "second", Actor::Admin)
        .await
        .unwrap();
    let entries = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (entries[0].kind.as_str(), entries[0].actor.as_str()),
        ("password.set", "admin")
    );
    assert!(users::get(&pool, &username).await.unwrap().has_password);

    // A first password set by the user never replaces one.
    assert!(
        !users::set_first_password(&pool, alice, "third", None, NOW)
            .await
            .unwrap()
    );
    let (_, hash) = users::credentials(&pool, &username).await.unwrap().unwrap();
    assert_eq!(hash.as_deref(), Some("second"));
    without_password(&pool, alice).await;
    assert!(
        users::set_first_password(
            &pool,
            alice,
            "third",
            Some("192.0.2.1".parse().unwrap()),
            NOW
        )
        .await
        .unwrap()
    );
    let entries = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    assert_eq!(
        (
            entries[0].kind.as_str(),
            entries[0].actor.as_str(),
            entries[0].client_ip.as_deref()
        ),
        ("password.set", "user", Some("192.0.2.1"))
    );
}

#[tokio::test]
async fn an_identity_belongs_to_one_account_which_has_one_per_provider() {
    let (_dir, pool, alice, bob) = fixture().await;
    let alices = google("108", "alice@gmail.com");
    let Bound::Bound(identity) = bind(&pool, alice, &alices).await else {
        panic!("not bound");
    };
    assert_eq!(
        (
            identity.provider,
            identity.realm.as_str(),
            identity.label.as_str(),
            identity.created_at
        ),
        (Provider::Google, GOOGLE_REALM, "alice@gmail.com", NOW)
    );
    assert!(matches!(
        bind(&pool, alice, &alices).await,
        Bound::Already(_)
    ));
    assert_eq!(bind(&pool, bob, &alices).await, Bound::OtherAccount);
    assert_eq!(
        bind(&pool, alice, &google("109", "other@gmail.com")).await,
        Bound::AccountHasOne
    );
    assert_eq!(
        bind(&pool, 9999, &google("110", "x@gmail.com")).await,
        Bound::NoAccount
    );

    // One per provider: GitHub and WeChat are others.
    bind(&pool, alice, &github("583231", "octocat")).await;
    bind(&pool, alice, &Claims::wechat(APP, "oAlice", Some("oUnion"))).await;
    let listed: Vec<(Provider, String)> = identities::list(&pool, alice)
        .await
        .unwrap()
        .into_iter()
        .map(|identity| (identity.provider, identity.label))
        .collect();
    assert_eq!(
        listed,
        [
            (Provider::WeChat, String::new()),
            (Provider::Google, "alice@gmail.com".to_owned()),
            (Provider::GitHub, "@octocat".to_owned()),
        ]
    );
    let found = identities::find(&pool, Provider::GitHub, GITHUB_REALM, "583231")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.user_id, alice);
    assert_eq!(
        identities::find(&pool, Provider::GitHub, GITHUB_REALM, "octocat")
            .await
            .unwrap(),
        None,
        "logins are no subjects"
    );

    // Recorded with the provider and how, never the subject.
    let entries = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    let kinds: Vec<&str> = entries.iter().map(|entry| entry.kind.as_str()).collect();
    assert_eq!(kinds, ["identity.bound"; 3]);
    let details: serde_json::Value = serde_json::from_str(&entries[2].details).unwrap();
    assert_eq!(
        details,
        serde_json::json!({ "provider": "google", "how": "account_page" })
    );
    for entry in &entries {
        assert!(!entry.details.contains("108") && !entry.details.contains("oAlice"));
    }
    assert!(entries[0].details.contains(APP), "WeChat names the AppID");
}

#[tokio::test]
async fn the_last_way_in_is_never_unbound() {
    let (_dir, pool, alice, bob) = fixture().await;
    bind(&pool, alice, &google("108", "alice@gmail.com")).await;
    bind(&pool, alice, &github("583231", "octocat")).await;
    without_password(&pool, alice).await;

    // Another identity is left: it goes.
    let Unbound::Done(gone) = unbind(&pool, alice, Provider::Google, GOOGLE_REALM).await else {
        panic!("not unbound");
    };
    assert_eq!(gone.provider, Provider::Google);
    assert_eq!(
        unbind(&pool, alice, Provider::Google, GOOGLE_REALM).await,
        Unbound::NotBound
    );
    // The last one stays, by realm or by id.
    assert_eq!(
        unbind(&pool, alice, Provider::GitHub, GITHUB_REALM).await,
        Unbound::LastSignIn
    );
    let last = identities::list(&pool, alice).await.unwrap().remove(0);
    let by_id = identities::unbind(
        &pool,
        alice,
        Which::Id(last.id),
        How::Admin,
        Actor::Admin,
        None,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(by_id, Unbound::LastSignIn);
    // Another account cannot name it by id.
    let elsewhere = identities::unbind(
        &pool,
        bob,
        Which::Id(last.id),
        How::Admin,
        Actor::Admin,
        None,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(elsewhere, Unbound::NotBound);
    // With a password it can go.
    users::set_password_hash(&pool, &Username::new("alice").unwrap(), "x", Actor::Cli)
        .await
        .unwrap();
    assert!(matches!(
        unbind(&pool, alice, Provider::GitHub, GITHUB_REALM).await,
        Unbound::Done(_)
    ));
    let entries = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    assert_eq!(entries[0].kind, "identity.unbound");
    assert_eq!(entries[0].client_ip.as_deref(), Some("192.0.2.5"));
}

#[tokio::test]
async fn pending_identities_wait_for_their_holder_and_bind_once() {
    let (_dir, pool, alice, bob) = fixture().await;
    let claims = google("108", "Alice@GMail.com");
    let (web, until) = identities::create_pending(&pool, Holder::Web, &claims, NOW)
        .await
        .unwrap();
    assert!(identities::is_token(web.expose_secret()));
    assert_eq!(until, NOW + PENDING_TTL_SECS);
    let pending = identities::pending(&pool, Holder::Web, web.expose_secret(), NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.claims.email.as_deref(), Some("alice@gmail.com"));
    assert!(pending.claims.email_verified);
    assert_eq!(pending.claims.name.as_deref(), Some("Alice Example"));
    // A token is found by its own holder only, and not after it expired.
    assert_eq!(
        identities::pending(&pool, Holder::MiniProgram, web.expose_secret(), NOW)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        identities::pending(&pool, Holder::Web, web.expose_secret(), until)
            .await
            .unwrap(),
        None
    );
    // A new one of the same identity and holder ends the earlier; other holders keep theirs.
    let (mini, _) = identities::create_pending(&pool, Holder::MiniProgram, &claims, NOW)
        .await
        .unwrap();
    let (newer, _) = identities::create_pending(&pool, Holder::Web, &claims, NOW + 1)
        .await
        .unwrap();
    assert_eq!(
        identities::pending(&pool, Holder::Web, web.expose_secret(), NOW + 1)
            .await
            .unwrap(),
        None
    );
    assert!(
        identities::pending(&pool, Holder::MiniProgram, mini.expose_secret(), NOW + 1)
            .await
            .unwrap()
            .is_some()
    );

    // Binding uses it up.
    let bound = identities::bind_pending(
        &pool,
        Holder::Web,
        newer.expose_secret(),
        alice,
        None,
        NOW + 2,
    )
    .await
    .unwrap();
    assert!(matches!(bound, BoundPending::Bound(_)), "{bound:?}");
    assert_eq!(
        identities::bind_pending(
            &pool,
            Holder::Web,
            newer.expose_secret(),
            alice,
            None,
            NOW + 2
        )
        .await
        .unwrap(),
        BoundPending::Expired
    );
    // Bound elsewhere meanwhile: used up all the same.
    let (late, _) = identities::create_pending(&pool, Holder::Web, &claims, NOW + 3)
        .await
        .unwrap();
    assert_eq!(
        identities::bind_pending(&pool, Holder::Web, late.expose_secret(), bob, None, NOW + 3)
            .await
            .unwrap(),
        BoundPending::OtherAccount
    );
    assert_eq!(
        identities::pending(&pool, Holder::Web, late.expose_secret(), NOW + 3)
            .await
            .unwrap(),
        None
    );
    // The account has one of the provider: the pending identity stays for another.
    let (other, _) = identities::create_pending(
        &pool,
        Holder::Web,
        &google("109", "second@gmail.com"),
        NOW + 4,
    )
    .await
    .unwrap();
    assert_eq!(
        identities::bind_pending(
            &pool,
            Holder::Web,
            other.expose_secret(),
            alice,
            None,
            NOW + 4
        )
        .await
        .unwrap(),
        BoundPending::AccountHasOne
    );
    assert!(matches!(
        identities::bind_pending(
            &pool,
            Holder::Web,
            other.expose_secret(),
            bob,
            None,
            NOW + 4
        )
        .await
        .unwrap(),
        BoundPending::Bound(_)
    ));

    // Ending one by its token, and purging the expired ones.
    identities::end_pending(&pool, Holder::MiniProgram, mini.expose_secret())
        .await
        .unwrap();
    assert_eq!(
        identities::pending(&pool, Holder::MiniProgram, mini.expose_secret(), NOW + 5)
            .await
            .unwrap(),
        None
    );
    identities::create_pending(&pool, Holder::Web, &github("1", "a"), NOW)
        .await
        .unwrap();
    assert_eq!(identities::purge_expired(&pool, NOW).await.unwrap(), 0);
    assert_eq!(
        identities::purge_expired(&pool, NOW + PENDING_TTL_SECS)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn signing_in_finds_the_account_and_binds_by_a_verified_address() {
    use gono_server_core::identities::SignedIn;

    let (_dir, pool, alice, bob) = fixture().await;
    let claims = google("108", "alice@gmail.com");
    assert_eq!(
        identities::sign_in(&pool, &claims, NOW).await.unwrap(),
        SignedIn::Unbound
    );
    // Only an address the account proved itself counts, and only one the provider verified.
    sqlx::query("UPDATE users SET email = 'alice@example.com' WHERE id = ?")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let none = identities::bind_by_email(&pool, &claims, &[], None, NOW)
        .await
        .unwrap();
    assert_eq!(none, None);
    let other = ["someone@example.com".to_owned()];
    assert_eq!(
        identities::bind_by_email(&pool, &claims, &other, None, NOW)
            .await
            .unwrap(),
        None
    );
    let verified = [
        "someone@example.com".to_owned(),
        "Alice@Example.COM".to_owned(),
    ];
    let bound = identities::bind_by_email(&pool, &claims, &verified, None, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (bound.user.id, bound.email.as_str()),
        (alice, "alice@example.com")
    );
    let entries = audit::list(&pool, Some(alice), None, 5).await.unwrap();
    assert!(entries[0].details.contains("\"how\":\"email\""));

    // Signing in finds it, and refreshes its label.
    let renamed = Claims {
        label: "alice.new@gmail.com".to_owned(),
        ..claims.clone()
    };
    let SignedIn::Account(user) = identities::sign_in(&pool, &renamed, NOW + 5).await.unwrap()
    else {
        panic!("not signed in");
    };
    assert_eq!(user.id, alice);
    let identity = identities::list(&pool, alice).await.unwrap().remove(0);
    assert_eq!(
        (identity.label.as_str(), identity.last_seen_at),
        ("alice.new@gmail.com", NOW + 5)
    );
    // An account with one of the provider gets no second one by address.
    assert_eq!(
        identities::bind_by_email(&pool, &google("109", "x"), &verified, None, NOW)
            .await
            .unwrap(),
        None
    );

    // Disabled, and waiting for deletion, the account does not sign in and binds nothing.
    sqlx::query("UPDATE users SET enabled = 0, email = 'bob@example.com' WHERE id = ?")
        .bind(bob)
        .execute(&pool)
        .await
        .unwrap();
    let bobs = github("1", "bob");
    let address = ["bob@example.com".to_owned()];
    assert_eq!(
        identities::bind_by_email(&pool, &bobs, &address, None, NOW)
            .await
            .unwrap(),
        None
    );
    bind(&pool, bob, &bobs).await;
    assert_eq!(
        identities::sign_in(&pool, &bobs, NOW).await.unwrap(),
        SignedIn::Disabled
    );
    sqlx::query("UPDATE users SET deleting_at = ? WHERE id = ?")
        .bind(NOW + 100)
        .bind(bob)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        identities::sign_in(&pool, &bobs, NOW).await.unwrap(),
        SignedIn::DeletionPending {
            user_id: bob,
            until: NOW + 100
        }
    );
}

#[tokio::test]
async fn sign_ups_make_accounts_without_password_or_service_within_their_caps() {
    use gono_server_core::users::{SIGNUPS_PER_NET_PER_DAY, SignedUp};

    let (_dir, pool, _, _) = fixture().await;
    let generated = users::generated_username(CreatedVia::Google);
    assert!(generated.as_str().starts_with("gg") && generated.as_str().len() == 10);
    assert!(
        users::generated_username(CreatedVia::WeChat)
            .as_str()
            .starts_with("wx")
    );
    let ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
    let username = Username::new("newcomer").unwrap();
    let claims = google("200", "new@gmail.com");
    let SignedUp::Created(user, identity) = users::sign_up(
        &pool,
        &claims,
        &username,
        "New Comer",
        Some("2026-11"),
        Some(ip),
        NOW,
        |_| Ok(()),
    )
    .await
    .unwrap() else {
        panic!("not created");
    };
    assert_eq!(
        (
            user.has_password,
            user.services,
            user.created_via,
            user.display_name.as_str()
        ),
        (false, Services::NONE, CreatedVia::Google, "New Comer")
    );
    assert_eq!(identity.user_id, user.id);
    let kinds: Vec<(String, String)> = audit::list(&pool, Some(user.id), None, 5)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| (entry.kind, entry.details))
        .collect();
    assert_eq!(kinds[0].0, "identity.bound");
    assert!(kinds[0].1.contains("\"how\":\"signup\""));
    assert_eq!(kinds[1].0, "account.created");
    assert!(kinds[1].1.contains("\"via\":\"google\"") && kinds[1].1.contains("2026-11"));
    // The identity signs up once; a name in use is refused.
    let again = users::sign_up(
        &pool,
        &claims,
        &Username::new("other").unwrap(),
        "x",
        None,
        Some(ip),
        NOW,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(again, SignedUp::AlreadyBound);
    let taken = users::sign_up(
        &pool,
        &google("201", "x"),
        &Username::new("alice").unwrap(),
        "x",
        None,
        Some(ip),
        NOW,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(taken, SignedUp::UsernameTaken);
    // The cap per network: this /24 made one already.
    for index in 1..SIGNUPS_PER_NET_PER_DAY {
        let name = Username::new(format!("n{index}")).unwrap();
        let other: std::net::IpAddr = format!("192.0.2.{}", 100 + index).parse().unwrap();
        let made = users::sign_up(
            &pool,
            &github(&index.to_string(), "x"),
            &name,
            "x",
            None,
            Some(other),
            NOW,
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert!(matches!(made, SignedUp::Created(..)), "{index}: {made:?}");
    }
    let limited = users::sign_up(
        &pool,
        &github("99", "x"),
        &Username::new("n99").unwrap(),
        "x",
        None,
        Some(ip),
        NOW,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(limited, SignedUp::Limited);
    let elsewhere: std::net::IpAddr = "198.51.100.1".parse().unwrap();
    let made = users::sign_up(
        &pool,
        &github("99", "x"),
        &Username::new("n99").unwrap(),
        "x",
        None,
        Some(elsewhere),
        NOW,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert!(matches!(made, SignedUp::Created(..)));
    // A day later the network may again.
    let later = users::sign_up(
        &pool,
        &github("98", "x"),
        &Username::new("n98").unwrap(),
        "x",
        None,
        Some(ip),
        NOW + 86_401,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert!(matches!(later, SignedUp::Created(..)));
}

#[tokio::test]
async fn self_service_accounts_rename_until_used_and_delete_after_a_cooling_off() {
    use gono_server_core::users::{DELETION_DELAY_SECS, Renamed, SignedUp};

    let (_dir, pool, alice, _) = fixture().await;
    let SignedUp::Created(user, _) = users::sign_up(
        &pool,
        &Claims::wechat("wxd930ea5d5a258f4f", "oNew", None),
        &Username::new("wxabcd1234").unwrap(),
        "新用户",
        None,
        None,
        NOW,
        |_| Ok(()),
    )
    .await
    .unwrap() else {
        panic!("not created");
    };
    let rename = |name: &str, at: i64| {
        let pool = pool.clone();
        let name = Username::new(name).unwrap();
        let id = user.id;
        async move {
            users::rename(&pool, id, &name, Actor::User, None, at)
                .await
                .unwrap()
        }
    };
    assert!(users::can_rename(&pool, user.id).await.unwrap());
    assert!(
        !users::can_rename(&pool, alice).await.unwrap(),
        "made by an admin"
    );
    assert_eq!(rename("alice", NOW).await, Renamed::Taken);
    assert_eq!(rename("wanda", NOW).await, Renamed::Done);
    assert!(
        users::find(&pool, &Username::new("wanda").unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        users::find(&pool, &Username::new("wxabcd1234").unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(rename("wanda2", NOW + 60).await, Renamed::TooSoon);
    assert_eq!(rename("wanda2", NOW + 86_401).await, Renamed::Done);
    // An app password locks the name: devices and apps sign in with it.
    gono_server_core::app_passwords::create(&pool, user.id, "phone", Vec::new(), None)
        .await
        .unwrap();
    assert_eq!(rename("wanda3", NOW + 200_000).await, Renamed::Locked);
    assert!(!users::can_rename(&pool, user.id).await.unwrap());

    // Deletion: only without a password, disabled at once, undone in time, due after 7 days.
    assert_eq!(
        users::request_deletion(&pool, alice, Actor::User, None, NOW)
            .await
            .unwrap(),
        None
    );
    let until = users::request_deletion(&pool, user.id, Actor::User, None, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(until, NOW + DELETION_DELAY_SECS);
    let waiting = users::by_id(&pool, user.id).await.unwrap().unwrap();
    assert!(!waiting.enabled && waiting.deleting_at == Some(until));
    assert_eq!(
        users::request_deletion(&pool, user.id, Actor::User, None, NOW)
            .await
            .unwrap(),
        None
    );
    assert!(
        users::due_deletions(&pool, until - 1)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        users::cancel_deletion(&pool, user.id, Actor::User, None, NOW + 10)
            .await
            .unwrap()
    );
    let back = users::by_id(&pool, user.id).await.unwrap().unwrap();
    assert!(back.enabled && back.deleting_at.is_none());
    assert!(
        !users::cancel_deletion(&pool, user.id, Actor::User, None, NOW + 11)
            .await
            .unwrap()
    );
    let until = users::request_deletion(&pool, user.id, Actor::User, None, NOW + 20)
        .await
        .unwrap()
        .unwrap();
    // Too late to undo once due; an admin enabling it undoes it as well.
    assert!(
        !users::cancel_deletion(&pool, user.id, Actor::User, None, until)
            .await
            .unwrap()
    );
    let due = users::due_deletions(&pool, until).await.unwrap();
    assert_eq!(due.len(), 1);
    users::set_enabled(&pool, &due[0].username, true)
        .await
        .unwrap();
    assert!(users::due_deletions(&pool, until).await.unwrap().is_empty());
    let kinds: Vec<String> = audit::list(&pool, Some(user.id), None, 20)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.kind)
        .collect();
    assert!(kinds.contains(&"account.deletion_requested".to_owned()));
    assert!(kinds.contains(&"account.deletion_cancelled".to_owned()));
    assert!(kinds.contains(&"account.renamed".to_owned()));
}

/// The AppIDs of two phone apps of the mini program's Open Platform account.
const PHONE_APP: &str = "wx0123456789abcdef";
const TABLET_APP: &str = "wx1123456789abcdef";

fn wechat(app_id: &str, openid: &str, unionid: Option<&str>) -> Claims {
    Claims::wechat(app_id, openid, unionid)
}

async fn by_unionid(pool: &Pool, claims: &Claims) -> (identities::SignedIn, bool) {
    identities::sign_in_by_unionid(
        pool,
        claims,
        &[APP, PHONE_APP, TABLET_APP],
        Some("192.0.2.9".parse().unwrap()),
        NOW,
    )
    .await
    .unwrap()
}

fn account_of(signed: &identities::SignedIn) -> Option<i64> {
    match signed {
        identities::SignedIn::Account(user) => Some(user.id),
        _ => None,
    }
}

#[tokio::test]
async fn a_phone_app_finds_the_account_by_the_unionid_and_binds_its_identity() {
    let (_dir, pool, alice, bob) = fixture().await;
    // Alice's WeChat in the mini program, with its unionid; Bob's without one yet.
    bind(
        &pool,
        alice,
        &wechat(APP, "oMiniAlice", Some("oUnionAlice")),
    )
    .await;
    bind(&pool, bob, &wechat(APP, "oMiniBob", None)).await;

    // The app's first login binds its identity to Alice by the unionid.
    let first = by_unionid(
        &pool,
        &wechat(PHONE_APP, "oPhoneAlice", Some("oUnionAlice")),
    )
    .await;
    assert_eq!((account_of(&first.0), first.1), (Some(alice), true));
    let entries = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    assert_eq!(entries[0].kind, "identity.bound");
    assert_eq!(entries[0].actor, "user");
    assert_eq!(entries[0].client_ip.as_deref(), Some("192.0.2.9"));
    let details: serde_json::Value = serde_json::from_str(&entries[0].details).unwrap();
    assert_eq!(
        details,
        serde_json::json!({ "provider": "wechat", "how": "unionid", "app_id": PHONE_APP })
    );
    // The next one signs in by the openid, binding nothing; so does one without a unionid.
    let again = by_unionid(
        &pool,
        &wechat(PHONE_APP, "oPhoneAlice", Some("oUnionAlice")),
    )
    .await;
    assert_eq!((account_of(&again.0), again.1), (Some(alice), false));
    let bare = by_unionid(&pool, &wechat(PHONE_APP, "oPhoneAlice", None)).await;
    assert_eq!((account_of(&bare.0), bare.1), (Some(alice), false));
    // Another app of the same Open Platform account finds Alice through either identity.
    let tablet = by_unionid(
        &pool,
        &wechat(TABLET_APP, "oTabletAlice", Some("oUnionAlice")),
    )
    .await;
    assert_eq!((account_of(&tablet.0), tablet.1), (Some(alice), true));

    // Unknown unionids and missing ones bind nothing, nor do realms not looked at.
    for claims in [
        wechat(PHONE_APP, "oPhoneCarol", Some("oUnionCarol")),
        wechat(PHONE_APP, "oPhoneBob", None),
    ] {
        assert_eq!(
            by_unionid(&pool, &claims).await,
            (identities::SignedIn::Unbound, false)
        );
    }
    let unlisted = identities::sign_in_by_unionid(
        &pool,
        &wechat(PHONE_APP, "oPhoneDan", Some("oUnionAlice")),
        &[TABLET_APP],
        None,
        NOW,
    )
    .await
    .unwrap();
    // The tablet's identity names Alice, who has another identity of this app already: nothing
    // is bound.
    assert_eq!((account_of(&unlisted.0), unlisted.1), (None, false));
    assert_eq!(
        identities::sign_in_by_unionid(
            &pool,
            &wechat(PHONE_APP, "oPhoneEve", Some("oUnionAlice")),
            &[],
            None,
            NOW
        )
        .await
        .unwrap(),
        (identities::SignedIn::Unbound, false)
    );
    // Google identities never bind this way.
    assert_eq!(
        by_unionid(&pool, &google("108", "alice@gmail.com")).await,
        (identities::SignedIn::Unbound, false)
    );
}

#[tokio::test]
async fn a_unionid_on_several_accounts_or_a_closed_account_binds_nothing() {
    let (_dir, pool, alice, bob) = fixture().await;
    // An old AppID of the mini program left Alice's WeChat on Bob too.
    bind(
        &pool,
        alice,
        &wechat(APP, "oMiniAlice", Some("oUnionAlice")),
    )
    .await;
    bind(&pool, bob, &wechat(TABLET_APP, "oOld", Some("oUnionAlice"))).await;
    assert_eq!(
        by_unionid(
            &pool,
            &wechat(PHONE_APP, "oPhoneAlice", Some("oUnionAlice"))
        )
        .await,
        (identities::SignedIn::Unbound, false)
    );
    // Bob alone, disabled: told, not bound.
    let (_dir, pool, _alice, bob) = fixture().await;
    bind(&pool, bob, &wechat(APP, "oMiniBob", Some("oUnionBob"))).await;
    users::set_enabled(&pool, &Username::new("bob").unwrap(), false)
        .await
        .unwrap();
    assert_eq!(
        by_unionid(&pool, &wechat(PHONE_APP, "oPhoneBob", Some("oUnionBob"))).await,
        (identities::SignedIn::Disabled, false)
    );
    assert!(
        identities::find(&pool, Provider::WeChat, PHONE_APP, "oPhoneBob")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unbinding_wechat_takes_the_apps_identities_of_the_same_wechat_along() {
    let (_dir, pool, alice, _bob) = fixture().await;
    bind(
        &pool,
        alice,
        &wechat(APP, "oMiniAlice", Some("oUnionAlice")),
    )
    .await;
    by_unionid(
        &pool,
        &wechat(PHONE_APP, "oPhoneAlice", Some("oUnionAlice")),
    )
    .await;
    // Another WeChat of an old AppID stays: it is someone else's unionid.
    bind(
        &pool,
        alice,
        &wechat(TABLET_APP, "oOther", Some("oUnionOther")),
    )
    .await;
    bind(&pool, alice, &github("583231", "octocat")).await;
    without_password(&pool, alice).await;

    let Unbound::Done(gone) = unbind(&pool, alice, Provider::WeChat, APP).await else {
        panic!("not unbound");
    };
    assert_eq!(gone.realm, APP);
    let left: Vec<(Provider, String)> = identities::list(&pool, alice)
        .await
        .unwrap()
        .into_iter()
        .map(|identity| (identity.provider, identity.realm))
        .collect();
    assert_eq!(
        left,
        [
            (Provider::WeChat, TABLET_APP.to_owned()),
            (Provider::GitHub, GITHUB_REALM.to_owned())
        ]
    );
    let unbound: Vec<String> = audit::list(&pool, Some(alice), None, 10)
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.kind == "identity.unbound")
        .map(|entry| entry.details)
        .collect();
    assert_eq!(unbound.len(), 2, "{unbound:?}");

    // The same WeChat in two realms is one way in: it is not unbound while it is the last.
    let (_dir, pool, alice, _bob) = fixture().await;
    bind(
        &pool,
        alice,
        &wechat(APP, "oMiniAlice", Some("oUnionAlice")),
    )
    .await;
    by_unionid(
        &pool,
        &wechat(PHONE_APP, "oPhoneAlice", Some("oUnionAlice")),
    )
    .await;
    without_password(&pool, alice).await;
    assert_eq!(
        unbind(&pool, alice, Provider::WeChat, PHONE_APP).await,
        Unbound::LastSignIn
    );
    assert_eq!(identities::list(&pool, alice).await.unwrap().len(), 2);
}
