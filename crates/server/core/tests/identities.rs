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
