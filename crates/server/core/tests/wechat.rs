//! WeChat mini program identities, bind tickets, signup tokens and sessions
//! (`gono_server_core::wechat`) on the backend the environment chooses (`db::testing`).

use gono_server_core::{
    Username, audit,
    db::{self, Pool},
    services::Services,
    users::{self, NewUser},
    wechat::{
        self, Bind, Lookup, MAX_SESSIONS, NewSession, NewTicket, SEEN_GRANULARITY_SECS,
        SESSION_TTL_SECS, SIGNUP_TTL_SECS, SignIn, TICKET_TTL_SECS,
    },
};
use secrecy::{ExposeSecret as _, SecretString};

/// A fixed "now" far from the real clock, so that the tests choose every time themselves.
const NOW: i64 = 1_800_000_000;

const APP: &str = "wxd930ea5d5a258f4f";
const OTHER_APP: &str = "wx0123456789abcdef";
const ALICE_OPENID: &str = "oGZUI0egBJY1zhBYw2KhdUfwVJJE";
const BOB_OPENID: &str = "o6_bmasdasdsad6_2sgVt7hMZOPfL";

async fn fixture() -> (tempfile::TempDir, Pool, i64, i64) {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::testing::database(dir.path()).await;
    let mut ids = Vec::new();
    for name in ["alice", "bob", "root"] {
        let username = Username::new(name).unwrap();
        let id = users::create(
            &pool,
            &NewUser {
                username: &username,
                display_name: &format!("{name} Example"),
                password_hash: "x",
                // Keeps one enabled admin, so that alice and bob can be disabled.
                is_admin: name == "root",
                services: if name == "alice" {
                    Services::NONE.with(gono_server_core::services::Service::Webdav, true)
                } else {
                    Services::NONE
                },
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        ids.push(id);
    }
    (dir, pool, ids[0], ids[1])
}

/// A new ticket of `user`; panics if the account is bound.
async fn new_ticket(pool: &Pool, user: i64, now: i64) -> String {
    match wechat::create_ticket(pool, user, APP, now).await.unwrap() {
        NewTicket::Ticket(ticket) => {
            assert_eq!(ticket.expires_at, now + TICKET_TTL_SECS);
            ticket.ticket.expose_secret().to_owned()
        }
        NewTicket::Bound => panic!("the account is bound"),
    }
}

/// The signup token of the unbound `openid`; panics if it is bound.
async fn signup(pool: &Pool, app: &str, openid: &str, now: i64) -> String {
    match wechat::sign_in(pool, app, openid, None, now).await.unwrap() {
        SignIn::Unbound { token, expires_at } => {
            assert_eq!(expires_at, now + SIGNUP_TTL_SECS);
            token.expose_secret().to_owned()
        }
        other => panic!("not unbound: {other:?}"),
    }
}

/// A new session of the bound `openid`; panics otherwise.
async fn new_session(pool: &Pool, openid: &str, now: i64) -> NewSession {
    match wechat::sign_in(pool, APP, openid, None, now).await.unwrap() {
        SignIn::Session { session, .. } => session,
        other => panic!("no session: {other:?}"),
    }
}

/// Binds `openid` to `user` at `now` and returns the session the binding opened.
async fn bind(pool: &Pool, user: i64, openid: &str, now: i64) -> NewSession {
    let ticket = new_ticket(pool, user, now).await;
    let token = signup(pool, APP, openid, now).await;
    match wechat::bind(pool, APP, &token, &ticket, None, now)
        .await
        .unwrap()
    {
        Bind::Bound { session, account } => {
            assert_eq!(account.user_id, user);
            session
        }
        other => panic!("not bound: {other:?}"),
    }
}

async fn lookup(pool: &Pool, token: &SecretString, now: i64) -> Lookup {
    wechat::lookup(pool, APP, token.expose_secret(), now)
        .await
        .unwrap()
}

/// Inserts an identity directly, as a binding that happened elsewhere would leave it.
async fn insert_identity(pool: &Pool, user: i64, app: &str, openid: &str) -> Result<(), String> {
    let mut tx = db::begin_immediate(pool).await.unwrap();
    let id = db::next_id(&mut tx, "wechat_identities").await.unwrap();
    let inserted = sqlx::query(
        "INSERT INTO wechat_identities (id, user_id, app_id, openid, created_at, last_seen_at) \
         VALUES (?, ?, ?, ?, 0, 0)",
    )
    .bind(id)
    .bind(user)
    .bind(app)
    .bind(openid)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {
            tx.commit().await.unwrap();
            Ok(())
        }
        Err(err) => Err(err.to_string()),
    }
}

async fn count(pool: &Pool, table: &str, user: i64) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE user_id = ?");
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn audit_entries(pool: &Pool, user: i64) -> Vec<(String, String)> {
    audit::list(pool, Some(user), None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| (entry.kind, entry.details))
        .collect()
}

#[tokio::test]
async fn a_ticket_binds_the_openid_of_a_signup_token() {
    let (_dir, pool, alice, _) = fixture().await;
    assert!(wechat::identities(&pool, alice).await.unwrap().is_empty());

    let ticket = new_ticket(&pool, alice, NOW).await;
    assert!(wechat::is_ticket(&ticket));
    assert!(
        wechat::ticket_is_live(&pool, alice, &ticket, NOW)
            .await
            .unwrap()
    );
    let token = signup(&pool, APP, ALICE_OPENID, NOW).await;
    assert!(wechat::is_token(&token));
    // Only digests are stored.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT ticket_hash FROM wechat_bind_tickets UNION ALL \
         SELECT token_hash FROM wechat_signup_tokens",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(stored.len(), 2);
    for digest in &stored {
        assert_eq!(digest.len(), 32);
        assert!(digest != ticket.as_bytes() && digest != token.as_bytes());
    }

    let ip = Some("192.0.2.9".parse().unwrap());
    let Bind::Bound { session, account } = wechat::bind(&pool, APP, &token, &ticket, ip, NOW + 5)
        .await
        .unwrap()
    else {
        panic!("not bound");
    };
    assert!(wechat::is_token(session.token.expose_secret()));
    assert_eq!(session.expires_at, NOW + 5 + SESSION_TTL_SECS);
    assert_eq!(account.username.as_str(), "alice");
    assert_eq!(account.display_name, "alice Example");
    assert!(account.services.webdav && !account.services.s3);
    assert_eq!(
        wechat::identity(&pool, alice, APP).await.unwrap(),
        Some(wechat::Identity {
            app_id: APP.to_owned(),
            created_at: NOW + 5,
            last_seen_at: NOW + 5,
        })
    );
    assert_eq!(
        wechat::identity(&pool, alice, OTHER_APP).await.unwrap(),
        None
    );
    // Recorded with the AppID and the client, never the openid.
    let entry = audit::list(&pool, Some(alice), None, 10).await.unwrap();
    assert_eq!(entry.len(), 1);
    assert_eq!(entry[0].kind, "wechat.bound");
    assert_eq!(entry[0].actor, "user");
    assert_eq!(entry[0].client_ip.as_deref(), Some("192.0.2.9"));
    assert_eq!(entry[0].details, format!("{{\"app_id\":\"{APP}\"}}"));

    // Both are used up.
    assert!(
        !wechat::ticket_is_live(&pool, alice, &ticket, NOW + 5)
            .await
            .unwrap()
    );
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &ticket, None, NOW + 6)
            .await
            .unwrap(),
        Bind::SessionExpired
    ));
    let other = signup(&pool, APP, BOB_OPENID, NOW + 6).await;
    assert!(matches!(
        wechat::bind(&pool, APP, &other, &ticket, None, NOW + 6)
            .await
            .unwrap(),
        Bind::TicketExpired
    ));
    // Bound, the account makes no tickets, and signing in opens a session.
    assert!(matches!(
        wechat::create_ticket(&pool, alice, APP, NOW + 7)
            .await
            .unwrap(),
        NewTicket::Bound
    ));
    let again = new_session(&pool, ALICE_OPENID, NOW + 8).await;
    assert_eq!(
        lookup(&pool, &again.token, NOW + 8).await,
        Lookup::Live(account.clone())
    );
    assert_eq!(
        wechat::identity(&pool, alice, APP)
            .await
            .unwrap()
            .unwrap()
            .last_seen_at,
        NOW + 8
    );
    assert_eq!(
        lookup(&pool, &session.token, NOW + 8).await,
        Lookup::Live(account)
    );
}

#[tokio::test]
async fn tickets_expire_and_a_new_one_ends_the_previous() {
    let (_dir, pool, alice, bob) = fixture().await;
    let first = new_ticket(&pool, alice, NOW).await;
    let second = new_ticket(&pool, alice, NOW + 1).await;
    assert!(
        !wechat::ticket_is_live(&pool, alice, &first, NOW + 1)
            .await
            .unwrap()
    );
    assert!(
        wechat::ticket_is_live(&pool, alice, &second, NOW + 1)
            .await
            .unwrap()
    );
    // A ticket names its own account only.
    assert!(
        !wechat::ticket_is_live(&pool, bob, &second, NOW + 1)
            .await
            .unwrap()
    );
    // Tickets of other accounts stay.
    let bobs = new_ticket(&pool, bob, NOW + 2).await;
    assert!(
        wechat::ticket_is_live(&pool, alice, &second, NOW + 2)
            .await
            .unwrap()
    );

    let token = signup(&pool, APP, ALICE_OPENID, NOW + 2).await;
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &first, None, NOW + 2)
            .await
            .unwrap(),
        Bind::TicketExpired
    ));
    let expired = NOW + 1 + TICKET_TTL_SECS;
    assert!(
        !wechat::ticket_is_live(&pool, alice, &second, expired)
            .await
            .unwrap()
    );
    let token = signup(&pool, APP, ALICE_OPENID, expired).await;
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &second, None, expired)
            .await
            .unwrap(),
        Bind::TicketExpired
    ));
    // The refusal left the signup token alone: it binds with a live ticket.
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &bobs, None, expired)
            .await
            .unwrap(),
        Bind::Bound { .. }
    ));
    assert_eq!(wechat::identities(&pool, bob).await.unwrap().len(), 1);
    assert!(wechat::identities(&pool, alice).await.unwrap().is_empty());
}

#[tokio::test]
async fn signup_tokens_expire_and_a_new_one_ends_the_previous() {
    let (_dir, pool, alice, _) = fixture().await;
    let first = signup(&pool, APP, ALICE_OPENID, NOW).await;
    let second = signup(&pool, APP, ALICE_OPENID, NOW + 1).await;
    // Tokens of other openids and AppIDs stay.
    let other = signup(&pool, APP, BOB_OPENID, NOW + 1).await;
    let elsewhere = signup(&pool, OTHER_APP, ALICE_OPENID, NOW + 1).await;
    let ticket = new_ticket(&pool, alice, NOW + 1).await;
    assert!(matches!(
        wechat::bind(&pool, APP, &first, &ticket, None, NOW + 1)
            .await
            .unwrap(),
        Bind::SessionExpired
    ));
    // A token binds only for the AppID it was made for.
    assert!(matches!(
        wechat::bind(&pool, APP, &elsewhere, &ticket, None, NOW + 1)
            .await
            .unwrap(),
        Bind::SessionExpired
    ));
    let expired = NOW + 1 + SIGNUP_TTL_SECS;
    let ticket = new_ticket(&pool, alice, expired).await;
    assert!(matches!(
        wechat::bind(&pool, APP, &second, &ticket, None, expired)
            .await
            .unwrap(),
        Bind::SessionExpired
    ));
    // The refusal left the ticket alone.
    assert!(
        wechat::ticket_is_live(&pool, alice, &ticket, expired)
            .await
            .unwrap()
    );
    assert!(matches!(
        wechat::bind(&pool, APP, &other, &ticket, None, NOW + 2)
            .await
            .unwrap(),
        Bind::Bound { .. }
    ));
}

#[tokio::test]
async fn an_openid_and_an_account_are_bound_once_per_app_id() {
    let (_dir, pool, alice, bob) = fixture().await;
    bind(&pool, alice, ALICE_OPENID, NOW).await;

    // The unique keys hold by themselves: (AppID, openid) and (account, AppID).
    assert!(
        insert_identity(&pool, bob, APP, ALICE_OPENID)
            .await
            .is_err()
    );
    assert!(
        insert_identity(&pool, alice, APP, BOB_OPENID)
            .await
            .is_err()
    );
    // The same openid of another AppID is another WeChat identity, and an account has one per
    // AppID.
    insert_identity(&pool, bob, OTHER_APP, ALICE_OPENID)
        .await
        .unwrap();
    insert_identity(&pool, alice, OTHER_APP, BOB_OPENID)
        .await
        .unwrap();
    assert_eq!(wechat::identities(&pool, alice).await.unwrap().len(), 2);

    // An openid that was bound elsewhere after its signup token was made: the token ends, the
    // ticket stays for another WeChat user.
    let token = signup(&pool, APP, BOB_OPENID, NOW + 1).await;
    let bobs = new_ticket(&pool, bob, NOW + 1).await;
    let carol = Username::new("carol").unwrap();
    let carol = users::create(
        &pool,
        &NewUser {
            username: &carol,
            display_name: "Carol",
            password_hash: "x",
            is_admin: false,
            services: Services::NONE,
        },
        |_| Ok(()),
    )
    .await
    .unwrap();
    insert_identity(&pool, carol, APP, BOB_OPENID)
        .await
        .unwrap();
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &bobs, None, NOW + 2)
            .await
            .unwrap(),
        Bind::AccountExists
    ));
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &bobs, None, NOW + 2)
            .await
            .unwrap(),
        Bind::SessionExpired
    ));
    assert!(
        wechat::ticket_is_live(&pool, bob, &bobs, NOW + 2)
            .await
            .unwrap()
    );

    // An account that got another openid of the AppID after its ticket was made: the ticket
    // ends, the token stays.
    let token = signup(&pool, APP, "oSomeoneElse", NOW + 3).await;
    insert_identity(&pool, bob, APP, "oBobElsewhere")
        .await
        .unwrap();
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &bobs, None, NOW + 3)
            .await
            .unwrap(),
        Bind::BindFailed
    ));
    assert!(
        !wechat::ticket_is_live(&pool, bob, &bobs, NOW + 3)
            .await
            .unwrap()
    );
    // Nothing was bound on the way.
    assert_eq!(count(&pool, "wechat_identities", bob).await, 2);
    assert_eq!(count(&pool, "mp_sessions", bob).await, 0);
}

#[tokio::test]
async fn sessions_slide_and_end_when_unused_or_logged_out() {
    let (_dir, pool, alice, _) = fixture().await;
    let session = bind(&pool, alice, ALICE_OPENID, NOW).await;
    assert!(matches!(
        lookup(&pool, &session.token, NOW + 1).await,
        Lookup::Live(_)
    ));
    // Within the granularity nothing is written.
    assert_eq!(newest_expiry(&pool).await, NOW + SESSION_TTL_SECS);
    let later = NOW + SEEN_GRANULARITY_SECS;
    assert!(matches!(
        lookup(&pool, &session.token, later).await,
        Lookup::Live(_)
    ));
    assert_eq!(newest_expiry(&pool).await, later + SESSION_TTL_SECS);
    // Each use extends it; unused for the whole lifetime, it ends.
    let ended = later + SESSION_TTL_SECS;
    assert!(matches!(
        lookup(&pool, &session.token, ended - 1).await,
        Lookup::Live(_)
    ));
    assert_eq!(newest_expiry(&pool).await, ended - 1 + SESSION_TTL_SECS);
    assert_eq!(
        lookup(&pool, &session.token, ended - 1 + SESSION_TTL_SECS).await,
        Lookup::Expired
    );
    // A session counts for its own AppID only.
    let other = new_session(&pool, ALICE_OPENID, NOW).await;
    assert_eq!(
        wechat::lookup(&pool, OTHER_APP, other.token.expose_secret(), NOW)
            .await
            .unwrap(),
        Lookup::Unknown
    );
    assert!(
        !wechat::logout(&pool, OTHER_APP, other.token.expose_secret())
            .await
            .unwrap()
    );
    assert!(
        wechat::logout(&pool, APP, other.token.expose_secret())
            .await
            .unwrap()
    );
    assert_eq!(lookup(&pool, &other.token, NOW).await, Lookup::Unknown);
    assert!(
        !wechat::logout(&pool, APP, other.token.expose_secret())
            .await
            .unwrap()
    );
    assert_eq!(
        wechat::lookup(&pool, APP, &"x".repeat(43), NOW)
            .await
            .unwrap(),
        Lookup::Unknown
    );
}

/// The expiry of the newest session.
async fn newest_expiry(pool: &Pool) -> i64 {
    sqlx::query_scalar("SELECT expires_at FROM mp_sessions ORDER BY id DESC LIMIT 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn sessions_end_with_unbinding_disabling_and_deleting() {
    let (_dir, pool, alice, bob) = fixture().await;
    let first = bind(&pool, alice, ALICE_OPENID, NOW).await;
    let second = new_session(&pool, ALICE_OPENID, NOW + 1).await;
    let bobs = bind(&pool, bob, BOB_OPENID, NOW + 1).await;

    let ip = Some("2001:db8::7".parse().unwrap());
    assert!(
        wechat::unbind(&pool, alice, APP, ip, NOW + 2)
            .await
            .unwrap()
    );
    for token in [&first.token, &second.token] {
        assert_eq!(lookup(&pool, token, NOW + 2).await, Lookup::Unknown);
    }
    assert_eq!(count(&pool, "mp_sessions", alice).await, 0);
    assert_eq!(wechat::identity(&pool, alice, APP).await.unwrap(), None);
    assert!(
        !wechat::unbind(&pool, alice, APP, ip, NOW + 3)
            .await
            .unwrap()
    );
    assert_eq!(
        audit_entries(&pool, alice).await.first().cloned(),
        Some((
            "wechat.unbound".to_owned(),
            format!("{{\"app_id\":\"{APP}\"}}")
        ))
    );
    // Bob's binding is not touched; alice's openid is free again.
    assert!(matches!(
        lookup(&pool, &bobs.token, NOW + 2).await,
        Lookup::Live(_)
    ));
    signup(&pool, APP, ALICE_OPENID, NOW + 3).await;

    // Disabling ends the sessions; enabling does not bring them back.
    let username = Username::new("bob").unwrap();
    users::set_enabled(&pool, &username, false).await.unwrap();
    assert_eq!(count(&pool, "mp_sessions", bob).await, 0);
    assert_eq!(lookup(&pool, &bobs.token, NOW + 4).await, Lookup::Unknown);
    assert!(matches!(
        wechat::sign_in(&pool, APP, BOB_OPENID, None, NOW + 4)
            .await
            .unwrap(),
        SignIn::Disabled
    ));
    users::set_enabled(&pool, &username, true).await.unwrap();
    assert_eq!(lookup(&pool, &bobs.token, NOW + 4).await, Lookup::Unknown);
    let renewed = new_session(&pool, BOB_OPENID, NOW + 5).await;
    assert!(matches!(
        lookup(&pool, &renewed.token, NOW + 5).await,
        Lookup::Live(_)
    ));
    // A disabled account, however it was disabled, has no live session and binds nothing.
    sqlx::query("UPDATE users SET enabled = 0 WHERE id = ?")
        .bind(bob)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        lookup(&pool, &renewed.token, NOW + 5).await,
        Lookup::Disabled
    );
    sqlx::query("UPDATE users SET enabled = 1 WHERE id = ?")
        .bind(bob)
        .execute(&pool)
        .await
        .unwrap();
    let ticket = new_ticket(&pool, alice, NOW + 6).await;
    users::set_enabled(&pool, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    let token = signup(&pool, APP, ALICE_OPENID, NOW + 6).await;
    assert!(matches!(
        wechat::bind(&pool, APP, &token, &ticket, None, NOW + 6)
            .await
            .unwrap(),
        Bind::Disabled
    ));

    assert_eq!(count(&pool, "wechat_bind_tickets", alice).await, 1);

    // Deleting an account removes its identity, tickets and sessions.
    users::delete(&pool, &username).await.unwrap();
    users::delete(&pool, &Username::new("alice").unwrap())
        .await
        .unwrap();
    for table in ["wechat_identities", "wechat_bind_tickets", "mp_sessions"] {
        for user in [alice, bob] {
            assert_eq!(count(&pool, table, user).await, 0, "{table}");
        }
    }
    assert_eq!(
        lookup(&pool, &renewed.token, NOW + 7).await,
        Lookup::Unknown
    );
    signup(&pool, APP, BOB_OPENID, NOW + 7).await;
}

#[tokio::test]
async fn an_identity_keeps_its_newest_sessions() {
    let (_dir, pool, alice, _) = fixture().await;
    let mut sessions = vec![bind(&pool, alice, ALICE_OPENID, NOW).await];
    for step in 1..=6 {
        sessions.push(new_session(&pool, ALICE_OPENID, NOW + step).await);
    }
    assert_eq!(count(&pool, "mp_sessions", alice).await, MAX_SESSIONS);
    let kept = sessions.len() - usize::try_from(MAX_SESSIONS).unwrap();
    for (index, session) in sessions.iter().enumerate() {
        let found = lookup(&pool, &session.token, NOW + 10).await;
        if index < kept {
            assert_eq!(found, Lookup::Unknown, "session {index}");
        } else {
            assert!(matches!(found, Lookup::Live(_)), "session {index}");
        }
    }
}

#[tokio::test]
async fn the_unionid_is_kept_once_wechat_reports_it() {
    let (_dir, pool, alice, _) = fixture().await;
    let ticket = new_ticket(&pool, alice, NOW).await;
    let SignIn::Unbound { token, .. } =
        wechat::sign_in(&pool, APP, ALICE_OPENID, Some("oUnion1"), NOW)
            .await
            .unwrap()
    else {
        panic!("bound");
    };
    assert!(matches!(
        wechat::bind(&pool, APP, token.expose_secret(), &ticket, None, NOW)
            .await
            .unwrap(),
        Bind::Bound { .. }
    ));
    assert_eq!(unionid(&pool, alice).await.as_deref(), Some("oUnion1"));
    // A sign-in without one keeps it; one with another replaces it.
    new_session(&pool, ALICE_OPENID, NOW + 1).await;
    assert_eq!(unionid(&pool, alice).await.as_deref(), Some("oUnion1"));
    wechat::sign_in(&pool, APP, ALICE_OPENID, Some("oUnion2"), NOW + 2)
        .await
        .unwrap();
    assert_eq!(unionid(&pool, alice).await.as_deref(), Some("oUnion2"));
}

async fn unionid(pool: &Pool, user: i64) -> Option<String> {
    let unionid: Option<db::Text> =
        sqlx::query_scalar("SELECT unionid FROM wechat_identities WHERE user_id = ?")
            .bind(user)
            .fetch_one(pool)
            .await
            .unwrap();
    unionid.map(String::from)
}

#[tokio::test]
async fn purging_removes_what_expired() {
    let (_dir, pool, alice, bob) = fixture().await;
    let session = bind(&pool, alice, ALICE_OPENID, NOW).await;
    new_ticket(&pool, bob, NOW).await;
    signup(&pool, APP, BOB_OPENID, NOW).await;
    assert_eq!(wechat::purge_expired(&pool, NOW).await.unwrap(), 0);
    // Tickets and signup tokens end after ten minutes, sessions after 30 days.
    assert_eq!(
        wechat::purge_expired(&pool, NOW + TICKET_TTL_SECS)
            .await
            .unwrap(),
        2
    );
    assert!(matches!(
        lookup(&pool, &session.token, NOW + TICKET_TTL_SECS).await,
        Lookup::Live(_)
    ));
    let ended = NOW + TICKET_TTL_SECS + SESSION_TTL_SECS;
    assert_eq!(wechat::purge_expired(&pool, ended).await.unwrap(), 1);
    assert_eq!(count(&pool, "mp_sessions", alice).await, 0);
    // The identity stays: only its sessions end.
    assert_eq!(wechat::identities(&pool, alice).await.unwrap().len(), 1);
}
