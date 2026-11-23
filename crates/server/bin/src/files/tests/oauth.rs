//! Signing in with Google and GitHub through the router, against the local mock of both
//! providers ([`crate::oauth::mock`]): the buttons of the sign-in pages, the callback, the
//! identities bound to no account, automatic binding by address, binding and confirming from the
//! account page, setting a first password, and the admin UI's sign-in.

use std::sync::Arc;

use axum::http::StatusCode;
use gono_server_core::{
    Username, audit, db,
    identities::{self, Provider},
    users,
};

use super::{ALICE_PASSWORD, Browser, Fixture, Reply, fixture};
use crate::{
    i18n::{Lang, Text, fill},
    mail::{Mailer, MemoryMailer},
    oauth::{
        OAuth,
        mock::{Mock, Person},
    },
};

fn t() -> &'static Text {
    Lang::En.t()
}

/// The fixture with Google and GitHub played by `mock`, and the in-memory mailer.
async fn with_oauth() -> (Fixture, Mock, Arc<MemoryMailer>) {
    let mut f = fixture().await;
    let mock = Mock::start().await;
    let oauth = OAuth::new(&f.state.base_url, Some(mock.google()), Some(mock.github())).unwrap();
    f.state.oauth = Some(Arc::new(oauth));
    let mailer = Arc::new(MemoryMailer::default());
    f.state.mailer = Some(mailer.clone() as Arc<dyn Mailer>);
    (f, mock, mailer)
}

async fn alice(f: &Fixture) -> users::User {
    users::get(&f.state.db, &Username::new("alice").unwrap())
        .await
        .unwrap()
}

/// The login CSRF token of the sign-in page `page`.
async fn login_csrf(browser: &mut Browser, page: &str) -> String {
    browser.get(page).await.field("name=\"csrf\" value=\"")
}

/// Starts a sign-in with `provider` from `/login` going on to `next`: the provider's URL.
async fn start(browser: &mut Browser, provider: &str, next: &str) -> String {
    let csrf = login_csrf(browser, "/login").await;
    let started = browser
        .post(
            &format!("/login/oauth/{provider}"),
            &[("csrf", &csrf), ("purpose", "sign_in"), ("next", next)],
        )
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{}", started.text());
    started.location().to_owned()
}

/// Signs in with `provider` as `person` from `/login`: the callback's answer.
async fn sign_in(browser: &mut Browser, mock: &Mock, provider: &str, person: &Person) -> Reply {
    let authorize = start(browser, provider, "/apps/files/").await;
    browser.get(&mock.approve(&authorize, person)).await
}

/// Binds `person`'s Google identity to alice's account directly.
async fn bind_google(f: &Fixture, person: &Person) {
    let claims = identities::Claims {
        provider: Provider::Google,
        realm: identities::GOOGLE_REALM.to_owned(),
        subject: person.subject.clone(),
        unionid: None,
        label: person.email.clone().unwrap_or_default(),
        email: None,
        email_verified: false,
        name: None,
    };
    let bound = identities::bind(
        &f.state.db,
        alice(f).await.id,
        &claims,
        identities::How::Cli,
        audit::Actor::Cli,
        None,
        db::unix_now(),
    )
    .await
    .unwrap();
    assert!(matches!(bound, identities::Bound::Bound(_)), "{bound:?}");
}

/// Creates account `name` without services.
async fn add_account(f: &Fixture, name: &str) -> i64 {
    let username = Username::new(name).unwrap();
    users::create(
        &f.state.db,
        &users::NewUser {
            username: &username,
            display_name: name,
            password_hash: "x",
            is_admin: false,
            services: gono_server_core::services::Services::NONE,
        },
        |_| Ok(()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn sign_in_pages_offer_the_configured_providers() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let page = browser.get("/login").await;
    assert!(!page.text().contains("/login/oauth/"), "{}", page.text());
    assert_eq!(
        browser
            .post("/login/oauth/google", &[("csrf", "x")])
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    let (f, mock, _) = with_oauth().await;
    let mut browser = Browser::new(&f.state);
    let page = browser.get("/login?next=/account/s3").await;
    let text = page.text();
    for provider in ["google", "github"] {
        assert!(
            text.contains(&format!("action=\"/login/oauth/{provider}\"")),
            "{text}"
        );
    }
    assert!(
        text.contains(&fill(t().sign_in_with, &["Google"])),
        "{text}"
    );
    assert!(
        text.contains("name=\"next\" value=\"/account/s3\""),
        "{text}"
    );
    // Browsers check a form's redirect against `form-action`: the providers are named there.
    let csp = page.header("content-security-policy");
    assert!(
        csp.contains(&format!(
            "form-action 'self' {}",
            mock.origin.origin().ascii_serialization()
        )),
        "{csp}"
    );
    // Other pages keep their policy.
    let other = browser.get("/login/forgot").await;
    assert!(
        !other
            .header("content-security-policy")
            .contains("127.0.0.1")
    );

    // A sign-in starts at the provider, with PKCE, a nonce and the state, bound to this browser.
    let authorize = start(&mut browser, "google", "/apps/files/").await;
    let url = url::Url::parse(&authorize).unwrap();
    let query: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query["scope"], "openid email profile");
    assert_eq!(query["prompt"], "select_account");
    assert_eq!(
        query["redirect_uri"],
        "https://cloud.example.com/login/oauth/google/callback"
    );
    assert!(!query["nonce"].is_empty() && !query["code_challenge"].is_empty());
    assert!(
        !authorize.contains("apps"),
        "next stays on the server: {authorize}"
    );
    let github = start(&mut browser, "github", "/apps/files/").await;
    assert!(github.contains("scope=user%3Aemail"), "{github}");
    // Without the sign-in page's token nothing starts.
    let forged = browser
        .post(
            "/login/oauth/google",
            &[("csrf", "forged"), ("purpose", "sign_in")],
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_unbound_identity_binds_after_a_password_sign_in_and_then_signs_in() {
    let (f, mock, _) = with_oauth().await;
    let person = Person::new("10769150350006150715113082367", "alice@gmail.com");
    let mut browser = Browser::new(&f.state);
    let callback = sign_in(&mut browser, &mock, "google", &person).await;
    assert_eq!(
        callback.status,
        StatusCode::SEE_OTHER,
        "{}",
        callback.text()
    );
    assert_eq!(
        callback.location(),
        "/login/unbound?next=%2Fapps%2Ffiles%2F"
    );
    let unbound = browser.get(callback.location()).await;
    let text = unbound.text();
    assert!(
        text.contains(&fill(t().unbound_title, &["Google"])),
        "{text}"
    );
    assert!(text.contains("alice@gmail.com"), "{text}");
    assert!(text.contains(t().unbound_sign_in), "{text}");
    assert!(!text.contains(t().unbound_signup), "sign-up is off: {text}");
    // The access token was revoked, and nothing is bound.
    assert_eq!(mock.revoked(1).await.len(), 1);
    assert!(
        identities::list(&f.state.db, alice(&f).await.id)
            .await
            .unwrap()
            .is_empty()
    );

    // The password sign-in leads to the confirmation, which names both sides.
    let csrf = login_csrf(&mut browser, "/login?next=%2Fapps%2Ffiles%2F").await;
    let signed = browser
        .post(
            "/login",
            &[
                ("csrf", &csrf),
                ("user", "alice"),
                ("password", ALICE_PASSWORD),
                ("next", "/apps/files/"),
            ],
        )
        .await;
    assert_eq!(signed.location(), "/login/link?next=%2Fapps%2Ffiles%2F");
    let link = browser.get(signed.location()).await;
    let title = fill(t().link_title, &["Google", "alice@gmail.com", "alice"]);
    assert!(link.text().contains(&title), "{}", link.text());
    let csrf = link.csrf();
    let bound = browser
        .post(
            "/login/link",
            &[
                ("csrf", &csrf),
                ("next", "/apps/files/"),
                ("action", "bind"),
            ],
        )
        .await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.text());
    assert!(bound.text().contains(t().link_done), "{}", bound.text());
    let user = alice(&f).await;
    let listed = identities::list(&f.state.db, user.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].label, "alice@gmail.com");
    let entries = audit::list(&f.state.db, Some(user.id), None, 5)
        .await
        .unwrap();
    assert_eq!(entries[0].kind, "identity.bound");
    assert!(entries[0].details.contains("\"how\":\"account_page\""));
    assert!(!entries[0].details.contains(&person.subject));

    // Signed out, Google signs alice in, without a password.
    let mut other = Browser::new(&f.state);
    let callback = sign_in(&mut other, &mock, "google", &person).await;
    assert_eq!(
        callback.status,
        StatusCode::SEE_OTHER,
        "{}",
        callback.text()
    );
    assert_eq!(callback.location(), "/apps/files/");
    let page = other.get("/account/").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("alice@gmail.com"), "{}", page.text());
    // A fresh third-party sign-in counts as confirming it is you.
    assert!(!page.text().contains("id=\"tf-on-password\""));
}

#[tokio::test]
async fn the_unbound_page_can_be_left_and_ends_with_the_identity() {
    let (f, mock, _) = with_oauth().await;
    let mut browser = Browser::new(&f.state);
    let person = Person::new("583231", "octo@example.com");
    let callback = sign_in(&mut browser, &mock, "github", &person).await;
    let unbound = browser.get(callback.location()).await;
    assert!(unbound.text().contains("@user583231"), "{}", unbound.text());
    let csrf = unbound.field("name=\"csrf\" value=\"");
    let cancelled = browser
        .post(
            "/login/unbound/cancel",
            &[("csrf", &csrf), ("next", "/apps/files/")],
        )
        .await;
    assert_eq!(cancelled.status, StatusCode::SEE_OTHER);
    assert_eq!(cancelled.location(), "/login?next=%2Fapps%2Ffiles%2F");
    let gone = browser.get("/login/unbound").await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert!(gone.text().contains(t().unbound_expired));
    // A password sign-in now goes on as usual.
    browser.sign_in().await;
    assert!(
        identities::list(&f.state.db, alice(&f).await.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_verified_address_of_the_account_binds_automatically_and_mails_a_notice() {
    let (f, mock, mailer) = with_oauth().await;
    let user = alice(&f).await;
    sqlx::query("UPDATE users SET email = 'alice@example.com' WHERE id = ?")
        .bind(user.id)
        .execute(&f.state.db)
        .await
        .unwrap();
    // Not verified by the provider: nothing is bound.
    let mut browser = Browser::new(&f.state);
    let unverified = Person {
        verified: false,
        ..Person::new("1", "Alice@Example.com")
    };
    let callback = sign_in(&mut browser, &mock, "google", &unverified).await;
    assert!(
        callback.location().starts_with("/login/unbound"),
        "{}",
        callback.location()
    );

    // Verified (GitHub's primary address): bound, signed in, and the address hears of it.
    let mut browser = Browser::new(&f.state);
    let verified = Person::new("2", "ALICE@example.com");
    let callback = sign_in(&mut browser, &mock, "github", &verified).await;
    assert_eq!(callback.status, StatusCode::OK, "{}", callback.text());
    let notice = fill(t().notice_bound_auto, &["GitHub", "@user2"]);
    assert!(callback.text().contains(&notice), "{}", callback.text());
    assert!(callback.text().contains("href=\"/apps/files/\""));
    assert_eq!(browser.get("/account/").await.status, StatusCode::OK);
    let sent = mailer.wait_for(1).await;
    assert_eq!(sent[0].to, "alice@example.com");
    assert!(sent[0].text.contains("@user2") && sent[0].text.contains("alice"));
    assert!(
        !sent[0].text.contains("/login/oauth"),
        "no link that signs in"
    );
    let entries = audit::list(&f.state.db, Some(user.id), None, 5)
        .await
        .unwrap();
    assert!(
        entries[0].details.contains("\"how\":\"email\""),
        "{}",
        entries[0].details
    );

    // An account with a GitHub identity already gets no second one.
    let mut browser = Browser::new(&f.state);
    let second = Person::new("3", "alice@example.com");
    let callback = sign_in(&mut browser, &mock, "github", &second).await;
    assert!(
        callback.location().starts_with("/login/unbound"),
        "{}",
        callback.location()
    );
    // A disabled account gets none either.
    users::set_enabled(&f.state.db, &user.username, false)
        .await
        .unwrap();
    let callback = sign_in(
        &mut browser,
        &mock,
        "google",
        &Person::new("4", "alice@example.com"),
    )
    .await;
    assert!(
        callback.location().starts_with("/login/unbound"),
        "{}",
        callback.location()
    );
    // Nor does a bound identity of a disabled account sign in.
    let callback = sign_in(&mut browser, &mock, "github", &verified).await;
    assert_eq!(callback.status, StatusCode::FORBIDDEN);
    assert!(callback.text().contains(t().account_cannot_sign_in));
}

#[tokio::test]
async fn failed_sign_ins_complete_nothing_and_count_as_failures() {
    let (f, mock, _) = with_oauth().await;
    let person = Person::new("108", "x@gmail.com");
    let mut browser = Browser::new(&f.state);

    // A state is used once, and only by the browser that started.
    let authorize = start(&mut browser, "google", "/apps/files/").await;
    let callback = mock.approve(&authorize, &person);
    let mut stranger = Browser::new(&f.state);
    let foreign = stranger.get(&callback).await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    assert!(foreign.text().contains(t().oauth_failed));
    let again = browser.get(&callback).await;
    assert_eq!(
        again.status,
        StatusCode::FORBIDDEN,
        "used by the stranger's try"
    );
    let unknown = browser
        .get(
            "/login/oauth/google/callback?code=c&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .await;
    assert_eq!(unknown.status, StatusCode::FORBIDDEN);

    // A code the provider refuses, or an ID token with another nonce.
    mock.set_refuse(true);
    let authorize = start(&mut browser, "google", "/apps/files/").await;
    let refused = browser.get(&mock.approve(&authorize, &person)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    mock.set_refuse(false);
    mock.set_wrong_nonce(true);
    let authorize = start(&mut browser, "google", "/apps/files/").await;
    let replayed = browser.get(&mock.approve(&authorize, &person)).await;
    assert_eq!(replayed.status, StatusCode::FORBIDDEN);
    mock.set_wrong_nonce(false);

    // The user cancels at the provider.
    let authorize = start(&mut browser, "github", "/apps/files/").await;
    let cancelled = browser.get(&mock.deny(&authorize)).await;
    assert_eq!(cancelled.status, StatusCode::OK);
    assert!(cancelled.text().contains(t().oauth_cancelled_lead));

    // A provider that fails says so, and is no failure of the client.
    let authorize = start(&mut browser, "github", "/apps/files/").await;
    mock.set_down(true);
    let down = browser.get(&mock.approve(&authorize, &person)).await;
    assert_eq!(down.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        down.text()
            .contains(&fill(t().oauth_unavailable, &["GitHub"]))
    );
    mock.set_down(false);

    // The failures count: the sign-in limiter blocks this address after a while.
    let mut blocked = false;
    for _ in 0..20 {
        let reply = browser
            .get("/login/oauth/github/callback?code=c&state=x")
            .await;
        if reply.status == StatusCode::TOO_MANY_REQUESTS {
            blocked = true;
            break;
        }
    }
    assert!(blocked, "failed callbacks count against the client");
    let oauth = f.state.oauth.as_ref().unwrap();
    assert_eq!(oauth.waiting(), 0, "every state was used up");
}

#[tokio::test]
async fn the_account_page_binds_and_confirms_with_a_provider() {
    let (f, mock, _) = with_oauth().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/").await.text();
    assert!(
        page.contains("href=\"/account/identities/google/bind\""),
        "{page}"
    );
    assert!(
        page.contains("href=\"/account/identities/github/bind\""),
        "{page}"
    );

    // Binding asks to confirm it is you, then goes to the provider.
    let bind_page = browser.get("/account/identities/google/bind").await;
    assert!(
        bind_page
            .text()
            .contains(&fill(t().bind_title, &["Google"]))
    );
    let started = browser
        .post(
            "/account/identities/google/bind",
            &[("csrf", &csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{}", started.text());
    let person = Person::new("108", "alice@gmail.com");
    let callback = browser
        .get(&mock.approve(started.location(), &person))
        .await;
    assert_eq!(callback.location(), "/account/?done=bound-google");
    let page = browser.get(callback.location()).await.text();
    assert!(
        page.contains(&fill(t().notice_identity_bound, &["Google"])),
        "{page}"
    );
    assert!(
        page.contains("href=\"/account/identities/google/unbind\""),
        "{page}"
    );

    // An identity bound to another account is refused.
    let bob = add_account(&f, "bob").await;
    let bobs = Person::new("999", "bob@gmail.com");
    let claims = identities::Claims {
        provider: Provider::GitHub,
        realm: identities::GITHUB_REALM.to_owned(),
        subject: bobs.subject.clone(),
        unionid: None,
        label: "@bob".to_owned(),
        email: None,
        email_verified: false,
        name: None,
    };
    identities::bind(
        &f.state.db,
        bob,
        &claims,
        identities::How::Cli,
        audit::Actor::Cli,
        None,
        db::unix_now(),
    )
    .await
    .unwrap();
    let started = browser
        .post("/account/identities/github/bind", &[("csrf", &csrf)])
        .await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "confirmed already");
    let callback = browser.get(&mock.approve(started.location(), &bobs)).await;
    assert_eq!(callback.location(), "/account/?failed=taken-github");
    let page = browser.get(callback.location()).await.text();
    assert!(
        page.contains(&fill(t().err_identity_taken, &["GitHub"])),
        "{page}"
    );

    // Without a password, the account confirms with Google, and the other Google account
    // does not count. A password sign-in confirms nothing by itself.
    let mut unconfirmed = Browser::new(&f.state);
    let unconfirmed_csrf = unconfirmed.sign_in().await;
    sqlx::query("UPDATE users SET password_hash = NULL WHERE id = ?")
        .bind(alice(&f).await.id)
        .execute(&f.state.db)
        .await
        .unwrap();
    let mut fresh = Browser::new(&f.state);
    let signed = sign_in(&mut fresh, &mock, "google", &person).await;
    assert_eq!(signed.location(), "/apps/files/");
    // The confirmation of the sign-in lasts; another browser session is not confirmed.
    let page = fresh.get("/account/").await.text();
    assert!(page.contains("action=\"/account/password/set\""), "{page}");
    let confirm = unconfirmed.get("/account/confirm?next=%2Faccount%2F").await;
    let text = confirm.text();
    assert!(
        text.contains(&fill(t().confirm_with, &["Google"])),
        "{text}"
    );
    assert!(
        !text.contains("id=\"confirm-password\""),
        "no password: {text}"
    );
    let page = unconfirmed.get("/account/").await.text();
    assert!(!page.contains("action=\"/account/password/set\""), "{page}");
    let started = reauth(&mut unconfirmed, &unconfirmed_csrf).await;
    let wrong = unconfirmed
        .get(&mock.approve(started.location(), &Person::new("777", "z@gmail.com")))
        .await;
    assert_eq!(wrong.location(), "/account/?failed=other-google");
    let page = unconfirmed.get(wrong.location()).await.text();
    assert!(
        page.contains(&fill(t().err_reauth_other, &["Google"])),
        "{page}"
    );
    let started = reauth(&mut unconfirmed, &unconfirmed_csrf).await;
    let right = unconfirmed
        .get(&mock.approve(started.location(), &person))
        .await;
    assert_eq!(right.location(), "/account/identities/google/unbind");
    let page = unconfirmed.get("/account/").await.text();
    assert!(page.contains("action=\"/account/password/set\""), "{page}");
}

/// Starts confirming it is alice with Google from `browser`, coming back to her unbind page.
async fn reauth(browser: &mut Browser, csrf: &str) -> Reply {
    browser
        .post(
            "/login/oauth/google",
            &[
                ("csrf", csrf),
                ("purpose", "reauth"),
                ("next", "/account/identities/google/unbind"),
            ],
        )
        .await
}

#[tokio::test]
async fn an_account_without_a_password_sets_its_first_one_after_a_fresh_sign_in() {
    let (f, mock, _) = with_oauth().await;
    let person = Person::new("108", "alice@gmail.com");
    bind_google(&f, &person).await;
    let user = alice(&f).await;
    sqlx::query("UPDATE users SET password_hash = NULL WHERE id = ?")
        .bind(user.id)
        .execute(&f.state.db)
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    assert_eq!(
        sign_in(&mut browser, &mock, "google", &person)
            .await
            .location(),
        "/apps/files/"
    );
    let page = browser.get("/account/").await;
    let csrf = page.csrf();
    assert!(page.text().contains(t().password_set_title));
    let differ = browser
        .post(
            "/account/password/set",
            &[
                ("csrf", &csrf),
                ("password", "a first password"),
                ("password_repeat", "another one"),
            ],
        )
        .await;
    assert_eq!(differ.status, StatusCode::UNPROCESSABLE_ENTITY);
    let set = browser
        .post(
            "/account/password/set",
            &[
                ("csrf", &csrf),
                ("password", "a first password"),
                ("password_repeat", "a first password"),
            ],
        )
        .await;
    assert_eq!(set.location(), "/account/?done=password-set");
    assert!(alice(&f).await.has_password);
    let entries = audit::list(&f.state.db, Some(user.id), None, 5)
        .await
        .unwrap();
    assert_eq!(
        (entries[0].kind.as_str(), entries[0].actor.as_str()),
        ("password.set", "user")
    );
    // The browser stays signed in; the password signs in elsewhere.
    assert_eq!(browser.get("/account/").await.status, StatusCode::OK);
    let mut other = Browser::new(&f.state);
    let csrf = login_csrf(&mut other, "/login").await;
    let signed = other
        .post(
            "/login",
            &[
                ("csrf", &csrf),
                ("user", "alice"),
                ("password", "a first password"),
            ],
        )
        .await;
    assert_eq!(signed.status, StatusCode::SEE_OTHER);
    // An account with a password does not set a first one.
    let csrf = browser.get("/account/").await.csrf();
    let again = browser
        .post(
            "/account/password/set",
            &[
                ("csrf", &csrf),
                ("password", "replaced"),
                ("password_repeat", "replaced"),
            ],
        )
        .await;
    assert_eq!(again.location(), "/account/");
}

#[tokio::test]
async fn two_step_verification_is_not_asked_after_a_third_party_sign_in() {
    let (f, mock, _) = with_oauth().await;
    let person = Person::new("108", "alice@gmail.com");
    bind_google(&f, &person).await;
    super::enrolled_alice(&f).await;
    let mut browser = Browser::new(&f.state);
    let signed = sign_in(&mut browser, &mock, "google", &person).await;
    assert_eq!(signed.location(), "/apps/files/");
    let page = browser.get("/account/").await.text();
    assert!(page.contains(t().methods_no_two_step), "{page}");
}

#[tokio::test]
async fn github_logins_are_labels_refreshed_at_each_sign_in() {
    let (f, mock, _) = with_oauth().await;
    let mut person = Person::new("583231", "octo@example.com");
    let claims = identities::Claims {
        provider: Provider::GitHub,
        realm: identities::GITHUB_REALM.to_owned(),
        subject: person.subject.clone(),
        unionid: None,
        label: "@octocat".to_owned(),
        email: None,
        email_verified: false,
        name: None,
    };
    identities::bind(
        &f.state.db,
        alice(&f).await.id,
        &claims,
        identities::How::Cli,
        audit::Actor::Cli,
        None,
        db::unix_now(),
    )
    .await
    .unwrap();
    person.login = "renamed".to_owned();
    let mut browser = Browser::new(&f.state);
    let signed = sign_in(&mut browser, &mock, "github", &person).await;
    assert_eq!(signed.location(), "/apps/files/");
    let listed = identities::list(&f.state.db, alice(&f).await.id)
        .await
        .unwrap();
    assert_eq!(listed[0].label, "@renamed");
    let revoked = mock.revoked(1).await;
    assert!(revoked[0].starts_with("gho_"), "{revoked:?}");
}

#[tokio::test]
async fn the_login_flow_page_comes_back_to_its_consent_after_a_provider() {
    let (f, mock, _) = with_oauth().await;
    let person = Person::new("108", "alice@gmail.com");
    bind_google(&f, &person).await;
    let mut browser = Browser::new(&f.state);
    let started = browser
        .send(
            "POST",
            "/login/v2",
            &[("User-Agent", "Mozilla/5.0 (Macintosh) mirall/3.15.0")],
            axum::body::Body::empty(),
        )
        .await;
    let body: serde_json::Value = serde_json::from_slice(&started.body).unwrap();
    let login = url::Url::parse(body["login"].as_str().unwrap()).unwrap();
    let path = login.path().to_owned();
    let page = browser.get(&path).await;
    let text = page.text();
    assert!(text.contains("action=\"/login/oauth/google\""), "{text}");
    assert!(
        text.contains(&format!("name=\"next\" value=\"{path}\"")),
        "{text}"
    );
    let csrf = page.field("name=\"csrf\" value=\"");
    let started = browser
        .post(
            "/login/oauth/google",
            &[("csrf", &csrf), ("purpose", "sign_in"), ("next", &path)],
        )
        .await;
    let callback = browser
        .get(&mock.approve(started.location(), &person))
        .await;
    assert_eq!(callback.location(), path);
    let consent = browser.get(&path).await;
    assert!(
        consent.text().contains("name=\"action\" value=\"grant\""),
        "{}",
        consent.text()
    );
}
