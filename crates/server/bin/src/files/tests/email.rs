//! Email addresses on the account page and password resets by mail, through the router, with
//! the in-memory mailer.

use std::{net::IpAddr, sync::Arc};

use axum::{body::Body, http::StatusCode};
use gono_server_core::{
    Username, audit, db,
    email::{self, Bind, CodeFor, Key, NewCode, Purpose, RESET_SENDS_PER_DAY},
    password,
    users::{self, NewUser},
};
use secrecy::SecretString;

use super::{
    ALICE_PASSWORD, Browser, Fixture, ORIGIN, Reply, enrol, fixture, password_step, pending_cookie,
};
use crate::{
    i18n::{Lang, Text},
    mail::{Mailer, MemoryMailer, Sent},
    ratelimit::RateLimiter,
    web::Web,
};

/// The name of the reset cookie on the fixture's HTTPS origin.
const RESET_COOKIE: &str = "__Host-gono_reset";

fn t() -> &'static Text {
    Lang::En.t()
}

/// The fixture with the in-memory mailer.
async fn with_mail() -> (Fixture, Arc<MemoryMailer>) {
    let mut f = fixture().await;
    let mailer = Arc::new(MemoryMailer::default());
    f.state.mailer = Some(mailer.clone() as Arc<dyn Mailer>);
    (f, mailer)
}

async fn user(f: &Fixture, name: &str) -> users::User {
    users::get(&f.state.db, &Username::new(name).unwrap())
        .await
        .unwrap()
}

/// Creates account `name` with `password`, which has no services.
async fn add_user(f: &Fixture, name: &str, password: &str) -> i64 {
    let username = Username::new(name).unwrap();
    let hash = password::hash(&SecretString::from(password.to_owned())).unwrap();
    users::create(
        &f.state.db,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: &hash,
            is_admin: false,
            services: gono_server_core::services::Services::NONE,
        },
        |_| Ok(()),
    )
    .await
    .unwrap()
}

/// Binds `address` to account `user_id` without the pages, with a code of an hour ago (so that
/// the codes of the test itself are not held back by the limit of one a minute).
async fn bind_directly(f: &Fixture, user_id: i64, address: &str) {
    // The fixture's key; the code is used at once, so any key would do.
    let key = Key::from_bytes(&[9; 32]);
    let then = db::unix_now() - 3600;
    let NewCode::Code(code) =
        email::send_code(&f.state.db, &key, user_id, CodeFor::Bind, address, then)
            .await
            .unwrap()
    else {
        panic!("no code");
    };
    let bound = email::bind(&f.state.db, &key, user_id, &code.code, None, then + 1)
        .await
        .unwrap();
    assert!(matches!(bound, Bind::Bound { .. }), "{bound:?}");
}

/// The `Set-Cookie` value of the reset cookie in `reply`.
fn reset_cookie(reply: &Reply) -> String {
    reply
        .headers
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .find(|value| value.starts_with(&format!("{RESET_COOKIE}=")))
        .unwrap_or_else(|| panic!("no reset cookie in {:?}", reply.headers))
}

/// Posts `fields` to `uri` from this origin in the language `accept_language`.
async fn post_in(
    browser: &mut Browser,
    uri: &str,
    fields: &[(&str, &str)],
    accept_language: &str,
) -> Reply {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish();
    browser
        .send(
            "POST",
            uri,
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", ORIGIN),
                ("Accept-Language", accept_language),
            ],
            Body::from(body),
        )
        .await
}

/// Asks for a reset code for `login` in `browser`; returns the answer.
async fn forgot(browser: &mut Browser, login: &str) -> Reply {
    let form = browser.get("/login/forgot").await;
    assert_eq!(form.status, StatusCode::OK, "{}", form.text());
    let csrf = form.field("name=\"csrf\" value=\"");
    browser
        .post("/login/forgot", &[("csrf", &csrf), ("login", login)])
        .await
}

/// Resets the password of `login` with `code` in `browser`; returns the answer.
async fn reset(browser: &mut Browser, login: &str, code: &str, new: &str) -> Reply {
    let form = browser.get("/login/reset").await;
    assert_eq!(form.status, StatusCode::OK, "{}", form.text());
    let csrf = form.field("name=\"csrf\" value=\"");
    browser
        .post(
            "/login/reset",
            &[
                ("csrf", &csrf),
                ("login", login),
                ("code", code),
                ("password", new),
                ("password_repeat", new),
            ],
        )
        .await
}

/// `text` without what differs from page to page: the CSP nonce, the CSRF token and the
/// login that was entered.
fn normalized(text: &str, login: &str) -> String {
    let mut out = text.replace(&format!("value=\"{login}\""), "value=\"LOGIN\"");
    for marker in ["nonce=\"", "name=\"csrf\" value=\""] {
        let mut rest = out.as_str();
        let mut done = String::new();
        while let Some(start) = rest.find(marker) {
            let value = start + marker.len();
            done.push_str(&rest[..value]);
            let end = rest[value..].find('"').unwrap();
            done.push('X');
            rest = &rest[value + end..];
        }
        done.push_str(rest);
        out = done;
    }
    out
}

/// Waits a moment for mail that may be on its way, and returns everything sent.
async fn settled(mailer: &MemoryMailer) -> Vec<Sent> {
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    mailer.sent()
}

#[tokio::test]
async fn an_address_is_bound_with_the_code_mailed_to_it() {
    let (f, mailer) = with_mail().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let (_, _, _) = enrol(&mut browser, &csrf).await;
    let alice = user(&f, "alice").await;

    let page = browser.get("/account/").await.text();
    assert!(page.contains("action=\"/account/email\""), "{page}");
    assert!(page.contains(t().email_none), "{page}");
    assert!(!page.contains("action=\"/account/email/remove\""), "{page}");

    // The password is needed, and an address.
    let wrong = browser
        .post(
            "/account/email",
            &[
                ("csrf", &csrf),
                ("email", "alice@example.com"),
                ("password", "wrong"),
            ],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(wrong.text().contains(t().err_current_password));
    let invalid = browser
        .post(
            "/account/email",
            &[
                ("csrf", &csrf),
                ("email", "alice@localhost"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    let forged = browser
        .post(
            "/account/email",
            &[
                ("csrf", "forged"),
                ("email", "alice@example.com"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert!(mailer.sent().is_empty());

    let sent = browser
        .post(
            "/account/email",
            &[
                ("csrf", &csrf),
                ("email", " Alice@Example.com "),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(
        sent.location(),
        "/account/?done=email-sent",
        "{}",
        sent.text()
    );
    let mails = mailer.sent();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, "alice@example.com");
    assert_eq!(mails[0].subject, Lang::En.t().mail_bind_subject);
    assert!(mails[0].text.contains(ORIGIN), "{}", mails[0].text);
    // A mail to an address not proven yet does not name the account.
    assert!(!mails[0].text.contains("alice@") && !mails[0].text.contains(" alice"));
    let code = mails[0].code();

    // Another code within a minute is refused.
    let again = browser
        .post(
            "/account/email",
            &[
                ("csrf", &csrf),
                ("email", "alice@example.com"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        again.text().contains("less than a minute ago"),
        "{}",
        again.text()
    );
    assert_eq!(mailer.sent().len(), 1);

    let page = browser.get("/account/?done=email-sent").await.text();
    assert_unique_ids(&page);
    assert!(page.contains(t().notice_email_sent), "{page}");
    assert!(
        page.contains("A code was sent to alice@example.com."),
        "{page}"
    );
    assert!(page.contains("action=\"/account/email/confirm\""), "{page}");

    let other = if code == "000000" { "111111" } else { "000000" };
    let wrong = browser
        .post(
            "/account/email/confirm",
            &[("csrf", &csrf), ("code", other)],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        wrong.text().contains(t().err_email_code),
        "{}",
        wrong.text()
    );
    assert_eq!(email::address(&f.state.db, alice.id).await.unwrap(), None);

    // Someone with the password waits at the second step: binding the address ends it.
    pending_cookie(&f, &alice).await;
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 1);
    let bound = browser
        .post(
            "/account/email/confirm",
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(
        bound.location(),
        "/account/?done=email-bound",
        "{}",
        bound.text()
    );
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 0);
    assert_eq!(
        email::address(&f.state.db, alice.id)
            .await
            .unwrap()
            .as_deref(),
        Some("alice@example.com")
    );
    let page = browser.get("/account/?done=email-bound").await.text();
    assert_unique_ids(&page);
    assert!(page.contains(t().notice_email_bound), "{page}");
    assert!(
        page.contains("<dd class=\"mono\">alice@example.com</dd>"),
        "{page}"
    );
    assert!(page.contains("action=\"/account/email/remove\""), "{page}");
    assert!(
        !page.contains("action=\"/account/email/confirm\""),
        "{page}"
    );
    assert!(
        audit::list(&f.state.db, Some(alice.id), None, 50)
            .await
            .unwrap()
            .iter()
            .any(|entry| entry.kind == "email.bound")
    );
    // Nothing was replaced, so nobody gets a notice; the same address is refused.
    assert_eq!(settled(&mailer).await.len(), 1);
    let same = browser
        .post(
            "/account/email",
            &[
                ("csrf", &csrf),
                ("email", "alice@example.com"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(same.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(same.text().contains(t().err_email_same), "{}", same.text());
}

#[tokio::test]
async fn an_address_of_another_account_is_refused_without_naming_it() {
    let (f, mailer) = with_mail().await;
    let bob = add_user(&f, "bob", "bob password").await;
    bind_directly(&f, bob, "bob@example.com").await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;

    // The code goes out: only who reads it learns that the address is taken.
    let sent = browser
        .post(
            "/account/email",
            &[
                ("csrf", &csrf),
                ("email", "bob@example.com"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(sent.location(), "/account/?done=email-sent");
    let code = mailer.wait_for(1).await[0].code();
    let taken = browser
        .post(
            "/account/email/confirm",
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert_eq!(taken.status, StatusCode::UNPROCESSABLE_ENTITY);
    let text = taken.text();
    assert!(text.contains(t().err_email_taken), "{text}");
    assert!(!web_mentions(&text, "bob"), "{text}");
    let alice = user(&f, "alice").await;
    assert_eq!(email::address(&f.state.db, alice.id).await.unwrap(), None);
    assert_eq!(
        email::address(&f.state.db, bob).await.unwrap().as_deref(),
        Some("bob@example.com")
    );
    // The code is used up.
    let again = browser
        .post(
            "/account/email/confirm",
            &[("csrf", &csrf), ("code", &code)],
        )
        .await;
    assert!(
        again.text().contains(t().err_email_expired),
        "{}",
        again.text()
    );
}

fn assert_unique_ids(html: &str) {
    let mut ids = crate::web::element_ids(html);
    let all = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), all, "duplicate ids in {html}");
}

fn web_mentions(html: &str, word: &str) -> bool {
    crate::web::mentions(html, word)
}

#[tokio::test]
async fn replacing_and_removing_the_address_notify_the_previous_one() {
    let (f, mailer) = with_mail().await;
    let alice = user(&f, "alice").await;
    bind_directly(&f, alice.id, "first@example.com").await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;

    let sent = post_in(
        &mut browser,
        "/account/email",
        &[
            ("csrf", &csrf),
            ("email", "second@example.com"),
            ("password", ALICE_PASSWORD),
        ],
        "zh-CN,zh;q=0.9",
    )
    .await;
    assert_eq!(sent.location(), "/account/?done=email-sent");
    let mail = mailer.wait_for(1).await.remove(0);
    assert_eq!(mail.to, "second@example.com");
    // In the language of the request.
    assert_eq!(mail.subject, Lang::Zh.t().mail_bind_subject);
    let bound = browser
        .post(
            "/account/email/confirm",
            &[("csrf", &csrf), ("code", &mail.code())],
        )
        .await;
    assert_eq!(bound.location(), "/account/?done=email-bound");
    let notice = mailer.wait_for(2).await.remove(1);
    assert_eq!(notice.to, "first@example.com");
    assert_eq!(notice.subject, Lang::En.t().mail_replaced_subject);
    assert!(notice.text.contains("alice"), "{}", notice.text);
    // The old address does not learn the new one.
    assert!(!notice.text.contains("second@"), "{}", notice.text);

    let wrong = browser
        .post(
            "/account/email/remove",
            &[("csrf", &csrf), ("password", "wrong")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        email::address(&f.state.db, alice.id)
            .await
            .unwrap()
            .is_some()
    );
    let before = user(&f, "alice").await.updated_at;
    pending_cookie_after_enrolment(&f, &mut browser, &csrf).await;
    let removed = browser
        .post(
            "/account/email/remove",
            &[("csrf", &csrf), ("password", ALICE_PASSWORD)],
        )
        .await;
    assert_eq!(removed.location(), "/account/?done=email-removed");
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 0);
    assert_eq!(email::address(&f.state.db, alice.id).await.unwrap(), None);
    assert!(user(&f, "alice").await.updated_at >= before);
    let notice = mailer.wait_for(3).await.remove(2);
    assert_eq!(notice.to, "second@example.com");
    assert_eq!(notice.subject, Lang::En.t().mail_removed_subject);
    let page = browser.get("/account/?done=email-removed").await.text();
    assert!(page.contains(t().notice_email_removed), "{page}");
    assert!(page.contains(t().email_none), "{page}");
}

/// Turns two-step verification on for alice in `browser` and starts a sign-in of hers that
/// waits for its second step.
async fn pending_cookie_after_enrolment(f: &Fixture, browser: &mut Browser, csrf: &str) {
    enrol(browser, csrf).await;
    let alice = user(f, "alice").await;
    pending_cookie(f, &alice).await;
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 1);
}

#[tokio::test]
async fn without_a_mailer_there_is_neither_a_form_nor_a_reset() {
    let f = fixture().await;
    no_email_features(&f).await;
}

#[tokio::test]
async fn without_the_key_file_there_is_neither_a_form_nor_a_reset() {
    // A mailer, but no key to key the codes with: as without a mailer.
    let (mut f, mailer) = with_mail().await;
    f.state.web = Arc::new(Web::new(
        f.state.db.clone(),
        Arc::new(RateLimiter::new()),
        &f.state.base_url,
    ));
    assert!(f.state.email().is_none());
    no_email_features(&f).await;
    assert!(settled(&mailer).await.is_empty());
}

/// Checks that `f` offers no email address on the account page and no password reset.
async fn no_email_features(f: &Fixture) {
    let alice = user(f, "alice").await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/account/").await.text();
    assert!(page.contains(t().email_unavailable), "{page}");
    assert!(!page.contains("action=\"/account/email"), "{page}");
    // An address bound while mail was on is still shown.
    bind_directly(f, alice.id, "alice@example.com").await;
    let page = browser.get("/account/").await.text();
    assert!(page.contains("alice@example.com"), "{page}");
    assert!(!page.contains("action=\"/account/email"), "{page}");
    for (uri, fields) in [
        (
            "/account/email",
            vec![
                ("csrf", csrf.as_str()),
                ("email", "new@example.com"),
                ("password", ALICE_PASSWORD),
            ],
        ),
        (
            "/account/email/confirm",
            vec![("csrf", csrf.as_str()), ("code", "123456")],
        ),
        (
            "/account/email/remove",
            vec![("csrf", csrf.as_str()), ("password", ALICE_PASSWORD)],
        ),
    ] {
        assert_eq!(
            browser.post(uri, &fields).await.status,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }

    let mut anonymous = Browser::new(&f.state);
    let sign_in = anonymous.get("/login").await.text();
    assert!(!sign_in.contains("/login/forgot"), "{sign_in}");
    for uri in ["/login/forgot", "/login/reset"] {
        assert_eq!(
            anonymous.get(uri).await.status,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
        assert_eq!(
            anonymous.post(uri, &[("login", "alice")]).await.status,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn a_mailed_code_resets_the_password_and_ends_the_sessions() {
    let (f, mailer) = with_mail().await;
    let alice = user(&f, "alice").await;
    bind_directly(&f, alice.id, "alice@example.com").await;
    let mut signed_in = Browser::new(&f.state);
    signed_in.sign_in().await;

    let mut browser = Browser::new(&f.state);
    let sign_in = browser.get("/login").await.text();
    assert!(sign_in.contains("href=\"/login/forgot\""), "{sign_in}");
    // By address, in any case.
    let answer = forgot(&mut browser, "Alice@Example.com").await;
    assert_eq!(answer.status, StatusCode::OK);
    let text = answer.text();
    assert!(text.contains(t().forgot_sent), "{text}");
    assert!(text.contains("action=\"/login/reset\""), "{text}");
    let mail = mailer.wait_for(1).await.remove(0);
    assert_eq!(mail.to, "alice@example.com");
    assert_eq!(mail.subject, Lang::En.t().mail_reset_subject);
    assert!(mail.text.contains("alice"), "{}", mail.text);
    assert!(
        mail.text.contains(&format!("{ORIGIN}/login/reset")),
        "{}",
        mail.text
    );
    let code = mail.code();

    // The form checks what needs no account first.
    let form = browser.get("/login/reset").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    let differ = browser
        .post(
            "/login/reset",
            &[
                ("csrf", &csrf),
                ("login", "alice"),
                ("code", &code),
                ("password", "a new password"),
                ("password_repeat", "another one"),
            ],
        )
        .await;
    assert_eq!(differ.status, StatusCode::UNPROCESSABLE_ENTITY);
    let short = reset(&mut browser, "alice", &code, "short").await;
    assert_eq!(short.status, StatusCode::UNPROCESSABLE_ENTITY);
    let forged = browser
        .post(
            "/login/reset",
            &[
                ("csrf", "forged"),
                ("login", "alice"),
                ("code", &code),
                ("password", "a new password"),
                ("password_repeat", "a new password"),
            ],
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);

    let other = if code == "000000" { "111111" } else { "000000" };
    let wrong = reset(&mut browser, "alice", other, "a new password").await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert!(wrong.text().contains(t().reset_wrong), "{}", wrong.text());
    // An unknown account gets the very same answer.
    let unknown = reset(&mut browser, "nobody", &code, "a new password").await;
    assert_eq!(unknown.status, StatusCode::FORBIDDEN);
    assert_eq!(
        normalized(&unknown.text(), "nobody"),
        normalized(&wrong.text(), "alice")
    );

    let done = reset(&mut browser, "alice", &code, "a new password").await;
    assert_eq!(
        done.location(),
        "/login?done=password-reset",
        "{}",
        done.text()
    );
    let notice = mailer.wait_for(2).await.remove(1);
    assert_eq!(notice.to, "alice@example.com");
    assert_eq!(notice.subject, Lang::En.t().mail_reset_done_subject);
    assert!(
        browser
            .get("/login?done=password-reset")
            .await
            .text()
            .contains(t().notice_password_reset)
    );
    // Every browser of the account is signed out.
    assert_eq!(
        signed_in.get("/account/").await.status,
        StatusCode::SEE_OTHER
    );
    // The code worked once.
    let again = reset(&mut browser, "alice", &code, "a third password").await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    // The new password signs in, the old one no longer.
    let mut fresh = Browser::new(&f.state);
    let old = password_step(&mut fresh).await;
    assert_eq!(old.status, StatusCode::FORBIDDEN);
    let form = fresh.get("/login").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    let new = fresh
        .post(
            "/login",
            &[
                ("csrf", &csrf),
                ("user", "alice"),
                ("password", "a new password"),
            ],
        )
        .await;
    assert_eq!(new.status, StatusCode::SEE_OTHER);
    assert_ne!(new.location(), "/login/two-step");
    assert!(
        audit::list(&f.state.db, Some(alice.id), None, 50)
            .await
            .unwrap()
            .iter()
            .any(|entry| entry.kind == "password.reset"
                && entry.client_ip.as_deref() == Some("192.0.2.7"))
    );
}

#[tokio::test]
async fn nothing_tells_which_accounts_exist_or_have_an_address() {
    let (f, mailer) = with_mail().await;
    let alice = user(&f, "alice").await;
    bind_directly(&f, alice.id, "alice@example.com").await;
    add_user(&f, "bob", "bob password").await;
    let mut browser = Browser::new(&f.state);

    let with_address = forgot(&mut browser, "alice").await;
    let without_address = forgot(&mut browser, "bob").await;
    let unknown = forgot(&mut browser, "nobody@example.com").await;
    for (answer, login) in [(&without_address, "bob"), (&unknown, "nobody@example.com")] {
        assert_eq!(answer.status, with_address.status);
        assert_eq!(
            normalized(&answer.text(), login),
            normalized(&with_address.text(), "alice"),
            "{login}"
        );
    }
    // Only alice's address got mail.
    let sent = settled(&mailer).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].to, "alice@example.com");

    // A second request within a minute sends nothing more, and says the same.
    let again = forgot(&mut browser, "alice").await;
    assert_eq!(
        normalized(&again.text(), "alice"),
        normalized(&with_address.text(), "alice")
    );
    assert_eq!(settled(&mailer).await.len(), 1);
}

#[tokio::test]
async fn a_reset_leaves_two_step_verification_on() {
    let (f, mailer) = with_mail().await;
    let mut owner = Browser::new(&f.state);
    let csrf = owner.sign_in().await;
    let (secret, _, step) = enrol(&mut owner, &csrf).await;
    let alice = user(&f, "alice").await;
    bind_directly(&f, alice.id, "alice@example.com").await;

    // Someone with the old password waits at the second step.
    let mut other = Browser::new(&f.state);
    assert_eq!(
        password_step(&mut other).await.location(),
        "/login/two-step"
    );
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 1);

    let mut browser = Browser::new(&f.state);
    forgot(&mut browser, "alice").await;
    let code = mailer.wait_for(1).await[0].code();
    let done = reset(&mut browser, "alice", &code, "a new password").await;
    assert_eq!(done.location(), "/login?done=password-reset");
    assert_eq!(f.state.web.pending_sign_ins(alice.id), 0);
    assert_eq!(
        other.get("/login/two-step").await.status,
        StatusCode::NOT_FOUND
    );

    // The new password still needs the second step.
    let form = browser.get("/login").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    let signed = browser
        .post(
            "/login",
            &[
                ("csrf", &csrf),
                ("user", "alice"),
                ("password", "a new password"),
            ],
        )
        .await;
    assert_eq!(signed.location(), "/login/two-step");
    let page = browser.get("/login/two-step").await;
    let csrf = page.field("name=\"csrf\" value=\"");
    let code = super::step_code(&secret, step + 1);
    let through = browser
        .post("/login/two-step", &[("csrf", &csrf), ("code", &code)])
        .await;
    assert_eq!(through.status, StatusCode::SEE_OTHER, "{}", through.text());
    assert!(
        gono_server_core::two_factor::is_enrolled(&f.state.db, alice.id)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn disabled_accounts_cannot_reset() {
    let (f, mailer) = with_mail().await;
    let alice = user(&f, "alice").await;
    bind_directly(&f, alice.id, "alice@example.com").await;
    let mut browser = Browser::new(&f.state);
    forgot(&mut browser, "alice").await;
    let code = mailer.wait_for(1).await[0].code();
    users::set_enabled(&f.state.db, &alice.username, false)
        .await
        .unwrap();
    let refused = reset(&mut browser, "alice", &code, "a new password").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(refused.text().contains(t().reset_wrong));
    let (_, hash) = users::credentials(&f.state.db, &alice.username)
        .await
        .unwrap()
        .unwrap();
    assert!(
        password::verify(
            &SecretString::from(ALICE_PASSWORD.to_owned()),
            hash.as_deref().unwrap()
        )
        .unwrap()
    );

    // A disabled account gets no code either, and the page says the same as ever.
    let answer = forgot(&mut browser, "alice").await;
    assert_eq!(answer.status, StatusCode::OK);
    assert!(answer.text().contains(t().forgot_sent));
    assert_eq!(settled(&mailer).await.len(), 1);
}

#[tokio::test]
async fn requests_for_codes_are_limited_per_client() {
    let (f, mailer) = with_mail().await;
    let mut browser = Browser::new(&f.state);
    let form = browser.get("/login/forgot").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    let burst = crate::ratelimit::BURST;
    for _ in 0..burst {
        let answer = browser
            .post("/login/forgot", &[("csrf", &csrf), ("login", "nobody")])
            .await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    let limited = browser
        .post("/login/forgot", &[("csrf", &csrf), ("login", "alice")])
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!limited.header("retry-after").is_empty());
    assert!(settled(&mailer).await.is_empty());
    // Forms from other sites are refused before anything is counted.
    let mut other = Browser::new(&f.state);
    let foreign = other
        .send(
            "POST",
            "/login/forgot",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "https://evil.example"),
            ],
            Body::from("login=alice"),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_code_that_cannot_be_mailed_is_reported_and_ended() {
    let (f, mailer) = with_mail().await;
    let alice = user(&f, "alice").await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    mailer.fail(true);
    let failed = browser
        .post(
            "/account/email",
            &[
                ("csrf", &csrf),
                ("email", "alice@example.com"),
                ("password", ALICE_PASSWORD),
            ],
        )
        .await;
    assert_eq!(failed.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        failed.text().contains(t().err_email_send),
        "{}",
        failed.text()
    );
    // No code waits for an address that got none.
    assert_eq!(
        email::pending(&f.state.db, alice.id, Purpose::Bind, db::unix_now())
            .await
            .unwrap(),
        None
    );
    assert!(!failed.text().contains("action=\"/account/email/confirm\""));
}

#[tokio::test]
async fn a_reset_code_works_only_in_the_browser_that_asked_for_it() {
    let (f, mailer) = with_mail().await;
    let alice = user(&f, "alice").await;
    bind_directly(&f, alice.id, "alice@example.com").await;
    let mut owner = Browser::new(&f.state);

    // A browser that asked for no code is told so, with a way to ask.
    let blank = owner.get("/login/reset").await.text();
    assert!(blank.contains(t().reset_no_request), "{blank}");
    assert!(blank.contains("href=\"/login/forgot\""), "{blank}");

    let answer = forgot(&mut owner, "alice").await;
    assert_eq!(answer.status, StatusCode::OK);
    let set = reset_cookie(&answer);
    for attribute in [
        "; Path=/;",
        "; HttpOnly",
        "; SameSite=Strict",
        "; Secure",
        &format!("; Max-Age={}", email::CODE_TTL_SECS + 60),
    ] {
        assert!(set.contains(attribute), "{attribute} in {set}");
    }
    let value = owner.cookies[RESET_COOKIE].clone();
    assert!(
        value.len() >= 22 && value.bytes().all(|b| b.is_ascii_alphanumeric()),
        "{value}"
    );
    assert!(!answer.text().contains(t().reset_no_request));
    let form = owner.get("/login/reset").await.text();
    assert!(!form.contains(t().reset_no_request), "{form}");
    let mail = mailer.wait_for(1).await.remove(0);
    assert!(mail.text.contains("browser window"), "{}", mail.text);
    let code = mail.code();

    // Asking again within a minute keeps the browser's value, and so its code.
    let again = forgot(&mut owner, "alice").await;
    assert_eq!(owner.cookies[RESET_COOKIE], value);
    assert!(reset_cookie(&again).starts_with(&format!("{RESET_COOKIE}={value};")));

    // The code in another browser without a reset cookie: refused, and told why it may be.
    let mut elsewhere = Browser::at(&f.state, IpAddr::from([198, 51, 100, 9]));
    let refused = reset(&mut elsewhere, "alice", &code, "a new password").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let text = refused.text();
    assert!(text.contains(t().reset_wrong), "{text}");
    assert!(text.contains(t().reset_no_request), "{text}");
    // A stranger with a reset cookie of its own, who asked for the account's code too: refused
    // (the refusal names another browser as a cause), and the owner's code lives on.
    forgot(&mut elsewhere, "alice").await;
    assert_ne!(elsewhere.cookies[RESET_COOKIE], value);
    let theirs = mailer.wait_for(2).await.remove(1).code();
    if theirs != code {
        for _ in 0..email::MAX_ATTEMPTS {
            let refused = reset(&mut elsewhere, "alice", &code, "a new password").await;
            assert_eq!(refused.status, StatusCode::FORBIDDEN);
            let text = refused.text();
            assert!(text.contains(t().reset_wrong), "{text}");
            assert!(!text.contains(t().reset_no_request), "{text}");
        }
    }
    // A browser with a forged value has no code either.
    let mut forged = Browser::at(&f.state, IpAddr::from([203, 0, 113, 5]));
    forged
        .cookies
        .insert(RESET_COOKIE.to_owned(), "A".repeat(value.len()));
    assert_eq!(
        reset(&mut forged, "alice", &code, "a new password")
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    // In the browser that asked, the code works, and the cookie goes with the reset.
    let done = reset(&mut owner, "alice", &code, "a new password").await;
    assert_eq!(
        done.location(),
        "/login?done=password-reset",
        "{}",
        done.text()
    );
    let removal = reset_cookie(&done);
    assert!(
        removal.starts_with(&format!("{RESET_COOKIE}=;")) && removal.contains("Max-Age=0"),
        "{removal}"
    );
    assert!(!owner.cookies.contains_key(RESET_COOKIE));
    let after = owner.get("/login/reset").await.text();
    assert!(after.contains(t().reset_no_request), "{after}");
    // The stranger's code ended with the reset as well.
    let ended = reset(&mut elsewhere, "alice", &theirs, "a third password").await;
    assert_eq!(ended.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_stranger_neither_ends_the_owners_code_nor_keeps_one_from_coming() {
    let (f, mailer) = with_mail().await;
    let alice = user(&f, "alice").await;
    bind_directly(&f, alice.id, "alice@example.com").await;
    // A stranger who knows the username asks for codes from networks of its own (one a
    // minute each), until the account's daily total is nearly used up.
    let stranger = |index: u8| Browser::at(&f.state, IpAddr::from([10, 0, index, 1]));
    let total = usize::try_from(RESET_SENDS_PER_DAY).unwrap();
    for index in 0..total - 2 {
        let mut browser = stranger(u8::try_from(index).unwrap());
        forgot(&mut browser, "alice").await;
        mailer.wait_for(index + 1).await;
    }
    // The owner still gets a code.
    let mut owner = Browser::new(&f.state);
    forgot(&mut owner, "alice").await;
    let code = mailer.wait_for(total - 1).await.remove(total - 2).code();
    // A stranger's request after it does not end it.
    forgot(&mut stranger(200), "alice").await;
    mailer.wait_for(total).await;
    // Beyond the account's total nobody gets a code, which bounds the mails of the address.
    forgot(&mut stranger(201), "alice").await;
    let mut neighbour = Browser::at(&f.state, IpAddr::from([198, 51, 100, 1]));
    forgot(&mut neighbour, "alice").await;
    assert_eq!(settled(&mailer).await.len(), total);

    let done = reset(&mut owner, "alice", &code, "a new password").await;
    assert_eq!(
        done.location(),
        "/login?done=password-reset",
        "{}",
        done.text()
    );
}
