//! The WeChat mini program's API (`/gono/v1/wechat/`, `docs/wechat-miniprogram.md`).
//!
//! The suite cannot answer for WeChat: every call that signs in exchanges a `wx.login()` code
//! with WeChat's `jscode2session`. These tests therefore send only requests that the server
//! refuses before it asks WeChat (the platform and scene rules, the shapes of tokens and
//! tickets, tokens that do not exist), and check that it refuses them with the documented code.
//! What happens after WeChat answers is covered by the server's own tests with a fake WeChat.
//!
//! They need `GONO_ACCEPT_WECHAT=1` and a server with `[wechat]` enabled; `run-new.sh` sets one
//! up with a stand-in AppID. Each refused `session` or `bind` takes a token of the client
//! address's bucket (20, one back every 10 seconds), so the tests send few of them.

use gono_acceptance::{Ctx, Resp, dav::send, skip};
use serde_json::{Value, json};

/// The context, or `None` (after a skip notice) without `GONO_ACCEPT_WECHAT=1`.
fn wechat_ctx() -> Option<Ctx> {
    let ctx = Ctx::bare()?;
    if std::env::var("GONO_ACCEPT_WECHAT").ok().as_deref() != Some("1") {
        skip("GONO_ACCEPT_WECHAT is not 1; the WeChat mini program tests are skipped");
        return None;
    }
    Some(ctx)
}

/// `n` random characters of `[A-Za-z0-9]`: the shape of a ticket (22) or a token (43).
fn random_token(n: usize) -> String {
    let mut token = String::new();
    while token.len() < n {
        token.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    token.truncate(n);
    token
}

/// `POST /gono/v1/wechat/<call>` with the JSON `body`, as `wx.request` sends it.
async fn post(ctx: &Ctx, call: &str, body: &Value) -> Resp {
    send(
        &ctx.http,
        ctx.http
            .post(ctx.url(&format!("/gono/v1/wechat/{call}")))
            .header("Content-Type", "application/json")
            .body(body.to_string()),
    )
    .await
}

/// Asserts that `response` is the error `code` with `status`, in the API's JSON form.
#[track_caller]
fn assert_error(response: &Resp, status: u16, code: &str) {
    assert_eq!(
        response.code(),
        status,
        "expected {status} {code}\n{}",
        response.describe()
    );
    assert_eq!(
        response.json()["error"],
        code,
        "expected {status} {code}\n{}",
        response.describe()
    );
    assert_eq!(
        response.header("cache-control").as_deref(),
        Some("no-store"),
        "{}",
        response.describe()
    );
}

#[tokio::test]
async fn without_a_session_the_account_is_not_read() {
    let Some(ctx) = wechat_ctx() else { return };
    let response = send(&ctx.http, ctx.http.get(ctx.url("/gono/v1/wechat/account"))).await;
    assert_error(&response, 401, "not_signed_in");
    assert_eq!(
        response.header("www-authenticate").as_deref(),
        Some("Bearer realm=\"gono\""),
        "{}",
        response.describe()
    );
}

/// WeChat on a desktop or in the developer tools signs in to nothing and binds nothing,
/// whatever the scene: the platform is checked before WeChat is asked.
#[tokio::test]
async fn the_mini_program_must_run_on_a_phone() {
    let Some(ctx) = wechat_ctx() else { return };
    let session = post(
        &ctx,
        "session",
        &json!({ "code": "acceptance-code", "scene": 1001, "platform": "windows" }),
    )
    .await;
    assert_error(&session, 403, "desktop_client");
    let bind = post(
        &ctx,
        "bind",
        &json!({
            "signup_token": random_token(43),
            "ticket": random_token(22),
            "scene": 1011,
            "platform": "devtools",
        }),
    )
    .await;
    assert_error(&bind, 403, "desktop_client");
}

/// Binding needs the mini program to have been opened by scanning (scene 1011 or 1047): opened
/// from the chat list (1001) or from a code in an image (1012), a phone binds nothing. Signing
/// in (`session`) takes every scene, which this suite cannot see without WeChat.
#[tokio::test]
async fn binding_needs_a_scan() {
    let Some(ctx) = wechat_ctx() else { return };
    for scene in [1001, 1012] {
        let bind = post(
            &ctx,
            "bind",
            &json!({
                "signup_token": random_token(43),
                "ticket": random_token(22),
                "scene": scene,
                "platform": "ios",
            }),
        )
        .await;
        assert_error(&bind, 403, "wrong_scene");
    }
}
