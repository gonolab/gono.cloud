//! A phone app's WeChat login while it registers as a device: `POST /gono/v1/login/wechat`
//! (`docs/connect-protocol.md`, 4.6).
//!
//! 1. The app starts a registration (`POST /gono/v1/login`, protocol 4.1). The answer lists the
//!    AppIDs of `[[wechat.mobile_apps]]` under `wechat.apps`; an app whose AppID is among them
//!    offers 微信登录.
//! 2. The app asks WeChat for a code (OpenSDK `SendAuth`, scope `snsapi_userinfo`) and sends
//!    `{token, app_id, code}`: the poll token of its registration, its AppID and the code.
//! 3. The server exchanges the code with the app's own AppSecret, which gives the openid and the
//!    unionid. It finds the account by the app's identity, or else by the unionid of the
//!    account's WeChat identities in the mini program or another app, and then binds the app's
//!    identity to it ([`identities::sign_in_by_unionid`]). A WeChat bound to no account gets
//!    `{"account": null}` and nothing changes: the app goes on another way.
//! 4. The account must pass what the consent page checks for a device (protocol 4.2): enabled,
//!    no deletion pending, direct connections on, two-step verification when the server requires
//!    it, room for another device. Then the registration is granted to it, as the consent page
//!    grants it, and the app polls and proves its key (4.3).
//!
//! The code reaches the server only with the poll token of a live registration, and WeChat gives
//! codes of an AppID only to the app registered with it. Refusals take a token of the client's
//! bucket, as the mini program's calls do ([`WeChat::charge`]); the registration stays live, so
//! the user can fix the cause and try again until it expires.

use std::net::{IpAddr, SocketAddr};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use gono_server_core::{
    db, devices,
    identities::{self, Claims, SignedIn},
    login_flows,
    services::Service,
    two_factor,
    users::User,
};
use serde::Deserialize;

use super::{
    WECHAT_RETRY_AFTER, WeChat, api::ApiError, bad_request, deletion_pending, error, is_code, json,
    parse, rate_limited, unavailable,
};
use crate::{app::AppState, client_ip::client_ip};

/// The longest poll token accepted (protocol 4.1's are 64 characters).
const MAX_TOKEN_CHARS: usize = 128;

#[derive(Deserialize)]
struct LoginRequest {
    /// The poll token of the registration.
    token: String,
    /// The app's AppID.
    app_id: String,
    /// The code of WeChat's login.
    code: String,
}

/// `POST /gono/v1/login/wechat`. `404 not_found` unless the mini program and remote
/// connectivity are on and `[[wechat.mobile_apps]]` lists an app.
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(wechat) = state
        .wechat
        .clone()
        .filter(|wechat| !wechat.mobile_apps.is_empty())
    else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    if state.connect.is_none() {
        return error(StatusCode::NOT_FOUND, "not_found");
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Err(response) = wechat.admit(client) {
        return *response;
    }
    let response = grant(&state, &wechat, client, body).await;
    wechat.charge(client, response)
}

/// Whether `token` can be a poll token: 1 to [`MAX_TOKEN_CHARS`] visible ASCII characters.
fn is_poll_token(token: &str) -> bool {
    (1..=MAX_TOKEN_CHARS).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The answer of `login/wechat` to an admitted `client`.
async fn grant(
    state: &AppState,
    wechat: &WeChat,
    client: IpAddr,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request: LoginRequest = match parse(body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if !is_poll_token(&request.token)
        || !is_code(&request.code)
        || !gono_server_core::wechat::is_app_id(&request.app_id)
    {
        return bad_request();
    }
    let Some(api) = wechat.mobile_app(&request.app_id) else {
        return error(StatusCode::FORBIDDEN, "not_permitted");
    };
    // The registration first, so that a code is not spent on a flow that ended.
    let now = db::unix_now();
    let flow = match login_flows::find_device(&state.db, &request.token, now).await {
        Ok(Some(flow)) if flow.granted_user_id.is_none() => flow,
        Ok(_) => return error(StatusCode::NOT_FOUND, "not_found"),
        Err(err) => {
            tracing::error!(error = %err, "cannot read a device registration");
            return unavailable();
        }
    };
    let login = match api.code_to_session(&request.code).await {
        Ok(login) => login,
        Err(ApiError::InvalidCode) => return error(StatusCode::BAD_REQUEST, "code_invalid"),
        Err(ApiError::RiskyUser) => return error(StatusCode::FORBIDDEN, "risky_user"),
        Err(ApiError::RateLimited) => {
            tracing::warn!(%client, "WeChat's rate limit refused an app's WeChat login");
            return rate_limited(WECHAT_RETRY_AFTER);
        }
        Err(ApiError::Failed(why)) => {
            tracing::warn!(%client, app_id = request.app_id, error = %why, "cannot exchange the code of an app's WeChat login");
            return unavailable();
        }
    };
    if login.unionid.is_none() {
        // The app's Open Platform account gives every user a unionid; without one the setup is
        // incomplete, and binding by the openid alone across realms is never done.
        tracing::warn!(
            %client,
            app_id = request.app_id,
            "WeChat reported no unionid for an app's WeChat login: check the app on the Open \
             Platform"
        );
        return unavailable();
    }
    let claims = Claims::wechat(&request.app_id, &login.openid, login.unionid.as_deref());
    let mut realms = vec![wechat.app_id()];
    realms.extend(wechat.mobile_app_ids());
    let signed =
        identities::sign_in_by_unionid(&state.db, &claims, &realms, Some(client), now).await;
    let user = match signed {
        Ok((SignedIn::Account(user), bound)) => {
            if bound {
                tracing::info!(%client, user = %user.username, app_id = request.app_id, "an app's WeChat identity bound by its unionid");
            }
            user
        }
        Ok((SignedIn::Unbound, _)) => {
            return json(StatusCode::OK, &serde_json::json!({ "account": null }));
        }
        Ok((SignedIn::Disabled, _)) => return error(StatusCode::FORBIDDEN, "account_disabled"),
        Ok((SignedIn::DeletionPending { until, .. }, _)) => return deletion_pending(until),
        Err(err) => {
            tracing::error!(error = %err, "cannot sign an app's WeChat login in");
            return unavailable();
        }
    };
    if let Some(refusal) = device_refusal(state, &user).await {
        return refusal;
    }
    match login_flows::grant(&state.db, flow.id, user.id, Some(client), now).await {
        Ok(true) => {
            tracing::info!(
                %client,
                user = %user.username,
                app_id = request.app_id,
                client_name = flow.client_name,
                "device registration granted by an app's WeChat login"
            );
            json(
                StatusCode::OK,
                &serde_json::json!({
                    "account": {
                        "username": user.username.as_str(),
                        "display_name": user.display_name,
                    }
                }),
            )
        }
        // Granted or ended meanwhile.
        Ok(false) => error(StatusCode::NOT_FOUND, "not_found"),
        Err(err) => {
            tracing::error!(error = %err, "cannot grant a device registration");
            unavailable()
        }
    }
}

/// Why `user` may not register a device, as the consent page refuses it (protocol 4.2): direct
/// connections off (`service_not_enabled`), no two-step verification while the server requires
/// it (`two_factor_required`), or the most devices already (`too_many_devices`).
async fn device_refusal(state: &AppState, user: &User) -> Option<Response> {
    if !user.services.has(Service::Direct) {
        return Some(error(StatusCode::FORBIDDEN, "service_not_enabled"));
    }
    let checked = async {
        let two_factor_ok = !state.remote_access_needs_two_factor()
            || two_factor::is_enrolled(&state.db, user.id).await?;
        let devices = devices::count_active(&state.db, user.id).await?;
        Ok::<_, gono_server_core::Error>((two_factor_ok, devices))
    }
    .await;
    match checked {
        Ok((false, _)) => Some(error(StatusCode::FORBIDDEN, "two_factor_required")),
        Ok((true, count)) if count >= devices::MAX_DEVICES_PER_ACCOUNT => {
            Some(error(StatusCode::CONFLICT, "too_many_devices"))
        }
        Ok(_) => None,
        Err(err) => {
            tracing::error!(error = %err, "cannot check a device registration");
            Some(unavailable())
        }
    }
}
