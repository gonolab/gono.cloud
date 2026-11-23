# The WeChat mini program API

Gono Cloud lets the users of a WeChat mini program bind their WeChat to their Gono Cloud
account and then sign in to the mini program with it. This document is for the developers of
that mini program: the endpoints with their requests and answers, the error codes, the rule
for scenes and platforms, sessions, the QR links, and what a deployment needs. How the operator
turns it on is in [deployment.md](deployment.md#wechat), what the reverse proxy forwards in
[reverse-proxy.md](reverse-proxy.md#the-wechat-mini-program).

- The server serves one mini program, the AppID of `wechat.app_id`. Its openids are bound to
  accounts: an account has at most one WeChat of that AppID, and a WeChat belongs to one
  account at most.
- Binding starts on the account page of the server (Overview, "Ways to sign in"): the user
  confirms with the web login password, and the page shows a QR code that the user scans with
  WeChat on the phone. It opens the mini program, which signs in and binds. Unbinding is done on
  the same page, in the admin UI, or with `gono-cloud user unlink`.
- A mini program session reads the account's name and services, nothing else: no files, no
  WebDAV, no S3, no page of the server.
- Without `[wechat]` every path below `/gono/v1/wechat/` answers
  `404 {"error":"not_found"}`, and the account page says that the server does not offer a mini
  program.

## The flow

1. **The QR code.** On the account page the user asks for a QR code, confirming with the web
   login password. It carries the link `{qr_url_prefix}bind/<ticket>` (for example
   `https://cloud.example.com/q/bind/Xq3MZb7RkT0aVd9LpW2sYc`), is valid for 10 minutes and once,
   and a new one ends the previous one. The page shows when it expires.
2. **Scanning.** The user scans it with WeChat's Scan on the phone. The rule
   "扫普通链接二维码打开小程序" of the mini program's console (see [Deployment](#deployment))
   opens the mini program with the link, URL-encoded, in the `q` parameter of the page's
   `onLoad(query)`: `decodeURIComponent(query.q)`. The mini program takes the ticket from it
   ([The links](#the-links)).
3. **Signing in.** The mini program calls `wx.login()` and sends the code to
   `POST /gono/v1/wechat/session` with the scene and the platform. The server asks WeChat whose
   code it is (`jscode2session`):
   - the WeChat is bound to an account: the answer is a session. The mini program was opened to
     bind, so it tells the user that this WeChat is bound to `account.username` already; to
     bind it to another account, the user unbinds it on that account's page first. The ticket
     stays unused.
   - the WeChat is bound to no account: the answer is a signup token, valid for 10 minutes.
4. **Binding.** `POST /gono/v1/wechat/bind` with the signup token and the ticket binds the
   WeChat to the ticket's account and answers with a session. The ticket is used up.
5. **Using the session.** The mini program keeps the session (`wx.setStorageSync`) and sends it
   as `Authorization: Bearer <session>` to `GET /gono/v1/wechat/account`; `POST
   /gono/v1/wechat/logout` ends it.

The page that made the QR code shows "Bound since ..." once the user reloads it.

## Conventions

- **Base URL.** The endpoints are below `/gono/v1/wechat/` on the host the mini program is
  configured for: `server.base_url`'s host, or another host name that the operator forwards to
  the server ([Deployment](#deployment)). HTTPS only.
- **Requests** with a body send JSON (`Content-Type: application/json`, what `wx.request`
  sends by default) of at most 4096 bytes. Unknown fields are ignored. A body that is not JSON,
  lacks a field, has a field of the wrong type or is larger answers `bad_request`.
- **Answers** are JSON (`application/json; charset=utf-8`, `Cache-Control: no-store`), except
  the `204` of `logout`. An error is `{"error": "<code>"}` with the status of
  [Errors](#errors). `wx.request` calls `success` for every status: read `statusCode` and
  `data.error`.
- **Times** (`expires_at`) are UNIX seconds.
- **Tokens.** Sessions and signup tokens are 43 characters of `[A-Za-z0-9]`, tickets 22. They
  are secrets: keep them out of logs, analytics, URLs and shared pages. Only their SHA-256
  digests are stored on the server; it never logs them, nor codes or openids.
- **Compatibility.** Within `/gono/v1/` answers may gain fields and new error codes may appear.
  Ignore fields you do not know, and treat an unknown error code like `unavailable` when its
  status is `5xx`, as a refusal otherwise.

## Scenes and platforms

`session` and `bind` take the scene and the platform of the mini program and refuse it unless
it was opened by scanning a code with WeChat on a phone:

| Field | Accepted | Refused with |
|---|---|---|
| `platform`, from `wx.getDeviceInfo().platform` (`wx.getSystemInfoSync().platform` before base library 2.20.1) | `ios`, `android`, `ohos` | `desktop_client`: `windows`, `mac`, `ohos_pc`, `devtools` and every other value |
| `scene`, from `wx.getEnterOptionsSync().scene` | `1011` (a QR code scanned with Scan), `1047` (a mini program code scanned with Scan) | `wrong_scene`: `1012` and `1048` (a code recognized in an image by a long press), `1013` and `1049` (a code picked from the album), `1007` and `1008` (a shared card in a chat), `1001` (the chat list), ... and every other value |

The platform is checked first: a desktop client gets `desktop_client` whatever its scene.

Binding gives a WeChat user the account in the mini program, so a QR code or a link that was
forwarded, photographed or opened on a desktop must not bind: someone who receives a screenshot
of the code in a chat would otherwise get the account. Scanning with the phone's camera is what
the person in front of the account page does.

**This is a safeguard, not proof.** The scene and the platform come from the mini program;
the server cannot check them, and a modified client can send any value. They stop mistakes and
lures, not a determined attacker: the ticket (10 minutes, once, shown only to whoever confirmed
being the account's user, with its password) is what protects the account.

Use `wx.getEnterOptionsSync()`, not `wx.getLaunchOptionsSync()`: when the mini program was in
the background and is opened again by scanning, only the former reports the scan. The account
page shows an ordinary QR code, which scans as `1011`; `1047` is accepted for mini program codes,
which the server does not make today. WeChat's developer tools report `devtools`, which is
refused: try binding on a phone (preview or a development version).

`account` and `logout` have no such rule: a mini program opened from the chat list keeps using
the session it holds.

## Endpoints

### `POST /gono/v1/wechat/session`

Signs the mini program in with a code of `wx.login()`. No authentication.

```json
{ "code": "0e3Kq0Ga1ZxPlq0LrQIa1HxGWQ0Kq0Gq", "scene": 1011, "platform": "ios" }
```

- `code`: the code of `wx.login()`, 1 to 256 visible ASCII characters. A code works once.
- `scene`, `platform`: see [Scenes and platforms](#scenes-and-platforms).

`200`, when the WeChat is bound to an enabled account:

```json
{
  "session": "Vb0YpTtq3mJw1f8RkzQe2cXnL5uA9sHdG7oKiE4rM6N",
  "expires_at": 1768000000,
  "account": {
    "username": "alice",
    "display_name": "Alice Example",
    "services": { "files": true, "webdav": true, "s3": false, "direct": true, "relay": false }
  }
}
```

`200`, when the WeChat is bound to no account:

```json
{ "signup_token": "hP2sWm9QbX4tLc7yRk1vZe8nJd3oFa6uGi0TqY5rBwE", "expires_at": 1765408600 }
```

- The signup token is valid for 10 minutes and names the WeChat that signed in. A new one for
  the same WeChat ends the earlier one; binding uses it up.
- Errors: `bad_request`, `desktop_client`, `wrong_scene`, `code_invalid` (WeChat's 40029 or
  40163: invalid, expired or used; call `wx.login()` again), `risky_user` (WeChat's 40226),
  `account_disabled` (the WeChat's account is disabled), `rate_limited`, `unavailable`.

### `POST /gono/v1/wechat/bind`

Binds the WeChat of a signup token to the account of a ticket. No authentication.

```json
{
  "signup_token": "hP2sWm9QbX4tLc7yRk1vZe8nJd3oFa6uGi0TqY5rBwE",
  "ticket": "Xq3MZb7RkT0aVd9LpW2sYc",
  "scene": 1011,
  "platform": "ios"
}
```

`200`: as a bound `session`, `{"session", "expires_at", "account"}`. The binding is recorded
in the account's audit log (`identity.bound` with `how: "mini_program"` and the AppID, never the
openid).

The signup token is checked first, then the ticket:

| Error | When | Afterwards |
|---|---|---|
| `session_expired` | The signup token is unknown, expired, used, of another AppID, or replaced by a newer one. | Sign in again (`session` with a new code); the ticket is untouched. |
| `ticket_expired` | The ticket is unknown, expired, used, or replaced by a newer QR code. | Ask the user for a new QR code; the signup token stays valid. |
| `account_disabled` | The ticket's account is disabled. | Both stay. |
| `account_exists` | The WeChat was bound to another account in the meantime. | The signup token has ended; the ticket stays valid for another WeChat. |
| `bind_failed` | The ticket's account got another WeChat of this AppID in the meantime. | The ticket has ended; the signup token stays valid. |

Also `bad_request` (a malformed token or ticket among them), `desktop_client`, `wrong_scene`,
`rate_limited` and `unavailable`.

### `GET /gono/v1/wechat/account`

The session's account. `Authorization: Bearer <session>`.

`200`:

```json
{
  "username": "alice",
  "display_name": "Alice Example",
  "services": { "files": true, "webdav": true, "s3": false, "direct": true, "relay": false }
}
```

- `username` is the login name; `display_name` what clients show. `services` are the
  account's switches (`files`: the web file UI, `webdav`: WebDAV and the Nextcloud clients,
  `s3`: the S3 API, `direct`: remote access for devices, `relay`: the relay at the full rate),
  whether or not this server offers each.
- Each use extends the session ([Sessions](#sessions)).
- Errors: `not_signed_in` (no `Authorization` header, not a bearer token, or no such session:
  logged out, ended by unbinding, by disabling or deleting the account, or by a newer session),
  `session_expired` (not used for 30 days), `account_disabled`, `rate_limited`, `unavailable`.
  Both `401` answers carry `WWW-Authenticate: Bearer realm="gono"`.

### `POST /gono/v1/wechat/logout`

Ends the session. `Authorization: Bearer <session>`; a body is ignored (at most 4096 bytes).

`204 No Content`, also for a session that expired. Errors: `not_signed_in` (no such session),
`rate_limited`, `unavailable`. Forget the session in any case.

### Accounts made in the mini program: `signup`, `PATCH account`, `account/delete`, `account/restore`

With `wechat.allow_signup` (off by default), `session` answers a WeChat bound to no account with
`"signup": true` beside its signup token, and the mini program may offer 新建账号:

- `POST /gono/v1/wechat/signup {"signup_token", "terms_version", "scene", "platform"}` creates the
  account: username `wx` and 8 random lower-case letters and digits, display name 新用户, no web
  login password, no service (an administrator turns them on), and binds the WeChat to it. The
  answer is a bound `session`'s, `{"session", "expires_at", "account"}`. `terms_version` (at most
  64 characters) names the terms the user accepted, and is required when the server has terms
  (`[sign_in] terms_url`). Errors: `signup_closed` (403) without `allow_signup`,
  `session_expired` (401) for a token that is gone, `account_exists` (409), `signup_limited`
  (429: 5 accounts a day per network, 200 for the server), and the scene and platform rules of
  `session`.
- `PATCH /gono/v1/wechat/account {"username"}` (Bearer) changes the username of an account made
  by a sign-up, until an app password or a device signed in to it (their statements name the
  account by its username), once a day: `200` with the account; `username_taken` (409),
  `username_locked` (409), `rate_limited` (429, `Retry-After` a day).
- `POST /gono/v1/wechat/account/delete {"code", "platform", "confirm"}` (Bearer, a fresh code of
  the session's WeChat, `confirm` the username) asks for the deletion of an account without a web
  login password: `204`. The account is disabled at once, its sessions end, and the server deletes
  it 7 days later. Until then `session` answers `409 {"error": "deletion_pending", "until"}`.
  `not_permitted` (403) for an account with a password or another WeChat's code.
- `POST /gono/v1/wechat/account/restore {"code", "platform"}` (no session: the code names the
  WeChat) undoes it within the 7 days and opens a session: `{"session", "expires_at",
  "account"}`; `not_pending` (409) when nothing waits.

### Signing in on the web: `scan`, `confirm`, `deny`, `flow`

With `wechat.web_sign_in`, the server's sign-in pages (`/login`, the Login Flow v2 page,
`/manage/login`) show a QR code of `{qr_url_prefix}<ticket>` ([The links](#the-links)) for the
browser that opened them, and the account page shows one to confirm it is the account's user.
The mini program's page that confirms web sign-ins takes it through these four calls; without
`web_sign_in` they answer `not_found`. No authentication: every call that acts carries a fresh
`wx.login()` code, which names the WeChat.

```mermaid
sequenceDiagram
    participant B as Browser
    participant GC as Gono Cloud
    participant MP as Mini program
    B->>GC: GET /login/wechat
    GC-->>B: QR {qr_url_prefix}<ticket>, 2 minutes, bound to this browser
    MP->>GC: POST scan {ticket, code, scene, platform}
    GC-->>MP: {kind, account, browser, expires_at}: locked to this WeChat
    MP->>GC: POST confirm {ticket, code, scene, platform}
    GC-->>MP: {enter_code: "482913", expires_at}
    Note over MP: The phone shows the digits; the user types them into the browser
    B->>GC: POST /login/wechat {code: "482913"}
    GC-->>B: signed in
    MP->>GC: GET flow?ticket= (every 2 s)
    GC-->>MP: {stage: "done"}
```

`POST /gono/v1/wechat/scan` takes `{"ticket", "code", "scene", "platform"}` and an optional
`"source": "scan_code"` for the in-app scanner (`wx.scanCode({onlyFromCamera: true})`), which
skips the scene test; the platform test stays. The scene and platform rules are `bind`'s. The
WeChat of the code locks the sign-in, and the answer says what to show:

```json
{
  "kind": "web_sign_in",
  "admin": false,
  "account": { "username": "alice", "display_name": "Alice Example" },
  "browser": { "name": "Chrome · Windows", "same_network": false },
  "expires_at": 1765408720
}
```

- `kind` is `web_sign_in` (a sign-in page; `admin: true` for the admin UI's, which admits admin
  accounts only) or `reauth` (the account page confirms it is its user, with the WeChat bound to
  it). `same_network` compares the phone's network with the browser's (the /24 of an IPv4
  address, the /64 of an IPv6 one). The page states it either way: the digits are always asked.
- A WeChat bound to no account gets `"account": null` and locks nothing: show how to bind it,
  and 新建账号 when `"signup": true`; after the sign-up, `scan` again.
- Refusals: `ticket_expired` (410: unknown, ended or 2 minutes passed; the browser shows a new
  one), `ticket_taken` (409: another WeChat scanned it first), `account_disabled` (403),
  `deletion_pending` (409, with `until`), `not_permitted` (403: a non-admin account on the admin
  UI, or another account's WeChat confirming an account), and the errors of `session`.

`POST /gono/v1/wechat/confirm` takes the same body with a fresh code of the WeChat that scanned:
`200 {"enter_code": "482913", "expires_at": <unix>}`. Show the 6 digits with "不要告诉任何人，只
输入到你自己正在登录的浏览器里"; they are valid for 2 minutes and 3 tries in the browser, and a new
`confirm` replaces them. Another WeChat gets `not_permitted`.

`POST /gono/v1/wechat/deny` (same body) cancels the sign-in for "不是我" and "取消这次登录": `204`.
The browser then says that the phone cancelled it and offers a new QR code.

`GET /gono/v1/wechat/flow?ticket=<ticket>` says where the sign-in is: `200 {"stage", "expires_at"}`
with `stage` `waiting`, `scanned`, `code`, `done` (the browser signed in), `denied`, `tries` (the
digits were entered wrong 3 times) or `expired`; `ticket_expired` for an unknown ticket. Poll it
every 2 seconds on the page of the digits.

The 6 digits are what makes this safe: a QR code forwarded from someone else's browser, or
relayed by a phishing page, signs in nothing unless the digits are typed into that browser. Only
digests of the ticket, of the browser's cookie and of the digits are stored. The calls that act
are limited like `bind`.

## Errors

| Code | Status | Meaning |
|---|---|---|
| `bad_request` | 400 | The body is not the JSON the endpoint takes, or a field has the wrong form. |
| `code_invalid` | 400 | WeChat refused the code: invalid, expired or used. |
| `not_signed_in` | 401 | No session, or one that does not exist (any more). |
| `session_expired` | 401 | The session was not used for 30 days; or, from `bind`, the signup token is gone. |
| `risky_user` | 403 | WeChat refuses this user as risky (its 40226). |
| `wrong_scene` | 403 | The mini program was not opened by scanning ([Scenes and platforms](#scenes-and-platforms)). |
| `desktop_client` | 403 | The mini program runs on a desktop or in the developer tools. |
| `account_disabled` | 403 | The account is disabled. |
| `not_found` | 404 | No such endpoint or method, or the server does not offer the mini program. |
| `not_permitted` | 403 | A web sign-in this WeChat may not confirm: of the admin UI for a non-admin account, of another account, or locked by another WeChat (`confirm`, `deny`). |
| `account_exists` | 409 | The WeChat is bound to another account. |
| `ticket_taken` | 409 | Another WeChat scanned the sign-in's QR code first. |
| `signup_closed` | 403 | The server lets no WeChat sign up (`allow_signup` is off). |
| `username_taken` | 409 | The username is in use or retired. |
| `username_locked` | 409 | The username can no longer change: an app password or a device uses it. |
| `not_pending` | 409 | `account/restore`: the account waits for no deletion. |
| `signup_limited` | 429 | Too many accounts were made today, from this network or on the server. |
| `deletion_pending` | 409 | The account waits for its deletion (`until`). |
| `bind_failed` | 409 | The account has another WeChat of this AppID. |
| `ticket_expired` | 410 | The QR code's ticket is expired, used or replaced. |
| `rate_limited` | 429 | Too many requests; `Retry-After` says how many seconds to wait. |
| `unavailable` | 503 | WeChat could not be reached or failed, or the server's database did; `Retry-After: 30`. |

**Rate limits.** Each client address (IPv6: each `/64`) has a bucket of 20 failures that
refills by one every 10 seconds, as the server's sign-in pages do. A `session` or `bind` that
does not succeed takes one, and while the bucket is empty both answer `rate_limited` without
doing anything. Successful ones cost nothing, so that many users behind one address (a
carrier's NAT) do not lock each other out. `account` and `logout` take one only for a bearer
token that is no session, and are refused only for those. When WeChat's own limit refuses the
server (its 45011), `session` answers `rate_limited` with `Retry-After: 60`.

## Sessions

- A session ends 30 days after its last use: `expires_at` of the answer that opened it is when
  it ends unless it is used, and every `account` moves the end to 30 days after that request
  (written at most once a minute).
- It ends at once when the mini program logs out, when the user unbinds the WeChat on the
  account page (every session of the account and AppID), when the account is disabled (enabling
  it again does not bring sessions back) or deleted.
- A WeChat has at most 5 sessions; a sixth ends the oldest.
- A session is bound to the AppID: if the operator changes `wechat.app_id`, the sessions and
  bindings of the old AppID no longer count.
- A session reads `account` and nothing else. It is not an app password: WebDAV, the
  Nextcloud endpoints, S3 and the pages answer it as if it were absent.

The server keeps the openid WeChat reports and the unionid when WeChat reports one. It never
stores the `session_key` of `jscode2session` and never sends it to the mini program: nothing
here decrypts data of the mini program.

## The links

Every QR link starts with `wechat.qr_url_prefix`, an `https://` URL ending in `/`, which is the
prefix of the rule in the mini program's console:

| Link | Use |
|---|---|
| `{qr_url_prefix}bind/<ticket>` | Binding, from the account page. |
| `{qr_url_prefix}<ticket>` | Signing in on the web, or confirming it is the account's user ([`scan`](#signing-in-on-the-web-scan-confirm-deny-flow)), with `wechat.web_sign_in`. |

Take the part after the prefix: `bind/` followed by 22 characters of `[A-Za-z0-9]` is a bind
ticket, 22 such characters alone a sign-in ticket. Tell the user that other links need a newer
version of the mini program.

The server answers every path below `/q/` with a page in English and Chinese that says to scan
the code with WeChat, for whoever opens a link in a browser; so the prefix's path is `/q/`, on
`server.base_url`'s host or on a host forwarded to the server. That page starts nothing and
uses no ticket.

## Deployment

What the operator and the mini program's developers set up together:

- **HTTPS** with a valid certificate on the host the mini program calls and on the host of
  `qr_url_prefix`.
- **The request domain.** The host the mini program sends its requests to is a "request合法域名"
  of the mini program's console (开发管理 → 开发设置 → 服务器域名): a mini program reaches only
  the host names listed there.
- **ICP filing (备案).** WeChat accepts request domains and QR link rules only for domain names
  with an ICP filing. That is why `qr_url_prefix` may have another host than `server.base_url`:
  an ICP-filed host name that the operator forwards to the server
  ([reverse-proxy.md](reverse-proxy.md#the-wechat-mini-program)).
- **The QR link rule** "扫普通链接二维码打开小程序" (开发管理 → 开发设置): its prefix is exactly
  `qr_url_prefix`, and it names the page of the mini program that binds. Before it accepts the
  rule, the console checks that the host serves its verification file at the root,
  `https://<host of qr_url_prefix>/<file name>`; the server does that for the file of
  `wechat.verify_file`, with its exact content.
- **The server's outgoing connection.** The server exchanges codes with
  `https://api.weixin.qq.com` (port 443), with the AppSecret of `wechat.secret_file`. The
  AppSecret goes to WeChat only; the mini program never needs it.
