# Gono Connect: Control Protocol

- Status: draft for review. This is Phase 0 of `plan/remote-connect-iroh.md`. Part 2b implements
  it: the server side is in `crates/server/connect`, the device side in `crates/client/connect`
  (`gono-connect`), and the wire types are in `crates/protocol`.
  Two-step verification (13) is part 2c, in `crates/server/core/src/two_factor.rs` and the
  server's pages.
- Protocol version: 1.
- Reviewers: gono-cloud, and Input Show NE.
- Companion document: [connect-threat-model.md](connect-threat-model.md). It explains why the
  rules below are needed, and its requirements (S1–S14, C1–C16) refer back to sections of this
  document.

This document specifies what gono-cloud does for devices that reach each other through iroh:
- registration;
- the device directory and presence;
- connection requests and address lookup;
- pairing that the account vouches for;
- revocation;
- relay access;
- the audit log;
- two-step verification on the account.

It does not cover:
- what devices say to each other once connected (Input Show's wire protocol over iroh);
- pairing on the LAN, and pairing in person by QR or invite code;
- iroh's own protocols.

---

## 1. Overview

### 1.1 Rules

1. **Trust between devices is decided on the devices.** Every device keeps its own trust list.
   The server only carries requests and signed statements between devices, and it cannot add a
   device to any trust list.
2. **The server may remove trust but never add it.** Revocation, which only removes trust, is
   the one thing devices take from the server on its word alone.
3. **Addresses are hints.** A device dials a peer by its key, and the TLS handshake fails on any
   other key. So a false address the server or the relay hands out can make a connection fail,
   but it cannot make a device talk to the wrong peer.
4. **Remote access needs two-step verification** on the account (13).
5. **LAN use does not depend on gono-cloud.** Input Show's LAN mode needs no account and sends
   nothing to the server, and none of this protocol applies to it.

### 1.2 Terms

| Term | Meaning |
|---|---|
| Device | One installation of a product (Input Show, later gono.md) with its own Ed25519 key |
| Endpoint ID | The device's Ed25519 public key: the device ID in Input Show and the `EndpointId` in iroh (plan D4) |
| Short ID | The first 8 bytes of the endpoint ID in upper-case hex, grouped in fours: `AB12-CD34-EF56-7890`. This is the form Input Show shows to people |
| Account | A gono-cloud user. Every device belongs to exactly one account |
| Directory | The server's list of the devices of each account (6) |
| Remote access available | The account is enabled and has two-step verification enrolled (13) |
| Trust list | A device's local list of the peers it accepts, each with how it was added (8.1) |
| Direct pairing | A trust-list entry added by the 6-digit comparison code, on the LAN or over a remote connection, or in person by QR or invite code |
| Vouched pairing | A trust-list entry added because a direct pairing approved it (8) |
| Statement | A JSON document signed with a device key and carried unchanged by the server (2.3) |

### 1.3 Components

```text
 device A ──HTTPS──▶ reverse proxy ──▶ gono-cloud ◀── HTTPS ── browser (consent, account page)
    │  ▲        (TLS ends here)          │  ├─ /gono/v1/login, /gono/v1/ws   (this document)
    │  │                                 │  ├─ directory, audit, two-step verification
    │  └── wss /gono/v1/ws ──────────────┘  └─ embedded iroh relay (relay host name, UDP 7842)
    │
    └──── iroh: direct, or through the relay; TLS 1.3 end to end ────▶ device B
```

---

## 2. Conventions

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

### 2.1 Encodings

| Value | Encoding |
|---|---|
| Endpoint ID | 64 lower-case hex digits. A server or device that receives any other form, upper case included, rejects it |
| Bytes (nonces, signatures, statements) | base64url without padding (RFC 4648, section 5) |
| Time | UNIX seconds (UTC) as a JSON integer |
| Server origin | `scheme://host[:port]`: lower-case host, no default port, no path, no trailing slash. It is gono-cloud's `server.base_url`, which never has a path |
| Relay URL | An iroh `RelayUrl` as a string, for example `https://relay.example.com/` |
| Direct address | `ip:port`, with IPv6 in brackets: `192.0.2.10:51820`, `[2001:db8::1]:51820` |
| Names | UTF-8, trimmed, 1–64 characters, no control characters |
| `product` | `[a-z0-9-]{1,32}`: `input-show`, later `gono-md`, … |
| `platform` | `[a-z0-9-]{1,32}`: `macos`, `windows`, `linux`, `harmonyos`, `ios`, `android`, … |
| Service | An ALPN as a string, for example `inputshow/1` |

### 2.2 JSON

- All bodies and WebSocket frames are UTF-8 JSON objects with snake_case field names.
- Receivers ignore unknown fields.
- Optional fields may be absent or `null`, and the two mean the same.
- A frame or body that a device sends over 64 KiB is refused; on the control channel, with
  the close code `1009` (5.4).
- Messages the server sends stay below 4 MiB, and devices refuse larger ones. The `welcome`
  keeps to that by sending part of the event backlog after it (5.6).

### 2.3 Signed statements

The server must carry some data unchanged between devices, or check that a device holds its
key. That data travels as a **statement**:

```json
{ "statement": "<base64url of the statement bytes>", "signature": "<base64url, 64 bytes>" }
```

- **The statement bytes** are a UTF-8 JSON object, serialized once by the signer. They must
  hold a `kind` field. They are carried as bytes so that nobody has to serialize JSON the same
  way twice.
- **The signature** is Ed25519 (RFC 8032) with the device's key over `context ‖ 0x00 ‖ statement
  bytes`, where `context` is the ASCII string of the kind:

  | `kind` | Context | Section |
  |---|---|---|
  | `login` | `gono-connect login v1` | 4.3 |
  | `hello` | `gono-connect hello v1` | 5.2 |
  | `pair-request` | `gono-connect pair-request v1` | 8.3 |
  | `pair-approval` | `gono-connect pair-approval v1` | 8.4 |

- **Verification:**
  1. Decode the bytes and parse them only to find the signer: the field the kind names
     (`endpoint_id` for `login` and `hello`, `requester.endpoint_id` for `pair-request`,
     `approver` for `pair-approval`). Nothing is acted on yet.
  2. Verify the signature over the context of that `kind` with `verify_strict` semantics
     (ed25519-dalek, which is what `iroh_base::PublicKey::verify` uses): non-canonical
     signatures and small-order keys are rejected.
  3. Then check the fields as the section of that kind says.
- **Limit:** statements are at most 16 KiB.
- **Domain separation.** The device key also signs TLS 1.3 handshakes and the iroh relay
  handshake.
  - Every context above starts with `gono-connect `, and every signed message is longer than
    32 bytes.
  - A TLS 1.3 `CertificateVerify` message starts with 64 spaces. The iroh relay handshake
    signs exactly 32 bytes: a BLAKE3-derived challenge, or a TLS exporter value.
  - So none of the three can be mistaken for another.
- **The server verifies too.** It verifies every statement before it stores or relays it, and
  refuses invalid ones (S5). Devices verify again on receipt and never rely on the server's
  check.

### 2.4 Versions and extensions

- **Paths.** HTTP paths start with `/gono/v1/`, and `version` in the discovery document is `1`.
- **Within version 1, changes are additions only.** New message types, new optional fields
  and new error codes. A field never changes meaning, and a released message never loses a
  field.
- **Features.** `hello` and `welcome` each list feature strings (`features`). A side uses an
  optional feature only when both lists name it. The features of version 1 are `pairing` and
  `session-reports`. The server sends a feature's events only to devices that negotiated it:
  `pair.requested` and `pair.closed` go to devices with `pairing`.
- **Breaking changes** get a new path (`/gono/v2/`), served next to v1 for at least the
  support period of the last release that spoke only v1.

---

## 3. Discovery

`GET /gono/v1/connect`. It needs no authentication, and devices fetch it from the server
origin the user entered.

```json
{
  "version": 1,
  "server": "https://cloud.example.com",
  "login": "https://cloud.example.com/gono/v1/login",
  "websocket": "wss://cloud.example.com/gono/v1/ws",
  "relay_url": "https://relay.example.com/",
  "two_factor_required": true
}
```

- **When it is served.** gono-cloud serves remote connectivity, this document included, only
  when the relay is enabled (`[relay] enabled`) and `server.base_url` is HTTPS or names a
  loopback host (for tests).
  - Otherwise the answer is `404`, and the device tells the user that this server does not
    offer remote access.
- **`server`** is the server origin that devices put into their statements.
- **`relay_url`** is the relay's `relay.public_url`. Devices configure their iroh endpoint
  with exactly this relay (`RelayMode::custom`) and no other (plan 3.5).
- **Capabilities.** The Nextcloud capabilities document carries the same object as
  `capabilities.gono_cloud.connect`, for clients that already read capabilities (gono.md).

---

## 4. Device registration

A device registers through a browser sign-in of the same kind as Login Flow v2:
- the same pages, the same consent step, and the same rule that every device gets its own app
  password;
- but its own start and poll endpoints, because it also proves that it holds its key.

### 4.1 Starting

`POST /gono/v1/login`. It needs no authentication, and it is limited per client address like
Login Flow v2 starts.

```json
{
  "endpoint_id": "3f6a…c210",
  "product": "input-show",
  "platform": "windows",
  "name": "Home PC",
  "version": "1.0.0"
}
```

`200`:

```json
{
  "login_url": "https://cloud.example.com/login/v2/flow/<login token>",
  "poll": { "endpoint": "https://cloud.example.com/gono/v1/login/poll", "token": "<poll token>" },
  "challenge": "<base64url, 32 random bytes>",
  "expires_at": 1763200000
}
```

- **The flow** lives 20 minutes and is used once, like a Login Flow v2 flow.
- **The login URL** is opaque. The device opens it in a browser, or shows it as a QR code so
  that the user can open it on another device; this is how a computer without a convenient
  browser signs in.
- **The short ID.** The device shows its own short ID while the flow runs.
- **Errors.**
  - `400` for a malformed body;
  - `404` when remote connectivity is off (3);
  - `429` with `Retry-After`;
  - `503` when too many flows are pending.

### 4.2 Consent page

The login URL leads to the usual sign-in page, which has the second step of 13.

The consent page for a device:
- names the product, the platform and the name the device reported;
- shows its short ID;
- says: "Continue only if you started this on that device and it shows this ID."
- states what the device gets: "reach your other devices remotely and be reached by them". It
  does not get file access (4.5).

Rules:
- **Two-step verification.** The page grants a device only to an account that has two-step
  verification enrolled. An account without it is first led through enrolment (13.2), and then
  comes back to the consent page.
- **Device limit.** The page refuses when the account already has 50 unrevoked devices (15).
- **No early answers.** Nothing on the page reveals whether the endpoint ID is registered
  anywhere. That is decided only when the flow completes (4.4), after the user has granted
  access.

### 4.3 Polling and proof

`POST /gono/v1/login/poll`:

```json
{
  "token": "<poll token>",
  "proof": { "statement": "…", "signature": "…" }
}
```

`proof.statement` is a `login` statement:

```json
{
  "kind": "login",
  "server": "https://cloud.example.com",
  "endpoint_id": "3f6a…c210",
  "challenge": "<the challenge from 4.1>"
}
```

**Answers:**

| Status | Body | Meaning |
|---|---|---|
| `202` | `{"status":"pending"}` | The user has not decided yet; poll again in 2–5 seconds |
| `200` | see below | Registered |
| `400` | `{"error":"bad_proof"}` | The proof is invalid. The flow stays usable until it expires |
| `404` | `{"error":"not_found"}` | The flow is unknown, expired, used already, or the user denied it |
| `409` | `{"error":"endpoint_taken"}` | The endpoint ID belongs to another account on this server. The flow is used up |
| `409` | `{"error":"endpoint_revoked"}` | The endpoint ID was revoked (9). The device needs a new key. The flow is used up |
| `409` | `{"error":"too_many_devices"}` | The account reached its device limit (15) since the consent. The flow is used up |

**The proof** is checked only once the user has granted the flow. The server checks:
- that `server` is its own origin;
- that `endpoint_id` and `challenge` are the ones of this flow;
- the signature.

`server` stops a malicious server from passing another server's challenge on to a device: the
device signs the origin it is talking to.

**When the proof holds**, one transaction:
- creates the device's app password (with no file access, 4.5) and its directory entry;
- records `device.registered` in the audit log (12);
- appends a `device.added` event to the account's event log (5.6).

The answer:

```json
{
  "status": "registered",
  "server": "https://cloud.example.com",
  "username": "kim",
  "app_password": "<device token>",
  "device": { "…": "the directory entry, 6.1" },
  "pairing_open_until": 1763203600
}
```

The app password is returned exactly once. Only its SHA-256 digest is stored, as for every app
password.

### 4.4 Registering again

The endpoint ID decides what happens:

| Its state | Outcome |
|---|---|
| Not registered | A new directory entry |
| Registered to this account, not revoked | The same entry. Name, platform and version are updated, the old app password is deleted and a new one is issued, and the pairing window opens again (8.6). No `device.added` event. Audit: `device.reregistered` |
| Registered to another account | `409 endpoint_taken` |
| Revoked | `409 endpoint_revoked`. A revoked key never comes back (9.1) |

### 4.5 What the device credential can do

- **App password.** A device's app password has no file scopes, so it reaches no files over
  WebDAV.
- **Its two uses:**
  - the control channel (5);
  - `DELETE /gono/v1/device`, which signs the device out (9.4).
- **One for one.** Each directory entry has exactly one app password and each such app
  password has exactly one entry.
- **Not an app password to the user.** The app password lists (account page, admin UI, CLI)
  leave these credentials out, and deleting app passwords never deletes one. Revoking the
  device (9.1) deletes its credential; the database refuses to delete it on its own.
- **Products that need both.** A product that also needs files, such as gono.md, signs in
  twice: through Login Flow v2 for files, and through this flow for its device entry.

---

## 5. Control channel

### 5.1 Connecting

`GET /gono/v1/ws` as a WebSocket upgrade, with `Authorization: Basic base64(username ":"
app_password)`.

**At the upgrade:**
- the credentials go through the server's device authenticator and its limiter of failed
  attempts, the same ones that WebDAV uses;
- the app password must be a device's (4.5).

| Upgrade answer | Meaning | What the device does |
|---|---|---|
| `101` | Connected | — |
| `401` | Credentials unknown or expired | Stop, and show "signed out". Keep the key |
| `403` | The app password is not a device's | Stop |
| `404` | Remote connectivity is off | Retry after an hour |
| `429` | Too many failures from this address | Retry after `Retry-After` |
| `503` | The server cannot check credentials now | Retry with backoff. This is never "signed out" |

**One connection per device.** A new connection of the same device closes the older one with
`4001`, and the older one answers no further request. When connections keep replacing each
other from different client addresses, that is recorded as `device.flapping` (12).

### 5.2 Handshake

```text
device                                   server
  │ ── WebSocket upgrade (Basic auth) ──▶ │
  │ ◀── challenge {nonce} ─────────────── │   right after the upgrade
  │ ── hello {proof, since, …} ─────────▶ │   within 10 s
  │ ◀── welcome {device, devices, …} ──── │
  │ ◀──────── events, results ─────────▶  │
```

**`challenge`** (server):

```json
{ "type": "challenge", "nonce": "<base64url, 32 bytes>", "server_time": 1763200000 }
```

**`hello`** (device):

```json
{
  "type": "hello",
  "proof": { "statement": "…", "signature": "…" },
  "since": 41,
  "version": "1.0.0",
  "features": ["pairing", "session-reports"],
  "settings": { "accept_remote": true, "unattended": false, "services": ["inputshow/1"] }
}
```

The `hello` statement:

```json
{
  "kind": "hello",
  "server": "https://cloud.example.com",
  "account": "kim",
  "endpoint_id": "3f6a…c210",
  "nonce": "<the challenge nonce>"
}
```

**Checks.** The server checks:
- the signature;
- that `server` is its origin;
- that `account` is the authenticated username;
- that `endpoint_id` is the authenticated device's;
- that `nonce` is this connection's.

A failure is answered with an `error` and the close code `4000`. So an app password without
the device key cannot open the channel (threat model 5.5).

**After the checks**, once the connection is registered, the server reads the device's entry
again: a revocation or sign-out that happened after the upgrade was authenticated refuses the
`hello` too. So does a device that opens more than 20 connections a minute.

| Refusal | `error` code | Close code | Device |
|---|---|---|---|
| Bad proof, malformed `hello` | `bad_signature`, `bad_request` | `4000` | Do not retry with the same credentials |
| Signed out since the upgrade | `not_found` | `4000` | As `4000` |
| Revoked since the upgrade | `not_permitted` | `4003` | As `4003` (9.3) |
| Over 20 connections a minute | `rate_limited` | `4029` | Reconnect after 60 seconds |
| The server's own trouble | `unavailable` | `1011` | Reconnect with backoff |

**Other fields of `hello`:**
- `since` is the last event sequence number the device has processed (5.6); `0` on first use.
- `settings` is optional; it is applied as in 6.3.

**`welcome`** (server):

```json
{
  "type": "welcome",
  "server_time": 1763200001,
  "account": { "username": "kim", "display_name": "Kim", "remote_access": true },
  "device": { "…": "own directory entry" },
  "relay_url": "https://relay.example.com/",
  "devices": [ { "…": "every directory entry of the account, revoked ones included" } ],
  "pair_requests": [ { "…": "pending requests, 8.6" } ],
  "events": [ { "…": "events after `since`" } ],
  "events_truncated": false,
  "cursor": 57,
  "features": ["pairing", "session-reports"],
  "limits": { "…": "the limits of section 15 that apply to this connection" }
}
```

- **`remote_access`** is false when the account lacks two-step verification. While it is
  false, `connect`, `lookup` and the pairing requests are refused with `two_factor_required`,
  and the device shows where to turn verification on.
- **`devices`** is the full state of the directory. A device always acts on it, even when
  `events_truncated` is true (5.6).

### 5.3 Messages

Every frame is a text frame holding one JSON object with a `type`.

**Requests** come from the device and carry an `id`, a device-chosen integer that is unique on
the connection. Every request gets exactly one answer with the same `id`:

```json
{ "type": "result", "id": 7, "…": "fields of that request's result" }
{ "type": "error", "id": 7, "code": "not_permitted", "message": "…", "retry_after": 30 }
```

**Events** come from the server and carry no `id`. The ones in the event log also carry a
`seq` (5.6).

**Unknown types:**
- an unknown request type is answered with `unknown_type`;
- an unknown event type is ignored.

**Error codes:**

| Code | Meaning |
|---|---|
| `bad_request` | Malformed message or field |
| `unknown_type` | Unknown request type |
| `bad_signature` | A statement failed verification |
| `not_found` | The device or request does not exist, or the caller may not know about it |
| `not_permitted` | The authorization rules (10) refuse it |
| `two_factor_required` | Remote access is not available on this account |
| `not_online` | The target has no control connection. `last_seen_at` is included |
| `conflict` | The state changed, for example a request was already decided |
| `rate_limited` | Over a limit (15); `retry_after` is included |
| `unavailable` | The server cannot answer now (database); retry |

`not_found` and `not_permitted` are chosen so that a device learns nothing about other
accounts: a device of another account gets `not_found`, exactly like one that does not exist.

### 5.4 Keep-alive and closing

- **Pings.** The server sends a WebSocket ping every 30 seconds. At each ping it also checks
  that the app password is still valid and the account enabled.
- **Timeouts.** A device that has sent nothing by the next ping, not even a pong, is
  disconnected (`4002`). So is one that does not read a frame within one ping interval.
- **Reconnects.** Devices reconnect with exponential backoff from 1 to 60 seconds with
  jitter, except where the table says otherwise.

| Close code | Meaning | Device |
|---|---|---|
| `1000` | Normal close, for example after signing out | — |
| `1001` | The server is shutting down | Reconnect |
| `1009` | A frame was too large | Fix the client |
| `1011` | Server error | Reconnect |
| `4000` | The handshake failed | Do not retry with the same credentials |
| `4001` | Replaced by a newer connection of this device | Do not reconnect automatically |
| `4002` | Timed out | Reconnect |
| `4003` | The device was revoked | Stop, delete the app password, tell the user (9.3) |
| `4004` | The account was disabled | Retry after an hour |
| `4008` | Protocol violation | Reconnect once; then report the bug |
| `4029` | Rate limited | Reconnect after 60 seconds |

### 5.5 Message reference

| Type | Direction | Kind | Section |
|---|---|---|---|
| `challenge` | server → device | handshake | 5.2 |
| `hello` | device → server | handshake | 5.2 |
| `welcome` | server → device | handshake | 5.2 |
| `settings` | device → server | request | 6.3 |
| `publish` | device → server | request | 7.1 |
| `connect` | device → server | request | 7.2 |
| `lookup` | device → server | request | 7.3 |
| `session` | device → server | request | 12.2 |
| `pair.request` | device → server | request | 8.2 |
| `pair.approve` | device → server | request | 8.2 |
| `pair.decline` | device → server | request | 8.2 |
| `pair.withdraw` | device → server | request | 8.2 |
| `revocations.applied` | device → server | request | 9.3 |
| `leave` | device → server | request | 9.4 |
| `ack` | device → server | request | 5.6 |
| `device.added` | server → device | logged event | 6.2 |
| `device.revoked` | server → device | logged event | 9.2 |
| `pair.approved` | server → device | logged event | 8.2 |
| `device.updated` | server → device | event | 6.2 |
| `device.removed` | server → device | event | 9.4 |
| `incoming` | server → device | event | 7.2 |
| `pair.requested` | server → device | event | 8.2 |
| `pair.closed` | server → device | event | 8.2 |
| `account` | server → device | event | 13.5 |

### 5.6 Event log

Some events must reach devices that are offline when they happen. These are:
- `device.added`;
- `device.revoked`;
- `pair.approved`.

**How they are kept.**
- They go into the event log, in the same transaction as the change, numbered by a sequence
  number `seq` that only grows. It is one sequence for the whole server, so a device sees gaps
  where other accounts' events are.
- A device sends the last `seq` it has processed in `hello.since`, and with `ack {"seq": n}`
  as it goes.
- The retained events after `since` are due, at most 1000 of them; when more are due, the
  newest 1000. `welcome.events` carries the first of them, up to 512 KiB; the server sends the
  rest right after the `welcome`, in order, as ordinary event messages, before any live one.
  `welcome.cursor` is the last `seq` the server had handed out when it built the `welcome`; the
  server does not send the same events again live.
- The server sends events as its event log has them, whichever process wrote them: a
  revocation made with the CLI reaches connected devices within seconds.

**What a device does with them:**
- It processes them in order and stores the cursor only after it has acted on them, so a
  crash replays them and does not skip them.
- Handling must be idempotent.

**Retention.** Events are kept for 45 days; approvals are valid for 30 (8.4).

**When events are missing.** If a device's `since` is older than the oldest retained event,
or more than 1000 events are due, `events_truncated` is true. The newest 1000 are sent then:
the snapshot covers the older additions and revocations, and the newest approvals are the
ones still valid. The device then:
- acts on the `devices` snapshot, which holds every revocation (9.2);
- misses the approvals it did not see, so those pairings must be approved again.

---

## 6. Directory and presence

### 6.1 Directory entry

```json
{
  "endpoint_id": "3f6a…c210",
  "name": "Home PC",
  "product": "input-show",
  "platform": "windows",
  "version": "1.0.0",
  "registered_at": 1763100000,
  "online": true,
  "last_seen_at": 1763200001,
  "accept_remote": true,
  "unattended": false,
  "services": ["inputshow/1"],
  "revoked_at": null
}
```

- **`online`.** The device has a control connection.
- **`last_seen_at`.** When it last had one. It is updated on disconnect and every 5 minutes
  while the device is connected.
- **`accept_remote`.** The device accepts remote connections. It is off until the user turns
  remote access on for the device on that device itself.
- **`unattended`.** Unattended access (plan D6) is on.
  - It is shown on other devices only so that they can tell the user, for example "someone
    must accept on Home PC".
  - The target enforces it; the server never does, and the server never sets it.
- **`services`.** The ALPNs the device accepts on its remote endpoint.
- **`revoked_at`.** Set for revoked devices, which stay in the directory as tombstones (9.1).
- **Not in the entry.** Addresses are never part of a directory entry (7).

### 6.2 Who sees what

Every device of an account sees every directory entry of that account, its own included, and
nothing of other accounts. Signed-out entries (9.4) are left out until the device registers
again.

| Event | When | Fields |
|---|---|---|
| `device.added` (logged) | A device registered | `seq`, `device`, `at` |
| `device.updated` | Presence, name or settings changed | `device` |
| `device.revoked` (logged) | 9.2 | `seq`, `endpoint_id`, `at`, `by` |
| `device.removed` | A device signed out (9.4) | `endpoint_id`, `at` |

`by` names the kind of actor, never a person or an address: `account_page`, `admin`, `cli`,
`app_password_deleted`.

### 6.3 Settings

`settings` changes the device's own entry: `name`, `accept_remote`, `unattended`, `services`,
each optional. The answer is `result` with the updated entry, and other devices get
`device.updated`.

- **Turning `accept_remote` off.** The server refuses `connect` to the device from then on.
  The device closes its remote sessions itself.
- **Renaming.** The account page can rename a device too. The device then gets
  `device.updated` for itself.

---

## 7. Connection requests and addresses

The server keeps addresses **in memory only**:
- They are dropped when the device's control connection ends.
- They never reach the database, the audit log or the server's log.

### 7.1 `publish`

```json
{ "type": "publish", "id": 3, "relay_url": "https://relay.example.com/",
  "direct": ["192.0.2.10:51820", "[2001:db8::1]:51820"] }
```

- **What it carries.** The device's current iroh addresses: its home relay, and up to 16
  direct addresses.
- **When to send it.** The device sends it after `welcome` and whenever
  `Endpoint::watch_addr()` changes, at most once a second (coalesced).
- **Checks.**
  - The relay URL must be the server's relay.
  - Direct addresses must parse.
  - Private and link-local addresses are allowed, because two devices on one LAN may reach
    each other through the remote endpoint.

### 7.2 `connect`

A device sends `connect` when it means to open a connection to a peer: the user picked the
peer, or a product feature needs it.

```json
{ "type": "connect", "id": 4, "target": "8c01…77aa", "service": "inputshow/1",
  "purpose": "session" }
```

**Purposes:**
- `session`: an ordinary connection;
- `pair`: the approver of a pending pairing request dials the new device (8.2). It then
  carries `"request_id"`.

**Result:**

```json
{ "type": "result", "id": 4, "target": "8c01…77aa",
  "relay_url": "https://relay.example.com/", "direct": ["198.51.100.7:40211"],
  "published_at": 1763200050 }
```

**At the target.** The target gets an `incoming` event:

```json
{ "type": "incoming", "from": "3f6a…c210", "service": "inputshow/1", "purpose": "session" }
```

- The target may use it to publish fresh addresses, or to show "Kim's iPhone is connecting…".
- It MUST NOT grant anything because of it: the connection is checked against its trust list
  as any other (C7).
- For `pair`, `incoming` also carries `request_id`, and the new device accepts pairing
  connections only from the key that `incoming` named (8.2).

**Recorded.** Every `connect` is recorded in the audit log as `connect.requested`, refused
ones included.

**Refusals:** `not_found`, `not_permitted`, `not_online` and `two_factor_required` follow 10.

### 7.3 `lookup`

```json
{ "type": "lookup", "id": 9, "target": "8c01…77aa" }
```

`lookup` returns the same fields as `connect`'s result, without notifying the target or
writing to the audit log. It backs iroh's `AddressLookup` in `gono-connect` while a connection
is set up or kept alive.

It is allowed only if the caller:
- was allowed `connect` for that target in the last 10 minutes, and that `connect` would still
  be allowed: the target still accepts remote connections and the service, or the pairing
  request is still pending; or
- has reported a session with it that has not ended (12.2), for at most 24 hours.

So every first disclosure of a device's addresses is a recorded `connect` that the target
hears about. What a device was allowed, like its rate limits (15), is kept per device and not
per connection, so reconnecting changes neither.

### 7.4 Caching and outages

- **Caching.** `gono-connect` caches the last result per peer for 10 minutes, and the relay
  URL until the next `welcome`.
- **During an outage of gono-cloud:**
  - the embedded relay is down too, so relayed paths fail;
  - established direct paths continue;
  - new connections can use cached direct addresses;
  - LAN use is untouched.
- **`not_online`.** The target has no control connection. The device should report "offline
  since `last_seen_at`" and not retry in a loop.

---

## 8. Account-vouched pairing

This is the guarded flow of plan 3.4. It lets a new device N join the trust lists of devices
it has never shared a LAN with.

### 8.1 What devices store

Each trust-list entry holds the fields of Input Show's `TrustedDevice` (`inputshow-config`) and
three new ones:

| Field | Content |
|---|---|
| Endpoint ID | The peer's key: the key of the trust list |
| `name` | As shown to the user |
| `allow_incoming` | The peer may control this device |
| `allow_outgoing` | This device may control the peer |
| `paired_at` | When it was added |
| `method` (new) | `lan-sas`, `remote-sas`, `in-person` (QR or invite code), or `vouched` |
| `vouched_by` (new) | For `vouched`: the endpoint ID of the approver |
| `request_nonce` (new) | For `vouched`: the nonce of the request (8.3) |

Entries that exist today have no `method`; they count as `lan-sas`.

Devices also keep the set of endpoint IDs they have seen revoked (9.3).

### 8.2 Flow

The roles:

| Role | Device |
|---|---|
| N | The new device, for example a work PC the user just installed |
| A | The approver: a device the user has at hand, directly paired with the devices N should join (typically the user's phone) |
| T | Each target: a device of the account that N should be able to reach or be reached by, for example the home PC, possibly with nobody there |

```text
N                         server                         A                          T
│ pair.request ─────────▶ │ ── pair.requested ─────────▶ │                          │
│                         │                              │ user taps "Approve"      │
│                         │ ◀── connect(N, purpose=pair) │                          │
│ ◀── incoming(A, pair) ─ │ ── result (N's addresses) ─▶ │                          │
│ ◀═════════ iroh connection, Input Show pairing (6-digit code typed on A) ═══════▶ │
│                         │ ◀──── pair.approve ───────── │  (statement signed by A) │
│ ◀── pair.approved ───── │ ──── pair.approved ────────────────────────────────────▶ │
│ adds each introduced T  │ ── pair.closed ────────────▶ │       T adds N (vouched) │
```

The steps:

1. **N asks.** N sends `pair.request` with a `pair-request` statement (8.3). The server checks
   the rules of 8.6. It then:
   - answers `result {request_id, expires_at}`;
   - sends `pair.requested` to every other online device of the account;
   - keeps the request pending for 10 minutes, so devices that connect in that time get it in
     `welcome.pair_requests`.

   `pair.requested` carries:
   - `request_id` and `expires_at`;
   - `requester`: the requester's directory entry;
   - `request`: the signed statement.

2. **The user approves on A.** A shows N's name, platform and short ID, and asks: "Approve only
   a device you have with you right now." On approval:
   - A sends `connect` with `purpose: "pair"` and the `request_id`, which is allowed even
     though N does not accept remote connections yet;
   - A dials N through iroh;
   - N accepts the connection only because `incoming` announced this key for its pending
     request, and only for pairing.
3. **Comparison code.** N and A run Input Show's pairing protocol over this connection, end to
   end: version 2, commit-then-reveal with 6 digits, with the code bound to this TLS session
   through its exporter (`inputshow-net` `pairing.rs`).
   - N shows the code. The user types it on A; A does not ask "do these match?".
   - Each side then adds the other as `remote-sas`.
   - A failed or abandoned comparison ends the flow, and A sends `pair.decline`.
4. **A signs the approval.** A's user chooses which of A's direct pairings N is introduced to,
   and the directions.
   - The default is A's direct pairings that are devices of the account. For targets that
     accept remote connections, N may control them; nobody else gets a direction by default.
   - A sends `pair.approve` with a `pair-approval` statement (8.4).
   - The server checks it (8.6), appends `pair.approved` to the account's event log, and sends
     it to every device of the account.
   - It sends `pair.closed {request_id, outcome: "approved"}` to the devices that got the
     request.
5. **The devices act on the approval.**
   - Every device named in `introduced` adds N if the checks of 8.5 pass.
   - N adds every introduced device.
   - Each of them shows a notice: "Work PC was added by Kim's iPhone."
   - Devices that are offline do this when they connect (5.6).

**Other outcomes.**
- `pair.decline {request_id}` from any account device ends the request with
  `outcome: "declined"`.
- `pair.withdraw {request_id}` from N ends it with `"withdrawn"`.
- Expiry ends it with `"expired"`.
- N gets `pair.closed` in every case.

**Messages of the flow:**

| Message | Fields |
|---|---|
| `pair.request` (N) | `id`, `request`: the signed `pair-request` statement. Result: `request_id`, `expires_at` |
| `pair.requested` (event) | `request_id`, `expires_at`, `requester`, `request` |
| `pair.approve` (A) | `id`, `request_id`, `approval`: the signed `pair-approval` statement |
| `pair.approved` (logged event) | `seq`, `request_id`, `approval`, `at` |
| `pair.decline` (any device but N), `pair.withdraw` (N) | `id`, `request_id` |
| `pair.closed` (event) | `request_id`, `outcome`: `approved`, `declined`, `withdrawn` or `expired` |

### 8.3 `pair-request` statement

```json
{
  "kind": "pair-request",
  "server": "https://cloud.example.com",
  "account": "kim",
  "requester": {
    "endpoint_id": "3f6a…c210",
    "name": "Work PC",
    "platform": "windows",
    "product": "input-show"
  },
  "nonce": "<base64url, 32 random bytes>",
  "issued_at": 1763200100
}
```

- **Who signs it.** N signs it. `requester.endpoint_id` must be the device on this control
  connection.
- **What it proves.** It shows the approver that the request comes from the key it names. It
  does not prove that the key belongs to the user: that is what the comparison code is for.

### 8.4 `pair-approval` statement

```json
{
  "kind": "pair-approval",
  "server": "https://cloud.example.com",
  "account": "kim",
  "approver": "a9d2…0b1e",
  "subject": {
    "endpoint_id": "3f6a…c210",
    "name": "Work PC",
    "platform": "windows",
    "product": "input-show"
  },
  "request_nonce": "<the nonce of the pair-request statement>",
  "method": "remote-sas",
  "introduced": [
    { "endpoint_id": "8c01…77aa", "name": "Home PC",
      "allow_incoming": true, "allow_outgoing": false }
  ],
  "issued_at": 1763200160,
  "expires_at": 1765792160
}
```

- **Who signs it.** A signs it. `expires_at` is at most 30 days after `issued_at`.
- **`introduced`** lists up to 50 devices. Its two flags are written from the point of view of
  the introduced device T, as in Input Show's `TrustedDevice`:
  - `allow_incoming`: N may control T;
  - `allow_outgoing`: T may control N.

  T applies them to its entry for N as they are. N applies them to its entry for T the other way
  round: N's `allow_incoming` for T is the statement's `allow_outgoing`.
- **Both directions.** The approval vouches N to the introduced devices and the introduced
  devices to N. So N learns their keys from A, whom it has just verified, and not from the
  server's directory, which could have substituted a key.

### 8.5 Checks on receipt

A device D that receives `pair.approved` accepts it only if all of these hold:

1. The signature is valid (2.3).
2. `server` is D's server origin, and `account` is D's account.
3. `approver` is in D's trust list with a method other than `vouched`. Vouching goes **one
   level deep**: a device that was itself vouched for cannot vouch.
4. `approver` is not in D's revoked set.
5. One of these:
   - D is named in `introduced`, and `subject` is the newcomer;
   - D is `subject.endpoint_id`, and D has a `remote-sas` pairing with `approver` from a
     request whose nonce is `request_nonce`.
6. `subject.endpoint_id` is not in D's revoked set, and is not D.
7. D's clock is before `expires_at`, and after `issued_at` minus 10 minutes (to allow for
   clock skew).
8. D's local policy allows vouched devices. This is a setting that the device's user can turn
   off. When it is off, D keeps the approval as a notice that the local user can accept or
   ignore.

**Applying it.**
- D applies the approval with the permissions it names, capped by D's own policy, D6 included.
- D records `method: vouched`, `vouched_by` and `request_nonce`.
- Applying the same approval twice changes nothing.
- An approval that fails a check is dropped, and the device logs it locally.

### 8.6 Server rules and limits

**`pair.request` is accepted only if:**
- remote access is available on the account;
- the requester is registered: neither revoked nor signed out;
- its **pairing window** is open:
  - for 1 hour after registration (4.3, 4.4);
  - or for 1 hour after the user presses "Allow pairing" for the device on the account page,
    which needs a session that passed the second step;
- it has no other pending request;
- the account has had fewer than 5 requests in the last hour.

**`pair.approve` is accepted only if:**
- the request is pending;
- the approver is a registered device of the account other than the subject;
- the statement is valid;
- its `subject` and `request_nonce` match the request;
- its `server` and `account` are this server's and this account's;
- its `issued_at` is within 10 minutes of the server's clock, which devices learn from
  `challenge` and `welcome`;
- its `expires_at` is in the future and at most 30 days after `issued_at`.

**The server does not check `introduced`.** It cannot know the approver's trust list.

**What the server keeps.** Pending requests live in memory: a restart drops them, and the user
asks again. Approvals are kept in the event log (5.6).

### 8.7 Changes from plan 3.4

This section turns the plan's step 3, "a device that is already trusted shows the new device's
name, platform and ID, and the user approves it there", into:

| Change | Why |
|---|---|
| The approver runs the 6-digit comparison with N over an iroh connection, and the user types N's code on A | The server delivers the request and could substitute its own key. Users do not reliably compare 16 hex digits, and a short ID is open to key grinding. The comparison code is already what Input Show uses on the LAN (threat model 5.2) |
| The approval introduces in both directions | Otherwise N would take T's keys from the server's directory, which a compromised server can forge |
| Only direct pairings may vouch, one level deep | One vouched device cannot vouch further devices |

Trust that A vouched for stays when A is revoked; it is not removed along with A. Revocation
instead shows the devices A introduced and offers to revoke them as well (9.1, 9.3). The threat
model weighs this choice (5.4).

---

## 9. Revocation

### 9.1 Who revokes, and what it means

**Who can revoke:**
- the user, on the account page, with a session that passed the second step;
- an admin, in the admin UI or with `gono-cloud device revoke <user> <endpoint id>`.


**What it means.** Revocation is for a device that is lost, stolen, compromised or retired for
good.
- **It is final for the key.** The directory entry stays as a tombstone with `revoked_at`, and
  the key can never be registered again on this server.
- **To come back**, a device needs a new key, and with it new pairings.
- **Account deletion** removes the tombstones too.

**Second confirmation.** Because it cannot be undone, revocation is never one click. The first
action opens a confirmation step, and nothing changes until it is confirmed:
- **What it shows:**
  - the device's name, platform and short ID;
  - that the key can never be used again on this server, and that the account's other devices
    will forget it, on the LAN as well;
  - the devices this device introduced through approvals (8.4), taken from the event log. They
    stay trusted unless the user ticks them here to be revoked as well.
- **Account page and admin UI.** A separate confirmation page with its own button. The account
  page also needs a session that passed the second step.
- **CLI.** `gono-cloud device revoke` asks interactively. Without a terminal it needs
  `--confirm <endpoint id>`, repeating the full ID.


### 9.2 What the server does

In one transaction:
- set `revoked_at`;
- delete the app password;
- append `device.revoked` to the event log;
- record `device.revoked` in the audit log.

Then, at once:
- close the device's control connection with `4003`;
- disconnect it from the relay (11.2);
- send `device.revoked` to every connected device of the account.

From then on:
- the relay refuses the key;
- `hello`, `connect`, `lookup` and the pairing requests refuse it as a caller, even on a
  connection that has not heard of the revocation yet, and `connect` and `lookup` refuse it as
  a target;
- and the registration refuses it (4.4).

The steps after the transaction follow from the event log, so they also happen when another
process revoked the device: `gono-cloud device revoke` takes effect on a running server within
seconds.

### 9.3 What devices do

A device D that learns of a revocation of X, from the event or from `revoked_at` in a
`welcome` snapshot:

1. adds X to its revoked set;
2. closes its sessions with X;
3. removes X from its trust list;
4. shows a notice that X was revoked. If D has entries whose `vouched_by` is X, the notice lists
   them and offers to remove them. They stay unless the user removes them;
5. sends `revocations.applied {"endpoint_ids": [...]}`.

From then on D refuses every approval signed by X, including approvals issued before the
revocation that D has not processed yet (8.5, check 4). A `welcome` carries the snapshot
before the events, so a device that was offline sees the revocation first.

The server records the last step (`revocation.applied`), and the account page shows each of the
account's devices as "applied" or "pending" for every revocation. That makes the delay
measurable (plan 4.3), and lets the user see which device has not heard yet.

**Scope.** Steps 1–3 apply to D's whole trust list, LAN pairings included: a key revoked for
remote access is not trusted on the LAN either.

**The revoked device.** A device closed with `4003`:
- stops using its credentials;
- tells the user that it was revoked and that its pairings are gone;
- offers to create a new identity. It MUST NOT try to register the old key again.

### 9.4 Signing out

`DELETE /gono/v1/device` (device app password) or `leave` on the control channel signs out a
device that is still in its user's hands.

- **What is deleted.** The app password. The directory entry stays, marked signed out.
- **The key stays bound to the account.** The device can register again with the same key,
  into the same account only; any other account gets `endpoint_taken`. A signed-out device is
  not admitted to the relay and does not count towards the limit of 50 devices.
- **No revocation.** Other devices get `device.removed`, which removes the entry from their
  directory views but **does not** touch their trust lists. Signed-out entries are left out of
  `welcome.devices`. When the device registers again, they get `device.added`.
- **It can still be revoked.** The account page, the admin UI and the CLI list it as signed
  out and offer revocation. An app password alone can sign a device out, so a leaked key and
  app password must not be able to hide the device from the user or move the key to another
  account.
- **The account page offers only revocation.** A user cleaning up there is either retiring a
  device or has lost it, and revocation is the safe choice in both cases.

---

## 10. Authorization rules

"Active device" means:
- not revoked;
- its account is enabled;
- its app password is valid.

| Action | Who | Allowed when |
|---|---|---|
| Start registration (4.1) | anyone | rate limits |
| Grant registration (4.2) | a signed-in user | password and second step passed; two-step verification enrolled; under the device limit |
| Complete registration (4.3) | the device | the flow is granted; the proof is valid; the endpoint is not taken or revoked (4.4) |
| Open the control channel (5) | a device | active; valid `hello` proof |
| Read the directory (6.2) | a device | same account |
| `settings`, `publish` | a device | its own entry |
| `connect` X | device A | remote access available; A active; X active, in A's account, `online`, and not A. X has `accept_remote`, or a pending request of X is being approved by A (`purpose: pair`). X lists the service |
| `lookup` X | device A | as `connect`, and A sent `connect` X within 10 minutes or has an open session with X (7.3) |
| `pair.request` | device N | 8.6 |
| `pair.approve`, `pair.decline` | device A | 8.6; same account |
| `pair.withdraw` | device N | its own request |
| `session` report | a device | the peer is a device of the account; one side of the session must be the reporter |
| Revoke a device | a user / an admin | after the second confirmation (9.1). The user: own account, session past the second step. The admin: any account |
| Sign out | a device | itself |
| Relay admission | endpoint E | 11.1 |
| Two-step verification | a user / an admin | 13 |

Two kinds of refusal:
- Refusals involving a device of another account, or one that does not exist, answer
  `not_found`.
- Every other refusal answers `not_permitted` or `two_factor_required`.

---

## 11. Relay access control

### 11.1 Admission

The relay's `AccessControl::on_connect` admits endpoint E if either holds:

1. E is listed in `relay.allowed_endpoints`. The static list stays for tests, for Phase 1
   spikes, and for relays on a host of their own (11.3).
2. E is an active device (10) of an account on which remote access is available.

**How it decides:**
- The decision uses the directory's admitted keys, held in memory so that no database query
  runs per connection. The server reads them again at once after every registration,
  revocation and sign-out it makes, after account changes in the admin UI, when a revocation
  appears in the event log, and every 30 seconds, which picks up changes made by another
  process (the CLI). Reads are serialized, so an older read never replaces a newer one.
- Unknown keys are refused as today (`Deny { reason: None }`, logged at info).
- A refused key that is a tombstone is also recorded as `relay.refused_revoked`, without the
  client IP, which the relay's access control does not see.

The relay handshake proves E: the client signs a challenge or a TLS exporter value. So
admission by key is admission by key holder.

### 11.2 Ending access at once

When a device stops being admissible, the server disconnects it from the relay immediately
through `Server::relay_service()` → `RelayService::clients()` → `Clients::disconnect(E, None)`
(iroh-relay 1.4.1). This happens when:
- the device is revoked or signs out;
- its account is disabled or deleted;
- two-step verification is turned off or reset on its account.

Every 2 seconds the server also checks each device connected to the relay against the admitted
keys and disconnects those no longer admitted. That ends connections a disconnect could not
reach, such as one admitted an instant before the change. The control connections of a
disabled or deleted account are closed with `4004` at the same time.

Changes made in the admin UI and on the account page take effect at once; changes made with
the CLI in another process within 30 seconds, except revocations, which reach the server
through the event log within seconds (9.2). Part 2b measures the time from the revocation to
the disconnect.

### 11.3 Limits of the relay in version 1

- **No separation between accounts.** The relay forwards between any two admitted endpoints:
  iroh-relay 1.4.1 decides per connection, not per pair. So a device of one account can send
  relayed packets to a device of another account whose endpoint ID it knows. Devices handle
  that (C8), and the threat model weighs it (5.6).
- **A relay on a host of its own** (`gono-cloud relay`) cannot read the directory, so it
  admits only `relay.allowed_endpoints`. Feeding it from the control plane over the network
  comes with hosted relays (plan 3.6).
- **Rate limits.** `relay.max_client_bytes_per_sec` applies per connection as today. New
  connections are limited at the reverse proxy (`docs/reverse-proxy.md`).

---

## 12. Audit

### 12.1 Records

The audit log records who did what, and when. It never records content: no keys typed, no
clipboard, no screen, no file names, and no addresses published by devices.

| Kind | Recorded when | Actor | Details |
|---|---|---|---|
| `device.registered`, `device.reregistered` | 4.3, 4.4 | user (web) | device, product, platform, name, client IP |
| `device.renamed`, `device.settings` | 6.3 | device or user | old and new values |
| `device.revoked` | 9.2 | user, admin, CLI | device; the devices it introduced that were revoked along with it |
| `device.removed` | 9.4 | device | — |
| `device.connected` | Control connection from an address the device did not use last time | device | client IP |
| `device.flapping` | 5.1 | — | device, the client IPs involved |
| `connect.requested` | 7.2 | device | target, service, purpose, outcome (allowed or error code) |
| `session.started`, `session.ended` | 12.2 | device | peer, role, service, path, duration, bytes |
| `pair.requested` | 8.2 | device N | request ID |
| `pair.approved` | 8.2 | device A | subject, introduced devices |
| `pair.declined`, `pair.withdrawn`, `pair.expired` | 8.2 | device or — | request ID |
| `revocation.applied` | 9.3 | device | revoked devices |
| `relay.refused_revoked` | 11.1 | — | endpoint |
| `two_factor.enabled`, `two_factor.disabled`, `two_factor.reset` | 13 | user, admin, CLI | client IP |
| `two_factor.failed`, `two_factor.locked` | 13.3 | — | client IP |
| `recovery_code.used`, `recovery_codes.renewed` | 13.4 | user | client IP |

- **Kept.** Records are kept for 180 days by default (configurable in 2b).
- **Who sees them.** Users see the records of their own account on the account page. Admins
  see all of them in the admin UI.
- **Rate.** The rate limits of 15 bound how fast a device can add records.

### 12.2 Session reports

The server cannot see direct connections, so the devices report their sessions. This needs
the feature `session-reports`.

```json
{ "type": "session", "id": 12, "event": "ended", "session_id": "<random, 16 bytes>",
  "peer": "8c01…77aa", "role": "controlled", "service": "inputshow/1",
  "started_at": 1763200200, "ended_at": 1763203800,
  "path": "direct", "bytes_direct": 1048576, "bytes_relayed": 2048 }
```

- **The fields.**
  - `event` is `started` or `ended`.
  - `role` is `controller` or `controlled`; for services without such roles it is
    `initiator` or `acceptor`.
  - `path` is the path in use when the report was made: `direct`, `relayed` or `mixed`.
- **Checks.** A `started` report is accepted only for a session that is open already (sent
  again after a reconnect), or between two devices one of which was allowed `connect` to the
  other in the last 10 minutes (7.2). `session_id` must be 16 bytes, `role` and `path` one of
  the values above, and `service` an ALPN as in 6.3. Other reports are refused with
  `not_permitted` or `bad_request`, and nothing is recorded.
- **Both sides report.** The controlled side's report is the one that counts.
- **Offline.** A device that is offline queues up to 100 reports and sends them later.
- **Remote only.** Only sessions on the remote endpoint are reported. **Sessions on Input
  Show's LAN path are never reported**, so LAN use stays invisible to the server (rule 5 of
  1.1).

---

## 13. Two-step verification

### 13.1 Scope

**Where it applies.** The second step is part of the web sign-in, which serves every page:
- the web file UI;
- the account page;
- the admin UI;
- the consent pages of Login Flow v2 and of device registration.

**Where it does not.**
- App passwords do not go through it, so existing devices and Nextcloud clients keep working.
- It does not protect the WebDAV files of an account against a leaked app password.

**Remote access needs it.** Remote access is available only on accounts that have it (4.2,
10, 11.1).

### 13.2 TOTP and enrolment

- **Method.** TOTP (RFC 6238): HMAC-SHA-1, 6 digits, a 30-second step, and the codes of the
  previous, current and next step accepted.
  - The secret is 20 random bytes.
  - The server clock must be synchronized (NTP), which `docs/deployment.md` states.
- **Replays.** A code of a step at or before the last accepted step is refused.
- **Enrolment** is on the account page and needs the web login password again.
  1. The page shows a QR code and the base32 secret in groups of four. The QR code is an SVG
     rendered on the server, since the pages work without scripts. It encodes:
     `otpauth://totp/Gono%20Cloud:<username>?secret=<base32>&issuer=Gono%20Cloud&digits=6&period=30`
  2. The user enters a code, which turns verification on.
  3. The page then shows the recovery codes once (13.4).

### 13.3 Signing in

1. **Password.** The sign-in form checks the web login password as today.
2. **The pending sign-in.** If the account has two-step verification, no session is created
   yet. The server sets a pending-sign-in cookie instead: a random token, bound to the
   account, valid for 5 minutes and usable once. It then shows the code form.
3. **The code.** The form at `/login/two-step`, shared by every sign-in form, takes a TOTP code
   or a recovery code, and only a correct one creates the session; the sign-in then continues
   where it started (the file UI, the admin UI, a consent page). Five wrong codes end the
   pending sign-in, and the password must be entered again.

**Limits.**
- The per-client limiter of the sign-in applies.
- Failed codes are also counted **per account**, from the audit log: after 5 in 15 minutes or
  20 in 24 hours, the second step is locked for that account until the window passes. The
  same codes guard the forms that renew recovery codes and turn verification off.
- The account page shows failures to its user: "your password was entered correctly but the
  second step failed, at … from …". They are recorded as `two_factor.failed` and
  `two_factor.locked`.

### 13.4 Recovery codes

- **The codes.** 10 codes, each 16 characters of Crockford base32 (80 bits) in groups of four,
  shown once.
- **Storage.** Only their SHA-256 digests are stored: 80 random bits are enough for a fast
  hash.
- **Use.** Each code works once. Using one is recorded and shown on the account page.
- **Renewal.** Generating new codes (password and a code required) replaces all of them.

### 13.5 Turning it off, and resets

- **Turning it off** needs the password and a code (TOTP or recovery).
- **Resetting.** An admin resets it in the admin UI, and the operator with
  `gono-cloud user reset-two-factor <user>`; a running server picks either up within seconds.
- **Effects of either:**
  - remote access becomes unavailable;
  - the account's devices are disconnected from the relay (11.2);
  - they get `account {"remote_access": false}`;
  - `connect`, `lookup` and the pairing requests are refused until verification is enrolled
    again.
- **What stays.** The devices stay registered, and their trust lists are untouched.

### 13.6 Storage of the secret

**Encryption.** TOTP secrets are encrypted with a 32-byte key that lives outside the database
directory, in `two_factor.key_file` (`two-factor.key` next to the configuration file by
default):
- created by the install script as root (mode 0640, owner root, group `gono-cloud`), and by
  `init` and `serve` when they can write there; never replaced once it exists;
- ChaCha20-Poly1305 from ring;
- a random 96-bit nonce, stored before the ciphertext;
- associated data `gono-cloud totp v1` and the user ID, so a secret cannot be moved to another
  account.

**Why.** A copy of the database alone, a backup for example, does not give away the second
factor.

**If the key file is lost**, every account must have its verification reset: `serve` refuses to
start while accounts use it and the file is missing, and says so. `docs/deployment.md`
describes it next to backups.

**Later.** WebAuthn and passkeys come after version 1.

---

## 14. Storage

The tables are in `crates/server/core/migrations/0001_initial.sql`, which follows the conventions
of that file (STRICT tables, UNIX seconds, digests of secrets):

| Table | Content |
|---|---|
| `devices` | The directory (6.1), with revoked entries as tombstones (9.1) and signed-out entries (9.4). An entry has its app password exactly when it is neither revoked nor signed out |
| `device_events` | The event log (5.6) |
| `device_approvals` | Which device approved which newcomer, so that a revocation can list them (9.1) |
| `revocations_applied` | Which device applied which revocation (9.3) |
| `audit_log` | The audit log (12) |
| `two_factor`, `recovery_codes` | Two-step verification (13) |
| `login_flows` | Registrations, in the columns `device_*` (4) |

Pending pairing requests, addresses, presence, `connect` grants, open sessions and rate limits
live in memory only. Ids of accounts, credentials, web sessions and devices are never reused,
so in-memory state never carries over to a newer row.

---

## 15. Limits

| Limit | Value |
|---|---|
| Registration flow lifetime | 20 minutes |
| Unrevoked devices per account | 50 |
| Frame or body size | 64 KiB from devices; 4 MiB from the server |
| Statement size | 16 KiB |
| `hello` after the upgrade | 10 seconds |
| Ping interval | 30 seconds |
| Requests per device | 10 per second, bursts of 100 |
| Control connections per device | 20 per minute |
| `publish` | 1 per second (coalesced); 16 direct addresses |
| `connect` | 30 per device per minute |
| `lookup` | 120 per device per minute |
| `session` reports | 60 per device per minute; 100 queued offline |
| Pairing window | 1 hour after registration or "Allow pairing" |
| Pending pairing requests | 1 per device; 5 per account per hour |
| Pairing request lifetime | 10 minutes |
| Approval validity | 30 days |
| Devices in `introduced` | 50 |
| Event log | 45 days; 1000 events per `welcome`, 512 KiB of them inside it |
| Address cache on devices | 10 minutes |
| Failed second steps per account | 5 per 15 minutes; 20 per 24 hours |
| Pending sign-in | 5 minutes, used once |
| Audit retention | 180 days (configurable) |

---

## 16. Open questions

1. **Cross-account access.** One endpoint ID belongs to one account per server. Reaching a
   computer that someone else's account owns (family, support) needs sharing between
   accounts, which is not in version 1.
2. **Revocation signed by a device.** A device could sign a revocation, so that it also
   travels between devices directly and a compromised server cannot hold it back. Version 1
   revokes only from the web, the admin UI and the CLI (threat model 6).
3. **A relay on a host of its own** gets no directory-based admission in version 1 (11.3).
4. **Retention.** Is 180 days of audit right for self-hosted installs? Should `connect.requested`
   rows be aggregated?
5. **Unattended targets and the control channel.** Should a target refuse remote sessions when
   its last `welcome` is older than 24 hours, so that it cannot miss revocations for long? The
   threat model recommends it (C14); Input Show decides.
