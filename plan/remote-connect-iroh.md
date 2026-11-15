# Remote Device Connectivity on iroh: Execution Plan

- Status: execution plan
- Date: 2026-11-14
- Language: English. Keep this document, and every future document in `plan/` and `docs/`, in English.
- Scope: gono-cloud's cloud interconnect. The first consumer is remote access in Input Show:
  keyboard, mouse and clipboard across the internet, later screen viewing. Port forwarding and
  other products follow.
- Owners:
  - **gono-cloud**: the control plane, the relay, accounts.
  - **Input Show**: the device side. Its work is split into lanes, named here by code: NE
    (networking and security), HM (HarmonyOS), QR (quality and test tooling), MB (phone apps),
    and the platform UI lanes.
- Measurements behind this plan: `docs/plan/远程互联调研.md` and
  `docs/notes/HM-汇报-iroh-probe.md` in the Input Show repository.

---

## 0. Summary

**What we build.**
- iroh 1.4.x, on its QUIC implementation noq, is the connection layer between devices. It handles
  NAT traversal, multipath and relay fallback.
- gono-cloud provides accounts, the device directory, authorization, address lookup, a
  self-hosted relay embedded in gono-cloud, and auditing.

**Why iroh.** Hole punching, multipath, relaying and network changes are the hardest and most
security-sensitive parts of remote connectivity. iroh has them working today, under a stable 1.x
wire protocol. It is also the same technology as Input Show: Rust, tokio, rustls with ring, and a
QUIC API close to quinn's. Writing these parts ourselves would take months.

**Two stages.**
1. **Remote access first.** It is an opt-in second endpoint on iroh, next to Input Show's
   existing quinn endpoint on the LAN.
2. **Then the LAN path moves to iroh as well**, once the gates in 4.5 pass. The end state is one
   stack.

**Already in place.**
- **Identity.** Input Show's device identity is an Ed25519 key, used as a raw public key
  (RFC 7250) on quinn. Device ID = the public key = the future iroh `EndpointId`, so no device
  re-pairs when iroh arrives.
- **HarmonyOS.** iroh runs inside the HarmonyOS app sandbox: direct, relayed, inbound, and
  through Wi-Fi off and on. Two integration conditions apply (3.3).
- **No n0 servers.** A configured endpoint contacts no one but the peer and our relay (V4, 3.5).

**Largest unknown.** How often NAT traversal succeeds on real Chinese networks (V8). It sets the
relay's bandwidth cost and whether an official hosted relay is offered. Until we know, only
self-hosted relays.

**Principles.**
- Relays forward ciphertext only; TLS is end to end between the devices.
- Input Show's LAN mode needs no account and sends nothing to the cloud. Remote access is opt-in
  and needs sign-in.
- Trust between devices comes from pairing. The account can vouch for a remote pairing only
  through the guarded flow in 3.4: a device that is already trusted approves it, and the server
  only relays the request.
- The cloud may revoke devices, since revocation only removes trust.
- Unattended access (nobody at the device, the lock screen, Ctrl+Alt+Del) is off by default and
  is switched on per device.
- Two-factor authentication on the account is required before remote control ships.

---

## 1. Background

### 1.1 What gono-cloud is for

gono-cloud is more than a WebDAV file server: it provides **cloud interconnect for the whole
product family**.

| Product | What it needs from gono-cloud |
|---|---|
| gono.md | Document sync (WebDAV, implemented) |
| Input Show | Reaching one's own computers across the internet: remote keyboard and mouse, clipboard, screen viewing |
| Future products | Accounts, device directory, device-to-device connections, port forwarding |

Users have Input Show on their computers and on their phones. The most direct need is "connect to
my own computer remotely, see its screen and control it".

### 1.2 Requirements

| Requirement | Consumer | Traffic profile | Priority |
|---|---|---|---|
| Device registration, presence, device list | All | Few control messages, long-lived connection | High |
| Keyboard, mouse and clipboard across the internet | Input Show | Small packets, low latency, sensitive to jitter; occasional large clipboard data | High |
| Remote screen viewing | Input Show | 2–6 Mbps video (1080p), long sessions | High |
| Private port forwarding between devices | General | TCP/UDP, variable bandwidth | Medium |
| Public port mapping (frp style) | General | Exposed to the internet, high risk | Low |

### 1.3 Current state

**gono-cloud**

- **Stack:** Rust 1.94, axum 0.8 on tokio, SQLite (sqlx).
- **Network:** listens on plain HTTP on loopback only. nginx or Caddy terminates TLS, and
  `base_url` is configured explicitly.
- **Service hardening:** a hardened systemd unit with `RestrictAddressFamilies=AF_INET AF_INET6
  AF_UNIX`, an empty `CapabilityBoundingSet=`, `PrivateDevices=yes` and system call filtering.
- **In place today:**
  - accounts and app passwords;
  - Login Flow v2, with a browser consent page;
  - notify_push over WebSocket;
  - the web file UI and the web admin UI.
- **Planned layout:**
  - `crates/protocol` holds the wire types shared by server and clients;
  - `crates/client/*` holds the clients;
  - components are released separately;
  - new abilities are advertised through capabilities, and a released protocol is only ever
    extended, never changed.

**Input Show's network stack** (`core/crates/inputshow-net`)

- **Transport:** quinn 0.11 on tokio, rustls 0.23 with ring, TLS 1.3 only, ALPN `inputshow/1`,
  UDP 24850.
- **Identity:**
  - Every device has an Ed25519 key. TLS authenticates both sides with raw public keys
    (RFC 7250).
  - The handshake accepts any key and then compares it with the paired devices ("accept, then
    check"), so pairing with a typed address works.
  - The device ID is the 32-byte public key, shown as 64 hex digits.
- **Discovery:** mDNS `_inputshow._udp`. The TXT record carries the full device ID.
- **Pairing:**
  - A commit-then-reveal 6-digit comparison code (SAS) computed over both public keys and
    nonces.
  - An unknown key can only enter pairing.
- **Channels, all on one connection:**
  - The control stream (the first bidirectional stream): keys, buttons, switching, wheel, and
    movement while a button is held. It is reliable and ordered.
  - Unidirectional streams: AUX low-priority messages and BULK data (the clipboard), at most 4
    extra streams per direction. Stream priorities: control 2, AUX 1, BULK 0.
  - QUIC datagrams (RFC 9221): pointer movement while no button is held. They fall back to the
    control stream when they are over the size limit.
- **Transport parameters:** 1 s keep-alive, 5 s idle timeout, 5 s handshake timeout, and 256 KB
  datagram buffers.
- **Releasing held keys:** a separate switching heartbeat (500 ms, with a 2 s timeout) releases
  held keys when a peer goes silent. It does not depend on the QUIC idle timeout.
- **Platforms:**
  - macOS, Windows (x64, ARM64) and Linux (X11; GNOME and KDE on Wayland; UOS, Kylin, deepin).
  - HarmonyOS PCs can only be controlled. The OS refuses injection while the screen is locked or
    off, and the app has to be running.
  - Phone apps are in development.
- **Release status:** no installer is released yet, so there are no users and no pairings to
  migrate.

---

## 2. Decisions

These are fixed inputs for the work below.

| # | Decision |
|---|---|
| D1 | iroh is the connection layer for remote access |
| D2 | Stage 1: remote access through a second endpoint on iroh; the LAN stays on quinn. Stage 2: the LAN moves to iroh too, after the gates in 4.5 |
| D3 | Two licences are accepted as per-crate exceptions: `webpki-roots` (CDLA-Permissive-2.0), which `iroh-relay` and `n0-dns-resolver` require, and `attohttpc` (MPL-2.0), which the portmapper brings. The licences allow the UPnP / NAT-PMP / PCP portmapper; it stays off for privacy until upstream can keep UPnP to the gateway (3.5). Every other licence in the tree is already on Input Show's allowlist (`core/deny.toml`) |
| D4 | Device identity = Ed25519 public key = iroh `EndpointId` |
| D5 | Pairing with a typed address stays. Once the LAN path is on iroh, a short unauthenticated "who are you" exchange fetches the peer's key before dialing, and the 6-digit comparison follows as today. mDNS discovery and QR or invite codes are offered as well |
| D6 | Unattended access is off by default and switched on per device |
| D7 | The account may vouch for a remote pairing, through the guarded flow in 3.4 |
| D8 | The LAN performance gate: p99 latency grows by less than 1 ms; CPU grows by at most 3 points of one core per side at 1 kHz pointer input (an absolute threshold, not a relative one); no noticeable change in connection setup time |
| D9 | HarmonyOS is included. Remote access covers all four desktop platforms that Input Show runs on, HarmonyOS PCs (controlled only) among them |
| D10 | Self-hosted relays only. Whether an official hosted relay is offered is decided with V8's data |

---

## 3. Architecture

### 3.1 Layers

```text
Services     input · clipboard · screen · forward · ...
             (stream classes / ALPNs on one connection)
Connection   iroh Endpoint / Connection (noq QUIC; TLS 1.3, mutual raw public keys, end to end)
Paths        LAN direct │ hole-punched direct │ self-hosted iroh-relay (multipath, switched by iroh)
Control      gono-cloud: accounts, device directory, presence, authorization,
             address lookup, relay access control, audit
```

### 3.2 gono-cloud

| Component | Content |
|---|---|
| Device directory | New table `devices`: `id`, `user_id`, `endpoint_id`, `product` (input-show / gono-md / …), `platform`, `name`, `created_at`, `last_seen_at`, `revoked_at`, remote access policy |
| Registration | Reuses Login Flow v2 with its browser consent page. The device proves that it holds its key by signing a server nonce |
| Authorization | Who may connect to whom: devices of the same account by default. Unattended access is a per-device setting (D6) |
| Control channel | gono's own WebSocket (for example `/gono/v1/ws`), not notify_push, which is Nextcloud's protocol. It carries presence, connection requests, addresses, pairing requests (3.4) and revocations |
| Address lookup | Devices implement iroh's `AddressLookup` by asking over the control channel. The server returns addresses only for devices the caller is authorized to reach |
| Relay | Embeds `iroh_relay::server::Server`. `AccessControl` admits only registered, unrevoked `EndpointId`s; `ClientRateLimit` limits each client. `Limits::accept_conn_limit` is not implemented in 1.4.1, so new connections are limited at the reverse proxy or in `AccessControl` |
| Audit | Who connected to which device, when, direct or relayed, for how long and how much traffic. Never content |
| Two-factor authentication | Required for accounts with remote control enabled |
| UI | The account page lists the user's devices, their presence and revocation. The admin UI shows relay load and sessions (`RelayMetrics`): a Relay page at `/apps/manage/relay` with the settings, the counters, the connected devices, the reported sessions and the refused tombstones |

### 3.3 Devices

**The `gono-connect` crate** (MIT OR Apache-2.0, under `crates/client/` here) is the only place
that configures iroh. Products depend on it, never on iroh's multipath API directly, so that iroh
API changes stay inside one crate.

- **One endpoint constructor.** It holds the whole configuration of 3.5:
  - the `Minimal` preset;
  - our relay only;
  - DNS with no public fallback;
  - a fixed port where the product needs one.
- **Network changes.** On HarmonyOS the sandbox refuses the netlink `bind` (EACCES), so iroh
  cannot see network changes by itself. The product forwards its platform's network events to
  `Endpoint::network_change()`.
  - Input Show's core already notices a local network change within about 1 s by polling
    interfaces, which can drive this call.
  - Android needs the same.
  - With the events forwarded, a connection recovers 0.5–1.3 s sooner after Wi-Fi returns.
- **DNS on HarmonyOS.** The app sees a static `/etc/resolv.conf` that lists public resolvers, not
  the network's own DNS. Host names (the relay URL) must therefore go through the system resolver:
  a `DnsResolver::custom` backed by `getaddrinfo`.
- **Control channel client.** Sign-in, presence, connection requests, pairing requests, the
  `AddressLookup` implementation.
- **Product API.** It offers only "connect to a device" and "accept connections".

**In Input Show**, `inputshow-net` gets a second connection type behind one enum. The framing,
the channels and the ALPN `inputshow/1` stay the same. A quinn peer and an iroh peer cannot
complete a TLS handshake with each other, so the ALPN does not decide interoperability; a new ALPN
would only help diagnostics. The channels map one to one:

| Input Show | iroh |
|---|---|
| Control stream | `open_bi` / `accept_bi`, highest priority |
| AUX / BULK streams | `open_uni` / `accept_uni`, `SendStream::set_priority` |
| Pointer datagrams | `send_datagram` / `read_datagram`; `max_datagram_size` can differ per path |
| "Direct / relayed" in the UI | `paths()`: `is_relay()`, `is_ip()`, `is_selected()` |
| Bitrate control for screen viewing | `stats`, and `rtt` / `congestion_state`, which take a `PathId` |

### 3.4 Identity, pairing and trust

- **What pairing stores.** The peer's `EndpointId`, which is its device ID.
- **iroh needs the key before dialing.** The dialer puts the expected key into a server name
  that only its own verifier reads (iroh 1.4.1 sends no SNI, so an observer does not see which
  device is dialed), and the handshake fails on any other key; there is no accept-any mode.
  Consequences:
  - Devices found by mDNS dial directly, because the TXT record carries the full ID.
  - A typed address first goes through the "who are you" exchange (D5). It is unauthenticated: the
    6-digit comparison that follows authenticates the key.
- **The comparison code over a relay.** It stays sound: TLS is end to end and the code is bound to
  both keys. Input Show's pairing version 2 already mixes in the TLS exporter for channel binding.
- **Remote pairing**, for two devices that have never been on one LAN:
  - **In person:** a QR or invite code that carries the ID and addresses, then the comparison code.
  - **Vouched for by the account (D7).** A compromised server must not be able to add a device on
    its own:
    1. The new device registers with the account (Login Flow v2 and proof of its key).
    2. gono-cloud relays a pairing request to the account's devices. The server cannot complete
       the pairing itself.
    3. A device that is already trusted shows the new device's name, platform and ID, and the user
       approves it there. The approval is signed with that device's key. Every other device checks
       the signature against its own local trust list before accepting the new device.
    4. Every device of the account shows a notice when a device is added, and the audit log
       records it.
    5. The flow requires two-factor authentication and is rate limited. The target still applies
       its own policy, including D6.
  - **What a compromised server can still do.** It can deny service and lie about addresses. It
    cannot add a device without an approval signed by a device key the targets already trust.
    Phase 0 writes this down as part of the threat model.
  - **As specified** in `docs/connect-protocol.md` (section 8), step 3 includes the 6-digit
    comparison between the approving device and the new device over iroh, and the approval
    introduces in both directions. The protocol's section 8.7 explains why.
- **Revocation.** gono-cloud tells devices that a device was revoked, and the relay refuses the
  revoked key at once. Each device then removes the pairing.
- **While controlled.** The controlled device shows "being controlled by …" with one-click
  disconnect. The lock screen and Ctrl+Alt+Del (Input Show capability bit 7, `SECURE_DESKTOP`)
  are reachable remotely only when unattended access is on for that device.

### 3.5 Staying off n0's infrastructure

Measured with every socket call traced and DNS captured: a configured endpoint talks only to the
peer and our relay. The configuration:

```rust
// iroh 1.4.1: no relay unless given, no address lookup, no n0 preset.
let dns = iroh::dns::DnsResolver::builder()
    .with_system_defaults()
    .disable_fallback()                                     // never Cloudflare, Google or Quad9
    .build();                                               // HarmonyOS: DnsResolver::custom (3.3)
let ep = iroh::Endpoint::builder(presets::Minimal)          // a crypto provider only
    .alpns(vec![ALPN.to_vec()])
    .dns_resolver(dns)
    .clear_ip_transports()                                  // drops the default sockets of both families
    .bind_addr("0.0.0.0:0")?                                // stage 1: any free port; stage 2: 24850
    .bind_addr("[::]:0")?                                   // IPv6 too: one call per address family
    .relay_mode(RelayMode::custom([our_relay_url]))         // remote endpoint only
    .bind().await?;
```

Rules:
- Never `presets::N0`, `n0_dns()` or any other constructor that points at n0's services.
- `disable_fallback()` is required. Without it the resolver falls back to Cloudflare, Google and
  Quad9 (UDP 53, DoT, DoH) whenever the system resolver fails or cannot be read.
- Bind both address families. `clear_ip_transports()` removes the IPv4 and the IPv6 socket that
  the builder sets up by default, so an endpoint that binds only `0.0.0.0` gives up every IPv6
  path. IPv6 is common on mobile and home broadband networks in China and usually needs no NAT
  traversal, only a firewall hole, so it matters for the direct rate (V8). `bind_addr` is called
  at most once per address family; a second call for the same family gives undefined routing.
- Ports by stage. In stage 1 the LAN quinn endpoint keeps UDP 24850, so the remote endpoint
  binds port 0 and the OS picks a free port: hole punching and relaying need no fixed port. In
  stage 2 the single endpoint binds 24850 as today. Firewall rules that allow the program, not a
  port, cover both stages (V3).
- The LAN-only endpoint has no relay and no address lookup.
- The portmapper (D3) stays off for now. NAT-PMP and PCP talk only to the default gateway, but
  UPnP follows the `LOCATION` of whichever device answers its SSDP search first: any device on
  the LAN can make the endpoint send HTTP GET and SOAP requests to an address it names (Input
  Show's V4 test, 2026-11-16). Neither igd-next nor the portmapper crate checks that host
  against the default gateway, and iroh 1.4.1's `PortmapperConfig` has only `Enabled` and
  `Disabled`, so UPnP cannot be turned off alone (the portmapper crate itself could). It comes
  on once upstream either checks the `LOCATION` host or lets UPnP be turned off with PCP and
  NAT-PMP kept, and V4 is run again then.
- Metrics stay local; never the `iroh-services` crate.
- A CI test keeps this true across upgrades (QR). Endpoints run under strace, or in a network
  namespace with LAN-only routes, and the test fails on any destination other than the peer and
  our relay.

### 3.6 Deployment

**Self-hosted, one host.**
- `gono-cloud serve` includes the relay; `gono-cloud relay` runs it on its own. Both read a
  `[relay]` section of the configuration.
- The relay runs in plain-HTTP mode behind nginx or Caddy, which terminates TLS and forwards
  WebSocket upgrades on `/relay`. The relay's HTTP listener stays on loopback.
- iroh-relay 1.4.1 cannot sit under a URL path prefix, so it gets its own host name (for example
  `relay.example.com`).
- QUIC address discovery (QAD) needs the relay's own TLS certificate and public UDP 7842.
  `/generate_204` answers on plain HTTP, port 80 by default.
- Devices need outbound TCP 443 and UDP 7842.
- The existing systemd hardening applies unchanged: UDP is allowed, and ports above 1024 need no
  privileges.

**What this means for self-hosting.**
- **A second host name.** Remote access needs the relay's host name in DNS, a certificate for it,
  and UDP 7842 open in the firewall. The install script gets a `--relay-host` option,
  `docs/reverse-proxy.md` and `docs/deployment.md` get relay sections, and
  `gono-cloud config check` validates the relay settings. Without a relay host, gono-cloud runs
  as today and remote access is unavailable.
- **A public UDP socket.** QAD binds a public address. The `[relay]` section names that address
  itself; `server.allow_non_loopback_bind` keeps covering only the HTTP listener.
- **The certificate for QAD.** nginx owns the relay host's certificate, and the service user
  cannot read it: certbot keeps private keys readable by root only. A renewal hook copies the
  certificate and key into a directory the service can read (for example
  `/etc/gono-cloud/relay-tls/`, owned by root, group `gono-cloud`, mode 0640, like the
  configuration file), and the relay reloads them on an interval through iroh-relay's
  `reloading_resolver`. The relay's built-in ACME is no simple alternative: as far as its
  documentation shows, its challenges are answered on ports that nginx holds (to be confirmed in
  part 2a).
- **`/generate_204` must not be redirected.** The usual server block that redirects all of
  port 80 to HTTPS breaks this probe. On the relay host, port 80 forwards `/generate_204` to the
  relay and redirects everything else. Caddy, which redirects to HTTPS by default, needs the same
  exception.

**Hosts in mainland China.** Without an ICP filing, cloud providers intercept plain HTTP on port
80 for the domain (a redirect to a block page; the server logs the request as answered). So
certificates need DNS-01, and probes on port 80 are unavailable: `gono-connect` turns iroh's
captive-portal check off, which needs port 80 and whose answer only decides whether the next
network report is a full one. HTTPS on 443 and UDP 7842 were not intercepted (2026-11-16).
`docs/deployment.md` ("Hosts in mainland China") says this.

**Official hosted relays**: not before V8 (D10). When they come, the same binary runs as
`gono-cloud relay` in several regions. Their access control asks the control plane, or checks
tickets the control plane signed.

### 3.7 Changes to Input Show's protocol

| Item | Plan |
|---|---|
| Transport parameters | The LAN keeps today's values. The remote endpoint uses a 10–15 s handshake timeout and a 15–30 s idle timeout. Per-connection options in iroh are experimental, so the second endpoint carries the remote profile |
| Releasing held keys | Already independent of the connection (the 500 ms heartbeat, 2 s timeout). Check over a relay whether remote sessions need a longer timeout |
| The relay path is TCP | Over a relay, datagrams travel inside the WebSocket: in order, not lost, but held up behind earlier bytes. Prefer the direct path, and show "direct / relayed" in the UI |
| Absolute pointer | A new message and a capability bit, for screen viewing |
| Text from phone keyboards | `RemoteMsg::Text` (`0x0604`) in the reserved remote range, capability bit 8 `REMOTE_INPUT` |
| Screen stream | A new stream class with a raised per-direction stream limit. The control stream keeps the highest priority, and at most 1–2 frames are in flight: frames are dropped, not queued |
| Capability bits | New ones are allocated from bit 9 by NE |
| ALPN | Stays `inputshow/1` |

---

## 4. Phases

Phase 0, Phase 1, and parts 2a and 2c of Phase 2 start now and run in parallel. Part 2b starts
once Phase 0's specification is reviewed, because it implements those messages. Phase 3 needs 1
and 2; Phase 4 needs the gates listed in it. The sizes are estimates.

### 4.1 Phase 0: specification and threat model

- **Owner**: gono-cloud; Input Show NE reviews. About one week.
- **Work**:
  - the control channel messages: presence, connection requests, addresses, pairing requests and
    signed approvals, revocation;
  - device registration;
  - the authorization rules;
  - the audit records;
  - relay access control;
  - the guarded account-vouched pairing of 3.4;
  - two-factor authentication;
  - the trust model:
    - a malicious relay: what can it drop, delay or inject, and how far can the addresses it
      reports be trusted?
    - a compromised gono-cloud;
    - a malicious device on the LAN;
    - a leaked device key: is revocation complete?
- **Deliverables**: the protocol specification and the threat model under `docs/`.
- **Done when**: both projects have reviewed them.
- **Status**: drafted as `docs/connect-protocol.md` and `docs/connect-threat-model.md`, and
  reviewed by Input Show NE on 2026-11-16 (Input Show
  `docs/notes/NE-汇报-connect-protocol-review.md`); the review's changes are in both documents
  (threat model 9). Decided with the user: remote pairing gets a confirmation on the new device
  (F-02, the minimum fix rather than a code each way); devices remember consumed approvals
  (F-07); approvers cannot grant more than they hold stays a SHOULD (F-08). Decisions taken
  while drafting:
  - Remote pairing runs Input Show's 6-digit comparison (version 2, bound to the TLS exporter)
    between the approver and the new device over iroh, with the code typed on the approver.
  - The approval introduces in both directions, so the new device takes its peers' keys from
    the approver and not from the directory.
  - Only direct pairings vouch, one level deep.
  - Revocation is final for the key: the key is tombstoned, peers forget it on the LAN as well,
    and the step is confirmed twice.
  - Devices vouched for by a revoked device stay; revocation lists them and offers to revoke
    them too.
  - TOTP secrets are encrypted with a key file kept in the configuration directory.

### 4.2 Phase 1: remote prototype

- **Owner**: Input Show NE and QR; gono-cloud provides the test relay. About two weeks.
- **Work**:
  - On an Input Show spike branch (not merged), the second endpoint on iroh carries the same wire
    protocol. Addresses come from a stub directory.
  - The relay is the user's own `iroh-relay`, already deployed (decided 2026-11-15), with an allowlist or HTTP-callout access control.
  - V8 (section 5) on real networks:
    - home broadband from China Telecom, China Unicom and China Mobile;
    - 4G and 5G;
    - campus and corporate networks;
    - cross-border.
  - V2 in the real product port: Input Show's latency and resource suites (`perf_latency`,
    `perf_resources`) run through two nodes, plus BULK throughput.
  - On HarmonyOS, the two conditions of 3.3, in the probe build.
  - The CI test of 3.5.
- **Deliverables**: the spike branch, a V8 report, V2 numbers for the real port, and the CI test
  merged into Input Show.
- **Done when**:
  - keyboard and mouse work remotely through the relay and directly;
  - V8 gives enough data to estimate relay bandwidth.

### 4.3 Phase 2: device directory and relay in gono-cloud

- **Owner**: gono-cloud. About five to six weeks, in three parts. An earlier estimate of three to
  four weeks left out that two-factor authentication is a feature of its own.
- **2a. Relay (V6).** Starts now; it does not depend on Phase 0. About one and a half weeks.
  **Implemented** (`crates/server/relay`); what is still open is listed under V6 in section 5.
  - `gono-cloud relay`, also embedded in `serve`, configured by a `[relay]` section;
  - dependency check against axum 0.8, hyper, tokio and rustls;
  - a static musl build;
  - running behind nginx;
  - `AccessControl`, first fed from a static allowlist, then from the directory (2b);
  - `ClientRateLimit`;
  - `RelayMetrics` in the admin UI;
  - the existing systemd hardening;
  - the self-hosting details of 3.6: the public UDP socket for QAD, the certificate hand-over
    through a renewal hook and `reloading_resolver`, the nginx and Caddy configuration with its
    `/generate_204` exception, the install script's `--relay-host`, the relay sections of
    `docs/reverse-proxy.md` and `docs/deployment.md`, and `config check` for the relay settings;
  - a load test: memory for 1000 idle clients, CPU per Gbps relayed.
- **2b. Directory and control channel.** Starts once Phase 0's specification is reviewed. About
  two to three weeks. **Server side implemented** ahead of the review (`crates/protocol`,
  `crates/server/connect`): registration, the control channel, presence, `connect` / `lookup`,
  pairing requests and approvals, session reports, revocation from the account page, the admin
  UI and the CLI, relay admission from the directory, the audit log. Remote access needs the
  `two_factor` table, which part 2c fills. **`gono-connect` implemented** (`crates/client/connect`):
  the endpoint of 3.5 (both address families, IPv4 alone where IPv6 is missing; the system's
  DNS without fallback, or `getaddrinfo` for HarmonyOS), registration, the control channel with
  reconnects, and iroh's `AddressLookup` through it. An end-to-end test runs `gono-cloud serve`
  with two such devices that register, connect by device ID alone and see a revocation made
  with the CLI. Revocation delay and lookup latency are measured on the test host (V7):
  `lookup` takes 3.4 ms at the server, and a CLI revocation reaches the relay, the device and
  its peers about 1.5 s later. Still open: latency from devices on real networks (V8), and the
  product's side of pairing (Phase 3).
  - the `devices` table;
  - registration;
  - the control channel `/gono/v1/ws`;
  - presence and address lookup (V7);
  - revocation pushed to devices and to the relay;
  - audit;
  - the account page;
  - the `gono-connect` crate (3.3).
- **2c. Two-factor authentication.** Starts now and runs alongside 2b. About one and a half to two
  weeks. **Implemented**: TOTP with recovery codes, the second step at `/login/two-step` for every
  web sign-in, enrolment and renewal on the account page, resets in the admin UI and the CLI,
  the secrets encrypted with `two_factor.key_file`, which the install script creates. Remote
  access now works end to end for accounts that turn it on.
  - TOTP with recovery codes;
  - the second step at every web sign-in: the file UI, the admin UI and Login Flow v2's consent
    page (app passwords of devices are unaffected);
  - resets by an admin and through the CLI;
  - required for accounts with remote control enabled (3.2).
- **Deliverables**: merged code with acceptance tests, and the updated install script and
  documentation.
- **Done when**:
  - an unauthorized device cannot obtain other devices' addresses;
  - a revocation takes effect at the relay, with the delay measured;
  - an outage of gono-cloud does not affect LAN use;
  - a fresh install with `--relay-host` behind nginx answers the relay's own probes:
    `/generate_204` on port 80, and QAD on UDP 7842 with the copied certificate, also after a
    renewal;
  - two-factor authentication is live for remote-control accounts.
- **Status** (2026-11-16, test host and tests):
  - Unauthorized devices: covered by the tests of `crates/server/connect` and the review of
    the implementation (threat model 9).
  - Revocation at the relay: measured. With the CLI it takes 1.5 s (V7); from the web UI it
    should be immediate, which is not measured yet.
  - Outage: the direct connection of two devices on the host's network survived 30 s
    without the server (V7).
  - Fresh install behind nginx: the probes answer on the test host (V6) and in the install
    test under the hardened unit (`test-relay.sh`), which also renews the certificate and
    checks that QAD serves the new one without a restart. A renewal on the test host is still
    to be observed: the one forced on 2026-11-16 failed at the CA's HTTP-01 check, outside
    gono-cloud, and the panel's own is due about 2027-01-15.
  - Two-step verification: live (2c).

### 4.4 Phase 3: remote access in Input Show

- **Owner**: Input Show NE and the platform UI lanes, with gono-cloud. About four weeks.
- **Product work:**
  - The remote endpoint goes into the product through `gono-connect`.
  - Sign-in in the apps.
  - A remote device list.
  - A "direct / relayed" indicator.
  - Pairing by QR or invite code, and account-vouched pairing (3.4).
  - The unattended-access setting.
  - The "being controlled" notice with disconnect.
  - Channel binding in the comparison code (done: pairing version 2 binds the code to the TLS
    exporter).
  - The remote transport profile.
- **Checks:**
  - V3: builds and permissions on every platform;
  - V9: the security review, finished before release;
  - V11: phones.
- **Done when**: keyboard, mouse and clipboard work across the internet on:
  - macOS, Windows and Linux;
  - HarmonyOS, as the controlled side;
  - a phone, as the controller.

  The security review must also be signed off, and two-factor authentication must be live.

### 4.5 Phase 4: the LAN path onto iroh

- **Owner**: Input Show NE and HM. A few weeks.
- **Gates**, all required:
  - V2 in the real port meets D8.
  - The HarmonyOS conditions of 3.3 are in production code.
  - The CI test of 3.5 is green.
  - No serious V9 finding is open.
- **Work:**
  - the "who are you" exchange for typed addresses (D5);
  - rewriting dialing (iroh dials an `EndpointAddr`'s candidates itself, and identity moves into
    TLS);
  - rewriting path diagnostics, reconnects and the network watcher;
  - the accept loop and its limit on pending handshakes;
  - the security tests and fuzz targets;
  - mDNS results feeding iroh's `MemoryLookup` (`iroh-mdns-address-lookup` is not used);
  - removing the quinn endpoint.
- **Done when**: Input Show runs on one stack and its LAN tests and performance suites pass.

### 4.6 Later phases

- **Traversal tuning.** A NAT matrix in CI (network namespaces with nftables: cone, restricted,
  symmetric, double NAT, CGNAT, UDP blocked, IPv6 only, dual stack, hairpinning), tuning from V8,
  and the decision on official hosted relays (D10).
- **Screen viewing.** Computers as the controlled side; confirmation on the spot, the
  "being controlled" indicator, audit; adaptive bitrate; phones as controllers and viewers.
- **Port forwarding and other products.** Private port forwarding between devices; gono.md
  receives real-time events over the control channel; multi-region relays.

---

## 5. Checks

| Check | Status | What remains | Owner | Needed for |
|---|---|---|---|---|
| V1 HarmonyOS | **Passed in the app.** iroh 1.4.1, unpatched. Bind, direct dial (10.6 ms), inbound dial-back. Relay first, then the direct path selected about 0.1 s later. One connection survives Wi-Fi off and on. No socket option refused | The two conditions of 3.3 in production code. GSO stays off on the HarmonyOS kernel (a version check in noq-udp), which does not affect input | HM | Phase 1, Phase 4 |
| V2 LAN performance | **Transport level at parity.** Wi-Fi datagram RTT p50 2.91 ms (quinn) vs 2.98 ms (iroh), p99 within radio noise. Loopback p99 +0.015–0.044 ms. CPU +1 to +2.5 points of one core per side at 1 kHz. Memory +5–7 MiB per process. Connection setup about +1 ms | The real product port, BULK throughput, HarmonyOS | NE, QR | Phase 4 |
| V3 Platform builds and permissions | Not started | Every platform builds. Windows firewall rules for the same executable on IPv4 and IPv6. iOS Local Network permission (LAN path only). Android background rules | NE, platform lanes | Phase 3 |
| V4 No n0 services | **Passed for a configured endpoint** (3.5). Only the peer and our relay are contacted, and no host name containing `iroh` or `n0` is queried | The CI test; macOS and Windows; a network switch; 30 minutes idle; IPv6 bound (3.5). The portmapper stays off: its UPnP follows any SSDP answer on the LAN (3.5); V4 runs again once upstream fixes that. The DNS fallback to public resolvers shows only on a fast failure (REFUSED, SERVFAIL, NXDOMAIN, no nameserver); `disable_fallback()` holds in each | QR | Phase 1 (CI), Phase 3 |
| V5 API | **Covered by reading the code.** Everything in 3.3 exists, and so do per-path idle and keep-alive defaults | In Phase 1: exercise unidirectional streams and `set_priority` under multipath; serve several ALPNs on one endpoint | NE | Phase 1 |
| V6 Relay in gono-cloud | **Part 2a implemented.** `gono-server-relay` runs iroh-relay 1.4.1 in `serve` and as `gono-cloud relay`: plain HTTP on loopback, QAD with a certificate reloaded from disk, a static allowlist, a per-connection rate limit, counters in the admin UI, `--relay-host` in the installer. **Measured** (macOS, Apple silicon, loopback): two devices relayed through nginx and through Caddy with TLS terminated there, the documented blocks (the handshake falls back to its challenge round trip, as expected); 1000 idle devices take about 26 KiB each (10 → 36 MiB); about 21 Gbit/s in 12 KB frames for about 2.2 cores, so roughly 0.1 core per Gbit/s; the static musl binary grows from 13.7 to 20.3 MB; one version each of tokio, hyper, rustls and axum. iroh-relay warns once per dropped packet (120 MB of log in ten seconds of overload), so its log level is `error`. 2b feeds `AccessControl` from the directory. **Deployed** (2026-11-15) on a test host: Debian 13 on Tencent Cloud Shanghai, behind an existing nginx managed by the BT panel, with `--relay-host`. Every check of `docs/reverse-proxy.md` passes (`/generate_204` answers its challenge over plain HTTP; HTTPS, the relay WebSocket and the control channel upgrade), and devices learn the host's public address through QAD on UDP 7842. The panel renews the certificate itself, so a systemd path unit copies it into `relay-tls/` instead of a certbot hook. **Install test under the hardened unit** (2026-11-16, `packaging/server/test-relay.sh`, CI job `relay`; `test-in-container.sh` runs it in a throwaway systemd container): a fresh install with `--relay-host` behind nginx with the blocks of `docs/reverse-proxy.md`, the certificate handed over by the certbot hook of `docs/deployment.md`. `/generate_204` answers its challenge on port 80 without a redirect; HTTPS and the relay WebSocket work; QAD on UDP 7842 serves the copied certificate over IPv4 and IPv6; a renewal reaches QAD within one reload interval, without a restart. Passed in rootless podman on Ubuntu 26.04 (an Ubuntu 24.04 container; every hardening option applied except `ProtectHostname`, which a container cannot give; exposure 1.2); not yet run on GitHub. **Found and fixed:** the panel writes `fullchain.pem` and then `privkey.pem` in place, and the path unit fires on the first, while iroh-relay's `reloading_resolver` serves any pair it reads: a copy made between the two writes would have broken QAD until the daily copy and the next reload, up to a day. The relay now reloads the files itself and serves a pair only once the key belongs to the certificate (tested, also end to end). The documented port 80 block redirected ACME challenges to the relay, which broke `certbot --webroot` renewals; it now serves them from a webroot. **Load on Linux** (Ryzen 7 8745HS, Ubuntu 26.04, loopback, method as on macOS, `crates/server/relay/examples/relay-probe.rs`): the released static musl build with mimalloc idles at 22 MiB, and 1000 idle devices take about 35 KiB each; overloaded with 12 KB frames it delivers 10.6 Gbit/s for 1.95 cores (0.18 core per Gbit/s); paced without loss, 1 Gbit/s takes 0.27 cores and 5 Gbit/s 0.94 cores. A glibc build: 11–12 MiB idle, 24–26 KiB per device, 9.4 Gbit/s for 2.06 cores; paced 0.26 and 1.00 cores. So about 0.2 core per Gbit/s on Linux, twice the overloaded macOS figure. **Renewal on the test host:** the certificate (TrustAsia, 2026-11-15 to 2027-02-12) is due for renewal about 2027-01-15 (the CA's renewal window, the panel's daily run). A renewal forced on 2026-11-16 failed at the CA's HTTP-01 check: the panel's own handler answered the challenge with 200, but the CA read no body ("reader size limit exceeded"), so something between nginx and the CA cut the response; the relay's blocks were not involved | The `relay` job on GitHub Actions. The renewal on the test host is covered by the install test's renewal instead (decided 2026-11-16). From outside, port 80 of the test host's names is intercepted (no ICP filing), so `/generate_204` over plain HTTP and HTTP-01 fail there. Follow-up: before mid-January 2027, move the test host's certificates to DNS-01 or decide otherwise; the relay's certificate expires on 2027-02-12 | gono-cloud | Phase 2 |
| V7 Address lookup | **LAN decided**: mDNS feeds `MemoryLookup`. **Measured on the test host** (2026-11-15, `crates/client/connect/examples/probe.rs`, five rounds). Both devices ran on the host and reached the server through its public name, nginx and TLS, so the numbers leave out the network's round trip; a device elsewhere adds about one round trip to `connect` and `lookup`. Results: `connect` p50 5.1 ms; `lookup` p50 3.4 ms, p95 3.6 ms, max 8.5 ms (250 lookups); channel open to `welcome` p50 25 ms; dial 6.7 ms, direct on the first path. **Revocation with the CLI:** the command exits after 17 ms, and the server acts at its next pass over the event log (every 2 s). A's channel closes with `4003`, the relay drops A, and B gets `device.revoked`, within 5 ms of each other and 1.49–1.53 s after the command; the relay refuses A's retries from then on. Revocations in the web UI wake the server at once instead (not measured). **Outage of 30 s:** the direct connection kept working (60 of 60 pings); the `502` answers while the server was down were retried, never taken as signed out; the channels were back 8–11 s after the restart (reconnect backoff), the relay 11–13 s. **Fixed while measuring** in `gono-connect`: the HTTPS client offered `h2` without HTTP/2 support and crashed against nginx; addresses were not coalesced, so the 1-per-second limit dropped the public address QAD found; and they were not published again after a reconnect | Latency from devices on real networks (V8); the cache across its 10-minute lifetime; that no address reaches a log (S3 holds by reading the code) | gono-cloud, NE | Phase 2 |
| V8 NAT traversal | Not started | Time to first use (relayed), time to direct, share of connections and bytes that go direct, fallback time when the direct path breaks, Wi-Fi ↔ cellular handover, input latency relayed and direct, the share of direct connections that use IPv6. Two devices behind one NAT must connect directly. For the IPv6 share: iroh ignores unique-local IPv6 addresses while there is IPv4 (netwatch takes ULA only when nothing else is left), so a LAN with ULA IPv6 alone gets no IPv6 direct path, while home networks with global IPv6 do; count the two apart. For the design: iroh keeps one state per remote endpoint, so a second connection to the same device rides on the path the first selected (dial the family to measure first); after a link goes down, iroh briefly advertises loopback addresses (Input Show's V4 test). For the firewall matrix: **a direct path that is one-way during the handshake stops the connection, relay or not** (reproduced by gono-cloud, 2026-11-16, iroh 1.4.1 with and without `gono-connect`): when the accepting device refuses outbound UDP (a host firewall; `sendmsg` returns EPERM), or the dialer's inbound UDP is dropped, and the dialer knows a direct address, `connect` times out although both ends hold the relay; a relay-only dial works at once, and so do a dead path in both directions and a silent inbound drop at the acceptor. An upstream issue is drafted. **A fallback in gono-connect** (2026-11-16, measured on loopback): redialing relay-only after a stuck handshake does not help, because iroh keeps the peer's direct address in its per-peer state, sends every Initial to all known paths, and forgets the peer only after 60 s without a connection (a relay-only redial works after 65 s, not after 3 s); no API drops a peer's paths. The reverse order works: dial relay-only first and let iroh's NAT traversal inside the connection find the direct path (connected in about 1 ms, direct after 11–13 ms on loopback; both one-way cases connect, twice in a row; with no filter the second connection starts direct). As a default it changes what V7 measured (a direct first path), needs the control plane's direct addresses only as a fallback when the relay fails (protocol 7.4: new connections during an outage use cached addresses), and waits for a decision. **Recovery of a relay-only session after a network change** is 1.6–13.4 s on HarmonyOS (HM, 2026-11-16), with or without `network_change()`: iroh's relay connection retries with an exponential backoff (10 ms to 16 s, jitter, no limit) that keeps growing while the network is down, and a network change neither resets it nor ends the wait (the check is ignored while dialing or backing off). The backoff is not configurable and gono-connect cannot replace the relay actor, so the fix is upstream (drafted); measure it in V8 | QR, NE | Phase 1, D10 |
| V9 Security review | **Known:** no third-party audit and no SECURITY.md for iroh or noq. Three GitHub advisories fixed in 1.1.0, one of them high (a crafted relay frame blocks a client's relay traffic). A pre-authentication relay crash, fixed in 1.0.2, was disclosed only in a blog post. `cargo audit` does not map quinn advisories onto noq | Review `tls/verifier.rs`, the relay trust model and address handling. Find out whether iroh and noq are fuzzed. Consider a paid audit shared by both projects. **NE's review (2026-11-16):** the verifier is sound for dialing by key; resumption and 0-RTT are on by default, and products never use 0-RTT; the relay can affect availability only; iroh filters no address, and a peer that completes a handshake can make the accepting device probe up to 32 addresses of its choice per round (gono-connect filters what the control plane hands out and closes strangers right after the handshake; threat model 5.6); property tests only, no continuous fuzzing. Still open: upstream issues for an address filter on NAT-traversal frames and a switch that holds NAT traversal until the application accepted the peer; for the portmapper, a check that the UPnP `LOCATION` host is the default gateway (igd-next, portmapper) or a `PortmapperConfig` that turns UPnP off (iroh), since UPnP is a request-forgery primitive on the LAN (fixed GET paths and SOAP bodies to any address a LAN device names); fuzz targets for iroh-relay's frame decoder (before authentication on gono-cloud's public port) and noq-proto's frame decoder, which belong upstream because both decoders are private to their crates; the paid audit | NE, gono-cloud | Before Phase 3 ships |
| V10 Maintenance | **Known:** majors get 1 year of full support (maintenance up to 3 years); minors get 3 months (up to 1 year). 2.x stays compatible on the wire with the non-deprecated parts of 1.x. About 7 core authors. noq takes quinn's fixes through periodic syncs | Upgrade at least every three months, reading quinn's advisories and noq's sync merges each time | NE | Ongoing |
| V11 Phones | Not started | iOS background suspension and reconnect. Android Doze: shut the endpoint down in the background, or keep it in a foreground service. Battery cost of the keep-alive during sessions | MB | Phase 3 |
| V12 Dependencies and size | **Measured:** with only `tls-ring`, +6.4 MB on macOS and +8.9 MB on HarmonyOS (stripped); default features add about 2 MB more. +155–170 crates. One "unmaintained" notice (`paste`, RUSTSEC-2024-0436, through netlink). Licences as in D3 | The final feature list: `tls-ring`, the portmapper (D3), `metrics` off unless needed; find out what `fast-apple-datapath` does on Apple platforms before keeping it | NE | Phase 3 |

---

## 6. Risks and mitigations

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | The HarmonyOS conditions (network events, system DNS) are missed in production code | HarmonyOS reconnects slowly, or asks public resolvers | Both conditions live in `gono-connect`/`inputshow-net`, and Phase 4 is gated on them |
| R2 | The privacy promise depends on configuration, and a future minor release may add new defaults | Traffic or metadata reaches third parties | One endpoint constructor holds the whole configuration (3.5); the CI test runs on every upgrade |
| R3 | noq is a single-vendor fork: quinn's fixes arrive late, and `cargo audit` cannot see them | Late security fixes | Pin versions; read advisories and noq's sync merges at each upgrade; upgrade at least every three months; isolate behind `gono-connect` |
| R4 | No third-party audit | Unknown flaws | V9 before Phase 3 ships; a paid audit if needed |
| R5 | +155–170 crates and +6–9 MB | Supply chain, app size on phones | Lean features; per-crate licence exceptions only (D3) |
| R6 | CPU +1 to +2.5 points of a core, memory +5–7 MiB | Battery on laptops and phones | D8 gate in the real port; in stage 1 only remote sessions pay it |
| R7 | Dialing needs the key | Typed-address pairing changes | The "who are you" exchange (D5) |
| R8 | The relay path is TCP | Pointer stalls under loss on relayed sessions | V8; prefer direct paths; show "direct / relayed" in the UI |
| R9 | NAT conditions in China: CGNAT is common, and some networks throttle UDP | A lower direct rate, higher relay cost | V8; IPv6 bound on every endpoint (3.5); relays close to users; bitrate caps on relayed paths; D10 |
| R10 | Remote control raises the stakes: account takeover, a compromised server vouching for a fake device, unattended access | Abuse | Signed approvals from an already-trusted device (3.4); two-factor authentication; notices on every device; audit; unattended access off by default |
| R11 | Background limits on phones | Phones are poor controlled devices | Computers are controlled; phones control and view |
| R12 | Remote access makes self-hosting harder: a second host name and certificate, UDP 7842, a certificate hand-over, a port-80 exception; in mainland China, port 80 intercepted for domains without an ICP filing | Fewer self-hosters enable it; relays that half work (QAD failing after a renewal, probes redirected); certificates that cannot renew over HTTP-01 | The installer's `--relay-host`, documentation (DNS-01 for unfiled mainland hosts), `config check`, the relay's own probes in part 2a's done criteria (3.6, 4.3), the install test under systemd, and devices that need no port 80 (no captive-portal check) |

---

## 7. Fallbacks

| Case | Fallback |
|---|---|
| The Phase 4 gates fail | Stay at stage 1: quinn on the LAN, iroh for remote. A device that comes home reconnects on the LAN (about 15 ms) |
| HarmonyOS cannot meet its conditions in production | HarmonyOS stays on quinn on the LAN, and its remote access waits |
| V4 cannot be kept across upgrades | Pin the last version that passes. Do not ship remote access with an endpoint that contacts third parties |
| iroh becomes unusable | Option A′: quinn plus a packet-forwarding relay in gono-cloud, without hole punching. Fine for input, expensive for screen viewing. Option A: our own path layer below quinn, months of work |
| Users who need remote access before Phase 3 | Their own VPN (Tailscale, WireGuard, ZeroTier) with a manually entered address already works, with no code |

---

## 8. Open questions

- Is screen viewing in a browser needed? If so, WebRTC comes in for that path.
- Does gono.md need direct device-to-device connections (LAN sync, large files)?
- What are the relay bandwidth quotas and rate-limit policy?
- Remote access to a Windows PC that nobody is signed in to needs Input Show's optional logon-time
  core, with its own endpoint and relay access. Is it in scope for the first release?

---

## 9. References

- [Iroh 1.0 - Dial Keys, not IPs](https://iroh.computer/blog/v1)
- [noq, noq, who's there?](https://iroh.computer/blog/noq-announcement)
- [iroh 1.0.2](https://iroh.computer/blog/iroh-1-0-2), [iroh 1.0.3 - Steadier Connections](https://iroh.computer/blog/iroh-1-0-3)
- [iroh release policy](https://docs.iroh.computer/about/release-policy)
- [iroh security advisories](https://github.com/n0-computer/iroh/security/advisories)
- [n0-computer/iroh (GitHub)](https://github.com/n0-computer/iroh), [iroh-relay README](https://github.com/n0-computer/iroh/tree/main/iroh-relay)
- [iroh documentation (docs.rs)](https://docs.rs/iroh/1.4.1/iroh/), [iroh::address_lookup](https://docs.rs/iroh/1.4.1/iroh/address_lookup/index.html), [iroh_relay::server](https://docs.rs/iroh-relay/latest/iroh_relay/server/index.html)
- [TLS verifier of iroh 1.4.1](https://docs.rs/crate/iroh/1.4.1/source/src/tls/verifier.rs)
- [RFC 7250: raw public keys in TLS](https://www.rfc-editor.org/rfc/rfc7250), [RFC 10069: Multipath QUIC](https://www.rfc-editor.org/rfc/rfc10069)
- [Rust platform support: OpenHarmony](https://doc.rust-lang.org/nightly/rustc/platform-support/openharmony.html)
- [Input Show](https://input.show)
