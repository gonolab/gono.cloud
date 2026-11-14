# Gono Connect: Threat Model

- Status: draft for review. This is Phase 0 of `plan/remote-connect-iroh.md`.
- Covers: [connect-protocol.md](connect-protocol.md), the control protocol (version 1). Section
  numbers in the form "protocol 8.5" point into it.
- Reviewers: gono-cloud, and Input Show NE.

This document lists what remote connectivity has to protect, from whom, and what each
adversary can and cannot do under the protocol. The rules it depends on are collected as
requirements (S for the server, C for devices) in section 7, and the risks that remain are
listed in section 8.

---

## 1. Scope

**Covered:**
- gono-cloud's control plane: registration, directory, control channel, pairing, revocation,
  audit and two-step verification;
- its embedded iroh relay;
- the device side of these as `gono-connect` and Input Show implement it, in stage 1: remote
  access on a second endpoint on iroh, with the LAN still on quinn.

**Taken as given:**
- **TLS 1.3 and the iroh handshakes** work as specified. Dialing by key fails on any other
  key, and the relay handshake proves the client's key.
- **Input Show's pairing protocol** (version 2: commit-then-reveal, with the code bound to the
  TLS session's exporter) gives a man in the middle one chance in 10^6 per attempt.
- **Devices that are not compromised** do what this document requires of them.

**Not covered:**
- Input Show's LAN threat model, except where remote access changes it (5.3);
- WebDAV and the files of an account;
- screen viewing and port forwarding, which come later;
- the security of the operating systems.

---

## 2. System and trust boundaries

```text
            ┌─────────────────────────── gono-cloud host ───────────────────────────┐
 browser ──TLS──▶ reverse proxy ──▶ gono-cloud: pages, /gono/v1/*, directory, audit,  │
 device  ──TLS──▶ (nginx, Caddy)    two-step verification, SQLite                     │
 device  ──TLS──▶ reverse proxy ──▶ embedded iroh relay (WebSocket); QAD on UDP 7842  │
            └───────────────────────────────────────────────────────────────────────┘
 device ◀════════ iroh connection: TLS 1.3 between the device keys, end to end ════════▶ device
         (directly, after hole punching, or through the relay, which sees only ciphertext)
```

| Boundary | What crosses it | Protection |
|---|---|---|
| Device ↔ gono-cloud | Credentials, statements, directory, addresses | TLS at the reverse proxy; an app password plus a signature by the device key (protocol 5.2) |
| Browser ↔ gono-cloud | Password, second step, consent, revocation | TLS; session cookie; CSRF tokens; a strict CSP |
| Device ↔ relay | Encrypted QUIC packets labelled with endpoint IDs | TLS (relay host name); key proven in the relay handshake |
| Device ↔ device | Input, clipboard, pairing | TLS 1.3 with raw public keys, end to end |
| Device ↔ its own storage | Device key, trust list, app password | The operating system (C13) |

---

## 3. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| **The ability to control a computer** | Keys typed, pointer, clipboard, and later the lock screen: whoever has it owns the computer | The target's trust list and permissions |
| Device keys | They make a device what it is to every peer; they can sign approvals | On each device |
| Trust lists | Who may control whom | On each device |
| Account credentials | Web password, TOTP secret, recovery codes, sessions | gono-cloud; the user's authenticator |
| Device app passwords | Control channel access (only together with the key) | Devices; gono-cloud stores digests |
| Session content | Keys, clipboard text (passwords!) | Only in transit, end to end |
| Metadata | Which devices exist, presence, IP addresses, who talks to whom and when, traffic volumes and timing | gono-cloud (memory and audit log), the relay, the network |
| Availability | Remote access when the user needs it; LAN use always | Everything |

---

## 4. Security goals

| # | Goal |
|---|---|
| G1 | Only devices in a target's own trust list, with the matching permission, can control it |
| G2 | Neither the relay nor the network can read or change what devices send each other |
| G3 | A compromised gono-cloud cannot add a device to any trust list |
| G4 | A revoked device loses relay access and the control channel at once, and every device that learns of the revocation stops trusting it on every path |
| G5 | Addresses of a device go only to devices of its own account, and each first disclosure is recorded and announced to the target |
| G6 | Taking over remote access needs the account password and a second factor, and even then it gives no device trust |
| G7 | LAN use works without gono-cloud and reveals nothing to it |
| G8 | Metadata is kept to what the features need, and content never reaches the server |

---

## 5. Adversaries

Each subsection lists what the adversary can do, what it cannot do, the mitigations, and what
remains.

### 5.1 A malicious relay

The relay of a self-hosted install runs inside gono-cloud, so a malicious relay usually means a
compromised gono-cloud (5.2). This subsection covers what the relay position alone gives,
which also applies to an attacker who controls only the relay host, and to a future hosted
relay.

**It can:**
- **see metadata:**
  - the endpoint IDs of connected devices (proven), and their client IP addresses;
  - who sends to whom, since the destination ID labels every frame;
  - packet sizes, timing and volumes;
- drop, delay or throttle relayed traffic, and close relay connections;
- send frames that claim to come from any endpoint ID, since the relay sets that label;
- **lie in QUIC address discovery** (QAD), reporting a false observed address;
- answer `/generate_204` falsely;
- refuse admission.

**It cannot:**
- **read or change session traffic.** QUIC packets are protected by keys that only the two
  devices hold. A forged or altered packet fails authentication and is dropped.
- **impersonate a device.** A connection attempt "from" endpoint X still has to complete a TLS
  handshake with X's key.

**Addresses: how far can they be trusted?** Not at all, and they need not be (rule 3 of
protocol 1.1).
- A QAD answer and a lookup result are only candidates. iroh validates a path with a
  challenge inside the authenticated connection before it uses it.
- So a false address can only make hole punching fail, which keeps the session on the relay.
  It can also make a device send a few probe packets to an address the attacker picked.
- iroh bounds how many probes it sends, so this is a weak reflection and not an amplification.

**Mitigations:**
- end-to-end TLS (G2), and dialing by key (C2);
- held keys are released by Input Show's switching heartbeat (500 ms, released after 2 s of
  silence), so dropped or delayed traffic cannot leave a key pressed down;
- relay frames' source labels are used only for routing, never for identity (C2).

**Remaining:**
- **Keystroke timing.** Packet timing on a relayed (or any observed) path reveals when keys
  are pressed, which is known to leak information about what is typed, passwords included.
  This is not specific to the relay: any on-path observer of a direct path sees the same.
  V9 should evaluate padding or batching of key events on remote sessions (8, R1).
- **Metadata** of who talks to whom and when (8, R2).

### 5.2 A compromised gono-cloud

This covers an attacker with control of the gono-cloud process, its database or its host, and
an operator who runs gono-cloud for other people and turns malicious.

**It can:**
- **deny service:** refuse sign-ins, hide devices, drop the control channel, stop the relay;
- **lie about the directory:** invent devices, rename them, show false presence and false
  settings;
- **lie about addresses** (5.1);
- **send false events:**
  - fabricate pairing requests, which makes approval prompts pop up on the user's devices;
  - announce false `incoming` connections;
- **hold back or delay** revocations, approvals and notices;
- **revoke devices.** This only removes trust, but revoked keys never come back, so the user
  has to re-pair those devices;
- **read metadata:** devices, presence, addresses, the audit log;
- **phish the account.** It serves the sign-in page, so it can capture the password and a live
  second-step code;
- register devices of its own into an account, and turn the second step off;
- read TOTP secrets, given the key file (protocol 13.6) as well, which root has;
- read and change the account's files over WebDAV (outside this document).

**It cannot:**
- **add a device to any trust list.** A device accepts a newcomer only through an approval
  signed by one of its own direct pairings (protocol 8.5). That approval is signed only after
  that device's user typed a 6-digit code shown on the newcomer. The code is bound to the
  end-to-end TLS session, and a key substituted by the server fails it.
- **pass off a forged key to a newcomer.** The newcomer N learns its peers' keys from the
  approval, which the approver signed, and not from the directory (protocol 8.4). Without this,
  a compromised server could hand N a false "Home PC" key, and the user would type passwords
  into the attacker's endpoint.
- **read or change session traffic**, or impersonate a device (5.1).
- **use a fabricated pairing request to get anything signed.** The approver dials the key in
  the request and runs the comparison code with it. The attacker's endpoint can complete the
  code only if the user types a code that the attacker's screen shows, which the user cannot
  see (but see 5.5 for social engineering).

**Mitigations:**
- devices decide trust locally (C1), verify every statement (C3), and take nothing on the
  server's word except revocation (C7);
- the approval mechanism of protocol 8;
- notices on devices that are added (C10);
- the revocation status per device, so the user can see which device has not applied a
  revocation (S13).

**Remaining:**
- **Withheld revocations.** A compromised server can keep a revocation from reaching devices
  (6, R3).
- **Metadata** and denial of service (R2, R6).
- **Collusion with a malicious directly paired device** (5.8).

### 5.3 A malicious device on the LAN

Stage 1 leaves the LAN path on quinn with Input Show's existing protections: TLS with raw public
keys, "accept, then check", and unknown keys limited to pairing. Remote access adds no LAN
listener.

**It can:**
- **spoof mDNS records:** claim another device's name, or announce another device's ID with its
  own address;
- send pairing requests to show prompts (UI spam);
- observe metadata on a shared network, block UDP, and try ARP spoofing;
- in stage 2, lie in the unauthenticated "who are you" exchange (plan D5).

**It cannot:**
- **impersonate a device.** A spoofed record leads to a handshake that fails against the
  expected key.
- **get trust** without the 6-digit code confirmed by the local user.
- **reach the control channel**, since that needs account credentials and a registered key.

**Interaction with remote access.**
- **LAN-paired devices from outside the account.** A LAN-paired device that is not in the
  account, such as a colleague's computer, is a direct pairing. Through an honest server it
  cannot vouch for anyone, because the server accepts approvals only from devices of the
  account (protocol 8.6). Through a compromised server it can (5.8).
- **mDNS reveals endpoint IDs.** The full device ID is in the TXT record (`_inputshow._udp`),
  so anyone who has shared a LAN with a device knows its endpoint ID. That is why endpoint IDs
  are treated as public (5.6).

**Remaining:** prompt spam, limited by Input Show's rate limits; LAN metadata.

### 5.4 A leaked device key

This covers a device that is stolen while unlocked, malware on a device, a key file in a backup
or a synced folder, and the administrator of a shared computer. The app password is usually
stored next to the key and leaks with it.

**With the key, the attacker can:**
- **impersonate the device to every peer that trusts it**, and control those peers as far as
  their permissions allow. This is the main danger;
- **sign approvals.** If the device is a direct pairing of other devices, the attacker can
  introduce devices of its own to them;
- **use remote access as the device** until it is revoked, if it also has the app password:
  open the control channel, use the relay, read presence, and get addresses through `connect`,
  which is recorded and announced to the target.

**Revocation** (protocol 9):
- **Second confirmation.** It is confirmed twice, because it is permanent.
- **On the server:**
  - the key becomes a tombstone;
  - the app password is deleted;
  - the control channel closes with `4003`;
  - the relay disconnects the key at once (protocol 11.2);
  - `connect`, `lookup` and registration refuse the key.
- **On the devices:** every device that learns of it closes its sessions with the key and
  removes it from its trust list, LAN pairings included.

Section 6 analyses whether that is complete.

**Approvals the key signed:**
- **After the revocation**, they are refused: the server does not accept `pair.approve` from a
  revoked device, and devices check their revoked set (protocol 8.5, check 4).
- **Before the revocation, and already applied:** they **stay** (protocol 8.7). Devices that an
  attacker introduced with a stolen key in the time before the revocation remain trusted by
  the devices that accepted them. The mitigations are:
  - each such approval showed a notice "X was added by <revoked device>" on every device that
    accepted it (C10);
  - the revocation's confirmation step lists every device that the revoked device introduced
    and offers to revoke them as well (protocol 9.1);
  - the revocation notice on each device lists its entries vouched by the revoked device and
    offers to remove them (protocol 9.3).

  This is accepted as R4. The alternative, removing vouched trust automatically, was weighed
  and not chosen, because it makes every lost phone cost the user all the pairings it ever
  approved.

**A key that leaked without anyone noticing** (copied by malware) is never revoked. These help
the user notice:
- **On the target:** the "being controlled by …" notice with one-click disconnect (C9).
- **In the audit log:** session reports with their path.
- **Flapping:** two copies of a device keep replacing each other's control connection from
  different addresses, which is recorded as `device.flapping` (S14).

**Protection of the key.** C13.

### 5.5 Stolen account credentials

| What the attacker has | What it gives |
|---|---|
| The web password only, two-step verification on | Nothing beyond the failed second step. The user sees "your password was entered correctly" on the account page (protocol 13.3) |
| The web password only, no two-step verification | The account's files (outside this document) and no remote access, which is unavailable without verification. The attacker could enrol verification and lock the user out; an admin reset restores the account. Every user should enrol |
| A device's app password only (a proxy log, a leaked config) | No file access (protocol 4.5). No control channel either, since `hello` needs a signature by the device key (protocol 5.2) |
| Password and a live second-step code (real-time phishing) | A web session: register devices, revoke devices (each confirmed twice), turn verification off, read the audit log and presence. **No device trust:** pairing still needs the comparison code on a device of the user's |

**Social engineering remains** (R5):
1. The attacker starts a registration at the real server, sends the user the login URL, and
   the user grants it. The consent page shows the device's short ID and a warning (S9).
2. The attacker then sends a pairing request, and gets the user to approve on their phone and
   to type the code that the attacker reads out over the phone.

The comparison code stops a man in the middle; it does not stop a user who is persuaded to
approve the attacker's own device. The approval prompt says "approve only a device you have
with you right now", the added device is announced on every device, and the audit log records
it.

### 5.6 Other accounts and strangers on the relay

**The relay does not separate accounts** (protocol 11.3). Any admitted endpoint can address any
other endpoint by its ID, and IDs are effectively public (5.3). So a device of another account
on the same server can:
- make a device run TLS handshakes, which costs CPU and could fill its handshake queue;
- try to show it a pairing prompt, which C8 forbids on the remote endpoint;
- learn whether a device is connected to the relay, from the relay's "peer gone" answers.

**On the control plane**, nothing crosses accounts: devices of another account get
`not_found`, and no addresses (S8).

**Mitigations:**
- the remote endpoint closes unknown keys right after the handshake, with one exception: the
  pairing connection that the server announced for a pending request (C8);
- limits on pending handshakes and on the handshake rate (C8);
- admission only of registered devices of accounts with two-step verification (S7), so the
  people on a self-hosted relay are the operator's own users.

**Remaining:** handshake load, and presence probing by other users of the same server (R7).

### 5.7 Network attacker

This covers anyone on the path: public Wi-Fi, an ISP, a state.

- **Protected:** the control channel, the consent pages and the relay run over TLS; QAD runs
  over QUIC with the relay's certificate; sessions are end to end.
- **What remains visible:**
  - the host names in TLS SNI (the cloud host and the relay host);
  - timing and volumes (5.1).
- **Possible attacks:**
  - blocking UDP, which forces sessions onto the relay. Over TCP, pointer movement stalls
    behind lost packets (plan R8);
  - blocking the relay, which ends remote access;
  - spoofing DNS, which fails against certificate validation;
  - spoofing the plain-HTTP `/generate_204` answer, which affects only iroh's network report,
    not security.

### 5.8 A trusted peer that turns malicious

A device in a target's trust list can do what its permissions allow, which is the point of
pairing. What remote access adds:
- **It can vouch**, if it is a direct pairing of the target and a device of the same account.
  This is by design (protocol 8).
- **A direct pairing from another account**, such as a colleague's computer paired on the
  office LAN, could vouch only if the server delivered its approval. An honest server refuses
  approvals from devices outside the account (protocol 8.6). A compromised server would
  deliver it, and the target would accept it, because the `account` field is self-asserted.
  This needs a compromised server and a malicious paired device acting together (R8).
- **Mitigations:** notices (C10); the setting that turns acceptance of vouched devices off
  (protocol 8.5, check 8).

### 5.9 Denial of service against gono-cloud

| Target | Limit |
|---|---|
| Registration starts (anonymous) | Per-address limiter and a cap on pending flows, as in Login Flow v2 |
| Control channel handshakes | Credentials checked at the upgrade with the failure limiter; 10 seconds to send `hello` |
| Messages | Size and rate limits (protocol 15) |
| Relay connections | Each costs a signature check before admission. The reverse proxy limits new connections (`docs/reverse-proxy.md`) |
| The second step | Per-account failure limits (protocol 13.3) |
| Database growth | Rate limits bound audit records; event and audit retention; at most 50 devices per account |

### 5.10 Dependencies

iroh and noq are young, have had no third-party audit, and noq takes quinn's fixes late (plan
V9, R3, R4).

Mitigations:
- pinned versions;
- reading the advisories at every upgrade, at least every three months;
- keeping iroh behind `gono-connect`;
- the CI test that a configured endpoint contacts no one but the peer and our relay (plan
  3.5).

---

## 6. Is revocation complete?

**When X is revoked:**

| Path X could use | Effect | Delay |
|---|---|---|
| Our relay | Disconnected at once and refused from then on | Measured in part 2b; expected well under a second |
| Control channel | Closed with `4003`; credentials deleted | Immediate |
| Registering again with the same key | Refused for good (tombstone) | Immediate |
| `connect`, `lookup` | Refused, as caller and as target | Immediate |
| Peers that are connected to gono-cloud | Remove X from their trust lists, LAN pairings included, and close sessions | Seconds |
| Peers that are offline | Remove X when they next connect: the snapshot in `welcome` holds every tombstone | Until they reconnect |
| Sessions already running | Relayed ones are cut by the relay. Direct ones end when the target applies the revocation | As the rows above |
| Approvals X signed later | Refused by the server and by every device that knows | — |
| Approvals X signed earlier, already applied | **Kept** (R4); listed for removal at revocation | — |

**Gaps:**
1. **A peer that has not heard yet.** X can still reach it on paths that do not go through our
   relay:
   - the LAN, if X is on the same network;
   - a direct address X learned earlier, if the peer is reachable without hole punching (a
     public IPv6 address with an open firewall, or a port that UPnP mapped).

   This lasts until the peer reconnects to gono-cloud. During an outage of gono-cloud it lasts
   until the outage ends. C14 bounds it: a device refuses remote sessions when its last
   `welcome` is older than 24 hours. That turns a long outage into a loss of remote access, but
   not of LAN use, and Input Show decides it (protocol 16).
2. **A compromised server that withholds the revocation.** Peers never hear of it. What helps:
   - the per-device revocation status on the account page (S13), which an honest server shows
     truthfully;
   - every device's own "forget this device".

   A revocation signed by a device, which would also travel between devices directly, is an
   open question (protocol 16).
3. **Devices outside the account** that paired with X on a LAN, such as a colleague's
   computer, never hear of the revocation. Their users have to forget X themselves.
4. **A key that leaked without anyone noticing** is never revoked (5.4).

**To measure in 2b:**
- the time from the confirmed revocation to the relay disconnect;
- the time to `revocations.applied` from a connected peer.

---

## 7. Requirements

These are the rules the analysis depends on. V9, the security review, checks each one.

### 7.1 Server (gono-cloud)

| # | Requirement | Protocol |
|---|---|---|
| S1 | `connect`, `lookup`, pairing and relay admission only for accounts with two-step verification | 4.2, 10, 11.1 |
| S2 | Statements are stored and relayed byte for byte; the server never creates or alters one | 2.3 |
| S3 | Device addresses live in memory only: never in the database, the audit log or the server log | 7 |
| S4 | The first disclosure of a device's addresses to a peer is a recorded `connect` that the target is told about | 7.2, 7.3 |
| S5 | Every statement is verified before it is stored or relayed | 2.3 |
| S6 | Revocation needs a second confirmation. It then tombstones the key, deletes the app password, closes the control channel, disconnects the relay at once, refuses the key everywhere, and pushes the event | 9.1, 9.2, 11.2 |
| S7 | The relay admits only active devices of accounts with two-step verification, besides the static list. A device that stops being admissible is disconnected at once | 11 |
| S8 | No answer tells a device anything about another account (`not_found`) | 5.3, 10 |
| S9 | Registration proves the key, with the server origin and a fresh challenge signed. The consent page shows product, platform, name and short ID with a warning. Nothing reveals before consent whether an endpoint is registered | 4 |
| S10 | The limits of protocol 15 | 15 |
| S11 | TOTP codes cannot be replayed; failures are limited per account; secrets are encrypted with a key outside the database directory; recovery codes have 80 bits and are stored as digests | 13 |
| S12 | The audit log records the events of protocol 12, and never content or device addresses | 12 |
| S13 | Each device's application of each revocation is shown on the account page | 9.3 |
| S14 | One control connection per device, with repeated replacement from different addresses recorded | 5.1 |

### 7.2 Devices (`gono-connect`, Input Show)

| # | Requirement | Protocol |
|---|---|---|
| C1 | The trust list is local. The server's directory is never a source of trust | 1.1, 8 |
| C2 | Peers are dialed by key. Keys come from the trust list or from a verified approval, never from the directory alone. Addresses and relay source labels are never identity | 1.1, 8.4 |
| C3 | Every statement is verified strictly, with all checks of protocol 8.5. Vouching goes one level deep | 2.3, 8.5 |
| C4 | Remote pairing uses Input Show's pairing protocol (version 2, bound to the TLS exporter), with the code typed on the approver | 8.2 |
| C5 | On a revocation: add the key to the revoked set, close sessions, remove the entry (LAN pairings included), list the entries it vouched for and offer to remove them, and report `revocations.applied` | 9.3 |
| C6 | On `4003`: stop using the credentials and never register the key again. On `503` or `1011`: never treat it as signed out | 5.1, 5.4, 9.3 |
| C7 | Nothing is granted because of `incoming`, presence, or any claim the server makes; revocation is the only thing taken on the server's word | 7.2 |
| C8 | On the remote endpoint, keys outside the trust list are closed right after the handshake. The only exception is the pairing connection that `incoming` announced for a pending request. Pending handshakes and the handshake rate are limited | 8.2, 11.3 |
| C9 | `accept_remote` and unattended access (plan D6) are enforced on the device. The controlled device shows "being controlled by …" with one-click disconnect | 6.1 |
| C10 | Every device added by an approval is announced on the device that accepted it, naming the approver. A setting turns acceptance of vouched devices off | 8.5 |
| C11 | Only remote sessions are reported; LAN sessions never are | 12.2 |
| C12 | Logged events are processed in order, and the cursor is stored only after acting on them | 5.6 |
| C13 | The device key and the app password are kept in the operating system's protected storage where it has one: Keychain; DPAPI, or TPM-backed storage, on Windows; a key wrapped by the Android Keystore; HUKS on HarmonyOS. Otherwise a file with mode 0600, as Input Show does today | — |
| C14 | (SHOULD) Remote sessions are refused when the last `welcome` is older than 24 hours (configurable). LAN use is unaffected | 16 |
| C15 | The iroh endpoint is configured as in plan 3.5, with exactly the discovery document's `relay_url` | 3 |
| C16 | Every signature made with the device key outside TLS and iroh uses a context of protocol 2.3. No data from the server is ever signed as it is | 2.3 |

---

## 8. Accepted residual risks

| # | Risk | Why it is accepted | Follow-up |
|---|---|---|---|
| R1 | Keystroke timing on observed paths | It is inherent to low-latency input, and the same for direct paths | V9 evaluates padding or batching of key events on remote sessions |
| R2 | Metadata: the relay and gono-cloud see who talks to whom and when | Self-hosted, the operator is usually the user | Retention limits (protocol 12.1) |
| R3 | A compromised server can withhold revocations | Revocation needs a channel. The status on the account page and the local "forget" help | Revocation signed by a device (protocol 16) |
| R4 | Devices introduced by a key that later turns out to have leaked stay trusted | The user chose not to remove vouched trust automatically. Revocation lists those devices and offers to revoke or remove them | Watch for confusion in the UI; reconsider after Phase 3 |
| R5 | Social engineering of the remote pairing | No code stops a user from approving the attacker's own device | Prompt wording; notices; audit |
| R6 | Denial of service by the server or the network | Availability against a compromised server is not a goal | — |
| R7 | Other users of the same relay can cause handshakes and probe presence | iroh-relay 1.4.1 decides per connection | Per-pair policy on hosted relays |
| R8 | A compromised server together with a malicious directly paired device from another account can introduce devices | It needs two parties; the approval is announced | — |
| R9 | A peer that has not heard of a revocation can be reached directly by the revoked key | Bounded by C14 | Measure the delays in 2b |

---

## 9. Review

The two projects review this document together with the protocol. In particular, Input Show NE
reviews:
- C4, C8, C9, C10 and C13 against `inputshow-net`, `inputshow-config` and the platform lanes;
- the trust-list fields of protocol 8.1;
- the default of the setting that turns acceptance of vouched devices off;
- whether to adopt C14.

The review is done when both projects have signed it off (plan 4.1).
