# Changelog: Gono Cloud server

All notable changes to the Gono Cloud server (the `gono-cloud` binary and the crates under
`crates/server/`) are recorded here. Server releases are tagged `server-v<version>` (see
`docs/repository-layout.md`); the release workflow takes the release notes from this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The protocol stays backward
compatible within a major version: released clients keep working with newer servers.

## [Unreleased]

### Added

- A relay through which devices (Input Show, and later other Gono products) reach each other
  across the internet when they cannot connect directly: the iroh relay (`iroh-relay` 1.4.1),
  configured by a new `[relay]` table and off by default. `serve` runs it when
  `relay.enabled` is true, and `gono-cloud relay` runs it alone on a host of its own. It serves
  plain HTTP on `relay.bind` (`127.0.0.1:16103`) behind the reverse proxy, which needs a host
  name of its own for it (`relay.public_url`); QUIC address discovery (`relay.qad_bind`, UDP
  7842) uses a copy of that host name's certificate (`relay.tls_cert`, `relay.tls_key`) and
  reads it again every `relay.tls_reload_interval_secs`, taking a renewal up once the key
  belongs to the certificate (a hook caught between copying the two files leaves the previous
  pair in service, with a warning in the log). Only the devices listed in
  `relay.allowed_endpoints` may connect; `relay.max_client_bytes_per_sec` limits each
  connection. The packets are encrypted end to end between the devices. The admin UI's
  overview shows the relay, and its Relay page (`/apps/manage/relay`) the settings, the
  counters, the devices connected right now, the sessions devices reported with their path,
  and the revoked devices that tried to connect; `config check` shows its settings, and the
  install script takes
  `--relay-host` for fresh installs. See "The relay" in `docs/deployment.md` and
  `docs/reverse-proxy.md`. The binary grows by about 6.6 MB (static Linux build).
- Remote access for devices, the server side of `docs/connect-protocol.md`: with the relay
  enabled and an https `base_url`, `serve` answers under `/gono/v1/`. Devices register through
  the browser like a Nextcloud client (`/gono/v1/login`), proving their Ed25519 key; the consent
  page names the device and its short ID. A registered device gets a credential without file
  access, keeps a control channel open (`/gono/v1/ws`, a WebSocket the reverse proxy must
  forward like `/push/ws`), sees the account's other devices and their presence, gets their
  addresses only through recorded connection requests, and passes pairing requests and signed
  approvals between devices. The relay admits these devices besides `relay.allowed_endpoints`.
  Only accounts with two-step verification on have remote access. The account page lists the
  devices, and stops remote access for one that stays in use ("Stop remote access" signs it
  out, keeping its pairings);
  revoking one (account page, admin UI, `gono-cloud device revoke`) is final for its key, needs
  a second confirmation, disconnects it at once and tells the account's other devices. A device
  that signs out stays listed as signed out and can still be revoked; its key can register
  again only into the same account. Revoked keys stay revoked after their account is deleted,
  and the name of a deleted account that registered devices cannot be given to a new account
  (pairing statements name the account by it). An audit log records registrations, revocations,
  connection requests, pairings and reported sessions.

- **Two-step verification** (TOTP) of web sign-ins. Users turn it on on the account page with a
  QR code and keep ten recovery codes; every web sign-in (file UI, admin UI, the sign-in pages of
  Nextcloud apps and devices) then asks for a code at `/login/two-step`. Codes work once;
  wrong codes lock the step of the account for a while, and the account page shows them and
  the use of recovery codes. Turning it on ends the account's other browser sessions. Admins
  reset it in the admin UI, operators with `gono-cloud user reset-two-factor`. The secrets are
  encrypted with a key in the configuration directory, `two_factor.key_file`
  (`two-factor.key`), which the install script, `init` and `serve` create when missing; back it
  up with the configuration. App passwords are unaffected.
- **An S3-compatible API** (`docs/s3.md`), built on s3s 0.17: a bucket is a folder of its
  owner's tree, so files uploaded through S3 appear in WebDAV, the Nextcloud clients and the web
  file UI, and theirs in S3. Configured by a new `[s3]` table and off by default; `serve` runs it
  on `s3.bind` (`127.0.0.1:16104`) behind a host name of its own (`s3.public_url`). Clients sign
  with SigV4 (headers and presigned URLs, `aws-chunked` bodies with trailer checksums) using
  access keys created on the account page, in the admin UI or with `gono-cloud s3 key`; their
  secrets are encrypted with `two_factor.key_file`, which the S3 API therefore requires.
  Buckets are created there, with `gono-cloud s3 bucket`, or with `CreateBucket` (in
  `s3.bucket_folder`, `Buckets/` by default), or bound to existing folders. Objects keep their
  MD5 ETag, content type, user metadata and checksum until they are overwritten other than
  through S3; listings come from the metadata database in S3 key order; multipart uploads are
  staged in `s3-uploads/` of the data directory; completing one renames the first part into
  place and appends the others, on Linux with `copy_file_range` (shared data on XFS and btrfs). With `s3.allow_anonymous`, bucket owners can
  publish objects uploaded with the `public-read` ACL or a whole bucket, and allow anonymous
  listings; anonymous requests only read. With `s3.virtual_host_domain`, buckets are also
  addressed by host name (`<bucket>.s3.example.com`, virtual-hosted style; wildcard DNS and
  certificate needed), and path style keeps working. Browser applications get per-bucket CORS
  rules (`PutBucketCors`, `GetBucketCors`, `DeleteBucketCors`; preflight requests are answered
  before s3s) and form uploads signed with a POST policy (`PostObject`, with the `acl` field
  that s3s does not read itself). Large copies use `UploadPartCopy` (whole objects or byte
  ranges); a repeated `CompleteMultipartUpload` (a retry after a lost answer) gets the first
  answer again, as from S3. Writes take the conditions `If-None-Match` (`*` or an ETag) and
  `If-Match` (an ETag or `*`). `ListBuckets` answers in pages. In `us-east-1`, a `CreateBucket` of one's own bucket
  succeeds and resets the bucket's ACL, as in S3. Responses carry a request id
  (`x-amz-request-id`, and `RequestId` in error documents), which the request log records.
  `ListObjectVersions` lists each object as its only version, `null` (versioning is
  never enabled), which cleanup tools need. Keys need not be in Unicode NFC (names from older
  macOS are NFD): the tree stores the NFC name and S3 keeps the key's spelling
  (`files.s3_path`), in listings too. `mc anonymous set download` and `none` work: the anonymous-download bucket policy
  maps onto the bucket's anonymous access, and other policies answer `NotImplemented`. The web
  file UI offers "Copy public link" for files anyone can download through S3. The `mtime`
  metadata of rclone and other sync tools becomes the file's modification time, so WebDAV and
  the Nextcloud clients see the original time. The `gono_cloud` capability tells the Gono
  client the S3 endpoint, region and addressing (`gono_cloud.s3`). The acceptance suite drives
  it with the AWS SDK, and CI with the AWS CLI, rclone, mc and restic
  (`acceptance/scripts/s3-clients.sh`) and a selection of Ceph's s3-tests
  (`acceptance/scripts/s3-tests.sh`).

### Changed

- **Rust 1.100** is needed to build from source (the newest stable release; s3s needs 1.96).
  CI no longer checks a separate minimum version, and release builds use 1.100.0.
- `config check` and `serve` no longer warn about an empty `relay.allowed_endpoints`, since
  `serve` admits the registered devices; `gono-cloud relay` on a host of its own still does.
- The credentials of devices registered for remote access are not listed among app passwords,
  and cannot be deleted as app passwords.

- **The database schema is one file again**, `0001_initial.sql`, which also holds the tables of
  remote access (the device directory, its event log, the audit log, two-step verification).
  There are no production deployments yet, so the schema is edited in place until the first
  one; migrations become append-only from then on. A database created by an earlier version
  is refused (its migration checksums differ) and must be created again with
  `gono-cloud init`.
- The web admin UI moves to `/apps/manage/` by default (`admin.path`), next to the web file UI
  and the account page; `admin.path` may now be `/apps/manage` although `/apps` is otherwise
  reserved. Configurations that set `path` keep their path: the one written by the install
  script of 1.0 to 1.2 sets `path = "/gono-admin"`; change it to `"/apps/manage"` or remove the
  line to move the admin UI, and adjust reverse proxy rules that restrict the old path.

- Database writes queue at an in-process write gate before they take a connection, instead of
  waiting in SQLite's busy handler while holding one: under many parallel uploads, reads
  (listings, PROPFIND, downloads) no longer wait for writers, and writes no longer come near
  `db.busy_timeout_secs`. With 256 parallel S3 uploads, reads during the burst took 0.2 ms at
  the median instead of 56 ms, and the longest write transaction 1 s instead of 3.3 s.

### Fixed

- The web file UI cut off the menu of the last files of a short folder at the bottom of the
  list, so their actions (rename, move, delete, and now "Copy public link") could not be
  reached there.

## [1.2.0] - 2026-11-12

A web file UI and account page in the browser, and every page in English or Chinese. There are
no database migrations. Upgrading turns the web file UI on: configurations written for 1.x have
no `[files_ui]` section, so `/` now leads to the sign-in page; add `[files_ui]` with
`enabled = false` to keep it off. The admin UI keeps its setting where the configuration sets
`enabled` in `[admin]`, as the one written by the 1.x install script does (`enabled = false`).

### Added

- A web file UI at `/apps/files/` (`/` leads there), on by default (`files_ui.enabled`). Users
  sign in at `/login` with their web login password and can browse, sort and search by name,
  preview images, video, audio and text, download files and folders (folders and selections
  as streamed `.zip` archives), upload (a form without JavaScript; drag and drop, folders and
  resumable chunked uploads with it), create folders, rename, move and delete (one or many
  entries), and mark favorites, which the apps see too. Everything works without JavaScript.
  Every change is a WebDAV operation of the server itself, so ETags, file ids, locks and
  notify_push behave as for the clients. User files never open as part of the site: downloads
  are attachments, and only images, video and audio are shown inline, with a type the server
  chooses.
- An account page at `/apps/account/`: users change their display name and web login password
  (the other browser sessions end) and create, view and revoke their own app passwords.
- Every browser page, the admin UI included, follows the browser's language (English or
  Chinese) and offers a light, dark or system theme.
- `/index.php/apps/files/` (Nextcloud's web address, which the apps link to) leads to the web
  file UI.

### Changed

- The web admin UI is on by default (`admin.enabled = true`). Installations that rely on the old
  default and do not want it must set `enabled = false` in `[admin]`.
- Every HTML page (sign-in, Login Flow, admin UI) has a new look and a shared masthead. Pages
  load one stylesheet and one script from `/apps/assets/` under content-hashed names; the
  Content-Security-Policy allows exactly that script by a per-response nonce and still no
  inline styles or scripts.

## [1.1.1] - 2026-11-11

Security fix for the direct download links added in 1.1.0. Every installation of 1.1.0 should
upgrade; there are no database migrations.

### Security

- User files no longer open as part of the site. Direct download links need no credentials and
  served a file with its own type, so a user could send an administrator a link to an HTML file
  whose scripts then ran on the server's origin, with the administrator's web session and
  access to the admin UI. File downloads through WebDAV and direct links are now sent with
  `Content-Disposition: attachment` (named after the file, not the link's token), and every
  response of the WebDAV routes and of direct links carries
  `Content-Security-Policy: default-src 'none'; sandbox` and `X-Content-Type-Options: nosniff`.
  1.0.0 had no direct links; its WebDAV downloads lacked these headers too, but reached a
  browser only with the file owner's app password.

## [1.1.0] - 2026-11-11

Fixes for the Nextcloud mobile apps found by testing them against 1.0.0, media streaming and
rclone uploads. Upgrading applies two database migrations; going back to 1.0.0 afterwards needs
the database backup that the install script takes before the upgrade (see "Upgrading" in
`docs/deployment.md`).

### Added

- Chunked upload accepts chunks named by byte range (`<start>-<end>`, the end inclusive), as
  rclone's Nextcloud backend sends them, so that `rclone` with `vendor = nextcloud` can upload
  files larger than its chunk size. The ranges must cover the file from byte 0 without gaps or
  overlaps; a session holds either numbered chunks or byte ranges.
- Direct download links (`POST /ocs/v2.php/apps/dav/api/v1/direct`, then
  `GET /remote.php/direct/<token>` without credentials), through which the Nextcloud mobile
  apps stream video and audio that is not downloaded yet; before, such files did not play. A
  link expires after 8 hours (at most a day) and ends with the app password that asked for it
  or the file it names.

### Changed

- The install script is attached to releases as `cloud.server.sh` instead of `install.sh`, and
  `https://gono.dev/cloud.server.sh` redirects to the one of the newest server release. Release
  1.0.0 carries both names.
- The server reports Nextcloud 32.0.0 instead of 30.0.0 in `status.php` and the capabilities.
  Nextcloud Android 35 no longer says the server has reached end of life and no longer
  lowercases the extensions of uploaded files.
- Large folders list much faster: dead properties are loaded once per entry and per listing in
  batches instead of one query per requested property and entry (20,000 entries with the
  Nextcloud iOS app's properties: 2 s instead of 15 s).
- The XML of WebDAV responses is gzipped for clients that send `Accept-Encoding: gzip`, as
  Nextcloud does for `PROPFIND` (a listing of 20,000 photos: 0.9 MB instead of 69 MB). File
  downloads are never compressed.

### Fixed

- Nextcloud Android can list the folders of users whose name contains `@`: hrefs leave `@`,
  `:`, `(` and `)` unencoded, as Nextcloud does, instead of writing `%40`, which the app could
  not match against the user name.
- A database error while checking credentials answers `503` instead of `401`. After a `401`
  the Nextcloud iOS app deleted the account from the device and Nextcloud Android discarded
  the stored password. The web login says the server is temporarily unavailable instead of
  "wrong username or password".
- Valid app passwords keep working from an address that has used up its failed attempts; only
  further wrong credentials get `429`. Before, one failing client (an old device, a WebDAV app
  set up with the web login password) locked out every device behind the same address. The web
  login has a limiter of its own.
- `PROPFIND` with `Depth: infinity` is answered like `Depth: 1`, as Nextcloud does, instead of
  `403`. Folders made available offline in the Nextcloud iOS app downloaded nothing.
- Uploads keep the creation time clients send in `X-OC-CTime`, reported as
  `nc:creation_time` and settable with `PROPPATCH` (a database migration adds the column).
  Nextcloud Android reported files that were already on the server as conflicts, for example
  after a reinstall or a lost response; images can still conflict, because their dimensions
  are not reported.
- A `MOVE` that assembles a chunked upload session without any chunk is refused with `400`
  unless a length of 0 was announced. Before, it replaced the destination with an empty file.

## [1.0.0] - 2026-11-10

First release of the rewrite on top of [dav-server-rs](https://github.com/messense/dav-server-rs).
It shares nothing with the legacy `v0.1.x` releases: there is no migration path from them, and
their tags stay as they are.

### Added

- WebDAV under `/remote.php/dav/files/<user>/` (and `/remote.php/webdav/`): `PROPFIND`, `GET`,
  `HEAD`, `PUT`, `MKCOL`, `COPY`, `MOVE`, `DELETE`, `PROPPATCH`, `LOCK` and `UNLOCK`, with
  Nextcloud live properties, `OC-*` headers, directory ETag propagation and lock timeouts.
- Nextcloud client protocol: `status.php`, capabilities and the OCS user endpoints, favorites
  with the `filter-files` REPORT, chunked upload v2, and Login Flow v2 with an explicit consent
  page that mints one app password per device.
- notify_push: real-time change notifications over WebSocket (`/push/ws`).
- Multiple users with web login passwords (Argon2) for the browser and app passwords for devices,
  optionally read-only, expiring or limited to mounted folders.
- Web admin UI (`admin.enabled`, `admin.path`): server overview, accounts, admin role, display
  names, web login passwords and app passwords.
- Command line: `init`, `serve`, `config check`, `user` (add, list, delete, set-password,
  enable, disable, promote, demote, set-display-name), `app-password` (add, list, delete) and
  `rescan` for files changed directly in the data directory.
- At least one enabled admin always remains: disabling, demoting or deleting the last one is
  refused.
- Management commands and `serve` refuse to run as root on an installation that belongs to the
  service user, so they cannot leave files behind that the service cannot write.
- Release archives for Linux (x86_64, aarch64; fully static musl binaries with mimalloc that run
  on any distribution, without glibc) and macOS (Apple silicon, Intel) with a hardened systemd
  unit, a launchd job (`cloud.gono.server`) and an install script
  that verifies the archive, creates a service user, runs `init` on fresh installs, backs the
  database up before upgrades and never deletes data when uninstalling.
- Documentation: deployment (`docs/deployment.md`), reverse proxies (`docs/reverse-proxy.md`),
  v1 scope and the mobile test checklist.

[Unreleased]: https://github.com/gonolab/gono.cloud/compare/server-v1.2.0...HEAD
[1.2.0]: https://github.com/gonolab/gono.cloud/compare/server-v1.1.1...server-v1.2.0
[1.1.1]: https://github.com/gonolab/gono.cloud/compare/server-v1.1.0...server-v1.1.1
[1.1.0]: https://github.com/gonolab/gono.cloud/compare/server-v1.0.0...server-v1.1.0
[1.0.0]: https://github.com/gonolab/gono.cloud/releases/tag/server-v1.0.0
