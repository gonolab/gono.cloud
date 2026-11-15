-- Schema of Gono Cloud.
--
-- Rules that apply to this file and every later migration:
--
-- 1. One file until the first production deployment. Gono Cloud has no production deployments
--    yet, so the whole schema lives in this file and is edited in place; a database created
--    from an older version of the file must be created again (sqlx refuses it, because the
--    file's checksum changed). From the first production deployment on, migrations are
--    append-only: a published migration is never edited, reformatted or renamed, schema
--    changes go into a new, higher-numbered file, and `crates/server/core/tests/migrations.rs`
--    pins the checksum of every published migration.
--
-- 2. `rel_path` columns use BINARY collation (spelled out explicitly below). Paths compare
--    byte-for-byte; `Foo` and `foo` are different files.
--
-- 3. Subtree ("prefix") queries use a half-open range, never LIKE:
--
--        rel_path >= 'a/' AND rel_path < 'a0'
--
--    '0' is the byte after '/'. LIKE treats '_' and '%' in file names as wildcards and is
--    case-insensitive for ASCII in SQLite, so it matches unrelated rows.
--
-- Conventions:
--
-- - `rel_path` is relative to the owner's root: no leading or trailing slash, '' for the root.
-- - Timestamps named `*_at` are UNIX seconds (UTC). `mtime_ns` is UNIX nanoseconds.
-- - Booleans are INTEGER 0/1 with a CHECK constraint.
-- - Secrets (app passwords, session cookies, Login Flow tokens, recovery codes) are stored only
--   as SHA-256 digests (32-byte BLOBs). They are high-entropy random tokens, so a fast hash is
--   enough and lookups are a single indexed equality match.
-- - Tables are STRICT so SQLite enforces the declared column types.

-- Server-wide settings that are generated once and must stay stable for the lifetime of the
-- installation.
CREATE TABLE settings (
    name  TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- Instance id in the Nextcloud format: "oc" followed by ten lowercase characters. It is the
-- suffix of every `oc:id` (`<zero-padded file id><instance id>`), which clients use to tell
-- files of different servers apart.
INSERT INTO settings (name, value) VALUES ('instance_id', 'oc' || lower(hex(randomblob(5))));

-- Accounts. Users authenticate devices with app passwords; the web login password below is
-- used only for the server's HTML pages (sign-in, Login Flow v2, the file and admin UIs).
-- Ids of accounts, credentials, sessions and devices are AUTOINCREMENT: in-memory state keyed
-- by them (the control channel, pending sign-ins, the "shown once" pages) must never carry
-- over to a newer row that reuses a deleted one's id.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Validated by `gono_server_core::Username`: lowercase ASCII, appears verbatim in DAV URLs.
    username      TEXT    NOT NULL UNIQUE COLLATE BINARY,
    display_name  TEXT    NOT NULL,
    -- Argon2id PHC string of the web login password.
    password_hash TEXT    NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
) STRICT;

-- Per-device credentials, minted by Login Flow v2, device registration, the CLI or the web
-- admin UI.
CREATE TABLE app_passwords (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the token. The plaintext is shown once at creation and never stored.
    token_hash   BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- Human-readable name, for example the device name reported by Login Flow v2.
    -- Not unique: the same device may sign in more than once.
    label        TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    -- NULL means the password never expires.
    expires_at   INTEGER,
    last_used_at INTEGER
) STRICT;

CREATE INDEX app_passwords_user_id ON app_passwords (user_id);

-- What an app password can reach. Each row mounts `storage_path` (inside the owner's tree) at
-- `mount_path` (in the tree the client sees). An app password without any scope row has no
-- access at all; full access is an explicit ('', '', 'full') row.
CREATE TABLE app_password_scopes (
    app_password_id INTEGER NOT NULL REFERENCES app_passwords (id) ON DELETE CASCADE,
    mount_path      TEXT    NOT NULL COLLATE BINARY,
    storage_path    TEXT    NOT NULL COLLATE BINARY,
    permission      TEXT    NOT NULL CHECK (permission IN ('view', 'full')),
    PRIMARY KEY (app_password_id, mount_path)
) STRICT;

-- Metadata of every file and directory, written only through MetaStore.
CREATE TABLE files (
    -- Exposed to clients as `oc:fileid`. AUTOINCREMENT so that ids of deleted entries are never
    -- handed out again; clients cache them. Preserved across MOVE.
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    rel_path      TEXT    NOT NULL COLLATE BINARY,
    is_dir        INTEGER NOT NULL CHECK (is_dir IN (0, 1)),
    -- Changes whenever the entry or, for directories, anything below it changes.
    etag          TEXT    NOT NULL,
    mtime_ns      INTEGER NOT NULL,
    size          INTEGER NOT NULL DEFAULT 0 CHECK (size >= 0),
    favorite      INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
    -- The creation time as the client reports it. Clients send it with uploads (`X-OC-CTime`)
    -- and read it back as `nc:creation_time`, the way Nextcloud stores it. Nextcloud Android
    -- compares it with the local file before it reports a name collision as "same file". UNIX
    -- seconds; 0 when no client reported one, as on Nextcloud.
    creation_time INTEGER NOT NULL DEFAULT 0 CHECK (creation_time >= 0),
    -- Also the index for subtree range scans (rule 3 above).
    UNIQUE (owner_id, rel_path)
) STRICT;

-- Favorites lookup for the `filter-files` REPORT.
CREATE INDEX files_favorites ON files (owner_id, rel_path) WHERE favorite = 1;

-- WebDAV dead properties set through PROPPATCH. Keyed by file id, so MOVE keeps them and
-- DELETE removes them.
CREATE TABLE dead_props (
    file_id   INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    namespace TEXT    NOT NULL,
    name      TEXT    NOT NULL,
    -- The serialized property element as received from the client.
    xml       BLOB    NOT NULL,
    PRIMARY KEY (file_id, namespace, name)
) STRICT;

-- Append-only journal of changes per owner, written in the same transaction as the change.
-- `id` is a monotonically increasing sequence number.
CREATE TABLE change_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- No foreign key: the row outlives the deleted file it describes.
    file_id      INTEGER NOT NULL,
    rel_path     TEXT    NOT NULL COLLATE BINARY,
    -- Previous path of a 'move'; NULL otherwise.
    old_rel_path TEXT    COLLATE BINARY,
    operation    TEXT    NOT NULL CHECK (operation IN ('create', 'modify', 'delete', 'move')),
    changed_at   INTEGER NOT NULL,
    CHECK ((operation = 'move') = (old_rel_path IS NOT NULL))
) STRICT;

CREATE INDEX change_log_owner ON change_log (owner_id, id);

-- WebDAV locks, keyed by storage location so that the same file reached through different
-- mounts conflicts correctly.
CREATE TABLE locks (
    -- `opaquelocktoken:` URI returned to the client.
    token      TEXT    PRIMARY KEY,
    owner_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    rel_path   TEXT    NOT NULL COLLATE BINARY,
    -- Principal that took the lock.
    principal  TEXT,
    -- The <D:owner> element sent by the client, returned verbatim in lock discovery.
    owner_xml  BLOB,
    shared     INTEGER NOT NULL CHECK (shared IN (0, 1)),
    deep       INTEGER NOT NULL CHECK (deep IN (0, 1)),
    created_at INTEGER NOT NULL,
    -- Absolute expiry. NOT NULL on purpose: `Timeout: Infinite` and overly long requests are
    -- clamped to the server maximum, so an abandoned lock always expires.
    timeout_at INTEGER NOT NULL
) STRICT;

CREATE INDEX locks_owner_path ON locks (owner_id, rel_path);
CREATE INDEX locks_timeout_at ON locks (timeout_at);

-- Nextcloud chunked upload v2 sessions (`/remote.php/dav/uploads/<user>/<upload_id>`).
--
-- Chunking v2 clients name the destination when they create a session (`MKCOL` with a
-- `Destination` header); older clients name it only in the final `MOVE`, so `target_path` is
-- NULL until the destination is known.
CREATE TABLE upload_sessions (
    owner_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Chosen by the client; unique per user only. Compared byte for byte.
    upload_id   TEXT    NOT NULL COLLATE BINARY,
    -- Final destination as a storage rel_path of the owner, or NULL until the MOVE names it.
    target_path TEXT    COLLATE BINARY,
    -- `OC-Total-Length`, when the client sent it.
    total_size  INTEGER CHECK (total_size IS NULL OR total_size >= 0),
    created_at  INTEGER NOT NULL,
    -- Last chunk received; sessions expire a fixed time after it.
    updated_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (owner_id, upload_id)
) STRICT;

CREATE INDEX upload_sessions_expires_at ON upload_sessions (expires_at);

-- Pending Login Flow v2 sign-ins, and device registrations, which use the same flow
-- (docs/connect-protocol.md, section 4). The credentials are minted when the client polls after
-- the user granted access, inside the transaction that deletes the flow row, so their plaintext
-- is never stored.
CREATE TABLE login_flows (
    id                 INTEGER PRIMARY KEY,
    -- SHA-256 of the token the client polls with.
    poll_token_hash    BLOB    NOT NULL UNIQUE CHECK (length(poll_token_hash) = 32),
    -- SHA-256 of the token embedded in the login URL opened in the browser.
    login_token_hash   BLOB    NOT NULL UNIQUE CHECK (length(login_token_hash) = 32),
    -- Device name derived from the client's User-Agent, or reported by a registering device;
    -- becomes the app password label.
    client_name        TEXT    NOT NULL,
    -- Set when the user approves the request on the consent page.
    granted_user_id    INTEGER REFERENCES users (id) ON DELETE CASCADE,
    -- The address of the browser that granted it, for the audit log.
    granted_client_ip  TEXT,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    -- Device registrations only: the device's Ed25519 public key, what it reported about
    -- itself, and the 32 random bytes it signs to prove that it holds its key. A flow without
    -- an endpoint id mints an app password for a Nextcloud client.
    device_endpoint_id BLOB    CHECK (device_endpoint_id IS NULL OR length(device_endpoint_id) = 32),
    device_product     TEXT,
    device_platform    TEXT,
    device_version     TEXT,
    device_challenge   BLOB    CHECK (device_challenge IS NULL OR length(device_challenge) = 32),
    CHECK ((device_endpoint_id IS NULL) = (device_challenge IS NULL))
) STRICT;

CREATE INDEX login_flows_expires_at ON login_flows (expires_at);

-- Browser sessions of the server's HTML pages. Created only by signing in with the web login
-- password; app passwords cannot create them.
CREATE TABLE web_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    -- SHA-256 of the session cookie value.
    token_hash   BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX web_sessions_user_id ON web_sessions (user_id);
CREATE INDEX web_sessions_expires_at ON web_sessions (expires_at);

-- Direct download links. The Nextcloud apps stream video and audio that is not downloaded yet
-- from a URL without credentials (`/remote.php/direct/<token>`), which they request through
-- `POST /ocs/v2.php/apps/dav/api/v1/direct`. A link names one file by id and acts with the app
-- password that requested it: revoking that app password, or deleting the file, removes the
-- link.
CREATE TABLE direct_downloads (
    -- SHA-256 of the token in the URL. The token is returned once and never stored.
    token_hash      BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
    app_password_id INTEGER NOT NULL REFERENCES app_passwords (id) ON DELETE CASCADE,
    file_id         INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
) STRICT;

-- The cascades look links up by these columns; without the indexes every deleted file would
-- scan the table.
CREATE INDEX direct_downloads_app_password_id ON direct_downloads (app_password_id);
CREATE INDEX direct_downloads_file_id ON direct_downloads (file_id);
CREATE INDEX direct_downloads_expires_at ON direct_downloads (expires_at);

-- Devices registered for remote access (docs/connect-protocol.md, sections 4 and 6). One row
-- per Ed25519 key: the key is the device's identity and its iroh `EndpointId`.
CREATE TABLE devices (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The 32-byte Ed25519 public key. Unique across accounts: a key belongs to one account.
    endpoint_id        BLOB    NOT NULL UNIQUE CHECK (length(endpoint_id) = 32),
    -- The device's credential for the control channel; NULL exactly when the device is
    -- revoked or signed out. No ON DELETE action: an app password that a device still uses
    -- cannot be deleted on its own (revocation and signing out clear this column first), while
    -- deleting the account removes both rows in one statement.
    app_password_id    INTEGER UNIQUE REFERENCES app_passwords (id),
    -- `[a-z0-9-]{1,32}`: input-show, gono-md, ...
    product            TEXT    NOT NULL,
    -- `[a-z0-9-]{1,32}`: macos, windows, linux, harmonyos, ios, android, ...
    platform           TEXT    NOT NULL,
    name               TEXT    NOT NULL,
    version            TEXT    NOT NULL DEFAULT '',
    -- Reported by the device: it accepts remote connections, and unattended access is on.
    accept_remote      INTEGER NOT NULL DEFAULT 0 CHECK (accept_remote IN (0, 1)),
    unattended         INTEGER NOT NULL DEFAULT 0 CHECK (unattended IN (0, 1)),
    -- JSON array of the ALPNs the device accepts.
    services           TEXT    NOT NULL DEFAULT '[]',
    -- The device may send pairing requests until then (protocol 8.6).
    pairing_open_until INTEGER,
    registered_at      INTEGER NOT NULL,
    last_seen_at       INTEGER,
    -- Set once and never cleared: a revoked key never comes back (protocol 9.1). The row stays
    -- as a tombstone until the account is deleted; `revoked_keys` keeps the key after that.
    revoked_at         INTEGER,
    -- Set when the device signed out (protocol 9.4), cleared when it registers again. The row
    -- stays, so that the key remains bound to this account and can still be revoked.
    left_at            INTEGER,
    CHECK ((app_password_id IS NOT NULL) = (revoked_at IS NULL AND left_at IS NULL))
) STRICT;

CREATE INDEX devices_user_id ON devices (user_id);

-- Every key that was ever revoked, also after its account was deleted, so that a revoked key
-- never registers again on this server, into any account (protocol 9.1). Keys only, no
-- account data.
CREATE TABLE revoked_keys (
    endpoint_id BLOB    PRIMARY KEY CHECK (length(endpoint_id) = 32),
    revoked_at  INTEGER NOT NULL
) STRICT;

-- Usernames of deleted accounts that had devices registered for remote access. Statements name
-- the account by its username (protocol 8.3, 8.4), so such a name is never given to a new
-- account: an approval issued for the old account would match the new one until it expired.
-- Accounts that never registered a device leave their names free.
CREATE TABLE retired_usernames (
    username   TEXT    PRIMARY KEY COLLATE BINARY,
    retired_at INTEGER NOT NULL
) STRICT;

-- Events that must reach devices that are offline when they happen (protocol 5.6). `seq` is
-- the event's number on the control channel; it only grows.
CREATE TABLE device_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('device.added', 'device.revoked', 'pair.approved')),
    -- The event's fields as a JSON object, without `type` and `seq`.
    body       TEXT    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX device_events_user_id ON device_events (user_id, seq);
CREATE INDEX device_events_created_at ON device_events (created_at);

-- Which device approved which newcomer (protocol 8.2), kept for as long as both rows exist, so
-- that revoking a device can list the devices it introduced (protocol 9.1).
CREATE TABLE device_approvals (
    approver_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    subject_id  INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    approved_at INTEGER NOT NULL,
    PRIMARY KEY (approver_id, subject_id)
) STRICT;

CREATE INDEX device_approvals_subject_id ON device_approvals (subject_id);

-- Which device has applied which revocation (protocol 9.3).
CREATE TABLE revocations_applied (
    revoked_device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    device_id         INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    applied_at        INTEGER NOT NULL,
    PRIMARY KEY (revoked_device_id, device_id)
) STRICT;

CREATE INDEX revocations_applied_device_id ON revocations_applied (device_id);

-- Who did what, and when (protocol 12). Never content, never addresses that devices publish.
CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The account the record belongs to; NULL for records about no account.
    user_id   INTEGER REFERENCES users (id) ON DELETE CASCADE,
    at        INTEGER NOT NULL,
    -- `device.registered`, `connect.requested`, ...
    kind      TEXT    NOT NULL,
    -- Who acted: `user`, `admin`, `cli`, `device`, `server`.
    actor     TEXT    NOT NULL,
    -- The device the record is about, and the other device involved.
    device    BLOB    CHECK (device IS NULL OR length(device) = 32),
    peer      BLOB    CHECK (peer IS NULL OR length(peer) = 32),
    client_ip TEXT,
    -- Further fields as a JSON object.
    details   TEXT    NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX audit_log_user_id ON audit_log (user_id, id);
CREATE INDEX audit_log_at ON audit_log (at);

-- Two-step verification (protocol 13). A row means the account has it enrolled, which remote
-- access requires.
CREATE TABLE two_factor (
    user_id    INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- The TOTP secret, encrypted with the key file of protocol 13.6.
    secret     BLOB    NOT NULL,
    -- The last accepted time step; codes of this step or earlier are refused.
    last_step  INTEGER NOT NULL DEFAULT 0,
    enabled_at INTEGER NOT NULL
) STRICT;

CREATE TABLE recovery_codes (
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the code; 80 random bits are enough for a fast hash.
    code_hash BLOB    NOT NULL CHECK (length(code_hash) = 32),
    used_at   INTEGER,
    PRIMARY KEY (user_id, code_hash)
) STRICT;
