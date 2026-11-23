-- Schema of Gono Cloud on SQLite.
--
-- `../mysql/0001_initial.sql` is its MySQL twin: the same tables, columns, keys and cascades in
-- MySQL's dialect. Every change is made to both, and the tests run on both backends. The
-- comments here explain the schema; the MySQL file explains only where MySQL differs.
--
-- Rules that apply to these files and every later migration:
--
-- 1. Until the next release the schema is edited in place: no installation has to keep a
--    database of it, so there are no migrations from earlier schemas (sqlx refuses a database
--    of an earlier version of this file, because its checksum differs). Once released, the
--    migrations are append-only: a published migration is never edited, reformatted or
--    renamed, schema changes go into a new, higher-numbered file in both directories, and
--    `crates/server/core/tests/migrations.rs` pins the checksum of every published migration.
--
-- 2. `rel_path` columns use BINARY collation (spelled out explicitly below; MySQL stores them
--    as VARBINARY). Paths compare byte-for-byte; `Foo` and `foo` are different files.
--
-- 3. Subtree ("prefix") queries use a half-open range, never LIKE:
--
--        rel_path >= 'a/' AND rel_path < 'a0'
--
--    '0' is the byte after '/'. LIKE treats '_' and '%' in file names as wildcards and is
--    case-insensitive for ASCII in SQLite, so it matches unrelated rows.
--
-- 4. Ids that must never be handed out again (see `users` below) come from `id_sequences`:
--    the inserting transaction allocates them with `gono_server_core::db::next_id` and names
--    them in the INSERT. There is no AUTOINCREMENT, because MySQL could not match it: MySQL
--    5.7 sets its AUTO_INCREMENT counter back to the highest id plus one when it restarts.
--
-- Conventions:
--
-- - `rel_path` is relative to the owner's root: no leading or trailing slash, '' for the root.
--   Paths have at most 4096 bytes (`gono_server_core::path::MAX_PATH_BYTES`, checked before
--   they are stored), the size of MySQL's path columns.
-- - Timestamps named `*_at` are UNIX seconds (UTC). `mtime_ns` is UNIX nanoseconds.
-- - Booleans are INTEGER 0/1 with a CHECK constraint.
-- - Secrets (app passwords, session cookies, Login Flow tokens, recovery codes) are stored only
--   as SHA-256 digests (32-byte BLOBs). They are high-entropy random tokens, so a fast hash is
--   enough and lookups are a single indexed equality match. The exceptions are secrets the
--   server must read back, TOTP secrets and S3 secret keys (an S3 signature is an HMAC keyed
--   with the secret): they are sealed with the key file of `two_factor.key_file`
--   (`gono_server_core::sealing`), so a copy of the database alone gives none of them away.
-- - Tables are STRICT so SQLite enforces the declared column types.

-- The last id handed out for each table whose ids are never reused (rule 4). Written only by
-- `gono_server_core::db::next_id`, inside the write transaction that inserts the row, so a
-- rolled back insert also gives its id back.
CREATE TABLE id_sequences (
    name    TEXT    NOT NULL PRIMARY KEY COLLATE BINARY,
    last_id INTEGER NOT NULL CHECK (last_id >= 0)
) STRICT;

INSERT INTO id_sequences (name, last_id) VALUES
    ('app_passwords', 0),
    ('audit_log', 0),
    ('change_log', 0),
    ('device_events', 0),
    ('devices', 0),
    ('email_codes', 0),
    ('external_identities', 0),
    ('files', 0),
    ('login_flows', 0),
    ('mp_sessions', 0),
    ('pending_identities', 0),
    ('s3_buckets', 0),
    ('users', 0),
    ('web_sessions', 0),
    ('wechat_bind_tickets', 0),
    ('wechat_sign_in_tickets', 0);

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

-- Accounts. Users authenticate devices with app passwords; the web login password below and
-- the third-party identities of `external_identities` are used only for the server's HTML
-- pages (sign-in, Login Flow v2, the file and admin UIs). Ids of accounts, credentials,
-- sessions, sign-ins and devices come from `id_sequences` (rule 4): in-memory state keyed by
-- them (the control channel, pending sign-ins, the "shown once" pages) must never carry over to
-- a newer row that reuses a deleted one's id.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    -- Validated by `gono_server_core::Username`: lowercase ASCII, appears verbatim in DAV URLs.
    username      TEXT    NOT NULL UNIQUE COLLATE BINARY,
    display_name  TEXT    NOT NULL,
    -- Argon2id PHC string of the web login password; NULL for an account without one, which
    -- signs in with its third-party identities only. Such an account keeps at least one
    -- identity (`gono_server_core::identities`).
    password_hash TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    -- How the account came to be: 'cli' (the command line, the first admin's `init` included)
    -- or 'admin' (the admin UI), or a sign-up with a third-party identity: 'wechat', 'google',
    -- 'github'.
    created_via   TEXT    NOT NULL
                          CHECK (created_via IN ('admin', 'cli', 'wechat', 'google', 'github')),
    -- When the server deletes the account, which asked for its deletion; NULL otherwise. Only
    -- accounts without a web login password ask for it themselves, and the account stays
    -- disabled until then or until the request is undone.
    deleting_at   INTEGER CHECK (deleting_at IS NULL OR enabled = 0),
    -- The account's email address (`gono_server_core::email`): NULL, or an address its user
    -- proved to receive mail at by entering a code sent there. Lets a forgotten web login
    -- password be reset by mail. Stored lower-cased (ASCII only), so that Alice@Example.com and
    -- alice@example.com are one address; an address belongs to one account at most.
    email         TEXT    UNIQUE COLLATE BINARY
                          CHECK (email IS NULL OR (length(email) BETWEEN 3 AND 254
                                                   AND email = lower(email))),
    -- The services the account may use (`gono_server_core::services`), all off until an admin
    -- turns them on: the web file UI, WebDAV and the rest of the Nextcloud surface, the S3 API,
    -- remote access for devices with the relay at the limited rate ("direct"), and the relay at
    -- the full rate, which needs direct.
    service_files  INTEGER NOT NULL DEFAULT 0 CHECK (service_files IN (0, 1)),
    service_webdav INTEGER NOT NULL DEFAULT 0 CHECK (service_webdav IN (0, 1)),
    service_s3     INTEGER NOT NULL DEFAULT 0 CHECK (service_s3 IN (0, 1)),
    service_direct INTEGER NOT NULL DEFAULT 0 CHECK (service_direct IN (0, 1)),
    service_relay  INTEGER NOT NULL DEFAULT 0 CHECK (service_relay IN (0, 1)),
    CHECK (service_relay = 0 OR service_direct = 1)
) STRICT;

-- Per-device credentials, minted by Login Flow v2, device registration, the CLI or the web
-- admin UI, and S3 access keys, minted by the CLI, the account page or the web admin UI.
-- A credential of one kind never works as the other: S3 keys never pass HTTP Basic, and app
-- passwords never sign S3 requests.
CREATE TABLE app_passwords (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- 'dav': an app password for HTTP Basic (WebDAV, OCS, notify_push), with scopes in
    -- app_password_scopes. 's3': an S3 access key, with grants in s3_key_grants.
    kind          TEXT    NOT NULL DEFAULT 'dav' CHECK (kind IN ('dav', 's3')),
    -- SHA-256 of the token ('dav' only). The plaintext is shown once at creation and never
    -- stored.
    token_hash    BLOB    UNIQUE CHECK (token_hash IS NULL OR length(token_hash) = 32),
    -- The access key id ('s3' only): `GONO` and 16 characters from [A-Z0-9].
    access_key_id TEXT    UNIQUE COLLATE BINARY,
    -- The secret key ('s3' only), sealed for `Purpose::S3Secret` and this row's id. Shown once
    -- at creation like a token.
    secret_sealed BLOB,
    -- Human-readable name, for example the device name reported by Login Flow v2.
    -- Not unique: the same device may sign in more than once.
    label         TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    -- NULL means the password never expires.
    expires_at    INTEGER,
    last_used_at  INTEGER,
    CHECK (
        (kind = 'dav' AND token_hash IS NOT NULL AND access_key_id IS NULL
            AND secret_sealed IS NULL)
        OR (kind = 's3' AND token_hash IS NULL AND access_key_id IS NOT NULL
            AND secret_sealed IS NOT NULL)
    )
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
    -- Exposed to clients as `oc:fileid`. From `id_sequences`, so that ids of deleted entries
    -- are never handed out again; clients cache them. Preserved across MOVE.
    id            INTEGER PRIMARY KEY,
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
    -- The path as S3 keys spell it, when that differs from rel_path: S3 keys need not be in
    -- NFC, the tree's names are. NULL: spelled as rel_path. Its NFC form is always rel_path.
    -- Set for what S3 writes; a row inserted below a spelled folder inherits the folder's
    -- spelling, and a MOVE carries it along (MetaStore).
    s3_path       TEXT    COLLATE BINARY,
    -- The MD5 of a file's content (16 bytes), written with the version it describes: by every
    -- write that streams the content (WebDAV, chunked uploads, single S3 uploads) and by
    -- `rescan --checksums`; carried by COPY and MOVE. NULL when unknown: for directories, S3
    -- multipart objects, and content that changed behind the server's back. It is the S3
    -- ETag of files without one of their own and Nextcloud's `oc:checksums`.
    md5           BLOB    CHECK (md5 IS NULL OR length(md5) = 16),
    -- Also the index for subtree range scans (rule 3 above).
    UNIQUE (owner_id, rel_path)
) STRICT;

-- Favorites lookup for the `filter-files` REPORT.
CREATE INDEX files_favorites ON files (owner_id, rel_path) WHERE favorite = 1;

-- S3 listings: file rows in the byte order of their S3 spelling. Queries must use exactly
-- this expression and `is_dir = 0` for SQLite to use the index. (MySQL indexes a generated
-- column with this expression, `s3_key`, which its queries name instead.)
CREATE INDEX files_s3_listing ON files (owner_id, COALESCE(s3_path, rel_path)) WHERE is_dir = 0;

-- S3 buckets: a bucket is a name bound to a folder of its owner's tree, and its objects are the
-- files below that folder.
CREATE TABLE s3_buckets (
    id             INTEGER PRIMARY KEY,
    -- Unique across the server: an anonymous request names only the bucket. 3 to 63 characters
    -- from [a-z0-9-], starting and ending with a letter or digit.
    name           TEXT    NOT NULL UNIQUE COLLATE BINARY,
    owner_id       INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The folder, by file id: the bucket follows it through MOVE, and deleting it deletes the
    -- bucket. A folder is bound to one bucket at most.
    root_file_id   INTEGER NOT NULL UNIQUE REFERENCES files (id) ON DELETE CASCADE,
    -- Anonymous reads: 'private' none; 'acl' objects with the public-read ACL
    -- (object_meta.public_read); 'public-read' every object. Effective only while
    -- `s3.allow_anonymous` is on.
    anonymous      TEXT    NOT NULL DEFAULT 'private'
                           CHECK (anonymous IN ('private', 'acl', 'public-read')),
    -- Anonymous requests may list the bucket.
    anonymous_list INTEGER NOT NULL DEFAULT 0 CHECK (anonymous_list IN (0, 1)),
    -- The bucket's CORS rules (PutBucketCors) as a JSON array, written and read by the S3 API;
    -- NULL: none, so browsers may not read responses of other origins.
    cors           TEXT    CHECK (cors IS NULL OR json_valid(cors)),
    -- The bucket's tags (PutBucketTagging) as a JSON object; NULL: none.
    tags           TEXT    CHECK (tags IS NULL OR json_valid(tags)),
    -- The bucket's lifecycle rules (PutBucketLifecycleConfiguration) as JSON, written and read
    -- by the S3 API and applied by its background task; NULL: none.
    lifecycle      TEXT    CHECK (lifecycle IS NULL OR json_valid(lifecycle)),
    -- The bucket's website configuration (PutBucketWebsite) as JSON, written and read by the
    -- S3 API; NULL: not a website.
    website        TEXT    CHECK (website IS NULL OR json_valid(website)),
    created_at     INTEGER NOT NULL
) STRICT;

CREATE INDEX s3_buckets_owner_id ON s3_buckets (owner_id);

-- What an S3 access key may reach. A key without grants reaches nothing.
CREATE TABLE s3_key_grants (
    app_password_id INTEGER NOT NULL REFERENCES app_passwords (id) ON DELETE CASCADE,
    -- One bucket of the key's owner, or NULL for every bucket of the owner, present and future.
    -- Only a key with a 'full' grant on every bucket may create and delete buckets and change
    -- their anonymous access.
    bucket_id       INTEGER REFERENCES s3_buckets (id) ON DELETE CASCADE,
    permission      TEXT    NOT NULL CHECK (permission IN ('view', 'full'))
) STRICT;

-- One grant per key and bucket; NULL counts as the bucket "every bucket". (MySQL: a generated
-- column with this expression.)
CREATE UNIQUE INDEX s3_key_grants_key_bucket ON s3_key_grants (app_password_id, ifnull(bucket_id, 0));
CREATE INDEX s3_key_grants_bucket_id ON s3_key_grants (bucket_id);

-- S3 multipart uploads in progress. Parts are staged in `s3-uploads/<upload id>/` of the data
-- directory and assembled into the object at completion.
CREATE TABLE s3_uploads (
    -- 32 random hex digits, chosen by the server.
    upload_id  TEXT    PRIMARY KEY COLLATE BINARY,
    bucket_id  INTEGER NOT NULL REFERENCES s3_buckets (id) ON DELETE CASCADE,
    -- The key of the object to create.
    key        TEXT    NOT NULL COLLATE BINARY,
    -- The S3 metadata of the object to create (content type, user metadata, ACL), as JSON.
    meta       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    -- Refreshed with every part; the purge removes uploads after it.
    expires_at INTEGER NOT NULL,
    -- The ETag of the object, once the upload is completed. A completed upload has no parts
    -- left; it is kept for a while so that a client repeating the completion (a retry after a
    -- lost answer) gets the same answer, as from S3.
    completed_etag TEXT,
    -- The checksum of the object (base64, as answered), once the upload is completed, if the
    -- upload has a checksum algorithm (in `meta`).
    completed_checksum TEXT
) STRICT;

CREATE INDEX s3_uploads_bucket_key ON s3_uploads (bucket_id, key);
CREATE INDEX s3_uploads_expires_at ON s3_uploads (expires_at);

CREATE TABLE s3_upload_parts (
    upload_id   TEXT    NOT NULL REFERENCES s3_uploads (upload_id) ON DELETE CASCADE,
    part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    -- The part's file in the upload's directory. Every upload of a part gets a new name, so
    -- a part uploaded twice at once never pairs one upload's file with the other's ETag.
    file_name   TEXT    NOT NULL,
    -- MD5 of the part, lowercase hex.
    etag        TEXT    NOT NULL,
    size        INTEGER NOT NULL CHECK (size >= 0),
    uploaded_at INTEGER NOT NULL,
    -- The part's checksum (base64) in the upload's checksum algorithm, if it has one.
    checksum    TEXT,
    PRIMARY KEY (upload_id, part_number)
) STRICT;

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

-- S3 metadata of the current version of a file: what a version written through the S3 API
-- carries besides its content, and its object ACL. Only files have rows. Every write of the
-- file that does not come through the S3 API, and every change of its content that `rescan`
-- finds, deletes the row, so the metadata never describes other content and a public object
-- becomes private again when it is overwritten. A MOVE keeps the row (same file id); a COPY
-- does not copy it.
CREATE TABLE object_meta (
    file_id             INTEGER PRIMARY KEY REFERENCES files (id) ON DELETE CASCADE,
    -- The S3 ETag without quotes: the MD5 of the content, or "<MD5 of the part MD5s>-<parts>"
    -- for a multipart upload. NULL for a version that was not written through the S3 API and
    -- only got an ACL: its S3 ETag is its WebDAV ETag.
    s3_etag             TEXT,
    -- The canned ACL `public-read`: anonymous requests may read the object, if its bucket
    -- honors object ACLs.
    public_read         INTEGER NOT NULL DEFAULT 0 CHECK (public_read IN (0, 1)),
    content_type        TEXT,
    content_encoding    TEXT,
    content_disposition TEXT,
    content_language    TEXT,
    cache_control       TEXT,
    expires             TEXT,
    -- `x-amz-meta-*` as a JSON object of strings, names in lowercase without the prefix.
    user_meta           TEXT    NOT NULL DEFAULT '{}',
    -- The `x-amz-checksum-*` the upload carried: algorithm (`CRC32`, `CRC32C`, `CRC64NVME`,
    -- `SHA1`, `SHA256`) and the value as sent (base64). For a multipart upload, the checksum
    -- of the whole content (`FULL_OBJECT`) or of the parts' checksums (`COMPOSITE`, value
    -- `<base64>-<parts>`).
    checksum_algorithm  TEXT,
    checksum_value      TEXT,
    checksum_type       TEXT    CHECK (checksum_type IN ('FULL_OBJECT', 'COMPOSITE')),
    -- The object's tags (`x-amz-tagging`, PutObjectTagging) as a JSON object of strings.
    tags                TEXT    NOT NULL DEFAULT '{}',
    -- When this version was written through the S3 API, UNIX seconds: the age lifecycle rules
    -- count from (never the modification time, which clients set). NULL for a version that
    -- only got an ACL or tags.
    written_at          INTEGER,
    CHECK ((checksum_algorithm IS NULL) = (checksum_value IS NULL)),
    CHECK (checksum_type IS NULL OR checksum_algorithm IS NOT NULL)
) STRICT;

-- The parts of an object written by a multipart upload, numbered 1 to the number of parts in
-- the object's order: `GetObject` and `HeadObject` with `partNumber` read one of them, and
-- `GetObjectAttributes` lists them. Written with the `object_meta` row and gone with it.
CREATE TABLE object_parts (
    file_id     INTEGER NOT NULL REFERENCES object_meta (file_id) ON DELETE CASCADE,
    part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    size        INTEGER NOT NULL CHECK (size >= 0),
    -- The part's checksum (base64) in the object's checksum algorithm, if it has one.
    checksum    TEXT,
    PRIMARY KEY (file_id, part_number)
) STRICT;

-- Append-only journal of changes per owner, written in the same transaction as the change.
-- `id` is a monotonically increasing sequence number (from `id_sequences`).
CREATE TABLE change_log (
    id           INTEGER PRIMARY KEY,
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
    -- From `id_sequences`: the consent page names the flow by id, and a stale page must never
    -- name a newer flow.
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
    -- Set when the consent page refused a device registration because of the account, so that
    -- the device's next poll learns why (protocol 4.3) and the flow ends: 'service_not_enabled'
    -- (the account may not use direct connections).
    refusal            TEXT    CHECK (refusal IS NULL OR refusal IN ('service_not_enabled')),
    CHECK ((device_endpoint_id IS NULL) = (device_challenge IS NULL))
) STRICT;

CREATE INDEX login_flows_expires_at ON login_flows (expires_at);

-- Browser sessions of the server's HTML pages. Created only by signing in with the web login
-- password; app passwords cannot create them.
CREATE TABLE web_sessions (
    id           INTEGER PRIMARY KEY,
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
    id                 INTEGER PRIMARY KEY,
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
-- the event's number on the control channel; it only grows (from `id_sequences`).
CREATE TABLE device_events (
    seq        INTEGER PRIMARY KEY,
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
    id        INTEGER PRIMARY KEY,
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

-- One-time codes sent by mail (`gono_server_core::email`): 'bind' proves an address before it
-- becomes the account's, 'reset' resets the web login password through the account's address.
-- Ids from `id_sequences`. A code is valid until `expires_at` and for 5 tries (`attempts`,
-- counted before each comparison); a used or replaced code gets `expires_at` set to the time it
-- ended. Rows stay a day after they were created, so that the limits of codes per day can count
-- them, and are removed by the janitor after that.
CREATE TABLE email_codes (
    id             INTEGER PRIMARY KEY,
    user_id        INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose        TEXT    NOT NULL CHECK (purpose IN ('bind', 'reset')),
    -- The address the code was sent to, lower-cased like `users.email`.
    email          TEXT    NOT NULL COLLATE BINARY CHECK (length(email) BETWEEN 3 AND 254),
    -- HMAC-SHA256 of the row's id, the purpose and the code, keyed with a key derived from
    -- `two_factor.key_file`: without that file the 6 digits cannot be found by trying them
    -- all. The code itself is never stored.
    code_hash      BLOB    NOT NULL CHECK (length(code_hash) = 32),
    -- Reset codes only: the keyed digest of the reset cookie of the browser that asked for the
    -- code, the only browser that may try it, and the network it asked from (the /24 of an
    -- IPv4 address or the /64 of an IPv6 one, `192.0.2.0/24`), for the limits per network.
    client_binding BLOB    CHECK (client_binding IS NULL OR length(client_binding) = 32),
    client_net     TEXT    COLLATE BINARY
                           CHECK (client_net IS NULL OR length(client_net) BETWEEN 1 AND 64),
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    CHECK ((purpose = 'reset') = (client_binding IS NOT NULL AND client_net IS NOT NULL)),
    CHECK ((client_binding IS NULL) = (client_net IS NULL))
) STRICT;

CREATE INDEX email_codes_user ON email_codes (user_id, purpose, created_at);
CREATE INDEX email_codes_created_at ON email_codes (created_at);

-- Third-party identities bound to accounts (`gono_server_core::identities`): a user of WeChat,
-- known by the AppID of the mini program and the openid WeChat gives that user for it; of
-- Google, by the `sub` of its ID tokens; or of GitHub, by its numeric user id (never the
-- login, which can be renamed and reused). An identity signs in to its account without the web
-- login password. It belongs to one account at most, and an account has one identity per
-- provider and realm at most. Ids from `id_sequences`.
CREATE TABLE external_identities (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider     TEXT    NOT NULL CHECK (provider IN ('wechat', 'google', 'github')),
    -- Who issued the subject: the AppID for WeChat (`wx` and 16 letters or digits),
    -- `https://accounts.google.com` for Google, `github.com` for GitHub.
    realm        TEXT    NOT NULL COLLATE BINARY CHECK (length(realm) BETWEEN 1 AND 64),
    -- The provider's opaque, stable id of the user. Never shown and never logged.
    subject      TEXT    NOT NULL COLLATE BINARY CHECK (length(subject) BETWEEN 1 AND 255),
    -- WeChat only: the id WeChat reports across the AppIDs of one developer account, once it
    -- reports one.
    unionid      TEXT    COLLATE BINARY
                         CHECK (unionid IS NULL OR length(unionid) BETWEEN 1 AND 128),
    -- What the account page shows of the identity: '' for WeChat (nothing of the openid), the
    -- address for Google, `@login` for GitHub (refreshed at each sign-in).
    label        TEXT    NOT NULL CHECK (length(label) <= 255),
    created_at   INTEGER NOT NULL,
    -- The last sign-in with it, on the web or in the mini program.
    last_seen_at INTEGER NOT NULL,
    CHECK (unionid IS NULL OR provider = 'wechat'),
    UNIQUE (provider, realm, subject),
    UNIQUE (user_id, provider, realm)
) STRICT;

-- Tickets that bind a WeChat identity to an account: made on the account page (once its user
-- confirmed it is them), shown there as a QR code, used up by the mini program that scans it.
-- Valid for 10 minutes; a new one ends the account's earlier ones.
CREATE TABLE wechat_bind_tickets (
    id          INTEGER PRIMARY KEY,
    -- SHA-256 of the ticket (128 random bits). The ticket itself is never stored.
    ticket_hash BLOB    NOT NULL UNIQUE CHECK (length(ticket_hash) = 32),
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX wechat_bind_tickets_user_id ON wechat_bind_tickets (user_id);
CREATE INDEX wechat_bind_tickets_expires_at ON wechat_bind_tickets (expires_at);

-- Third-party identities that signed in while bound to no account (`gono_server_core::
-- identities`): what the provider reported, kept for 10 minutes for whoever holds the token, so
-- that binding the identity to an account or creating an account with it needs no second round
-- trip to the provider. The mini program holds its token as a signup token, a browser in a
-- cookie. A new one of the same identity and holder ends the earlier ones.
CREATE TABLE pending_identities (
    id             INTEGER PRIMARY KEY,
    -- SHA-256 of the token (256 random bits).
    token_hash     BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- Who holds the token: 'mini_program' or 'web' (a browser). A token is taken only from its
    -- holder.
    holder         TEXT    NOT NULL CHECK (holder IN ('mini_program', 'web')),
    -- The identity, as in `external_identities`.
    provider       TEXT    NOT NULL CHECK (provider IN ('wechat', 'google', 'github')),
    realm          TEXT    NOT NULL COLLATE BINARY CHECK (length(realm) BETWEEN 1 AND 64),
    subject        TEXT    NOT NULL COLLATE BINARY CHECK (length(subject) BETWEEN 1 AND 255),
    unionid        TEXT    COLLATE BINARY
                           CHECK (unionid IS NULL OR length(unionid) BETWEEN 1 AND 128),
    label          TEXT    NOT NULL CHECK (length(label) <= 255),
    -- The address the provider reported, lower-cased, and whether it verified it. Never written
    -- into `users.email`: the server verifies addresses itself.
    email          TEXT    COLLATE BINARY
                           CHECK (email IS NULL OR length(email) BETWEEN 3 AND 254),
    email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    -- The user's name at the provider, offered as the display name of a new account.
    name           TEXT    CHECK (name IS NULL OR length(name) <= 255),
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    CHECK (unionid IS NULL OR provider = 'wechat')
) STRICT;

CREATE INDEX pending_identities_subject ON pending_identities (provider, realm, subject);
CREATE INDEX pending_identities_expires_at ON pending_identities (expires_at);

-- Tickets of signing in on the web by scanning a QR code with the mini program
-- (`gono_server_core::wechat`, `plan/third-party-sign-in-design.md` 5.3): made for a browser,
-- whose sign-in page shows the ticket as a QR code; locked to the WeChat identity whose mini
-- program scanned it; then 6 digits shown on the phone, which the same browser enters. Valid
-- for 2 minutes, extended when scanned and confirmed; a new one of the browser ends its earlier
-- ones.
CREATE TABLE wechat_sign_in_tickets (
    id            INTEGER PRIMARY KEY,
    -- SHA-256 of the ticket (128 random bits) and of the browser's cookie (256 random bits).
    ticket_hash   BLOB    NOT NULL UNIQUE CHECK (length(ticket_hash) = 32),
    browser_hash  BLOB    NOT NULL CHECK (length(browser_hash) = 32),
    -- 'sign_in' (a sign-in page), 'admin' (the admin UI's, for admin accounts only) or
    -- 'reauth' (confirming it is the user of `user_id` on the account page).
    purpose       TEXT    NOT NULL CHECK (purpose IN ('sign_in', 'admin', 'reauth')),
    user_id       INTEGER REFERENCES users (id) ON DELETE CASCADE,
    -- What the mini program shows of the browser: its name from the User-Agent, and its network
    -- (the /24 or /64 of its address), compared with the phone's.
    browser_name  TEXT    NOT NULL CHECK (length(browser_name) <= 64),
    browser_net   TEXT    NOT NULL COLLATE BINARY CHECK (length(browser_net) BETWEEN 1 AND 64),
    -- 'waiting' for a scan; 'scanned': locked to `identity_id`; 'code': the digits were shown on
    -- the phone; 'done': the browser signed in; 'ended': `ended` says why.
    stage         TEXT    NOT NULL CHECK (stage IN ('waiting', 'scanned', 'code', 'done', 'ended')),
    ended         TEXT    CHECK (ended IS NULL OR ended IN ('denied', 'tries')),
    identity_id   INTEGER REFERENCES external_identities (id) ON DELETE CASCADE,
    -- SHA-256 of the digits with the ticket, never the digits; they end at `code_expires_at`.
    code_hash     BLOB    CHECK (code_hash IS NULL OR length(code_hash) = 32),
    code_expires_at INTEGER,
    tries_left    INTEGER NOT NULL DEFAULT 3 CHECK (tries_left >= 0),
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    CHECK ((purpose = 'reauth') = (user_id IS NOT NULL)),
    CHECK ((stage = 'ended') = (ended IS NOT NULL)),
    CHECK (stage = 'waiting' OR identity_id IS NOT NULL),
    CHECK ((code_hash IS NULL) = (code_expires_at IS NULL))
) STRICT;

CREATE INDEX wechat_sign_in_tickets_browser ON wechat_sign_in_tickets (browser_hash);
CREATE INDEX wechat_sign_in_tickets_expires_at ON wechat_sign_in_tickets (expires_at);

-- Sessions of the mini program with a bound WeChat identity. They read the account's name and
-- services and nothing else: no files, no WebDAV, no S3. A session ends 30 days after its last
-- use, when its identity is unbound (with it, by the cascade), and when the account is
-- disabled or deleted.
CREATE TABLE mp_sessions (
    id           INTEGER PRIMARY KEY,
    -- SHA-256 of the bearer token (256 random bits).
    token_hash   BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- The WeChat identity the session was opened with.
    identity_id  INTEGER NOT NULL REFERENCES external_identities (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX mp_sessions_identity_id ON mp_sessions (identity_id);
CREATE INDEX mp_sessions_expires_at ON mp_sessions (expires_at);
