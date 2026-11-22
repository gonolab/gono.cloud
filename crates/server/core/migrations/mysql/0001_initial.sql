-- Schema of Gono Cloud on MySQL 5.7.44 or later: the twin of `../sqlite/0001_initial.sql`.
--
-- Both files have the same tables, columns, keys and cascades, and the rules in the header of
-- the SQLite file apply here as well; its comments explain what the tables are for. This file
-- explains only where MySQL differs:
--
-- - Every table is InnoDB with the DYNAMIC row format (index keys of up to 3072 bytes) and
--   utf8mb4 with the `utf8mb4_bin` collation.
-- - Text that is compared byte for byte (BINARY collation in SQLite: paths, usernames, keys) is
--   VARBINARY, because `utf8mb4_bin` ignores trailing spaces in comparisons ('a' = 'a ') in
--   MySQL 5.7. Its values are UTF-8, and queries read them through `db::Text`. Paths hold at
--   most 4096 bytes (`gono_server_core::path::MAX_PATH_BYTES`, checked before a path is
--   stored); S3 spellings of paths three times that, the most a spelling whose NFC is such a
--   path can have.
-- - Index keys have at most 3072 bytes, so a long path cannot be a key. Unique keys on paths
--   use the SHA-256 of the path (a stored generated column), and subtree range scans
--   (`rel_path >= ? AND rel_path < ?`) use an index on the first 3000 bytes of the path, which
--   MySQL then checks against the whole path. Rule 3 of the SQLite file holds unchanged.
-- - Booleans are INT 0/1 and ids, sizes and timestamps BIGINT: the `Any` driver of sqlx reads
--   neither TINYINT nor DECIMAL.
-- - Ids come from `id_sequences` as in SQLite; there is no AUTO_INCREMENT.
-- - MySQL 5.7 parses CHECK constraints but does not enforce them. They are kept where MySQL
--   accepts their syntax, as documentation; the code keeps every one of them. Partial indexes
--   are plain indexes, expression indexes indexes on generated columns.
-- - TEXT and BLOB columns cannot have defaults in MySQL 5.7; the code always writes them.
-- - `write_lock` exists only here: every write transaction locks its one row first, which
--   serializes writers across processes the way SQLite's single writer does
--   (`gono_server_core::db::begin_immediate`).
-- - The column `key` of `s3_uploads` is a reserved word in MySQL, quoted with backticks
--   (which SQLite accepts as well) wherever it is named.

-- See `id_sequences` in the SQLite file.
CREATE TABLE id_sequences (
    name    VARCHAR(64) NOT NULL PRIMARY KEY,
    last_id BIGINT      NOT NULL,
    CHECK (last_id >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

INSERT INTO id_sequences (name, last_id) VALUES
    ('app_passwords', 0),
    ('audit_log', 0),
    ('change_log', 0),
    ('device_events', 0),
    ('devices', 0),
    ('files', 0),
    ('login_flows', 0),
    ('s3_buckets', 0),
    ('users', 0),
    ('web_sessions', 0);

-- The row every write transaction locks first (`SELECT ... FOR UPDATE`), so that one writer
-- at a time changes the database, across all processes, as with SQLite.
CREATE TABLE write_lock (
    id INT NOT NULL PRIMARY KEY,
    CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

INSERT INTO write_lock (id) VALUES (1);

CREATE TABLE settings (
    name  VARCHAR(64)   NOT NULL PRIMARY KEY,
    value VARCHAR(1024) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

INSERT INTO settings (name, value) VALUES ('instance_id', CONCAT('oc', LOWER(HEX(RANDOM_BYTES(5)))));

CREATE TABLE users (
    id            BIGINT        NOT NULL PRIMARY KEY,
    -- `gono_server_core::Username`: at most 64 bytes.
    username      VARBINARY(64) NOT NULL UNIQUE,
    display_name  VARCHAR(255)  NOT NULL,
    password_hash VARCHAR(255)  NOT NULL,
    enabled       INT           NOT NULL DEFAULT 1,
    is_admin      INT           NOT NULL DEFAULT 0,
    created_at    BIGINT        NOT NULL,
    updated_at    BIGINT        NOT NULL,
    -- The services the account may use; see the SQLite schema.
    service_files  INT NOT NULL DEFAULT 0,
    service_webdav INT NOT NULL DEFAULT 0,
    service_s3     INT NOT NULL DEFAULT 0,
    service_direct INT NOT NULL DEFAULT 0,
    service_relay  INT NOT NULL DEFAULT 0,
    CHECK (enabled IN (0, 1)),
    CHECK (is_admin IN (0, 1)),
    CHECK (service_files IN (0, 1)),
    CHECK (service_webdav IN (0, 1)),
    CHECK (service_s3 IN (0, 1)),
    CHECK (service_direct IN (0, 1)),
    CHECK (service_relay IN (0, 1)),
    CHECK (service_relay = 0 OR service_direct = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE app_passwords (
    id            BIGINT        NOT NULL PRIMARY KEY,
    user_id       BIGINT        NOT NULL,
    kind          VARCHAR(8)    NOT NULL DEFAULT 'dav',
    token_hash    BINARY(32)    UNIQUE,
    -- `GONO` and 16 characters.
    access_key_id VARBINARY(20) UNIQUE,
    secret_sealed VARBINARY(1024),
    label         VARCHAR(255)  NOT NULL,
    created_at    BIGINT        NOT NULL,
    expires_at    BIGINT,
    last_used_at  BIGINT,
    CHECK (kind IN ('dav', 's3')),
    CHECK (token_hash IS NULL OR LENGTH(token_hash) = 32),
    CHECK (
        (kind = 'dav' AND token_hash IS NOT NULL AND access_key_id IS NULL
            AND secret_sealed IS NULL)
        OR (kind = 's3' AND token_hash IS NULL AND access_key_id IS NOT NULL
            AND secret_sealed IS NOT NULL)
    ),
    INDEX app_passwords_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE app_password_scopes (
    app_password_id BIGINT          NOT NULL,
    mount_path      VARBINARY(4096) NOT NULL,
    storage_path    VARBINARY(4096) NOT NULL,
    permission      VARCHAR(4)      NOT NULL,
    -- The primary key of SQLite, (app_password_id, mount_path), with the path's digest.
    mount_hash      BINARY(32)      AS (UNHEX(SHA2(mount_path, 256))) STORED NOT NULL,
    CHECK (permission IN ('view', 'full')),
    PRIMARY KEY (app_password_id, mount_hash),
    FOREIGN KEY (app_password_id) REFERENCES app_passwords (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE files (
    id            BIGINT           NOT NULL PRIMARY KEY,
    owner_id      BIGINT           NOT NULL,
    rel_path      VARBINARY(4096)  NOT NULL,
    is_dir        INT              NOT NULL,
    etag          VARCHAR(64)      NOT NULL,
    mtime_ns      BIGINT           NOT NULL,
    size          BIGINT           NOT NULL DEFAULT 0,
    favorite      INT              NOT NULL DEFAULT 0,
    creation_time BIGINT           NOT NULL DEFAULT 0,
    s3_path       VARBINARY(12288),
    md5           BINARY(16),
    -- The unique key of SQLite, (owner_id, rel_path), with the path's digest.
    path_hash     BINARY(32)       AS (UNHEX(SHA2(rel_path, 256))) STORED NOT NULL,
    -- The expression SQLite's `files_s3_listing` indexes; S3 listings on MySQL name this
    -- column instead of the expression.
    s3_key        VARBINARY(12288) AS (COALESCE(s3_path, rel_path)) STORED NOT NULL,
    CHECK (is_dir IN (0, 1)),
    CHECK (size >= 0),
    CHECK (favorite IN (0, 1)),
    CHECK (creation_time >= 0),
    CHECK (md5 IS NULL OR LENGTH(md5) = 16),
    UNIQUE files_owner_path (owner_id, path_hash),
    -- Subtree range scans (rule 3).
    INDEX files_owner_rel_path (owner_id, rel_path(3000)),
    -- Favorites lookup for the `filter-files` REPORT (a partial index in SQLite).
    INDEX files_favorites (owner_id, favorite, rel_path(3000)),
    -- S3 listings: file rows in the byte order of their S3 spelling.
    INDEX files_s3_listing (owner_id, is_dir, s3_key(3000)),
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE s3_buckets (
    id             BIGINT        NOT NULL PRIMARY KEY,
    name           VARBINARY(63) NOT NULL UNIQUE,
    owner_id       BIGINT        NOT NULL,
    root_file_id   BIGINT        NOT NULL UNIQUE,
    anonymous      VARCHAR(16)   NOT NULL DEFAULT 'private',
    anonymous_list INT           NOT NULL DEFAULT 0,
    cors           MEDIUMTEXT,
    tags           MEDIUMTEXT,
    lifecycle      MEDIUMTEXT,
    website        MEDIUMTEXT,
    created_at     BIGINT        NOT NULL,
    CHECK (anonymous IN ('private', 'acl', 'public-read')),
    CHECK (anonymous_list IN (0, 1)),
    CHECK (cors IS NULL OR JSON_VALID(cors)),
    CHECK (tags IS NULL OR JSON_VALID(tags)),
    CHECK (lifecycle IS NULL OR JSON_VALID(lifecycle)),
    CHECK (website IS NULL OR JSON_VALID(website)),
    INDEX s3_buckets_owner_id (owner_id),
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (root_file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE s3_key_grants (
    app_password_id BIGINT     NOT NULL,
    bucket_id       BIGINT,
    permission      VARCHAR(4) NOT NULL,
    -- SQLite's `ifnull(bucket_id, 0)` index. VIRTUAL: MySQL forbids a stored generated column
    -- on a base column with a cascading foreign key.
    bucket_key      BIGINT     AS (IFNULL(bucket_id, 0)) VIRTUAL,
    CHECK (permission IN ('view', 'full')),
    UNIQUE s3_key_grants_key_bucket (app_password_id, bucket_key),
    INDEX s3_key_grants_bucket_id (bucket_id),
    FOREIGN KEY (app_password_id) REFERENCES app_passwords (id) ON DELETE CASCADE,
    FOREIGN KEY (bucket_id) REFERENCES s3_buckets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE s3_uploads (
    upload_id          VARBINARY(32)   NOT NULL PRIMARY KEY,
    bucket_id          BIGINT          NOT NULL,
    -- An S3 key: at most 1024 bytes.
    `key`              VARBINARY(1024) NOT NULL,
    meta               MEDIUMTEXT      NOT NULL,
    created_at         BIGINT          NOT NULL,
    expires_at         BIGINT          NOT NULL,
    completed_etag     VARCHAR(64),
    completed_checksum VARCHAR(255),
    INDEX s3_uploads_bucket_key (bucket_id, `key`),
    INDEX s3_uploads_expires_at (expires_at),
    FOREIGN KEY (bucket_id) REFERENCES s3_buckets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE s3_upload_parts (
    upload_id   VARBINARY(32) NOT NULL,
    part_number INT           NOT NULL,
    file_name   VARCHAR(255)  NOT NULL,
    etag        VARCHAR(64)   NOT NULL,
    size        BIGINT        NOT NULL,
    uploaded_at BIGINT        NOT NULL,
    checksum    VARCHAR(255),
    CHECK (part_number BETWEEN 1 AND 10000),
    CHECK (size >= 0),
    PRIMARY KEY (upload_id, part_number),
    FOREIGN KEY (upload_id) REFERENCES s3_uploads (upload_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE dead_props (
    file_id   BIGINT     NOT NULL,
    -- Byte-compared like SQLite's TEXT, and as long as a request body allows.
    namespace BLOB       NOT NULL,
    name      BLOB       NOT NULL,
    xml       MEDIUMBLOB NOT NULL,
    -- The primary key of SQLite, (file_id, namespace, name), with the digest of the two names;
    -- the length prefix keeps ('a', 'bc') and ('ab', 'c') apart.
    prop_hash BINARY(32) AS (UNHEX(SHA2(CONCAT(LENGTH(namespace), ':', namespace, name), 256)))
              STORED NOT NULL,
    PRIMARY KEY (file_id, prop_hash),
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE object_meta (
    file_id             BIGINT       NOT NULL PRIMARY KEY,
    s3_etag             VARCHAR(64),
    public_read         INT          NOT NULL DEFAULT 0,
    content_type        TEXT,
    content_encoding    TEXT,
    content_disposition TEXT,
    content_language    TEXT,
    cache_control       TEXT,
    expires             TEXT,
    -- SQLite's default is '{}'; here every INSERT names a value.
    user_meta           MEDIUMTEXT   NOT NULL,
    checksum_algorithm  VARCHAR(16),
    checksum_value      VARCHAR(255),
    checksum_type       VARCHAR(16),
    -- SQLite's default is '{}'; here every INSERT names a value.
    tags                MEDIUMTEXT   NOT NULL,
    written_at          BIGINT,
    CHECK (public_read IN (0, 1)),
    CHECK (checksum_type IN ('FULL_OBJECT', 'COMPOSITE')),
    CHECK ((checksum_algorithm IS NULL) = (checksum_value IS NULL)),
    CHECK (checksum_type IS NULL OR checksum_algorithm IS NOT NULL),
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE object_parts (
    file_id     BIGINT       NOT NULL,
    part_number INT          NOT NULL,
    size        BIGINT       NOT NULL,
    checksum    VARCHAR(255),
    CHECK (part_number BETWEEN 1 AND 10000),
    CHECK (size >= 0),
    PRIMARY KEY (file_id, part_number),
    FOREIGN KEY (file_id) REFERENCES object_meta (file_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE change_log (
    id           BIGINT          NOT NULL PRIMARY KEY,
    owner_id     BIGINT          NOT NULL,
    file_id      BIGINT          NOT NULL,
    rel_path     VARBINARY(4096) NOT NULL,
    old_rel_path VARBINARY(4096),
    operation    VARCHAR(8)      NOT NULL,
    changed_at   BIGINT          NOT NULL,
    CHECK (operation IN ('create', 'modify', 'delete', 'move')),
    CHECK ((operation = 'move') = (old_rel_path IS NOT NULL)),
    INDEX change_log_owner (owner_id, id),
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE locks (
    token      VARBINARY(255)  NOT NULL PRIMARY KEY,
    owner_id   BIGINT          NOT NULL,
    rel_path   VARBINARY(4096) NOT NULL,
    principal  VARCHAR(255),
    owner_xml  MEDIUMBLOB,
    shared     INT             NOT NULL,
    deep       INT             NOT NULL,
    created_at BIGINT          NOT NULL,
    timeout_at BIGINT          NOT NULL,
    CHECK (shared IN (0, 1)),
    CHECK (deep IN (0, 1)),
    INDEX locks_owner_path (owner_id, rel_path(3000)),
    INDEX locks_timeout_at (timeout_at),
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE upload_sessions (
    owner_id    BIGINT          NOT NULL,
    -- Chosen by the client: at most 255 bytes (the Nextcloud chunking code checks).
    upload_id   VARBINARY(255)  NOT NULL,
    target_path VARBINARY(4096),
    total_size  BIGINT,
    created_at  BIGINT          NOT NULL,
    updated_at  BIGINT          NOT NULL,
    expires_at  BIGINT          NOT NULL,
    CHECK (total_size IS NULL OR total_size >= 0),
    PRIMARY KEY (owner_id, upload_id),
    INDEX upload_sessions_expires_at (expires_at),
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE login_flows (
    id                 BIGINT       NOT NULL PRIMARY KEY,
    poll_token_hash    BINARY(32)   NOT NULL UNIQUE,
    login_token_hash   BINARY(32)   NOT NULL UNIQUE,
    client_name        TEXT         NOT NULL,
    granted_user_id    BIGINT,
    granted_client_ip  VARCHAR(64),
    created_at         BIGINT       NOT NULL,
    expires_at         BIGINT       NOT NULL,
    device_endpoint_id BINARY(32),
    device_product     VARCHAR(255),
    device_platform    VARCHAR(255),
    device_version     VARCHAR(255),
    device_challenge   BINARY(32),
    -- Why the consent page refused a device registration; see the SQLite schema.
    refusal            VARCHAR(32),
    CHECK (LENGTH(poll_token_hash) = 32),
    CHECK (LENGTH(login_token_hash) = 32),
    CHECK ((device_endpoint_id IS NULL) = (device_challenge IS NULL)),
    INDEX login_flows_expires_at (expires_at),
    FOREIGN KEY (granted_user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE web_sessions (
    id           BIGINT     NOT NULL PRIMARY KEY,
    token_hash   BINARY(32) NOT NULL UNIQUE,
    user_id      BIGINT     NOT NULL,
    created_at   BIGINT     NOT NULL,
    last_seen_at BIGINT     NOT NULL,
    expires_at   BIGINT     NOT NULL,
    INDEX web_sessions_user_id (user_id),
    INDEX web_sessions_expires_at (expires_at),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE direct_downloads (
    token_hash      BINARY(32) NOT NULL PRIMARY KEY,
    app_password_id BIGINT     NOT NULL,
    file_id         BIGINT     NOT NULL,
    created_at      BIGINT     NOT NULL,
    expires_at      BIGINT     NOT NULL,
    INDEX direct_downloads_app_password_id (app_password_id),
    INDEX direct_downloads_file_id (file_id),
    INDEX direct_downloads_expires_at (expires_at),
    FOREIGN KEY (app_password_id) REFERENCES app_passwords (id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE devices (
    id                 BIGINT        NOT NULL PRIMARY KEY,
    user_id            BIGINT        NOT NULL,
    endpoint_id        BINARY(32)    NOT NULL UNIQUE,
    -- No ON DELETE action, as in SQLite. InnoDB checks it at once rather than at the end of the
    -- statement, so deleting an account deletes its devices first (`users::delete`).
    app_password_id    BIGINT        UNIQUE,
    product            VARCHAR(32)   NOT NULL,
    platform           VARCHAR(32)   NOT NULL,
    name               VARCHAR(255)  NOT NULL,
    version            VARCHAR(255)  NOT NULL DEFAULT '',
    accept_remote      INT           NOT NULL DEFAULT 0,
    unattended         INT           NOT NULL DEFAULT 0,
    services           VARCHAR(4096) NOT NULL DEFAULT '[]',
    pairing_open_until BIGINT,
    registered_at      BIGINT        NOT NULL,
    last_seen_at       BIGINT,
    revoked_at         BIGINT,
    left_at            BIGINT,
    CHECK (LENGTH(endpoint_id) = 32),
    CHECK (accept_remote IN (0, 1)),
    CHECK (unattended IN (0, 1)),
    CHECK ((app_password_id IS NOT NULL) = (revoked_at IS NULL AND left_at IS NULL)),
    INDEX devices_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (app_password_id) REFERENCES app_passwords (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE revoked_keys (
    endpoint_id BINARY(32) NOT NULL PRIMARY KEY,
    revoked_at  BIGINT     NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE retired_usernames (
    username   VARBINARY(64) NOT NULL PRIMARY KEY,
    retired_at BIGINT        NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE device_events (
    seq        BIGINT      NOT NULL PRIMARY KEY,
    user_id    BIGINT      NOT NULL,
    kind       VARCHAR(32) NOT NULL,
    body       MEDIUMTEXT  NOT NULL,
    created_at BIGINT      NOT NULL,
    CHECK (kind IN ('device.added', 'device.revoked', 'pair.approved')),
    INDEX device_events_user_id (user_id, seq),
    INDEX device_events_created_at (created_at),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE device_approvals (
    approver_id BIGINT NOT NULL,
    subject_id  BIGINT NOT NULL,
    approved_at BIGINT NOT NULL,
    PRIMARY KEY (approver_id, subject_id),
    INDEX device_approvals_subject_id (subject_id),
    FOREIGN KEY (approver_id) REFERENCES devices (id) ON DELETE CASCADE,
    FOREIGN KEY (subject_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE revocations_applied (
    revoked_device_id BIGINT NOT NULL,
    device_id         BIGINT NOT NULL,
    applied_at        BIGINT NOT NULL,
    PRIMARY KEY (revoked_device_id, device_id),
    INDEX revocations_applied_device_id (device_id),
    FOREIGN KEY (revoked_device_id) REFERENCES devices (id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE audit_log (
    id        BIGINT      NOT NULL PRIMARY KEY,
    user_id   BIGINT,
    at        BIGINT      NOT NULL,
    kind      VARCHAR(64) NOT NULL,
    actor     VARCHAR(16) NOT NULL,
    device    BINARY(32),
    peer      BINARY(32),
    client_ip VARCHAR(64),
    -- SQLite's default is '{}'; here every INSERT names a value.
    details   MEDIUMTEXT  NOT NULL,
    CHECK (device IS NULL OR LENGTH(device) = 32),
    CHECK (peer IS NULL OR LENGTH(peer) = 32),
    INDEX audit_log_user_id (user_id, id),
    INDEX audit_log_at (at),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE two_factor (
    user_id    BIGINT          NOT NULL PRIMARY KEY,
    secret     VARBINARY(1024) NOT NULL,
    last_step  BIGINT          NOT NULL DEFAULT 0,
    enabled_at BIGINT          NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;

CREATE TABLE recovery_codes (
    user_id   BIGINT     NOT NULL,
    code_hash BINARY(32) NOT NULL,
    used_at   BIGINT,
    CHECK (LENGTH(code_hash) = 32),
    PRIMARY KEY (user_id, code_hash),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC;
