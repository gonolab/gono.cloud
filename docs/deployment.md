# Deploying Gono Cloud

This guide installs the Gono Cloud server as a system service, puts it behind a reverse proxy
and covers the day-to-day operation: accounts, logs, upgrades, backups, `rescan` and
uninstalling. The reverse proxy itself is described in [reverse-proxy.md](reverse-proxy.md).

Release builds and the install script are for Linux. The server builds and runs on macOS
from source for development (see `CONTRIBUTING.md`), but there are no macOS releases.

## Requirements

| | |
|---|---|
| **Linux** | x86_64 or aarch64, any distribution: the binary is statically linked (musl) and needs no C library, so glibc-based and musl-based systems (Alpine) work alike. The install script and the unit need systemd; systemd 247 or newer applies every hardening option of the unit, older versions ignore some of them with a warning. Without systemd, run the binary from the archive with your own service manager ([Installing by hand](#installing-by-hand)). |
| **Reverse proxy** | nginx or Caddy on the same host, terminating HTTPS for a domain name. Gono Cloud has no TLS of its own and listens on `127.0.0.1:16102`. |
| **Storage** | A local file system for the database and the data directory; the data directory must be a single file system. A case-sensitive file system (ext4, XFS, Btrfs) is recommended: on a case-insensitive one, `Report.pdf` and `report.pdf` cannot coexist. Keep the SQLite database off network file systems. |
| **Database** | SQLite, built in: nothing to install. Or MySQL 5.7.44 or later, on this host or another ([Choosing the database](#choosing-the-database)). |

## Installing with the install script

Every server release on the [releases page](https://github.com/gonolab/gono.cloud/releases)
has a `cloud.server.sh` that installs that release. `https://gono.dev/cloud.server.sh`
redirects to the one of the newest server release
(`https://github.com/gonolab/gono.cloud/releases/latest/download/cloud.server.sh`). Download
it, read it if you like, and run it as root with the public address of the server:

```sh
curl -fsSLo cloud.server.sh https://gono.dev/cloud.server.sh
sudo sh cloud.server.sh --base-url https://cloud.example.com
```

To install a particular release, take its script instead
(`https://github.com/gonolab/gono.cloud/releases/download/server-v2.0.0/cloud.server.sh`) or
pass `--version`. Release 1.0.0 also carries the same script under its original name,
`install.sh`.

The script:

1. downloads the archive for this machine and `SHA256SUMS` from the same release and stops if
   the checksum does not match;
2. creates the system user `gono-cloud` (no login shell, no home directory) and the
   directories;
3. installs the binary to `/usr/local/bin/gono-cloud`;
4. writes `/etc/gono-cloud/config.toml` from `config.example.toml` with your `--base-url` and
   absolute paths, and validates it;
5. runs `gono-cloud init` as the service user, which creates the database and the first admin
   account and asks for its web login password;
6. installs the systemd unit, enables and starts it, and waits
   until the server answers on `http://127.0.0.1:16102/healthz`.

It never overwrites an existing configuration, database or data directory. Steps 4 and 5 only
run on a fresh install; if the script stops halfway, fix the cause and run it again.

Options for a fresh install:

| Option | Meaning |
|---|---|
| `--base-url URL` | Public origin, exactly as users type it: `https://cloud.example.com`, no path. Required. |
| `--admin NAME` | Username of the first admin account (default `admin`). |
| `--admin-password-stdin` | Read the admin's password from standard input instead of the terminal, for automated installs: `printf '%s\n' "$PASSWORD" \| sudo sh cloud.server.sh ... --admin-password-stdin`. |
| `--data-dir DIR` | Keep the users' files in `DIR` instead of `/var/lib/gono-cloud/data`. The directory must be new or empty. On Linux the script adds a systemd drop-in that lets the service write it. |
| `--no-start` | Install everything but do not start the service. |
| `--archive FILE` | Install a downloaded archive instead of downloading one (offline installs). `SHA256SUMS` must be next to it, or name it with `--checksums FILE`. |
| `--version VERSION` | Install another release than the one the script came from. |

`sh cloud.server.sh --help` lists every option.

### Verifying a download yourself

The install script checks the archive against `SHA256SUMS`. To check the release files by
hand, and that they were built by this repository's release workflow:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify gono-cloud-2.0.0-x86_64-unknown-linux-musl.tar.gz --repo gonolab/gono.cloud
```

### Paths

| | |
|---|---|
| Binary | `/usr/local/bin/gono-cloud` |
| Configuration | `/etc/gono-cloud/config.toml` |
| Database | `/var/lib/gono-cloud/gono-cloud.db` (SQLite) |
| Files | `/var/lib/gono-cloud/data/` |
| Database backups of upgrades | `/var/lib/gono-cloud/backups/` |
| Logs | the journal: `journalctl -u gono-cloud` |
| Service | `/etc/systemd/system/gono-cloud.service` |
| Service user and group | `gono-cloud` |

The configuration is owned by root and readable by the service group (`0640`); the service only
reads it. The database and the files belong to the service user and are not readable by other
users.

## Installing by hand

The release archive contains everything the script uses. On Linux:

```sh
tar -xzf gono-cloud-2.0.0-x86_64-unknown-linux-musl.tar.gz
cd gono-cloud-2.0.0-x86_64-unknown-linux-musl

sudo useradd --system --user-group --home-dir /var/lib/gono-cloud --no-create-home \
  --shell /usr/sbin/nologin gono-cloud
sudo install -m 0755 gono-cloud /usr/local/bin/gono-cloud
sudo install -d -m 0750 -o root -g gono-cloud /etc/gono-cloud
sudo install -d -m 0750 -o gono-cloud -g gono-cloud /var/lib/gono-cloud

# Set base_url, and absolute paths: data_dir = "/var/lib/gono-cloud/data",
# path = "/var/lib/gono-cloud/gono-cloud.db".
sudo install -m 0640 -o root -g gono-cloud config.example.toml /etc/gono-cloud/config.toml
sudoedit /etc/gono-cloud/config.toml
sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml config check

sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml init --admin admin

sudo install -m 0644 systemd/gono-cloud.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gono-cloud
```

The unit expects exactly these paths. To use others, override them in a drop-in (see
[Service management](#service-management)) rather than editing the unit, which upgrades replace.

On a system without systemd (Alpine with OpenRC, a container), skip the unit: create the user,
directories and configuration the same way (on Alpine:
`addgroup -S gono-cloud && adduser -S -D -H -G gono-cloud gono-cloud`) and let the
service manager run `gono-cloud --config /etc/gono-cloud/config.toml serve` as `gono-cloud`. It
logs to standard output and stops cleanly on SIGTERM within 30 seconds.

## Choosing the database

The database holds the accounts, app passwords and sessions, the metadata of the files (ids,
ETags, favorites, dead properties, locks, S3 metadata), the device directory and the audit log.
The files themselves are always in the data directory. `[db] backend` chooses where the
database lives:

- **SQLite** (`backend = "sqlite"`, the default): built into the binary, one file
  (`db.path`) next to the data. There is nothing to set up or administer, and it is the right
  choice for most installations. Everything else in this guide assumes it.
- **MySQL 5.7.44 or later** (`backend = "mysql"`): for operators who run MySQL already, want
  the metadata on a database server of its own, or back it up with their database tooling.
  The tables are InnoDB with utf8mb4. MariaDB is not supported.

Both behave the same: paths compare byte for byte (`Report.pdf`, `report.pdf` and
`report.pdf ` with a trailing space are three files), paths have at most 4096 bytes, ids are
never handed out again, and one writer at a time changes the database, the server and the
command line together. There is no tool that moves an installation from one backend to the
other: choose before `gono-cloud init`.

### Setting up MySQL

1. Create an empty database with the utf8mb4 character set, and an account that may use it,
   in the `mysql` client as an administrator:

   ```sql
   CREATE DATABASE gono_cloud CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
   CREATE USER 'gono'@'127.0.0.1' IDENTIFIED BY '<password>';
   GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
     ON gono_cloud.* TO 'gono'@'127.0.0.1';
   ```

   The schema changes need `CREATE`, `ALTER`, `INDEX`, `DROP` and `REFERENCES`; the account
   needs nothing outside its database. Use the host the server connects from instead of
   `127.0.0.1` for a database on another host.
2. Put the password into a file that only the service can read, as its first line:

   ```sh
   sudo install -m 0640 -o root -g gono-cloud /dev/null /etc/gono-cloud/mysql-password
   sudoedit /etc/gono-cloud/mysql-password
   ```

3. In `/etc/gono-cloud/config.toml`, replace `path` in `[db]`:

   ```toml
   [db]
   backend = "mysql"
   url = "mysql://gono@127.0.0.1:3306/gono_cloud"
   password_file = "/etc/gono-cloud/mysql-password"
   ```

   The URL never contains the password (`config check` refuses one). For a database on another
   host, require TLS: `?ssl-mode=verify_identity`, with `&ssl-ca=/etc/gono-cloud/mysql-ca.pem`
   for a private CA; `config check` warns about a remote database without it. By default
   (`ssl-mode=preferred`) the connection uses TLS when the server offers it.
4. Run `gono-cloud init` as the service user, which creates the tables in the empty database
   and the first admin account, and start the service.

With the install script, install with `--no-start`: it writes the configuration and runs
`init` on SQLite. Delete the SQLite files it created (`/var/lib/gono-cloud/gono-cloud.db*`),
follow the steps above, and start the service with `sudo systemctl start gono-cloud`. Upgrades
with the install script work as with SQLite, except that it does not back up a MySQL database:
do that yourself first ([Backup and restore](#backup-and-restore)).

`init` refuses a database that holds tables of something else, and `serve` and the other
commands refuse a database without Gono Cloud's tables, so that a typo in `db.url` never starts
from an empty database. At every start the server also refuses, with a message that says what
to change: MySQL older than 5.7.44, a database whose default character set is not utf8mb4,
tables that are not InnoDB, InnoDB without index keys of 3072 bytes (keep
`innodb_default_row_format = DYNAMIC`, the default), and binary logging with
`binlog_format = STATEMENT` (`ROW`, the default, and `MIXED` work). Gono Cloud's connections
set what they need themselves (strict mode, `READ COMMITTED` isolation, UTC, utf8mb4); the
defaults of the MySQL server's configuration need no changes.

**MySQL 8.0 and later** authenticate accounts with `caching_sha2_password` by default. Without
TLS, that needs an RSA key exchange, which Gono Cloud does not include, so the connection must
use TLS: the default `ssl-mode=preferred` does when the server offers TLS (MySQL 8 does out of
the box), and `ssl-mode=required` or `verify_identity` insist on it. Where the server still
offers it, an account `IDENTIFIED WITH mysql_native_password` works without TLS.

## The first admin account

`gono-cloud init` creates the database, the data directory layout and one account with the
admin flag. Its web login password (at least 8 characters) is used in the browser only: for the
web file UI, the Login Flow consent page and the web admin UI. `init` refuses to run against a
database that already has accounts.

To connect the first device, enter the server address (`https://cloud.example.com`) in a
Nextcloud client. The client opens the browser, you sign in with the web login password and
approve the device, and the server creates an app password for that device. Each device gets its
own app password, which you can revoke on its own.

## The browser

Opening `https://cloud.example.com/` in a browser leads to the **web file UI** at
`/apps/files/`. Every user signs in there with their web login password and can browse, search,
preview, upload (drag and drop, folders, large files in resumable chunks), download (folders as
`.zip`), create folders, rename, move, delete and mark favorites. The **account page**
(`/apps/account/`) lets users change their display name and web login password and create or
revoke their own app passwords, for example for Finder, Windows Explorer or rclone. The pages
work without JavaScript; with it, uploads and the theme switch need no page reloads. They follow
the browser's language (English or Chinese) and its light or dark mode.

Changes made in the browser are the same WebDAV operations the clients use, so the apps see
them at once (notify_push included). Deleting is permanent: there is no trash bin. Files are
never opened as web pages: downloads are attachments, and only images, video, audio and text are
previewed. App passwords cannot sign in to the browser, and the browser session cannot be used
for WebDAV.

The **web admin UI** at `https://cloud.example.com/manage/` (`admin.path`) shows this server
and manages accounts and app passwords. Only accounts with the admin flag can sign in; for them,
the file UI links to it. The configuration written by the install script of 1.0 to 1.2 sets
`path = "/gono-admin"`, so the admin UI stays there until that line is changed or removed.
Consider limiting the path to a VPN or office network in the reverse proxy
([examples](reverse-proxy.md)).

Both are on by default. To turn one off, set `enabled = false` in the `[files_ui]` or `[admin]`
section of the configuration and restart the service.

## Managing accounts

The command line manages accounts and app passwords directly in the database. Run it as the
service user, so that every file it creates belongs to the service:

```sh
sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml user list
```

A shell alias saves typing:

```sh
alias gono='sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml'
gono user add alice --display-name "Alice Example"
gono user promote alice
gono app-password add alice --label "Alice's laptop"
```

Accounts start without services, the first admin's too: a new account can sign in to its
account page, change its password and display name and set up two-step verification, and
nothing else until an admin turns its services on:

| Service | What it allows |
|---|---|
| `files` | The web file UI at `/apps/files/`. |
| `webdav` | WebDAV and everything else Nextcloud clients use: Login Flow v2, OCS, chunked uploads, notify_push and direct links. |
| `s3` | The S3 API with the account's access keys, and anonymous reads of its public buckets. |
| `direct` | Remote access for devices: registering them, finding the account's other devices and their addresses, pairing, and the relay at a limited rate, enough to set up direct connections. |
| `relay` | The relay at the full rate, for devices that cannot connect directly. Needs `direct`, which it turns on. |

```sh
gono user services alice --enable webdav,files
gono user services alice --enable all --disable s3
```

The admin UI switches them too, on the page of each account (`/manage/users/<name>`), an
admin's own included. A running server applies a change to the next request; open control
channels and relay connections follow at once after a change in the admin UI, and within 30
seconds after one made with the command line.

Run as root (`sudo gono-cloud ...`), the commands refuse to touch an installation that belongs to
the service user: files they would create, such as the database's write-ahead log or a new
user's directories, would belong to root and could no longer be written by the server.

| Command | Purpose |
|---|---|
| `user add NAME [--display-name NAME] [--admin]` | Create an account; asks for its web login password. |
| `user list` | List the accounts. |
| `user set-password NAME` | Set a new web login password; ends the user's browser sessions. |
| `user set-display-name NAME DISPLAY_NAME` | Change the name clients show. |
| `user promote NAME`, `user demote NAME` | Grant or withdraw access to the admin UI. |
| `user services NAME [--enable LIST] [--disable LIST]` | Show or switch the services of an account (see below). |
| `user disable NAME`, `user enable NAME` | Block or allow signing in; disabling stops the user's app passwords too. |
| `user delete NAME` | Delete the account; its files move to `data/deleted/`. The name of an account that registered devices for remote access cannot be given to a new account afterwards, and its revoked devices stay revoked. |
| `app-password add NAME --label LABEL [--scope ...] [--expires-in-days N]` | Create an app password, shown once. |
| `app-password list NAME`, `app-password delete NAME ID` | List or revoke app passwords. |
| `user reset-two-factor NAME` | Turn the user's two-step verification off (a lost phone without recovery codes). |
| `device list NAME`, `device revoke NAME ENDPOINT_ID` | List or revoke the devices registered for remote access ("Remote access"). |

At least one enabled admin always remains: disabling, demoting or deleting the last one is
refused. `gono-cloud <command> --help` explains every command and option.

### Two-step verification

Users turn two-step verification on themselves, on the account page: they scan a QR code with
an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, ...), enter a
code, and keep the ten recovery codes it shows once. From then on every web sign-in (the file
UI, the admin UI, the sign-in pages of Nextcloud apps and devices) asks for a code after the
password. App passwords do not change: devices and Nextcloud apps keep working. Remote access
for devices is available only on accounts that have it on, once `[connect]
require_two_factor` is true; during development it defaults to false ("Remote access").

- **The server's clock must be right** (NTP): codes change every 30 seconds.
- **The key file.** The TOTP secrets are encrypted with the key in `two_factor.key_file`,
  `/etc/gono-cloud/two-factor.key`. The
  install script creates it at the path the configuration names (32 random bytes,
  `root:gono-cloud`, mode 0640) and never replaces it, nor a symbolic link put there;
  `config check` shows whether it exists. Keep it out of the data directory and the database's
  directory, which `serve` warns about. **Back it up with the configuration,
  apart from the database**: a copy of the database alone does not give the second factor
  away. Without the file, accounts with two-step verification cannot sign in, so `serve`
  refuses to start while any account uses it; restore the file, or reset those accounts with
  `gono-cloud user reset-two-factor`.
- **A lost phone.** The user signs in with a recovery code and turns two-step verification off
  and on again, or an admin resets it (the account's page in the admin UI, or
  `user reset-two-factor`). The account then signs in with its password alone until it turns it
  on again.
- **Turning it on ends the account's other browser sessions**, so that a session opened with
  the password alone does not outlive it.
- **Failures.** After 5 wrong codes in 15 minutes, or 20 in a day, the second step of the
  account is locked until the window passes. The account page shows its user when the password
  was right but the code was not, and when a recovery code was used.

## Service management

```sh
sudo systemctl status gono-cloud
sudo systemctl restart gono-cloud       # after changing the configuration
sudo systemctl stop gono-cloud
sudo systemctl disable --now gono-cloud # stop it and do not start it at boot
```

On `stop` and `restart`, systemd sends SIGTERM. The server stops accepting connections, closes
notify_push WebSockets (clients reconnect on their own) and gives running requests, such as
uploads and downloads, up to 30 seconds to finish. systemd kills it after 45 seconds.

The unit runs the server with a strict sandbox: the whole file system is read-only for it except
`/var/lib/gono-cloud`, home directories are hidden, and it has no capabilities. Changes belong in
a drop-in, which upgrades keep:

```sh
sudo systemctl edit gono-cloud
```

```ini
[Service]
# A data directory or log file outside /var/lib/gono-cloud must be writable:
ReadWritePaths=/srv/gono-cloud/data
# A more detailed log filter (see "Logs"):
Environment=GONO_CLOUD_LOG=info,gono_server_dav=debug
```

### Changing the configuration

Edit `/etc/gono-cloud/config.toml` (`sudoedit` keeps the file's owner and mode), validate it,
then restart:

```sh
sudoedit /etc/gono-cloud/config.toml
sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml config check
sudo systemctl restart gono-cloud
```

`config check` prints the effective settings and warnings. Unknown keys are errors, so typos do
not go unnoticed.

## Reverse proxy

Clients must reach the server only through a reverse proxy that terminates HTTPS. Set it up as
described in [reverse-proxy.md](reverse-proxy.md), which has tested configurations for nginx
and Caddy. Two settings of Gono Cloud have to match the proxy:

- `server.base_url` is the public origin, exactly as users open it. The server never derives it
  from request headers.
- `server.trusted_proxies` lists the proxies whose `X-Forwarded-For` headers are believed. The
  default configuration trusts `127.0.0.1` and `::1`, which fits a proxy on the same host.

The proxy is as trusted as Gono Cloud itself: HTTPS ends there, so it sees every password and
app password that clients send, and with remote access also every device's credential,
statement and address (`docs/connect-threat-model.md`, section 2). Keep it on a host and under
an administration you trust as much as the server; a hosting panel that manages it is part of
that.

## The S3 API

S3 clients and applications can upload files to Gono Cloud and publish them for anonymous
download ([s3.md](s3.md) describes it for users). It is off by default (`[s3]`,
`enabled = false`). What it needs:

| | |
|---|---|
| **A host name of its own** | For example `s3.example.com`, with DNS pointing at this host and a certificate. It must not be `base_url`'s host name. |
| **A server block in the reverse proxy** | HTTPS for the host name, forwarded to `s3.bind` (`127.0.0.1:16104`) with `Host` unchanged: [reverse-proxy.md](reverse-proxy.md#the-s3-api). |
| **The key file** | The secrets of access keys are encrypted with `two_factor.key_file`, like TOTP secrets. `serve` refuses to start the S3 API without it. |
| **Virtual-hosted style** (optional) | `<bucket>.s3.example.com` besides `s3.example.com/<bucket>`: `s3.virtual_host_domain`, a wildcard DNS record `*.s3.example.com` and a wildcard certificate ([reverse-proxy.md](reverse-proxy.md#virtual-hosted-style)). Path style works without it. |
| **Websites** (optional) | Buckets with a website configuration as static sites at `<bucket>.web.example.com`: `s3.website_domain`, a domain of its own with a wildcard DNS record and certificate, forwarded to `s3.bind` like the S3 host ([reverse-proxy.md](reverse-proxy.md#websites)). |

Turn it on in `/etc/gono-cloud/config.toml` and restart the service:

```toml
[s3]
enabled = true
public_url = "https://s3.example.com"
# Let bucket owners publish files for anonymous download. Off by default.
# allow_anonymous = true
# Buckets as host names too (<bucket>.s3.example.com); needs wildcard DNS and a certificate.
# virtual_host_domain = "s3.example.com"
# Buckets as static websites (<bucket>.web.example.com); a wildcard of its own.
# website_domain = "web.example.com"
```

Then create a bucket and an access key, for example for the admin account (users can do the
same on their account page):

```sh
sudo -u gono-cloud gono-cloud s3 bucket create admin photos
sudo -u gono-cloud gono-cloud s3 key create admin --label "photo app"
# Publish objects uploaded with the public-read ACL (needs allow_anonymous):
sudo -u gono-cloud gono-cloud s3 bucket set admin photos --anonymous acl
```

`s3 key create` prints the access key id and the secret key once. Without `--bucket` the key
reaches every bucket of the account; `--bucket photos:view` limits it to reading one bucket.
`s3 key list`, `s3 key delete`, `s3 bucket list`, `s3 bucket bind` (an existing folder) and
`s3 bucket unbind` manage the rest.

## The relay

Devices of Gono products (Input Show today) connect to each other directly when they can. When
they cannot, for example behind two NATs, they send their packets through a relay. The packets
are encrypted end to end between the devices; the relay forwards them without seeing their
content. The relay also tells devices the public address it sees them at (QUIC address
discovery, QAD), which they need to punch through NAT and connect directly. Gono Cloud can run
this relay; it is off by default (`[relay]`, `enabled = false`).

What it needs:

| | |
|---|---|
| **A host name of its own** | For example `relay.example.com`, with DNS pointing at this host and a certificate. The relay cannot run below a path, so it cannot share `base_url`'s host name. |
| **A server block in the reverse proxy** | HTTPS for the host name and WebSockets forwarded to `relay.bind` (`127.0.0.1:16103`); on port 80, `/generate_204` and the ACME challenges of the certificate: [reverse-proxy.md](reverse-proxy.md#the-relay). Gono's devices do not need port 80. |
| **UDP 7842 open** (for QAD) | Devices reach QAD directly, not through the proxy. |
| **A copy of the certificate** (for QAD) | QUIC brings its own TLS, so the relay needs the certificate of its host name and the key, readable by the service user. |
| **An https `base_url`** | Devices register and keep their control channel on the main host name (`/gono/v1/`), with their credentials; without HTTPS, remote access is off and the relay admits only `relay.allowed_endpoints`. |

### Turning it on

A fresh install with `--relay-host relay.example.com` writes `[relay]` with `enabled = true` and
`public_url`, creates `/etc/gono-cloud/relay-tls/` for the certificate, and lists the remaining
steps. On an existing installation, edit the configuration:

```toml
[relay]
enabled = true
public_url = "https://relay.example.com"

# QUIC address discovery, once the certificate is in place (below).
qad_bind = "[::]:7842"
tls_cert = "relay-tls/fullchain.pem"   # relative to the configuration file
tls_key = "relay-tls/privkey.pem"

# Optional: devices that may use the relay without being registered (tests, a relay on a host
# of its own): the 64 hex digits Input Show shows for a device.
# allowed_endpoints = [
#   "6f6e8a2a5c1d0b9e7f3a4c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f",  # laptop
# ]
```

Then validate the configuration and restart the service (see "Changing the configuration").
`config check` warns while QAD is off. `serve` admits the devices registered for remote access
("Remote access" below), and the devices of `relay.allowed_endpoints` besides. A device that is
refused is named in the log, with its full id:

```text
INFO gono_server_relay::access: relay connection refused: the device is neither registered for remote access nor in relay.allowed_endpoints device=6f6e8a…
```

Optional: `relay.max_client_bytes_per_sec` and `relay.max_client_burst_bytes` limit what the
relay reads from one device connection.

### The certificate for QUIC address discovery

The reverse proxy owns the certificate of the relay's host name, and the service user cannot
read it (certbot keeps private keys readable by root only). Copy the certificate and the key
into `/etc/gono-cloud/relay-tls/` after every renewal; the relay reads them again every
`relay.tls_reload_interval_secs` (an hour by default), so a renewal needs no restart. It takes a
renewal up only once the key belongs to the certificate: a read that falls between the copies
of the two files keeps the previous pair in service and logs `relay certificate not reloaded`,
and the next read picks the renewal up. The relay does not start while `qad_bind` is set and the
files are missing or do not belong together.

With **certbot**, a deploy hook does it after each renewal. The certificate itself comes from
certbot's nginx plugin (`certbot --nginx -d relay.example.com`) or from
`certbot certonly --webroot -w /var/www/letsencrypt -d relay.example.com`, whose challenges the
relay's server block in [reverse-proxy.md](reverse-proxy.md#the-relay) serves on port 80. Save
the hook as `/etc/letsencrypt/renewal-hooks/deploy/gono-cloud-relay` and make it executable:

```sh
#!/bin/sh
# Hands the renewed certificate of the relay's host name to Gono Cloud.
set -eu
case ${RENEWED_LINEAGE:-} in
*/relay.example.com) ;;
*) exit 0 ;;
esac
install -m 0644 -o root -g gono-cloud "$RENEWED_LINEAGE/fullchain.pem" /etc/gono-cloud/relay-tls/fullchain.pem
install -m 0640 -o root -g gono-cloud "$RENEWED_LINEAGE/privkey.pem" /etc/gono-cloud/relay-tls/privkey.pem
```

Run it once by hand for the certificate certbot already has:

```sh
sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/gono-cloud-relay
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/relay.example.com \
  /etc/letsencrypt/renewal-hooks/deploy/gono-cloud-relay
```

With **Caddy**, which renews on its own schedule, copy the files daily instead, for example from
`/etc/cron.daily/gono-cloud-relay` with the same two `install` lines. Caddy keeps them under its
data directory (`caddy environ` shows it), in
`certificates/acme-v02.api.letsencrypt.org-directory/relay.example.com/relay.example.com.crt`
and `.key`.

### Hosts in mainland China

Cloud providers in mainland China (Tencent Cloud, Alibaba Cloud and others) intercept plain
HTTP on port 80 for domains without an ICP filing (备案): clients get a redirect to the
provider's block page, although the server's access log shows the request answered as usual.
For the relay's host name, and for `base_url`'s, this means:

- **Certificates need DNS validation (DNS-01).** HTTP-01 fails: the CA reads the block page
  instead of the challenge, and reports an error such as `reader size limit exceeded`. This
  applies to every client that validates over port 80: certbot's webroot and nginx plugins,
  Caddy's HTTP challenge, and the file validation of hosting panels. Use certbot with a DNS
  plugin, acme.sh with the DNS API of your DNS provider, Caddy with a DNS provider module, or
  the DNS validation of the panel. Renewals use the same validation as the first issue, so
  switch before the certificate is due.
- **Probes on port 80 are unavailable.** `/generate_204` over plain HTTP returns the block
  page. Gono's devices do not use it (they skip iroh's captive-portal check), so remote
  access works without it; other iroh clients would take the block page for a captive
  portal, which only makes them probe again more often.
- **HTTPS on port 443 and UDP 7842 were not intercepted** when this was written: the relay's
  WebSocket, its HTTPS probe, QUIC address discovery and the control channel work. Providers
  may extend the block; an ICP filing, or a host outside mainland China, avoids it.

### Checking it

- The log shows `relay listening` with the public URL, the address and, when QAD is on, its
  socket.
- The admin UI's overview shows the relay's host name, the allowed devices connected now, the
  traffic it relayed and the connections it refused, or "no address discovery" while QAD is
  off.
- The admin UI's **Relay** page (`/manage/relay`) shows more:
  - its settings: who may connect, address discovery, the certificate and the rate limit;
  - its counters;
  - the devices connected right now, with their accounts and whether their control channel
    is open;
  - the last sessions devices reported, with the path they took (direct or relayed);
  - the revoked devices that tried to connect.
- [reverse-proxy.md](reverse-proxy.md#checking-the-relay) has `curl` checks for the proxy.

### Remote access

With the relay enabled and an https `base_url`, Gono Cloud serves remote access under
`/gono/v1/` on the main host name; `gono-cloud serve` logs `remote connectivity enabled`. The
protocol is [connect-protocol.md](connect-protocol.md), and
[connect-threat-model.md](connect-threat-model.md) says what it protects against.

- **Registering a device.** A device (Input Show) signs in through the browser like a Nextcloud
  client: it opens a link, the user signs in with the web login password, and the consent page
  names the device, its platform and its short device ID, which the device shows as well. The
  device gets a credential of its own, without access to files.
- **Two-step verification is required** when `[connect] require_two_factor = true`. Then only
  accounts with two-step verification on ("Two-step verification" above) register devices,
  reach each other's addresses and use the relay, and the consent page of a device leads
  through turning it on and comes back.
- **For now it is not required by default.** While remote control is in development,
  `require_two_factor` defaults to false, so that test accounts need no authenticator: every
  enabled account registers devices and uses the relay, and two-step verification stays
  voluntary (users who turn it on still enter codes at every web sign-in). `config check`, the
  log of `serve` and the admin UI warn about it. This is a temporary setting: the default
  becomes true before remote control is released. To require it now:

  ```toml
  [connect]
  require_two_factor = true
  ```
- **The account page** lists the account's devices, whether they are online, and lets a device
  ask the account's other devices to pair for an hour.
- **Stopping remote access** for a device that stays in use: "Stop remote access" on the
  account page signs it out. It keeps its key and its pairings, and can sign in again.
- **Revoking a device** (lost, stolen, retired) is final for its key: the account's other
  devices forget it, on the local network as well, and it can never be registered again on
  this server. Revoke on the account page or the admin UI, both of which ask for confirmation
  on a page of its own, or with the CLI:

  ```sh
  sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml device list alice
  sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml device revoke alice <ENDPOINT_ID>
  ```

  The CLI asks for the device's short ID, or takes `--confirm <ENDPOINT_ID>` without a terminal.
  A running server picks the revocation up within seconds: it closes the device's control
  channel and disconnects it from the relay.
- **The audit log** records registrations, revocations, connection requests, pairings and the
  sessions devices report, never what they send each other, for 180 days.
- **The reverse proxy** forwards the WebSocket upgrade of `/gono/v1/ws`, as for `/push/ws`
  ([reverse-proxy.md](reverse-proxy.md#nginx)).

### A relay on a host of its own

`gono-cloud relay` runs only the relay, without the file server: no database and no data
directory. It cannot read the device directory, so it admits only the devices of
`relay.allowed_endpoints`. It reads the same configuration file, which still needs the required keys of
`[server]`, `[storage]` and `[db]`, and `relay.enabled = true`. Run it with a copy of the
systemd unit whose `ExecStart` is `/usr/local/bin/gono-cloud relay`, and do not run `serve` with
the same `[relay]` on that host.

## Logs

The server logs to the journal:

```sh
journalctl -u gono-cloud -f                 # follow
journalctl -u gono-cloud --since today
```

Every request is logged at level `info` with its method, path, status, duration and client
address. Credentials never are: headers are not logged, query values are dropped and Login Flow
tokens in paths are replaced by `<redacted>`.
`logging.level` sets the level of Gono Cloud's own messages (`warn` drops the request lines);
dependencies log only warnings and errors. For debugging, the `GONO_CLOUD_LOG` environment
variable replaces the whole filter, for example `GONO_CLOUD_LOG=info,sqlx=debug` (set it in a
drop-in, see above). `logging.file` writes to a file instead of standard output; under systemd
the file must be in a writable path.

## Upgrading

Read the [changelog](../crates/server/CHANGELOG.md) of the new release first. Then download its
`cloud.server.sh` and run it without `--base-url`:

```sh
curl -fsSLo cloud.server.sh https://gono.dev/cloud.server.sh   # the newest server release
sudo sh cloud.server.sh
```

To upgrade to a particular release instead, download the script from that release
(`https://github.com/gonolab/gono.cloud/releases/download/server-v<version>/cloud.server.sh`).

The script checks that the new binary accepts the existing configuration, stops the service,
copies the database to `/var/lib/gono-cloud/backups/<time>-<old version>/`, replaces the binary
and the service file and starts the service again. The server applies database migrations when
it starts. The configuration and the files are not touched, and old backups are never deleted:
remove them yourself once the new version runs well.

Downgrading is not supported once a newer version has migrated the database: an older server
refuses to start on it. To go back, install the older release without starting it, restore the
database from the backup taken before the upgrade (see [Restoring](#restoring)), and start the
service:

```sh
sudo sh cloud.server.sh --version 2.0.0 --no-start   # the cloud.server.sh of any release
# restore /var/lib/gono-cloud/backups/<time>-2.0.0/gono-cloud.db as described below
sudo systemctl start gono-cloud
```

A release before 2.0.0 cannot read the database of 2.0.0 or later at all.

Changes made since the upgrade are lost from the database; `rescan --all` picks up the files
uploaded in the meantime.

Without the script: stop the service, back up the database, replace `/usr/local/bin/gono-cloud`
and the unit file with the ones from the new archive, run `systemctl daemon-reload` and start
the service.

### Upgrading from 1.x

2.0.0 starts with a new database schema, and the database of a 1.x server cannot be migrated to
it: there were no production deployments to carry over. The install script of 2.0.0 and later
stops, without changing anything, when it finds a 1.x server with its database, and a 2.0.0
server refuses to start on a 1.x database. The configuration of 1.x keeps working and the files
stay, but accounts, app passwords and file metadata (ids, favorites, locks) start anew. To start
over:

1. Stop the service: `sudo systemctl stop gono-cloud`.
2. Move the database and the data directory away, and keep them until the new installation
   works:

   ```sh
   sudo mkdir /var/lib/gono-cloud/1.x
   sudo sh -c 'mv /var/lib/gono-cloud/gono-cloud.db* /var/lib/gono-cloud/data /var/lib/gono-cloud/1.x/'
   ```

   (`storage.data_dir` and `db.path` in the configuration say where they are, if you moved them.)
3. Run the new install script without `--base-url`, from a terminal: it keeps the configuration,
   finds no database, creates one with a new admin account (`--admin`, `admin` by default) as a
   fresh install does, and starts the service.
4. Create the other accounts again ([Managing accounts](#managing-accounts)), and sign the
   Nextcloud clients and devices in again: their app passwords are gone.
5. Bring the files back, through a client, or by copying an account's files from the old data
   directory into its new one (owned by the service user) and running `rescan` for it. The files
   of the account with id `<n>` are in `files/<n>/` of a data directory; `user list` shows the
   new ids.

Configurations written by the install script of 1.0 to 1.2 set `admin.path = "/gono-admin"`;
the admin UI now lives at `/manage/` by default (see the changelog).

## Backup and restore

A complete backup consists of:

- the configuration, `/etc/gono-cloud/config.toml`, and the key of two-step verification next
  to it, `/etc/gono-cloud/two-factor.key` (keep it apart from copies of the database; it also
  encrypts the secrets of S3 access keys);
- the database, `/var/lib/gono-cloud/gono-cloud.db` (or the MySQL database): accounts, app
  passwords, file metadata (ids, ETags, favorites, locks) and the instance id;
- the data directory, `/var/lib/gono-cloud/data/`: the users' files.

### The database

The database is SQLite in WAL mode: committed changes may still sit in the write-ahead log,
`gono-cloud.db-wal`, next to it. **Copying `gono-cloud.db` alone while the server runs can
produce a backup that misses recent changes or is corrupt.** Use one of these:

- **While the server runs**, with SQLite's online backup, which writes a consistent snapshot to
  a single file (needs the `sqlite3` command line tool, for example `apt install sqlite3`):

  ```sh
  sudo -u gono-cloud mkdir -p /var/lib/gono-cloud/backups
  sudo -u gono-cloud sqlite3 /var/lib/gono-cloud/gono-cloud.db \
    ".backup '/var/lib/gono-cloud/backups/gono-cloud-$(date +%Y%m%d).db'"
  ```

  Run it as the service user, as shown: SQLite may need to create the database's shared-memory
  file, which must belong to the service user. Then copy the backup file wherever your backups
  go. `VACUUM INTO '<file>'` gives the same result in a compacted file.
- **With the server stopped**: stop the service, copy `gono-cloud.db` and, if it exists,
  `gono-cloud.db-wal` together, start the service. This is what the install script does before
  an upgrade.

A **MySQL** database is backed up with `mysqldump`, while the server runs: `--single-transaction`
reads every table in one consistent snapshot without locking the server out, and `--hex-blob`
writes the byte strings (paths, digests, keys) in hex:

```sh
mysqldump --single-transaction --hex-blob --default-character-set=utf8mb4 \
  -h 127.0.0.1 -u gono -p gono_cloud > gono-cloud-$(date +%Y%m%d).sql
```

To restore it, create an empty database as in [Setting up MySQL](#setting-up-mysql), load the
dump with `mysql --default-character-set=utf8mb4 -h 127.0.0.1 -u gono -p gono_cloud < <file>`
with the service stopped, and continue with `rescan --all` below.

### The files

Back up the data directory with any file-level tool (restic, Borg, rsync, a file system
snapshot). Files that change during the backup may be captured in an intermediate state, as
with any live file server; a file system snapshot (LVM, ZFS, Btrfs) avoids that.

Back up the database first and the files right after it. Files that change in between do not
matter: `rescan` reconciles the metadata with the files after a restore.

### Restoring

1. Stop the service: `sudo systemctl stop gono-cloud`.
2. Put back the configuration, then the data directory, owned by the service user:
   `sudo chown -R gono-cloud:gono-cloud /var/lib/gono-cloud/data`.
3. Put back the database as `/var/lib/gono-cloud/gono-cloud.db`, owned by `gono-cloud` with mode
   `0640`, and delete any `gono-cloud.db-wal` and `gono-cloud.db-shm` left next to it from the
   replaced database. A `-wal` file from the same backup (a copy taken with the server stopped)
   belongs next to it. A MySQL dump goes into an empty database (see above).
4. Reconcile the metadata with the restored files, as the service user:
   `sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml rescan --all`.
5. Start the service: `sudo systemctl start gono-cloud`.

Clients notice changed ETags and synchronize. Devices keep their app passwords as long as the
restored database has them.

## Files changed outside Gono Cloud: rescan

The data directory belongs to the server, and clients see changes only when they go through
WebDAV. After changing files directly (over SSH, Samba, rsync, or by restoring a backup), run
`rescan` as the service user:

```sh
gono rescan alice --dry-run           # show what would change (alias from above)
gono rescan alice --path Photos/2024  # only this folder of alice's files
gono rescan --all                     # every account
gono rescan --all --checksums         # also compute the MD5s that are missing
```

`rescan` adds metadata for new files and folders, removes it for missing ones, gives changed
files new ETags, recomputes folder sizes and renames names that are not Unicode NFC to NFC. It
may run while the server runs; connected clients learn about the changes through notify_push
within a few seconds, others at their next poll.

The server records the MD5 of every file it writes: it is the file's checksum for the Nextcloud
clients (`oc:checksums`) and its ETag in the S3 API. Files changed outside Gono Cloud, and
files written by an earlier version, have none until `rescan --checksums` reads them (once);
with `--dry-run` it only counts them. An MD5 is recorded only if the file is still the version
that was read, so it is safe while the server runs.

## Uninstalling

```sh
sudo sh cloud.server.sh --uninstall
```

This stops and removes the service and the binary. The configuration, the database, the files,
the upgrade backups, the logs and the service user stay, so that nothing is lost by accident.
Remove them yourself when you no longer need them:

```sh
sudo rm -r /etc/gono-cloud /var/lib/gono-cloud
sudo userdel gono-cloud
```

A data directory chosen with `--data-dir` is wherever `storage.data_dir` in the configuration
points.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| The service does not start | `journalctl -u gono-cloud -n 50` shows why. Validate the configuration with `config check`. |
| "Request blocked" after submitting a form in the browser | The browser's origin does not match `server.base_url`; see [reverse-proxy.md](reverse-proxy.md). |
| "this command runs as root, but ... belongs to user id ..." | Run the command as the service user: `sudo -u gono-cloud gono-cloud ...`. |
| "Read-only file system" or "Permission denied" for a data directory outside `/var/lib/gono-cloud` | Allow it with `ReadWritePaths=` in a drop-in, and make it owned by `gono-cloud`. |
| Files copied into the data directory do not appear in clients | Run `rescan` for that user. |
| Clients do not get changes in real time | The proxy must pass WebSocket upgrades on `/push/ws`; see [reverse-proxy.md](reverse-proxy.md#checking-the-setup). |
