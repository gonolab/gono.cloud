#!/bin/sh
# Gono Cloud server installer for Linux with systemd.
#
# Installs or upgrades a release: takes the release archive for this machine (downloaded from
# GitHub, or a local file), verifies it against SHA256SUMS, installs the binary, creates the
# service user and the directories, writes a configuration and runs `gono-cloud init` on a
# fresh install, and installs and (re)starts the service.
#
# It never overwrites an existing configuration, database or data directory. Before an upgrade
# it stops the service and copies the database to a backups/ directory next to it.
# `--uninstall` removes the service and the binary and keeps the configuration, the data and
# the service user.
#
# Run `cloud.server.sh --help` for the options; docs/deployment.md describes the whole setup.

set -eu
umask 022

# The release this copy installs by default. The release workflow fills it in for the copy it
# attaches to a release; the copy in the repository needs --version.
DEFAULT_VERSION=""
REPO="gonolab/gono.cloud"

SERVICE_NAME="gono-cloud"

usage() {
	cat <<'EOF'
Install, upgrade or uninstall the Gono Cloud server (Linux with systemd).

Usage:
  sudo sh cloud.server.sh [--version VERSION] --base-url URL [options]   fresh install
  sudo sh cloud.server.sh [--version VERSION] [options]                  upgrade
  sudo sh cloud.server.sh --uninstall

Release:
  --version VERSION       Release to install, for example 1.0.0. Defaults to the release this
                          script was downloaded from.
  --archive FILE          Install this release archive instead of downloading one. It is
                          verified against SHA256SUMS next to it (or --checksums).
  --checksums FILE        SHA256SUMS file for --archive.
  --repo OWNER/NAME       GitHub repository to download from (default: gonolab/gono.cloud).

Fresh install (ignored when a configuration exists):
  --base-url URL          Public origin of the server, for example https://cloud.example.com.
                          Required.
  --admin NAME            Username of the first admin account (default: admin).
  --admin-password-stdin  Read the admin's web login password from the first line of standard
                          input instead of prompting on the terminal.
  --data-dir DIR          Directory for the users' files (default: <state dir>/data). It must
                          not exist yet or be empty.
  --relay-host HOST       Also run the relay through which devices reach each other, at
                          https://HOST, for example relay.example.com: a host name of its own,
                          not the one of --base-url. The reverse proxy needs a server block
                          for it, and QUIC address discovery a copy of its certificate; the
                          summary lists the next steps.

Other:
  --no-start              Install or upgrade, but do not start the service.
  --uninstall             Stop and remove the service and the binary. The configuration, the
                          database, the files, the logs and the service user are kept.
  -h, --help              Show this help.

Paths:
  binary         /usr/local/bin/gono-cloud
  configuration  /etc/gono-cloud/config.toml
  state          /var/lib/gono-cloud
  logs           journalctl -u gono-cloud
  service user   gono-cloud
EOF
}

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# ---------------------------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------------------------

VERSION=$DEFAULT_VERSION
ARCHIVE=""
CHECKSUMS=""
BASE_URL=""
ADMIN="admin"
PASSWORD_STDIN=0
DATA_DIR=""
RELAY_HOST=""
RELAY_CONFIGURED=0
START=1
ACTION=install

need_value() {
	[ $# -ge 2 ] || die "$1 needs a value (see --help)"
}

while [ $# -gt 0 ]; do
	case $1 in
	--version)
		need_value "$@"
		VERSION=$2
		shift 2
		;;
	--archive)
		need_value "$@"
		ARCHIVE=$2
		shift 2
		;;
	--checksums)
		need_value "$@"
		CHECKSUMS=$2
		shift 2
		;;
	--repo)
		need_value "$@"
		REPO=$2
		shift 2
		;;
	--base-url)
		need_value "$@"
		BASE_URL=$2
		shift 2
		;;
	--admin)
		need_value "$@"
		ADMIN=$2
		shift 2
		;;
	--admin-password-stdin)
		PASSWORD_STDIN=1
		shift
		;;
	--data-dir)
		need_value "$@"
		DATA_DIR=$2
		shift 2
		;;
	--relay-host)
		need_value "$@"
		RELAY_HOST=$2
		shift 2
		;;
	--no-start)
		START=0
		shift
		;;
	--uninstall)
		ACTION=uninstall
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
done

# Accept 1.0.0, v1.0.0 and server-v1.0.0.
VERSION=${VERSION#server-}
VERSION=${VERSION#v}

# ---------------------------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------------------------

detect_platform() {
	[ "$(uname -s)" = Linux ] ||
		die "unsupported operating system $(uname -s); release builds and the installer are for Linux with systemd"

	ARCH=$(uname -m)
	case $ARCH in
	x86_64 | amd64) ARCH=x86_64 ;;
	aarch64 | arm64) ARCH=aarch64 ;;
	*) die "unsupported CPU architecture $ARCH; release builds exist for x86_64 and aarch64" ;;
	esac

	BIN=/usr/local/bin/gono-cloud
	# Statically linked against musl: runs on any distribution, with or without glibc.
	TARGET=$ARCH-unknown-linux-musl
	CONFIG_DIR=/etc/gono-cloud
	STATE_DIR=/var/lib/gono-cloud
	SERVICE_USER=gono-cloud
	SERVICE_GROUP=$SERVICE_USER
	UNIT=/etc/systemd/system/$SERVICE_NAME.service
	DROPIN_DIR=/etc/systemd/system/$SERVICE_NAME.service.d
	DROPIN=$DROPIN_DIR/10-install-data-dir.conf
	CONFIG_FILE=$CONFIG_DIR/config.toml
}

need_command() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is needed but not installed"
}

preflight() {
	[ "$(id -u)" = 0 ] || die "run the installer as root, for example: sudo sh $0 ..."
	[ -d /run/systemd/system ] || die "systemd is not running; the installer sets the server up as a systemd service. Without systemd (Alpine with OpenRC, containers), run the binary from the release archive yourself: see docs/deployment.md"
	for command in systemctl useradd groupadd getent tar gzip; do
		need_command "$command"
	done
}

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

# Rejects values that cannot be written into the configuration or a unit file verbatim.
check_plain() {
	case $2 in
	*[[:space:]\"\\\|\&\']*) die "$1 must not contain spaces, quotes, backslashes, '|' or '&': $2" ;;
	esac
}

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$2" "$1"
	else
		die "curl or wget is needed to download the release"
	fi
}

http_ok() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsS -o /dev/null --max-time 5 "$1" 2>/dev/null
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O /dev/null --timeout=5 "$1" 2>/dev/null
	else
		return 1
	fi
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	else
		die "sha256sum or shasum is needed to verify the release"
	fi
}

# Runs a command as the service user, from the state directory, with the service's umask.
as_service_user() {
	if command -v runuser >/dev/null 2>&1; then
		(cd "$STATE_DIR" && umask 027 && runuser -u "$SERVICE_USER" -- "$@")
	else
		need_command sudo
		(cd "$STATE_DIR" && umask 027 && sudo -u "$SERVICE_USER" -- "$@")
	fi
}

# Prints one effective setting (`server.bind`, `db.path`, ...) of a configuration file, as
# reported by `gono-cloud config check`.
setting() {
	"$1" --config "$2" config check | awk -v key="$3" '$1 == key { sub(/^[ \t]*[^ \t]+[ \t]+/, ""); print; exit }'
}

# ---------------------------------------------------------------------------------------------
# Release archive
# ---------------------------------------------------------------------------------------------

# Leaves the verified, extracted release in $PAYLOAD and its version in $NEW_VERSION.
obtain_release() {
	if [ -n "$ARCHIVE" ]; then
		[ -f "$ARCHIVE" ] || die "archive $ARCHIVE not found"
		archive=$ARCHIVE
		[ -n "$CHECKSUMS" ] || CHECKSUMS=$(dirname "$ARCHIVE")/SHA256SUMS
		[ -f "$CHECKSUMS" ] || die "checksum file $CHECKSUMS not found; pass --checksums"
		checksums=$CHECKSUMS
	else
		[ -n "$VERSION" ] || die "pass the release to install with --version, for example --version 1.0.0"
		name=gono-cloud-$VERSION-$TARGET.tar.gz
		base=https://github.com/$REPO/releases/download/server-v$VERSION
		archive=$WORK/$name
		checksums=$WORK/SHA256SUMS
		log "Downloading $base/$name"
		fetch "$base/SHA256SUMS" "$checksums" || die "cannot download $base/SHA256SUMS; does release server-v$VERSION exist?"
		fetch "$base/$name" "$archive" || die "cannot download $base/$name"
	fi

	name=$(basename "$archive")
	case $name in
	gono-cloud-*-"$TARGET".tar.gz) ;;
	*) die "$name is not a Gono Cloud release archive for this machine ($TARGET)" ;;
	esac
	expected=$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1; exit }' "$checksums")
	[ -n "$expected" ] || die "$name is not listed in $checksums"
	actual=$(sha256_of "$archive")
	[ "$expected" = "$actual" ] || die "checksum mismatch for $name: expected $expected, got $actual"
	log "Verified $name (sha256 $actual)"

	mkdir "$WORK/release"
	tar -xzf "$archive" -C "$WORK/release"
	PAYLOAD=$WORK/release/${name%.tar.gz}
	[ -f "$PAYLOAD/gono-cloud" ] || die "$name does not contain ${name%.tar.gz}/gono-cloud"
	NEW_VERSION=$("$PAYLOAD/gono-cloud" --version 2>/dev/null) ||
		die "the binary in $name does not run on this machine"
	NEW_VERSION=${NEW_VERSION#gono-cloud }
	if [ -n "$VERSION" ] && [ "$VERSION" != "$NEW_VERSION" ]; then
		die "$name contains version $NEW_VERSION, not $VERSION"
	fi
}

# ---------------------------------------------------------------------------------------------
# Service user and directories
# ---------------------------------------------------------------------------------------------

ensure_service_user() {
	if ! getent group "$SERVICE_GROUP" >/dev/null; then
		log "Creating group $SERVICE_GROUP"
		groupadd --system "$SERVICE_GROUP"
	fi
	if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
		log "Creating user $SERVICE_USER"
		nologin=/usr/sbin/nologin
		[ -x "$nologin" ] || nologin=/sbin/nologin
		[ -x "$nologin" ] || nologin=/bin/false
		useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" --no-create-home \
			--shell "$nologin" --comment "Gono Cloud" "$SERVICE_USER"
	fi
}

# Creates a directory with the given mode and owner, leaving existing directories alone.
ensure_dir() {
	[ -d "$1" ] || install -d -m "$2" -o "$3" -g "$4" "$1"
}

# The key the TOTP secrets of two-step verification are encrypted with (two_factor.key_file of
# the configuration, resolved against $CONFIG_DIR as the server does): 32 random bytes,
# readable by the service, created once and never replaced. Losing it means resetting the
# two-step verification of every account, so it belongs in backups of $CONFIG_DIR, apart from
# the database.
ensure_two_factor_key() {
	key=$(setting "$BIN" "$CONFIG_FILE" two_factor.key_file)
	key=${key% (missing)}
	case $key in
	/*) ;;
	*) die "cannot read two_factor.key_file from $CONFIG_FILE" ;;
	esac
	if [ -L "$key" ]; then
		# A link is the operator's choice: keep it, even when its target is gone.
		[ -e "$key" ] || warn "$key is a symbolic link to a missing file; left alone. Restore its target, or remove the link to have a new key created"
		return 0
	fi
	[ -e "$key" ] && return 0
	key_dir=$(dirname "$key")
	if ! [ -d "$key_dir" ]; then
		warn "the directory of two_factor.key_file $key does not exist; create it and run the installer again, or two-step verification stays unavailable"
		return 0
	fi
	# A new name in the same directory, then a hard link, which fails if the key appeared
	# meanwhile: an existing key is never replaced, and a crash leaves no partial key behind.
	key_tmp=$(mktemp "$key.XXXXXX")
	head -c 32 /dev/urandom >"$key_tmp"
	chown "root:$SERVICE_GROUP" "$key_tmp"
	chmod 0640 "$key_tmp"
	sync
	if ln "$key_tmp" "$key" 2>/dev/null; then
		log "Created $key, the key of two-step verification (back it up with $CONFIG_DIR)"
	elif ! [ -e "$key" ] && ! [ -L "$key" ]; then
		rm -f "$key_tmp"
		die "cannot create $key"
	fi
	rm -f "$key_tmp"
}

# ---------------------------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------------------------

stop_service() {
	if systemctl is-active --quiet "$SERVICE_NAME.service"; then
		log "Stopping the service"
		systemctl stop "$SERVICE_NAME.service"
	fi
}

install_service() {
	install -m 0644 -o root -g root "$PAYLOAD/systemd/$SERVICE_NAME.service" "$UNIT"
	systemctl daemon-reload
	systemctl enable --quiet "$SERVICE_NAME.service"
	log "Installed $UNIT"
}

start_service() {
	log "Starting the service"
	systemctl restart "$SERVICE_NAME.service"
}

wait_until_healthy() {
	bind=$(setting "$BIN" "$CONFIG_FILE" server.bind)
	[ -n "$bind" ] || bind=127.0.0.1:16102
	case $bind in
	0.0.0.0:*) bind=127.0.0.1:${bind#*:} ;;
	"[::]:"*) bind="[::1]:${bind##*:}" ;;
	esac
	attempt=0
	while [ "$attempt" -lt 30 ]; do
		if http_ok "http://$bind/healthz"; then
			log "The server answers on http://$bind"
			return 0
		fi
		sleep 1
		attempt=$((attempt + 1))
	done
	warn "the server did not answer on http://$bind/healthz within 30 seconds; see: journalctl -u $SERVICE_NAME -n 50"
	return 1
}

# ---------------------------------------------------------------------------------------------
# Install and upgrade
# ---------------------------------------------------------------------------------------------

# Copies the database of a stopped server to backups/<time>-<version>/ next to it.
backup_database() {
	db=$1
	old_version=$2
	[ -f "$db" ] || return 0
	backups=$(dirname "$db")/backups
	target=$backups/$(date -u +%Y%m%dT%H%M%SZ)-$old_version
	ensure_dir "$backups" 0750 "$SERVICE_USER" "$SERVICE_GROUP"
	install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$target"
	# The write-ahead log holds committed changes until they are checkpointed: copy it too.
	for file in "$db" "$db-wal"; do
		if [ -f "$file" ]; then
			cp -p "$file" "$target/"
		fi
	done
	log "Backed the database up to $target"
}

# The database schema a version uses: 2.0.0 and 3.0.0 each started a new one, which the databases
# of the versions before them cannot be migrated to. Releases from 3.0.0 on migrate in place.
schema_generation() {
	case $1 in
	0.* | 1.*) echo 1 ;;
	2.*) echo 2 ;;
	*) echo 3 ;;
	esac
}

# Stops before anything changes when the installed server's database exists and uses an older
# schema than the new version: the new server would refuse it.
refuse_upgrade_across_schemas() {
	db=$1
	[ -x "$BIN" ] || return 0
	installed=$("$BIN" --version 2>/dev/null) || return 0
	installed=${installed#gono-cloud }
	[ "$(schema_generation "$installed")" -lt "$(schema_generation "$NEW_VERSION")" ] || return 0
	die "gono-cloud $installed cannot be upgraded to $NEW_VERSION in place: $NEW_VERSION starts with a new database schema, which the database of $installed cannot be migrated to. Nothing was changed. To start over with $NEW_VERSION, stop the service, move $db and the data directory away (keep them), and run the installer again; see \"Upgrading from 1.x or 2.x\" in docs/deployment.md"
}

# Writes the configuration of a fresh install to $WORK/config.toml and validates it.
prepare_config() {
	db_path=$1
	data_dir=$2
	config=$WORK/config.toml
	{
		printf '# Written by cloud.server.sh from config.example.toml of Gono Cloud %s on %s.\n' \
			"$NEW_VERSION" "$(date -u +%Y-%m-%d)"
		printf '# Validate changes with: gono-cloud --config %s config check\n\n' "$CONFIG_FILE"
		sed -e "s|^base_url = .*|base_url = \"$BASE_URL\"|" \
			-e "s|^data_dir = .*|data_dir = \"$data_dir\"|" \
			-e "s|^path = \"gono-cloud.db\"|path = \"$db_path\"|" \
			"$PAYLOAD/config.example.toml"
	} >"$config"
	for expected in "base_url = \"$BASE_URL\"" "data_dir = \"$data_dir\"" "path = \"$db_path\""; do
		grep -qxF "$expected" "$config" || die "cannot adapt config.example.toml ($expected missing)"
	done
	if [ -n "$RELAY_HOST" ]; then
		# Turns on the [relay] table and sets its public_url. Only that table changes: others
		# have keys of the same names ([s3] has `enabled = false` and `# public_url = ...` too).
		# QUIC address discovery stays off until its certificate is in place: the relay would
		# not start without it.
		sed -e '/^\[relay\]$/,/^\[/{' \
			-e 's|^enabled = false$|enabled = true|' \
			-e "s|^# public_url = .*|public_url = \"https://$RELAY_HOST\"|" \
			-e '}' \
			"$config" >"$config.relay"
		mv "$config.relay" "$config"
		relay_table=$(sed -n '/^\[relay\]$/,/^\[/p' "$config")
		if ! printf '%s\n' "$relay_table" | grep -qxF "public_url = \"https://$RELAY_HOST\"" ||
			! printf '%s\n' "$relay_table" | grep -qx 'enabled = true'; then
			die "cannot adapt config.example.toml ([relay] missing)"
		fi
	fi
	"$PAYLOAD/gono-cloud" --config "$config" config check >/dev/null ||
		die "the configuration written for --base-url $BASE_URL is invalid"
}

# Checks --relay-host: a bare host name, different from the one of --base-url.
check_relay_host() {
	check_plain --relay-host "$RELAY_HOST"
	case $RELAY_HOST in
	*://* | */* | *:*) die "--relay-host takes a host name only, for example relay.example.com" ;;
	esac
	base_host=${BASE_URL#*://}
	base_host=${base_host%%/*}
	base_host=${base_host%%:*}
	[ "$RELAY_HOST" != "$base_host" ] ||
		die "--relay-host needs a host name of its own: the relay cannot share $base_host with --base-url"
}

install_release() {
	WORK=$(mktemp -d)
	trap 'rm -rf "$WORK"' EXIT
	trap 'exit 130' INT TERM

	fresh_config=0
	[ -e "$CONFIG_FILE" ] || fresh_config=1
	if [ "$fresh_config" = 1 ]; then
		[ -n "$BASE_URL" ] || die "no configuration at $CONFIG_FILE yet: pass --base-url for a fresh install"
		case $BASE_URL in
		http://* | https://*) ;;
		*) die "--base-url must start with https:// (or http:// for a test setup)" ;;
		esac
		check_plain --base-url "$BASE_URL"
		[ -n "$DATA_DIR" ] || DATA_DIR=$STATE_DIR/data
		case $DATA_DIR in
		/*) ;;
		*) die "--data-dir must be an absolute path" ;;
		esac
		check_plain --data-dir "$DATA_DIR"
		if [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR")" ]; then
			die "$DATA_DIR is not empty; choose an empty or new directory with --data-dir"
		fi
		[ -z "$RELAY_HOST" ] || check_relay_host
		db_path=$STATE_DIR/gono-cloud.db
		if [ -e "$db_path" ]; then
			die "found a database at $db_path but no configuration at $CONFIG_FILE; restore the configuration or move the database away"
		fi
		needs_init=1
	else
		[ -z "$BASE_URL" ] || warn "--base-url is ignored: $CONFIG_FILE exists"
		[ -z "$DATA_DIR" ] || warn "--data-dir is ignored: $CONFIG_FILE exists"
		[ -z "$RELAY_HOST" ] || warn "--relay-host is ignored: $CONFIG_FILE exists; set up [relay] in it as described in docs/deployment.md"
		needs_init=0
	fi

	obtain_release

	if [ "$fresh_config" = 1 ]; then
		prepare_config "$db_path" "$DATA_DIR"
	else
		# The new binary must accept the existing configuration before anything changes.
		if ! "$PAYLOAD/gono-cloud" --config "$CONFIG_FILE" config check >/dev/null; then
			die "Gono Cloud $NEW_VERSION does not accept $CONFIG_FILE; fix it and run the installer again"
		fi
		if [ "$(setting "$PAYLOAD/gono-cloud" "$CONFIG_FILE" db.backend)" = mysql ]; then
			# MySQL: the database is no file here, and `init` ran when it was set up
			# (docs/deployment.md, "Choosing the database"). Its backups are the operator's.
			db_path=""
			log "The database is MySQL: back it up with mysqldump before upgrades"
		else
			db_path=$(setting "$PAYLOAD/gono-cloud" "$CONFIG_FILE" db.path)
			# A configuration without a database: an earlier install stopped before `init`.
			[ -e "$db_path" ] || needs_init=1
			[ "$needs_init" = 1 ] || refuse_upgrade_across_schemas "$db_path"
		fi
	fi
	if [ "$needs_init" = 1 ] && [ "$PASSWORD_STDIN" = 0 ] && ! [ -t 0 ]; then
		die "a fresh install creates the first admin account: run the installer from a terminal, or pass --admin-password-stdin"
	fi

	ensure_service_user
	ensure_dir "$CONFIG_DIR" 0750 root "$SERVICE_GROUP"
	ensure_dir "$STATE_DIR" 0750 "$SERVICE_USER" "$SERVICE_GROUP"

	old_version=""
	if [ -x "$BIN" ]; then
		old_version=$("$BIN" --version 2>/dev/null) || old_version="gono-cloud unknown"
		old_version=${old_version#gono-cloud }
	fi
	if [ "$needs_init" = 0 ]; then
		stop_service
		backup_database "$db_path" "${old_version:-unknown}"
	fi

	# Replace the binary atomically: a running server keeps its old copy until it restarts.
	mkdir -p "$(dirname "$BIN")"
	install -m 0755 -o root -g root "$PAYLOAD/gono-cloud" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	if [ -n "$old_version" ]; then
		log "Replaced gono-cloud $old_version with $NEW_VERSION at $BIN"
	else
		log "Installed gono-cloud $NEW_VERSION at $BIN"
	fi

	if [ "$fresh_config" = 1 ]; then
		if [ -d "$DATA_DIR" ]; then
			# Checked to be empty above: hand it to the service user, which `init` runs as.
			chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
			chmod 0750 "$DATA_DIR"
		elif [ "$DATA_DIR" != "$STATE_DIR/data" ]; then
			mkdir -p "$(dirname "$DATA_DIR")"
			install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
		fi
		install -m 0640 -o root -g "$SERVICE_GROUP" "$WORK/config.toml" "$CONFIG_FILE"
		log "Wrote $CONFIG_FILE"
		if [ -n "$RELAY_HOST" ]; then
			# Where the renewal hook puts the relay's certificate for QUIC address discovery.
			ensure_dir "$CONFIG_DIR/relay-tls" 0750 root "$SERVICE_GROUP"
			RELAY_CONFIGURED=1
		fi
	fi
	if [ "$fresh_config" = 1 ]; then
		case $DATA_DIR in
		"$STATE_DIR"/*) ;;
		*)
			# The unit only lets the server write /var/lib/gono-cloud.
			mkdir -p "$DROPIN_DIR"
			printf '# Written by cloud.server.sh: the data directory chosen at install time.\n[Service]\nReadWritePaths=%s\n' \
				"$DATA_DIR" >"$DROPIN"
			log "Wrote $DROPIN"
			;;
		esac
	fi

	ensure_two_factor_key

	if [ "$needs_init" = 1 ]; then
		log "Creating the database and the admin account $ADMIN"
		if [ "$PASSWORD_STDIN" = 1 ]; then
			as_service_user "$BIN" --config "$CONFIG_FILE" init --admin "$ADMIN" --password-stdin
		else
			as_service_user "$BIN" --config "$CONFIG_FILE" init --admin "$ADMIN"
		fi
	fi

	install_service
	healthy=1
	if [ "$START" = 1 ]; then
		start_service
		wait_until_healthy || healthy=0
	fi
	summary
	[ "$healthy" = 1 ] || exit 1
}

summary() {
	status="systemctl status $SERVICE_NAME"
	logs="journalctl -u $SERVICE_NAME"
	cat <<EOF

Gono Cloud $NEW_VERSION is installed.

  binary         $BIN
  configuration  $CONFIG_FILE
  state          $STATE_DIR
  service        $status
  logs           $logs

Manage accounts as the service user, for example:
  sudo -u $SERVICE_USER $BIN --config $CONFIG_FILE user list

Put a reverse proxy with HTTPS in front of the server before clients connect; see
docs/reverse-proxy.md and docs/deployment.md.
EOF
	if [ "$RELAY_CONFIGURED" = 1 ]; then
		cat <<EOF

The relay runs at https://$RELAY_HOST. Next steps (see "The relay" in docs/deployment.md):
  1. Give $RELAY_HOST a server block of its own in the reverse proxy, with HTTPS, and with
     plain HTTP for /generate_204 (docs/reverse-proxy.md).
  2. For QUIC address discovery, copy the certificate of $RELAY_HOST into
     $CONFIG_DIR/relay-tls/ after every renewal, then set relay.qad_bind,
     relay.tls_cert and relay.tls_key, and open UDP 7842 in the firewall.
  3. Restart the service.
EOF
		# The server admits the devices registered for remote access, which needs an https
		# base URL; relay.allowed_endpoints is only for devices that are not registered.
		case $BASE_URL in
		https://*)
			cat <<EOF

Devices use the relay once they are registered for remote access, from accounts with two-step
verification on ("Remote access" in docs/deployment.md); nothing needs to be listed for them.
relay.allowed_endpoints in the configuration is only for devices that are not registered, such
as test setups.
EOF
			;;
		*)
			cat <<EOF

Remote access needs an https base URL, so devices cannot register with
$BASE_URL. Until it is https, the relay admits only the device ids listed in
relay.allowed_endpoints in the configuration.
EOF
			;;
		esac
	fi
	if [ "$START" = 0 ]; then
		printf '\nThe service was not started (--no-start).\n'
	fi
}

# ---------------------------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------------------------

uninstall() {
	if [ -f "$UNIT" ]; then
		systemctl disable --now "$SERVICE_NAME.service" || true
		rm -f "$UNIT" "$DROPIN"
		rmdir "$DROPIN_DIR" 2>/dev/null || true
		systemctl daemon-reload
		log "Removed the systemd service"
	fi
	if [ -f "$BIN" ]; then
		rm -f "$BIN"
		log "Removed $BIN"
	fi

	cat <<EOF

Gono Cloud is uninstalled. Kept, so that nothing is lost by accident:

  configuration  $CONFIG_DIR
  state          $STATE_DIR (database, backups and, by default, the files)
EOF
	printf '  service user   %s\n\n' "$SERVICE_USER"
	printf '%s\n' 'Remove them yourself once you no longer need them. A data directory chosen with' \
		'--data-dir is named in the configuration (storage.data_dir).'
	printf '  sudo rm -r %s %s\n  sudo userdel %s\n' "$CONFIG_DIR" "$STATE_DIR" "$SERVICE_USER"
}

# ---------------------------------------------------------------------------------------------

detect_platform
preflight
case $ACTION in
install) install_release ;;
uninstall) uninstall ;;
esac
