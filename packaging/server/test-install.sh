#!/bin/sh
# End-to-end test of cloud.server.sh on a throwaway machine: refused installs, a fresh install, the
# running service, WebDAV through the (sandboxed) service, the root guard of the CLI, a
# graceful stop, an upgrade, a refused upgrade from 1.x and the uninstall.
#
# Usage: packaging/server/test-install.sh <cloud.server.sh> <archive> [<SHA256SUMS>]
#
# Without a SHA256SUMS file, one is written for a copy of the archive. The test installs a
# system service and creates a system user, so it only runs where CI=true (GitHub Actions sets
# it, and so does packaging/server/test-in-container.sh); never run it on a machine you care
# about. It needs sudo without a password.

set -eu

[ "${CI:-}" = true ] || {
	echo "error: $0 installs a system service and only runs in CI (CI=true)" >&2
	exit 1
}
[ $# -ge 2 ] || {
	echo "usage: $0 <cloud.server.sh> <archive> [<SHA256SUMS>]" >&2
	exit 2
}
installer=$1
archive=$2
checksums=${3:-}

PASSWORD="install test password"
BASE_URL=https://cloud.example.com
ADDR=127.0.0.1:16102
RELAY_HOST=relay.example.com
RELAY_ADDR=127.0.0.1:16103
BIN=/usr/local/bin/gono-cloud

[ "$(uname -s)" = Linux ] || {
	echo "error: the installer supports Linux only, not $(uname -s)" >&2
	exit 1
}
user=gono-cloud
config=/etc/gono-cloud/config.toml
state=/var/lib/gono-cloud

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

step() { printf '\n### %s\n' "$*"; }

dump_logs() {
	sudo journalctl -u gono-cloud --no-pager -n 100 || true
}

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	dump_logs
	exit 1
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

if [ -z "$checksums" ]; then
	cp "$archive" "$work/"
	archive=$work/$(basename "$archive")
	(cd "$work" && sha256 "$(basename "$archive")" >SHA256SUMS)
	checksums=$work/SHA256SUMS
fi

run_installer() {
	sudo sh "$installer" --archive "$archive" --checksums "$checksums" "$@"
}

as_service_user() {
	(cd / && sudo -u "$user" "$BIN" --config "$config" "$@")
}

wait_until_healthy() {
	attempt=0
	until curl -fsS "http://$ADDR/healthz" >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 30 ] || fail "the server does not answer on $ADDR"
		sleep 1
	done
}

owner_and_mode() {
	sudo stat -c '%U:%G %a' "$1"
}

# ---------------------------------------------------------------------------------------------

step "Nothing is installed yet"
[ ! -e "$config" ] || fail "$config exists before the test"
if id -u "$user" >/dev/null 2>&1; then fail "user $user exists before the test"; fi

step "A fresh install without --base-url is refused and changes nothing"
if run_installer </dev/null >"$work/out" 2>&1; then fail "installed without --base-url"; fi
cat "$work/out"
grep -q -- "--base-url" "$work/out" || fail "the error does not mention --base-url"
[ ! -e "$config" ] || fail "$config was written"
if id -u "$user" >/dev/null 2>&1; then fail "user $user was created"; fi

step "A fresh install without a terminal needs --admin-password-stdin"
if run_installer --base-url "$BASE_URL" </dev/null >"$work/out" 2>&1; then fail "installed without a password"; fi
cat "$work/out"
grep -q -- "--admin-password-stdin" "$work/out" || fail "the error does not mention --admin-password-stdin"
[ ! -e "$config" ] || fail "$config was written"

step "An archive that does not match SHA256SUMS is refused"
sed 's/^[0-9a-f]*/0000000000000000000000000000000000000000000000000000000000000000/' "$checksums" >"$work/BAD"
# shellcheck disable=SC2024 # The output file belongs to the test user, not to root.
if printf '%s\n' "$PASSWORD" | sudo sh "$installer" --archive "$archive" --checksums "$work/BAD" \
	--base-url "$BASE_URL" --admin-password-stdin >"$work/out" 2>&1; then
	fail "installed an archive with a wrong checksum"
fi
cat "$work/out"
grep -q "checksum mismatch" "$work/out" || fail "the error does not mention the checksum"
[ ! -e "$config" ] || fail "$config was written"

step "A relay host that shares the base URL's host name is refused"
if run_installer --base-url "$BASE_URL" --relay-host cloud.example.com </dev/null >"$work/out" 2>&1; then
	fail "installed a relay on the host name of --base-url"
fi
cat "$work/out"
grep -q "host name of its own" "$work/out" || fail "the error does not explain the refusal"
[ ! -e "$config" ] || fail "$config was written"

step "Fresh install, with the relay"
printf '%s\n' "$PASSWORD" | run_installer --base-url "$BASE_URL" --relay-host "$RELAY_HOST" \
	--admin-password-stdin

step "The service runs and answers"
wait_until_healthy
curl -fsS "http://$ADDR/status.php" | tee "$work/status"
echo
grep -q '"installed":true' "$work/status" || fail "status.php does not report an installed server"
systemctl is-active gono-cloud
systemctl is-enabled gono-cloud

step "Ownership and modes"
[ "$(owner_and_mode "$config")" = "root:$user 640" ] || fail "config: $(owner_and_mode "$config")"
[ "$(owner_and_mode "$(dirname "$config")")" = "root:$user 750" ] || fail "config dir: $(owner_and_mode "$(dirname "$config")")"
[ "$(owner_and_mode "$state")" = "$user:$user 750" ] || fail "state dir: $(owner_and_mode "$state")"
owner_and_mode "$state/gono-cloud.db" | grep -q "^$user:$user " || fail "database: $(owner_and_mode "$state/gono-cloud.db")"
owner_and_mode "$state/data/files/1" | grep -q "^$user:$user " || fail "admin files: $(owner_and_mode "$state/data/files/1")"
sudo grep -qx "base_url = \"$BASE_URL\"" "$config" || fail "base_url not in $config"
sudo grep -qx "public_url = \"https://$RELAY_HOST\"" "$config" || fail "relay.public_url not in $config"
[ "$(owner_and_mode "$(dirname "$config")/relay-tls")" = "root:$user 750" ] ||
	fail "relay-tls dir: $(owner_and_mode "$(dirname "$config")/relay-tls")"
key="$(dirname "$config")/two-factor.key"
[ "$(owner_and_mode "$key")" = "root:$user 640" ] || fail "two-factor key: $(owner_and_mode "$key")"
[ "$(sudo wc -c "$key" | awk '{print $1}')" = 32 ] || fail "the two-factor key is not 32 bytes"

step "The relay runs inside the (sandboxed) service"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://$RELAY_ADDR/generate_204")
[ "$code" = 204 ] || fail "the relay's /generate_204 answered $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://$RELAY_ADDR/healthz")
[ "$code" = 200 ] || fail "the relay's /healthz answered $code"

step "Management commands refuse root and work as the service user"
if (cd / && sudo "$BIN" --config "$config" user list) >"$work/out" 2>&1; then
	fail "user list ran as root on the service user's installation"
fi
cat "$work/out"
grep -q "runs as root" "$work/out" || fail "the error does not explain the refusal"
as_service_user user list | tee "$work/users"
grep -q "^1 *admin " "$work/users" || fail "no admin account"

step "WebDAV through the service"
token=$(as_service_user app-password add admin --label install-test | sed -n 's/^App password: //p')
[ -n "$token" ] || fail "no app password"
printf 'hello from the install test\n' >"$work/hello.txt"
dav=http://$ADDR/remote.php/dav/files/admin
curl -fsS -u "admin:$token" -T "$work/hello.txt" "$dav/hello.txt"
curl -fsS -u "admin:$token" "$dav/hello.txt" >"$work/back.txt"
cmp "$work/hello.txt" "$work/back.txt" || fail "downloaded file differs"
status=$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$token" -X PROPFIND -H 'Depth: 1' "$dav/")
[ "$status" = 207 ] || fail "PROPFIND answered $status"
sudo test -f "$state/data/files/1/hello.txt" || fail "the file is not in the data directory"

step "systemd unit verification and exposure"
sudo systemd-analyze verify /etc/systemd/system/gono-cloud.service
systemd-analyze security gono-cloud.service --no-pager | tail -n 1

step "SIGTERM stops the server cleanly"
sudo systemctl stop gono-cloud
result=$(systemctl show gono-cloud -p Result --value)
code=$(systemctl show gono-cloud -p ExecMainStatus --value)
[ "$result" = success ] && [ "$code" = 0 ] || fail "stop: Result=$result ExecMainStatus=$code"
sudo systemctl start gono-cloud
wait_until_healthy

step "Upgrade keeps the configuration and the files and backs the database up"
before=$(sudo cat "$config" | sha256)
key_before=$(sudo cat "$key" | sha256)
run_installer </dev/null
after=$(sudo cat "$config" | sha256)
[ "$before" = "$after" ] || fail "the upgrade changed $config"
[ "$key_before" = "$(sudo cat "$key" | sha256)" ] || fail "the upgrade replaced the two-factor key"
sudo ls "$state/backups"
backup=$(sudo ls "$state/backups" | head -n 1)
sudo test -f "$state/backups/$backup/gono-cloud.db" || fail "no database backup"
wait_until_healthy
curl -fsS -u "admin:$token" "$dav/hello.txt" | cmp - "$work/hello.txt" || fail "the file is gone after the upgrade"

step "An upgrade keeps a dangling link at the two-factor key, and warns"
sudo mv "$key" "$key.saved"
sudo ln -s "$key.gone" "$key"
if ! run_installer </dev/null >"$work/out" 2>&1; then
	cat "$work/out"
	fail "the upgrade failed with a dangling key link"
fi
cat "$work/out"
grep -q "symbolic link to a missing file" "$work/out" || fail "no warning about the dangling key link"
sudo test -L "$key" || fail "the upgrade replaced the key link"
if sudo test -e "$key.gone"; then fail "the upgrade created the target of the key link"; fi
sudo rm "$key"
sudo mv "$key.saved" "$key"
wait_until_healthy

step "An upgrade from 1.x stops before it changes anything"
sudo cp -p "$BIN" "$work/gono-cloud.real"
printf '#!/bin/sh\necho "gono-cloud 1.2.0"\n' >"$work/gono-cloud.old"
sudo install -m 0755 "$work/gono-cloud.old" "$BIN"
backups_before=$(sudo ls "$state/backups" | wc -l)
if run_installer </dev/null >"$work/out" 2>&1; then
	cat "$work/out"
	fail "the installer upgraded 1.2.0 in place"
fi
cat "$work/out"
grep -q "cannot be upgraded to .* in place" "$work/out" || fail "no explanation of the refused upgrade"
sudo cmp -s "$work/gono-cloud.old" "$BIN" || fail "the refused upgrade replaced the binary"
[ "$backups_before" = "$(sudo ls "$state/backups" | wc -l)" ] || fail "the refused upgrade made a backup"
sudo install -m 0755 "$work/gono-cloud.real" "$BIN"
wait_until_healthy

step "Uninstall keeps the configuration, the data and the service user"
sudo sh "$installer" --uninstall
[ ! -e "$BIN" ] || fail "$BIN is still there"
[ ! -e /etc/systemd/system/gono-cloud.service ] || fail "the unit is still installed"
if curl -fsS "http://$ADDR/healthz" >/dev/null 2>&1; then fail "the server still answers"; fi
sudo test -f "$config" || fail "the configuration was removed"
sudo test -f "$state/gono-cloud.db" || fail "the database was removed"
sudo test -f "$state/data/files/1/hello.txt" || fail "the files were removed"
id -u "$user" >/dev/null || fail "the service user was removed"

step "Reinstalling after the uninstall picks the old installation up"
run_installer </dev/null
wait_until_healthy
curl -fsS -u "admin:$token" "$dav/hello.txt" | cmp - "$work/hello.txt" || fail "the file is gone after reinstalling"

printf '\nAll install tests passed.\n'
