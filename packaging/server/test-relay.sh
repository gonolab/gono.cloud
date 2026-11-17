#!/bin/sh
# End-to-end test of the relay as a fresh install with --relay-host sets it up: inside the
# hardened systemd unit, behind nginx with the server blocks of docs/reverse-proxy.md, and with
# its certificate handed over by the certbot deploy hook of docs/deployment.md. It checks the
# relay's own probes the way devices use them:
#
# - /generate_204 on port 80 answers its challenge with 204 and is not redirected, while the
#   rest of port 80 is, except ACME challenges, which come from certbot's webroot;
# - HTTPS reaches the relay, and two devices reach each other through its WebSocket;
# - QUIC address discovery on UDP 7842 serves the certificate the hook copied into
#   /etc/gono-cloud/relay-tls/ and reports the address it sees, over IPv4 and IPv6;
# - after a renewal (a new key and certificate, handed over by the same hook) QAD serves the
#   new certificate without a restart of the service; while only the certificate has been
#   copied, it keeps serving the previous pair.
#
# Usage: packaging/server/test-relay.sh <cloud.server.sh> <archive> <relay-probe>
#
# <relay-probe> is crates/server/relay/examples/relay-probe.rs built for this machine. The test
# needs systemd, nginx, openssl and curl, and runs from the repository root (it reads the
# nginx blocks and the hook from docs/). It installs a system service, writes to /etc/nginx,
# /etc/letsencrypt and /etc/hosts, and creates a system user, so it only runs where CI=true:
# GitHub Actions, or a throwaway container (packaging/server/test-in-container.sh). It needs
# sudo without a password.

set -eu

[ "${CI:-}" = true ] || {
	echo "error: $0 installs a system service and only runs in CI (CI=true)" >&2
	exit 1
}
[ $# -eq 3 ] || {
	echo "usage: $0 <cloud.server.sh> <archive> <relay-probe>" >&2
	exit 2
}
installer=$1
archive=$2
probe=$3

PASSWORD="relay test password"
BASE_URL=https://cloud.example.com
RELAY_HOST=relay.example.com
ADDR=127.0.0.1:16102
CONFIG=/etc/gono-cloud/config.toml
TLS_DIR=/etc/gono-cloud/relay-tls
LINEAGE=/etc/letsencrypt/live/$RELAY_HOST
HOOK=/etc/letsencrypt/renewal-hooks/deploy/gono-cloud-relay
SITE=/etc/nginx/conf.d/gono-cloud-relay.conf
# Short, so that a renewal reaches QAD within the test; the default is an hour.
RELOAD_SECS=2

for command in systemctl nginx openssl curl; do
	command -v "$command" >/dev/null || {
		echo "error: $command is needed" >&2
		exit 1
	}
done
[ -f docs/reverse-proxy.md ] && [ -f docs/deployment.md ] || {
	echo "error: run $0 from the repository root" >&2
	exit 1
}

work=$(mktemp -d)
hosts_line="127.0.0.1 $RELAY_HOST # gono-cloud relay test"
cleanup() {
	if grep -qxF "$hosts_line" /etc/hosts 2>/dev/null; then
		grep -vxF "$hosts_line" /etc/hosts >"$work/hosts" || true
		sudo sh -c "cat '$work/hosts' >/etc/hosts"
	fi
	rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n### %s\n' "$*"; }

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	sudo journalctl -u gono-cloud --no-pager -n 100 || true
	sudo tail -n 20 /var/log/nginx/error.log || true
	exit 1
}

sha256() {
	sha256sum "$@" | awk '{ print $1 }'
}

owner_and_mode() {
	sudo stat -c '%U:%G %a' "$1"
}

wait_until_healthy() {
	attempt=0
	until curl -fsS "http://$ADDR/healthz" >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 30 ] || fail "the server does not answer on $ADDR"
		sleep 1
	done
}

# Prints the fenced block of language $3 that follows the heading $2 in the Markdown file $1.
doc_block() {
	awk -v heading="$2" -v fence="$3" '
		$0 == heading { found = 1; next }
		found && !inside && $0 == "```" fence { inside = 1; next }
		inside && $0 == "```" { exit }
		inside { print }
	' "$1"
}

# Writes a certificate for $RELAY_HOST signed by the test CA, with a new key, to $1.pem and
# $1.key, and prints the SHA-256 of the certificate as QAD reports it.
issue() {
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/$1.key" \
		-subj "/CN=$RELAY_HOST" -out "$work/$1.csr" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
		"$RELAY_HOST" >"$work/$1.ext"
	openssl x509 -req -in "$work/$1.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
		-CAcreateserial -days 2 -extfile "$work/$1.ext" -out "$work/$1.pem" 2>/dev/null
	openssl x509 -in "$work/$1.pem" -outform DER | sha256sum | awk '{ print $1 }'
}

# Puts certificate $1 where certbot keeps the lineage of $RELAY_HOST, private key readable by
# root only, as certbot does.
deploy_to_lineage() {
	cat "$work/$1.pem" "$work/ca.pem" >"$work/$1.fullchain.pem"
	sudo install -d -m 0755 "$LINEAGE"
	sudo install -m 0644 -o root -g root "$work/$1.fullchain.pem" "$LINEAGE/fullchain.pem"
	sudo install -m 0600 -o root -g root "$work/$1.key" "$LINEAGE/privkey.pem"
}

# Runs the deploy hook the way certbot does after it renewed $RELAY_HOST.
run_hook() {
	sudo env RENEWED_LINEAGE="$LINEAGE" "$HOOK"
}

# QUIC address discovery against $1 (address:port); sets $observed and $served.
qad() {
	"$probe" qad "$1" "$RELAY_HOST" "$work/ca.pem" >"$work/qad" 2>&1 || return 1
	observed=$(sed -n 's/^observed //p' "$work/qad")
	served=$(sed -n 's/^certificate //p' "$work/qad")
}

service_property() {
	systemctl show gono-cloud -p "$1" --value
}

# ---------------------------------------------------------------------------------------------

step "Nothing is installed yet"
[ ! -e "$CONFIG" ] || fail "$CONFIG exists before the test"

step "A test CA and the first certificate of $RELAY_HOST, where certbot keeps it"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
	-subj "/CN=Gono Cloud relay test CA" -keyout "$work/ca.key" -out "$work/ca.pem" \
	-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
first=$(issue first)
deploy_to_lineage first
echo "first certificate: $first"

step "Fresh install with --relay-host"
cp "$archive" "$work/"
archive=$work/$(basename "$archive")
(cd "$work" && sha256sum "$(basename "$archive")" >SHA256SUMS)
printf '%s\n' "$PASSWORD" | sudo sh "$installer" --archive "$archive" --checksums "$work/SHA256SUMS" \
	--base-url "$BASE_URL" --relay-host "$RELAY_HOST" --admin-password-stdin
wait_until_healthy
[ "$(owner_and_mode "$TLS_DIR")" = "root:gono-cloud 750" ] || fail "relay-tls: $(owner_and_mode "$TLS_DIR")"

step "nginx with the relay's server blocks of docs/reverse-proxy.md"
{
	echo "# Written by $0 from docs/reverse-proxy.md."
	echo "map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }"
	doc_block docs/reverse-proxy.md "## The relay" nginx
} >"$work/site.conf"
grep -q "server_name $RELAY_HOST;" "$work/site.conf" || fail "no nginx block found in docs/reverse-proxy.md"
grep -q "ssl_certificate .*$LINEAGE/fullchain.pem;" "$work/site.conf" ||
	fail "the documented nginx block does not use $LINEAGE"
cat "$work/site.conf"
sudo install -m 0644 "$work/site.conf" "$SITE"
sudo nginx -t
sudo systemctl restart nginx

step "/generate_204 answers its challenge over plain HTTP on port 80, without a redirect"
code=$(curl -sS -o /dev/null -D "$work/headers" -w '%{http_code}' --resolve "$RELAY_HOST:80:127.0.0.1" \
	-H 'X-Iroh-Challenge: gono-ci-204' "http://$RELAY_HOST/generate_204")
cat "$work/headers"
[ "$code" = 204 ] || fail "/generate_204 on port 80 answered $code"
tr -d '\r' <"$work/headers" | grep -qix 'x-iroh-response: response gono-ci-204' ||
	fail "/generate_204 did not answer the challenge"
if grep -qi '^location:' "$work/headers"; then fail "/generate_204 was redirected"; fi

step "ACME challenges of the relay's certificate come from the webroot, not from the relay"
sudo install -d -m 0755 /var/www/letsencrypt/.well-known/acme-challenge
echo "gono-ci-token.key-authorization" >"$work/token"
sudo install -m 0644 "$work/token" /var/www/letsencrypt/.well-known/acme-challenge/gono-ci-token
code=$(curl -sS -o "$work/body" -w '%{http_code}' --resolve "$RELAY_HOST:80:127.0.0.1" \
	"http://$RELAY_HOST/.well-known/acme-challenge/gono-ci-token")
[ "$code" = 200 ] || fail "the ACME challenge on port 80 answered $code"
cmp "$work/token" "$work/body" || fail "the ACME challenge on port 80 is not the webroot's file"

step "The rest of port 80 redirects to HTTPS"
code=$(curl -sS -o /dev/null -D "$work/headers" -w '%{http_code}' --resolve "$RELAY_HOST:80:127.0.0.1" \
	"http://$RELAY_HOST/relay")
[ "$code" = 301 ] || fail "http://$RELAY_HOST/relay answered $code"
tr -d '\r' <"$work/headers" | grep -qix "location: https://$RELAY_HOST/relay" || fail "no redirect to HTTPS"

step "HTTPS reaches the relay, and devices reach each other through its WebSocket"
code=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$work/ca.pem" \
	--resolve "$RELAY_HOST:443:127.0.0.1" "https://$RELAY_HOST/healthz")
[ "$code" = 200 ] || fail "https://$RELAY_HOST/healthz answered $code"
sudo sh -c "printf '%s\n' '$hosts_line' >>/etc/hosts"
# Devices 0 and 1 of the probe may use the relay without being registered.
ids=$("$probe" ids 2 | tr -d ' \n')
sudo sed -i "s|^allowed_endpoints = \[\]\$|allowed_endpoints = [${ids%,}]|" "$CONFIG"
sudo grep -q "^allowed_endpoints = \[\"" "$CONFIG" || fail "cannot set relay.allowed_endpoints in $CONFIG"

step "The documented deploy hook copies the certificate for QAD"
doc_block docs/deployment.md "### The certificate for QUIC address discovery" sh >"$work/hook"
grep -q 'RENEWED_LINEAGE' "$work/hook" || fail "no deploy hook found in docs/deployment.md"
cat "$work/hook"
sudo install -d -m 0755 "$(dirname "$HOOK")"
sudo install -m 0755 "$work/hook" "$HOOK"
sudo env RENEWED_LINEAGE=/etc/letsencrypt/live/other.example.com "$HOOK"
if sudo test -e "$TLS_DIR/fullchain.pem"; then fail "the hook copied the certificate of another host"; fi
run_hook
[ "$(owner_and_mode "$TLS_DIR/fullchain.pem")" = "root:gono-cloud 644" ] ||
	fail "fullchain.pem: $(owner_and_mode "$TLS_DIR/fullchain.pem")"
[ "$(owner_and_mode "$TLS_DIR/privkey.pem")" = "root:gono-cloud 640" ] ||
	fail "privkey.pem: $(owner_and_mode "$TLS_DIR/privkey.pem")"

step "QAD on, as docs/deployment.md says, and the service restarted"
sudo sed -i \
	-e 's|^# qad_bind = "\[::\]:7842"$|qad_bind = "[::]:7842"|' \
	-e 's|^# tls_cert = "relay-tls/fullchain.pem"$|tls_cert = "relay-tls/fullchain.pem"|' \
	-e "s|^# tls_key = \"relay-tls/privkey.pem\"\$|tls_key = \"relay-tls/privkey.pem\"\ntls_reload_interval_secs = $RELOAD_SECS|" \
	"$CONFIG"
sudo awk '/^\[/ { relay = ($0 == "[relay]") } relay && NF && !/^#/' "$CONFIG"
[ "$(owner_and_mode "$CONFIG")" = "root:gono-cloud 640" ] || fail "config: $(owner_and_mode "$CONFIG")"
(cd / && sudo -u gono-cloud gono-cloud --config "$CONFIG" config check) >"$work/check" 2>&1 || {
	cat "$work/check"
	fail "config check refuses the relay settings"
}
grep -E '^relay\.' "$work/check" || true
sudo systemctl restart gono-cloud
wait_until_healthy
attempt=0
until sudo journalctl -u gono-cloud --no-pager -n 50 | grep 'relay listening' | grep -q 7842; do
	attempt=$((attempt + 1))
	[ "$attempt" -lt 10 ] || fail "the log does not show the relay listening with QAD"
	sleep 1
done
sudo journalctl -u gono-cloud --no-pager -n 50 | grep 'relay listening'

step "Two devices reach each other through nginx and the relay"
PROBE_CA=$work/ca.pem "$probe" pair "https://$RELAY_HOST" || fail "no datagram through the relay"

step "QAD on UDP 7842 serves the copied certificate and reports the address it sees (IPv4)"
qad 127.0.0.1:7842 || {
	cat "$work/qad"
	fail "no QAD over IPv4"
}
cat "$work/qad"
[ "$served" = "$first" ] || fail "QAD served $served, not the copied certificate $first"
case $observed in
127.0.0.1:*) ;;
*) fail "QAD reported $observed for a client on 127.0.0.1" ;;
esac

if grep -q '^0\{31\}1 ' /proc/net/if_inet6 2>/dev/null; then
	step "QAD over IPv6 on the same socket"
	qad '[::1]:7842' || {
		cat "$work/qad"
		fail "no QAD over IPv6"
	}
	cat "$work/qad"
	[ "$served" = "$first" ] || fail "QAD over IPv6 served $served, not $first"
	case $observed in
	"[::1]:"*) ;;
	*) fail "QAD reported $observed for a client on ::1" ;;
	esac
else
	step "No IPv6 loopback here: QAD over IPv6 not checked"
fi

step "A renewal reaches QAD without a restart"
pid=$(service_property MainPID)
restarts=$(service_property NRestarts)
started=$(service_property ExecMainStartTimestampMonotonic)
renewed=$(issue renewed)
echo "renewed certificate: $renewed"
[ "$renewed" != "$first" ] || fail "the renewed certificate is the first one"
deploy_to_lineage renewed

step "Caught between the hook's two copies, QAD keeps the previous pair"
sudo install -m 0644 -o root -g gono-cloud "$LINEAGE/fullchain.pem" "$TLS_DIR/fullchain.pem"
sleep $((RELOAD_SECS * 2 + 1))
qad 127.0.0.1:7842 || {
	cat "$work/qad"
	fail "QAD failed with the new certificate and the old key in place"
}
[ "$served" = "$first" ] || fail "QAD served $served with the old key in place, not $first"
sudo journalctl -u gono-cloud --no-pager -n 20 | grep 'relay certificate not reloaded' | tail -n 1 |
	grep 'does not belong' || fail "no warning about the certificate and key that do not belong together"

step "The hook completes the renewal, and QAD serves it without a restart"
run_hook
begin=$(date +%s)
attempt=0
while :; do
	qad 127.0.0.1:7842 || {
		cat "$work/qad"
		fail "QAD failed after the renewal"
	}
	[ "$served" = "$first" ] || break
	attempt=$((attempt + 1))
	[ "$attempt" -lt $((RELOAD_SECS * 10)) ] || fail "QAD still serves the replaced certificate"
	sleep 0.5
done
echo "QAD serves the renewed certificate after $(($(date +%s) - begin)) s"
[ "$served" = "$renewed" ] || fail "QAD served $served, neither the first nor the renewed certificate"
[ "$(service_property MainPID)" = "$pid" ] || fail "the service was restarted (MainPID changed)"
[ "$(service_property NRestarts)" = "$restarts" ] || fail "the service was restarted (NRestarts)"
[ "$(service_property ExecMainStartTimestampMonotonic)" = "$started" ] || fail "the service was restarted"
systemctl is-active gono-cloud

printf '\nAll relay tests passed.\n'
