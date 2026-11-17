#!/bin/sh
# Runs one of the install tests (test-install.sh, test-relay.sh) on a workstation, the way CI runs
# it on a throwaway machine: in a container whose init is systemd, so that the server runs in its
# hardened unit. podman (rootless works) starts Ubuntu 24.04, the image of GitHub's
# ubuntu-latest, with systemd, nginx, curl, openssl and sudo; the repository is mounted
# read-only at /src; the test runs there as root with CI=true; the container is removed
# afterwards (KEEP=1 keeps it for a look around: podman exec -it <name> bash).
#
# Usage, from the repository root, with an archive and a probe built for Linux:
#   packaging/server/test-in-container.sh <test script> [<argument>...]
# for example
#   packaging/server/test-in-container.sh packaging/server/test-relay.sh \
#     packaging/server/cloud.server.sh dist/gono-cloud-<version>-x86_64-unknown-linux-musl.tar.gz \
#     target/release/examples/relay-probe
#
# Paths in the arguments are relative to the repository root. The container has no network.

set -eu

[ $# -ge 1 ] || {
	echo "usage: $0 <test script> [<argument>...]" >&2
	exit 2
}
[ -f Cargo.toml ] && [ -d packaging/server ] || {
	echo "error: run $0 from the repository root" >&2
	exit 1
}
command -v podman >/dev/null || {
	echo "error: podman is needed" >&2
	exit 1
}

image=localhost/gono-cloud-install-test:24.04
name=gono-cloud-install-test-$$
work=$(mktemp -d)
cleanup() {
	if [ "${KEEP:-}" = 1 ]; then
		echo "kept container $name" >&2
	else
		podman rm -f "$name" >/dev/null 2>&1 || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/Containerfile" <<'EOF'
FROM docker.io/library/ubuntu:24.04
RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates curl dbus file nginx openssl sudo systemd systemd-sysv \
	&& rm -rf /var/lib/apt/lists/*
# Units that have nothing to do in a container.
RUN systemctl mask systemd-logind.service getty.target console-getty.service \
	systemd-udevd.service systemd-udev-trigger.service systemd-networkd-wait-online.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
podman build --quiet -t "$image" "$work" >/dev/null

podman run -d --name "$name" --systemd=always --network=none -v "$PWD:/src:ro" "$image" >/dev/null
attempt=0
until state=$(podman exec "$name" systemctl is-system-running 2>/dev/null) ||
	[ "$state" = degraded ]; do
	attempt=$((attempt + 1))
	[ "$attempt" -lt 60 ] || {
		echo "error: systemd in $name did not come up (state: $state)" >&2
		podman exec "$name" systemctl --failed --no-pager >&2 || true
		exit 1
	}
	sleep 1
done
echo "systemd in $name is $state"

podman exec -e CI=true -w /src "$name" sh "$@"
