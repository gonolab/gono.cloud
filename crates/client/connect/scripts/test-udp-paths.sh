#!/bin/sh
# Direct and relayed paths under UDP filters (plan V8's firewall matrix): gono-connect dials
# relay first, so one-way direct paths do not stop it, where iroh's own dial is stuck.
#
# Usage: crates/client/connect/scripts/test-udp-paths.sh <udp-paths>
#
# <udp-paths> is crates/client/connect/examples/udp-paths.rs built for this machine. Every case
# runs in a network namespace of its own, with an nftables rule on one side's UDP port (the
# dialer A binds 41001, the acceptor B 41002):
#
# - outbound UDP refused: a drop in the output hook, so sendmsg returns EPERM, as a host
#   firewall that refuses the program's outgoing UDP does;
# - inbound UDP dropped: a drop in the input hook, as a network that drops UDP does.
#
# For both sides, both filters and both address sets (the relay alone; the relay and B's direct
# address, as the control plane hands them out):
# - `gono` (gono-connect's endpoint::dial) must connect in all 8 cases;
# - `plain` (iroh's Endpoint::connect) is the control: it must connect in 6 of them and stay
#   stuck in the 2 where the direct path works one way only (B cannot send, or A cannot
#   receive) and A knows it. If those connect, the filters did not apply.
# Then: with no filter, `gono` must connect over the relay and then find the direct path; with
# the relay down, it must connect directly (protocol 7.4).
#
# Last, a silent break: once the direct path carries the connection, all UDP to both ports is
# dropped on arrival (udp-paths --silent-break), as a network that starts dropping UDP does.
# With the remote endpoint's path timers, probes sent after the drop must come back over the
# relay within OUTAGE_BOUND_MS; with iroh's own (15 s idle timeout, 5 s keep-alive), the
# control, not before 10 s. Both must find the direct path again once UDP returns: iroh punches
# again only at its upgrade check, every 60 s, when no address changes (as here).
#
# Linux only. As root (CI, under sudo) it uses `unshare --net` with a dummy interface;
# otherwise pasta (rootless). Needs nft. A stuck case takes about 30 s (iroh's idle timeout),
# a silent break up to 75 s.

set -eu

[ $# -eq 1 ] || {
	echo "usage: $0 <udp-paths>" >&2
	exit 2
}
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
[ -x "$bin" ] || {
	echo "error: $bin is not executable" >&2
	exit 1
}
command -v nft >/dev/null || {
	echo "error: nft is needed" >&2
	exit 1
}
if [ "$(id -u)" = 0 ]; then
	isolate=unshare
elif command -v pasta >/dev/null; then
	isolate=pasta
else
	echo "error: run as root (unshare) or install pasta" >&2
	exit 1
fi

failures=0

# The remote endpoint's path idle timeout (3 s) plus the retransmission over the relay, with
# room for a slow runner.
OUTAGE_BOUND_MS=${OUTAGE_BOUND_MS:-5000}

# Runs udp-paths with arguments $3... in a new network namespace, with rule $2 in hook $1 (or
# none for hook "none"), and prints its line. Returns its exit code.
run() {
	hook=$1
	rule=$2
	shift 2
	setup=":"
	if [ "$hook" != none ]; then
		setup="nft add table inet t && nft add chain inet t c '{ type filter hook $hook priority 0; policy accept; }' && nft add rule inet t c $rule drop"
	fi
	case $isolate in
	unshare)
		unshare --net sh -c "ip link set lo up && ip link add d0 type dummy && ip addr add 192.0.2.1/24 dev d0 && ip link set d0 up && $setup && exec '$bin' $*" 2>/dev/null
		;;
	pasta)
		pasta --config-net -- sh -c "$setup && exec '$bin' $*" 2>/dev/null
		;;
	esac
}

# expect <ok|stuck> <hook> <rule> <label> <udp-paths arguments...>
expect() {
	want=$1
	hook=$2
	rule=$3
	label=$4
	shift 4
	if run "$hook" "$rule" "$@" >"${TMPDIR:-/tmp}/udp-paths.$$"; then got=ok; else got=stuck; fi
	line=$(cat "${TMPDIR:-/tmp}/udp-paths.$$")
	rm -f "${TMPDIR:-/tmp}/udp-paths.$$"
	if [ "$got" = "$want" ]; then
		printf 'ok    %-34s %s\n' "$label" "$line"
	else
		printf 'FAIL  %-34s expected %s: %s\n' "$label" "$want" "$line"
		failures=$((failures + 1))
	fi
}

for side in acceptor dialer; do
	case $side in acceptor) port=41002 ;; dialer) port=41001 ;; esac
	for filter in outbound inbound; do
		case $filter in
		outbound) hook=output rule="udp sport $port" ;;
		inbound) hook=input rule="udp dport $port" ;;
		esac
		for addrs in relay-only with-direct; do
			expect ok "$hook" "$rule" "gono  $side $filter $addrs" gono "$addrs"
			# One-way direct paths that A knows of: iroh's own dial is stuck.
			want=ok
			if [ "$addrs" = with-direct ]; then
				case $side-$filter in acceptor-outbound | dialer-inbound) want=stuck ;; esac
			fi
			expect "$want" "$hook" "$rule" "plain $side $filter $addrs" plain "$addrs"
		done
	done
done
expect ok none "" "gono  no filter, relay then direct" gono with-direct --expect-direct
expect ok none "" "gono  relay down, direct" gono with-direct --relay-down --expect-direct
expect ok none "" "gono  silent break" gono with-direct --silent-break \
	--outage-below "$OUTAGE_BOUND_MS"
expect ok none "" "gono  silent break, iroh's timers" gono with-direct --silent-break \
	--path-timers 15000/5000 --outage-above 10000

if [ "$failures" -gt 0 ]; then
	printf '\n%s case(s) failed.\n' "$failures"
	exit 1
fi
printf '\nAll UDP path cases passed.\n'
