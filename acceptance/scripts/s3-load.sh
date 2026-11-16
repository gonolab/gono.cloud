#!/usr/bin/env bash
# Measure the S3 API under many parallel small uploads, the load that rclone and restic put
# on the single SQLite writer (every object write is one `BEGIN IMMEDIATE` transaction that
# also updates the ETags of every ancestor folder).
#
# The script builds `gono-cloud` (release profile by default), initializes a throwaway
# installation with the S3 API on and the request log at `info`, writes a tree of small files,
# and then, for each concurrency in TRANSFERS:
#
#   1. uploads the tree into a new bucket with `rclone copy --transfers <n>`,
#   2. checks it with `rclone check`,
#
# and finally backs the tree up with restic (`-o s3.connections=<largest n>`) and checks the
# repository. For each run it prints the wall time, the uploads per second, and, from the
# server's request log, the number of requests by status and the server-side latency of the
# object writes (p50, p95, p99, max). It exits non-zero when a client fails or the server
# answered an upload with a 5xx status.
#
# Usage:
#   acceptance/scripts/s3-load.sh
#
# Environment:
#   FILES=<n>              number of files (default 5000), spread over DIRS folders
#   DIRS=<n>               number of folders (default 50), two levels deep
#   SIZE=<bytes>           size of each file (default 2048)
#   TRANSFERS="<n> ..."    rclone concurrencies to run (default "4 16 64")
#   RUN_RESTIC=0           skip the restic backup
#   PROFILE=debug          build and measure the debug profile instead of release
#   RCLONE=<path> RESTIC=<path>   client binaries (default: from PATH)
#   NEW_TARGET_DIR=<dir>   cargo target dir for the server build (default: the repository's)
#   KEEP_WORK_DIR=1        keep the configuration, data, files and logs
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
FILES="${FILES:-5000}"
DIRS="${DIRS:-50}"
SIZE="${SIZE:-2048}"
TRANSFERS="${TRANSFERS:-4 16 64}"
RUN_RESTIC="${RUN_RESTIC:-1}"
PROFILE="${PROFILE:-release}"
RCLONE="${RCLONE:-rclone}"
RESTIC="${RESTIC:-restic}"
USER_NAME="gono"

case "${1:-}" in
  "") ;;
  -h | --help)
    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "unknown argument: $1" >&2
    exit 2
    ;;
esac

for cmd in cargo curl python3 "${RCLONE}"; do
  command -v "${cmd}" >/dev/null 2>&1 || {
    echo "missing required command: ${cmd}" >&2
    exit 1
  }
done
if [[ "${RUN_RESTIC}" == "1" ]]; then
  command -v "${RESTIC}" >/dev/null 2>&1 || {
    echo "missing required command: ${RESTIC} (RUN_RESTIC=0 skips it)" >&2
    exit 1
  }
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gono-s3-load.XXXXXX")"
TARGET_DIR="${NEW_TARGET_DIR:-${REPO_ROOT}/target}"
CONFIG_FILE="${WORK_DIR}/config.toml"
LOG_FILE="${WORK_DIR}/server.log"
STDOUT_LOG="${WORK_DIR}/server-stdout.log"
CLIENT_LOG="${WORK_DIR}/client.log"
TREE="${WORK_DIR}/tree"
SERVER_PID=""

# shellcheck disable=SC2329 # the EXIT trap calls it
cleanup() {
  local status=$?
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ "${KEEP_WORK_DIR}" == "1" ]]; then
    echo "kept work dir: ${WORK_DIR}" >&2
  else
    rm -rf "${WORK_DIR}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "FAIL: $*" >&2
  tail -n 20 "${CLIENT_LOG}" >&2 2>/dev/null || true
  exit 1
}

find_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

echo "==> building gono-cloud (${PROFILE}, target dir: ${TARGET_DIR})"
BUILD_ARGS=(--quiet --manifest-path "${REPO_ROOT}/Cargo.toml" -p gono-server --bin gono-cloud)
if [[ "${PROFILE}" == "release" ]]; then
  BUILD_ARGS+=(--release)
fi
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build "${BUILD_ARGS[@]}"
BIN="${TARGET_DIR}/${PROFILE}/gono-cloud"

PORT="$(find_port)"
S3_PORT="$(find_port)"
BASE_URL="http://127.0.0.1:${PORT}"
S3_URL="http://127.0.0.1:${S3_PORT}"

# `info`: the request log gives every request's status and duration.
cat >"${CONFIG_FILE}" <<EOF
[server]
bind = "127.0.0.1:${PORT}"
base_url = "${BASE_URL}"

[storage]
data_dir = "${WORK_DIR}/data"

[db]
path = "${WORK_DIR}/gono-cloud.db"

[logging]
level = "info"
file = "${LOG_FILE}"

[s3]
enabled = true
public_url = "http://s3.localhost:${S3_PORT}"
bind = "127.0.0.1:${S3_PORT}"
EOF

gono() {
  "${BIN}" --config "${CONFIG_FILE}" "$@"
}

echo "==> initializing a fresh installation in ${WORK_DIR}"
python3 -c 'import secrets; print(secrets.token_urlsafe(18))' |
  gono init --admin "${USER_NAME}" --password-stdin >/dev/null
KEY_OUTPUT="$(gono s3 key create "${USER_NAME}" --label s3-load 2>&1)"
ACCESS_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Access key id: \([^[:space:]]*\)$/\1/p')"
SECRET_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Secret key: *\([^[:space:]]*\)$/\1/p')"
[[ -n "${ACCESS_KEY}" && -n "${SECRET_KEY}" ]] || fail "s3 key create did not print a key"

echo "==> starting gono-cloud (S3 on ${S3_URL})"
"${BIN}" --config "${CONFIG_FILE}" serve >"${STDOUT_LOG}" 2>&1 &
SERVER_PID="$!"
for _ in $(seq 1 200); do
  curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1 && break
  kill -0 "${SERVER_PID}" 2>/dev/null || fail "the server exited: $(tail -n 5 "${STDOUT_LOG}")"
  sleep 0.1
done
curl -fsS "${BASE_URL}/healthz" >/dev/null || fail "the server did not become ready"

echo "==> writing ${FILES} files of ${SIZE} bytes in ${DIRS} folders"
python3 - "${TREE}" "${FILES}" "${DIRS}" "${SIZE}" <<'PY'
import os, sys
root, files, dirs, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
for i in range(files):
    folder = os.path.join(root, f"d{i % dirs:03d}", f"e{(i // dirs) % 4}")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"f{i:06d}.bin"), "wb") as f:
        f.write(os.urandom(size))
PY

cat >"${WORK_DIR}/rclone.conf" <<EOF
[gono]
type = s3
provider = Other
access_key_id = ${ACCESS_KEY}
secret_access_key = ${SECRET_KEY}
endpoint = ${S3_URL}
region = us-east-1
force_path_style = true
EOF

now() {
  python3 -c 'import time; print(time.monotonic())'
}

# Summarizes the S3 request log lines after line $1: requests by method and status, and the
# latency of object writes (PUT and POST of keys).
summarize() {
  tail -n "+$(($1 + 1))" "${LOG_FILE}" | python3 -c '
import re, sys
statuses, writes = {}, []
for line in sys.stdin:
    if "s3 request" not in line:
        continue
    method = re.search(r"method=(\S+)", line).group(1)
    target = re.search(r"target=(\S+)", line).group(1)
    status = int(re.search(r"status=(\d+)", line).group(1))
    elapsed = int(re.search(r"elapsed_ms=(\d+)", line).group(1))
    statuses[(method, status)] = statuses.get((method, status), 0) + 1
    # An object write names a key below the bucket: /<bucket>/<key>.
    if method in ("PUT", "POST") and target.count("/") >= 2:
        writes.append(elapsed)
counts = ", ".join(f"{m} {s}: {n}" for (m, s), n in sorted(statuses.items()))
print(f"    requests: {counts}")
if writes:
    writes.sort()
    pick = lambda q: writes[min(len(writes) - 1, int(q * len(writes)))]
    print(f"    object writes: {len(writes)}, server ms p50 {pick(0.5)} p95 {pick(0.95)} "
          f"p99 {pick(0.99)} max {writes[-1]}")
errors = sum(n for (m, s), n in statuses.items() if s >= 500)
sys.exit(1 if errors else 0)
'
}

lines() {
  wc -l <"${LOG_FILE}" | tr -d ' '
}

STATUS=0
for transfers in ${TRANSFERS}; do
  bucket="load-${transfers}"
  echo "==> rclone copy, --transfers ${transfers}"
  "${RCLONE}" --config "${WORK_DIR}/rclone.conf" mkdir "gono:${bucket}" >>"${CLIENT_LOG}" 2>&1 ||
    fail "rclone mkdir"
  mark="$(lines)"
  start="$(now)"
  "${RCLONE}" --config "${WORK_DIR}/rclone.conf" copy --transfers "${transfers}" \
    --checkers "${transfers}" --stats 0 "${TREE}" "gono:${bucket}" >>"${CLIENT_LOG}" 2>&1 ||
    fail "rclone copy --transfers ${transfers}"
  end="$(now)"
  python3 -c "import sys; s = float(sys.argv[2]) - float(sys.argv[1]); \
print(f'    {int(sys.argv[3])} files in {s:.1f} s: {int(sys.argv[3]) / s:.0f} uploads/s')" \
    "${start}" "${end}" "${FILES}"
  summarize "${mark}" || {
    echo "    the server answered with 5xx"
    STATUS=1
  }
  "${RCLONE}" --config "${WORK_DIR}/rclone.conf" check "${TREE}" "gono:${bucket}" \
    >>"${CLIENT_LOG}" 2>&1 || fail "rclone check after --transfers ${transfers}"
  retries="$(grep -c "low level retry\|Attempt [0-9]/[0-9] failed" "${CLIENT_LOG}" || true)"
  echo "    rclone check ok; retries logged so far: ${retries}"
done

if [[ "${RUN_RESTIC}" == "1" ]]; then
  connections="${TRANSFERS##* }"
  echo "==> restic backup, -o s3.connections=${connections}"
  export AWS_ACCESS_KEY_ID="${ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${SECRET_KEY}"
  export RESTIC_REPOSITORY="s3:${S3_URL}/load-restic" RESTIC_PASSWORD="load-test-only"
  restic_run() {
    "${RESTIC}" --cache-dir "${WORK_DIR}/restic-cache" -o "s3.connections=${connections}" "$@"
  }
  restic_run init >>"${CLIENT_LOG}" 2>&1 || fail "restic init"
  mark="$(lines)"
  start="$(now)"
  restic_run backup "${TREE}" >>"${CLIENT_LOG}" 2>&1 || fail "restic backup"
  end="$(now)"
  python3 -c "import sys; print(f'    backup of {sys.argv[3]} files in {float(sys.argv[2]) - float(sys.argv[1]):.1f} s')" \
    "${start}" "${end}" "${FILES}"
  summarize "${mark}" || {
    echo "    the server answered with 5xx"
    STATUS=1
  }
  restic_run check >>"${CLIENT_LOG}" 2>&1 || fail "restic check"
  echo "    restic check ok"
fi

exit "${STATUS}"
