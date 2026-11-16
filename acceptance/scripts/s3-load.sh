#!/usr/bin/env bash
# Measure the S3 API under many parallel small uploads, the load that rclone and restic put
# on the single SQLite writer (every object write is one `BEGIN IMMEDIATE` transaction that
# also updates the ETags of every ancestor folder).
#
# The script builds `gono-cloud` (release profile by default), initializes a throwaway
# installation with the S3 API on and the request log at `info`, writes a tree of small files,
# and then, for each concurrency in TRANSFERS:
#
#   1. uploads the tree into a new bucket with `rclone copy --transfers <n>`, from ACCOUNTS
#      accounts at once (each with a key and a bucket of its own), and with WEBDAV=1 at the
#      same time through WebDAV into a folder of the first one (plain PUTs from <n> threads:
#      rclone's WebDAV backend paces its requests, so it would not load the server),
#   2. checks every copy with `rclone check`,
#
# and finally backs the tree up with restic (`-o s3.connections=<largest n>`) and checks the
# repository. With BIG_MB set, it also uploads one file of that many MiB in parts of
# BIG_PART_MB (default 16) and reports how long the server took to complete it
# (CompleteMultipartUpload assembles the parts). For each run it prints the wall time, the uploads per second, and, from the
# server's request log, the number of requests by status and the server-side latency of the
# object writes (p50, p95, p99, max), S3 and WebDAV apart. It exits non-zero when a client
# fails or the server answered an upload with a 5xx status.
#
# Usage:
#   acceptance/scripts/s3-load.sh
#
# Environment:
#   FILES=<n>              number of files (default 5000), spread over DIRS folders
#   DIRS=<n>               number of folders (default 50), two levels deep
#   SIZE=<bytes>           size of each file (default 2048)
#   TRANSFERS="<n> ..."    rclone concurrencies to run (default "4 16 64"), per client
#   ACCOUNTS=<n>           accounts uploading at once, each its own rclone (default 1)
#   WEBDAV=1               also upload the tree through WebDAV at the same time
#   RUN_RESTIC=0           skip the restic backup
#   BIG_MB=<n>             also upload one file of n MiB in parts (default: none)
#   BIG_PART_MB=<n>        the part size of that upload in MiB (default 16)
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
ACCOUNTS="${ACCOUNTS:-1}"
WEBDAV="${WEBDAV:-0}"
RUN_RESTIC="${RUN_RESTIC:-1}"
BIG_MB="${BIG_MB:-0}"
BIG_PART_MB="${BIG_PART_MB:-16}"
PROFILE="${PROFILE:-release}"
RCLONE="${RCLONE:-rclone}"
RESTIC="${RESTIC:-restic}"
USER_NAME="gono"

case "${1:-}" in
  "") ;;
  -h | --help)
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
# The accounts: the first is USER_NAME, the others load2, load3, ...
ACCOUNT_NAMES=("${USER_NAME}")
for ((i = 2; i <= ACCOUNTS; i++)); do
  python3 -c 'import secrets; print(secrets.token_urlsafe(18))' |
    gono user add "load${i}" --password-stdin >/dev/null
  ACCOUNT_NAMES+=("load${i}")
done
: >"${WORK_DIR}/rclone.conf"
for i in "${!ACCOUNT_NAMES[@]}"; do
  KEY_OUTPUT="$(gono s3 key create "${ACCOUNT_NAMES[${i}]}" --label s3-load 2>&1)"
  ACCESS_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Access key id: \([^[:space:]]*\)$/\1/p')"
  SECRET_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Secret key: *\([^[:space:]]*\)$/\1/p')"
  [[ -n "${ACCESS_KEY}" && -n "${SECRET_KEY}" ]] || fail "s3 key create did not print a key"
  # Remotes gono1, gono2, ...; the first account's is also `gono` (the big file, restic).
  remotes=("gono$((i + 1))")
  ((i == 0)) && remotes+=(gono)
  for remote in "${remotes[@]}"; do
    cat >>"${WORK_DIR}/rclone.conf" <<EOF
[${remote}]
type = s3
provider = Other
access_key_id = ${ACCESS_KEY}
secret_access_key = ${SECRET_KEY}
endpoint = ${S3_URL}
region = us-east-1
force_path_style = true

EOF
  done
done

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

# Uploads the tree in $1 into the folder $2 of USER_NAME through WebDAV with $3 threads:
# MKCOL of every folder, then a PUT of every file, each thread with a connection of its own.
cat >"${WORK_DIR}/dav-upload.py" <<'PY'
import base64, concurrent.futures, http.client, os, sys, threading, urllib.parse

url, user, password, root, folder, transfers = sys.argv[1:7]
target = urllib.parse.urlsplit(url)
auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
base = f"/remote.php/dav/files/{urllib.parse.quote(user)}/{urllib.parse.quote(folder)}"
local = threading.local()

def request(method, path, body=None):
    for attempt in range(2):
        try:
            if getattr(local, "connection", None) is None:
                local.connection = http.client.HTTPConnection(target.hostname, target.port, timeout=300)
            local.connection.request(method, path, body=body, headers={"Authorization": auth})
            response = local.connection.getresponse()
            response.read()
            return response.status
        except (http.client.HTTPException, OSError):
            local.connection = None
            if attempt:
                raise

def remote(rel):
    return base + "/" + "/".join(urllib.parse.quote(part) for part in rel.split(os.sep))

folders = sorted({os.path.relpath(d, root) for d, _, _ in os.walk(root)} - {"."})
files = [os.path.relpath(os.path.join(d, f), root) for d, _, names in os.walk(root) for f in names]
for path in [base] + [remote(rel) for rel in folders]:
    status = request("MKCOL", path)
    if status not in (201, 405):
        sys.exit(f"MKCOL {path}: {status}")

def put(rel):
    with open(os.path.join(root, rel), "rb") as f:
        status = request("PUT", remote(rel), f.read())
    if status not in (201, 204):
        raise SystemExit(f"PUT {rel}: {status}")

with concurrent.futures.ThreadPoolExecutor(int(transfers)) as pool:
    list(pool.map(put, files))
PY

if [[ "${WEBDAV}" == "1" ]]; then
  APP_PASSWORD="$(gono app-password add "${USER_NAME}" --label s3-load 2>&1 |
    sed -n 's/^App password: \([^[:space:]]*\)$/\1/p' | tail -n 1)"
  [[ -n "${APP_PASSWORD}" ]] || fail "app-password add did not print a password"
  cat >>"${WORK_DIR}/rclone.conf" <<EOF
[dav]
type = webdav
url = ${BASE_URL}/remote.php/dav/files/${USER_NAME}/
vendor = nextcloud
user = ${USER_NAME}
pass = $("${RCLONE}" obscure "${APP_PASSWORD}")
EOF
fi

now() {
  python3 -c 'import time; print(time.monotonic())'
}

# Summarizes the request log lines after line $1: S3 and WebDAV requests by method and
# status, and the latency of their file writes (S3 PUT and POST of keys, WebDAV PUT).
summarize() {
  tail -n "+$(($1 + 1))" "${LOG_FILE}" | python3 -c '
import re, sys
statuses, writes = {}, {"S3": [], "WebDAV": []}
for line in sys.stdin:
    if "s3 request" in line:
        kind = "S3"
    elif "target=/remote.php/dav/" in line:
        kind = "WebDAV"
    else:
        continue
    method = re.search(r"method=(\S+)", line).group(1)
    target = re.search(r"target=(\S+)", line).group(1)
    status = int(re.search(r"status=(\d+)", line).group(1))
    elapsed = int(re.search(r"elapsed_ms=(\d+)", line).group(1))
    statuses[(kind, method, status)] = statuses.get((kind, method, status), 0) + 1
    # An S3 object write names a key below the bucket: /<bucket>/<key>.
    if kind == "S3" and method in ("PUT", "POST") and target.count("/") >= 2:
        writes[kind].append(elapsed)
    if kind == "WebDAV" and method == "PUT":
        writes[kind].append(elapsed)
counts = ", ".join(f"{k} {m} {s}: {n}" for (k, m, s), n in sorted(statuses.items()))
print(f"    requests: {counts}")
for kind, times in writes.items():
    if times:
        times.sort()
        pick = lambda q: times[min(len(times) - 1, int(q * len(times)))]
        print(f"    {kind} writes: {len(times)}, server ms p50 {pick(0.5)} p95 {pick(0.95)} "
              f"p99 {pick(0.99)} max {times[-1]}")
errors = sum(n for (k, m, s), n in statuses.items() if s >= 500)
sys.exit(1 if errors else 0)
'
}

lines() {
  wc -l <"${LOG_FILE}" | tr -d ' '
}

STATUS=0
rc() {
  "${RCLONE}" --config "${WORK_DIR}/rclone.conf" "$@"
}

for transfers in ${TRANSFERS}; do
  bucket="load-${transfers}"
  # Every account's bucket (names are unique across the server), and with WEBDAV=1 a folder
  # of the first account.
  targets=("gono1:${bucket}")
  for ((i = 2; i <= ${#ACCOUNT_NAMES[@]}; i++)); do
    targets+=("gono${i}:${bucket}-a${i}")
  done
  checked=("${targets[@]}")
  if [[ "${WEBDAV}" == "1" ]]; then
    checked+=("dav:dav-${bucket}")
  fi
  label="rclone copy, --transfers ${transfers}"
  if ((${#ACCOUNT_NAMES[@]} > 1)); then
    label+=", ${#ACCOUNT_NAMES[@]} accounts at once"
  fi
  if [[ "${WEBDAV}" == "1" ]]; then
    label+=", WebDAV at the same time"
  fi
  echo "==> ${label}"
  for target in "${targets[@]}"; do
    rc mkdir "${target}" >>"${CLIENT_LOG}" 2>&1 || fail "rclone mkdir ${target}"
  done
  mark="$(lines)"
  start="$(now)"
  pids=()
  for target in "${targets[@]}"; do
    rc copy --transfers "${transfers}" --checkers "${transfers}" --stats 0 "${TREE}" \
      "${target}" >>"${CLIENT_LOG}" 2>&1 &
    pids+=("$!")
  done
  if [[ "${WEBDAV}" == "1" ]]; then
    python3 "${WORK_DIR}/dav-upload.py" "${BASE_URL}" "${USER_NAME}" "${APP_PASSWORD}" \
      "${TREE}" "dav-${bucket}" "${transfers}" >>"${CLIENT_LOG}" 2>&1 &
    pids+=("$!")
  fi
  for pid in "${pids[@]}"; do
    wait "${pid}" || fail "rclone copy --transfers ${transfers}"
  done
  end="$(now)"
  python3 -c "import sys; s = float(sys.argv[2]) - float(sys.argv[1]); \
print(f'    {int(sys.argv[3])} files in {s:.1f} s: {int(sys.argv[3]) / s:.0f} uploads/s')" \
    "${start}" "${end}" "$((FILES * ${#checked[@]}))"
  summarize "${mark}" || {
    echo "    the server answered with 5xx"
    STATUS=1
  }
  for target in "${checked[@]}"; do
    rc check "${TREE}" "${target}" >>"${CLIENT_LOG}" 2>&1 ||
      fail "rclone check of ${target} after --transfers ${transfers}"
  done
  retries="$(grep -c "low level retry\|Attempt [0-9]/[0-9] failed" "${CLIENT_LOG}" || true)"
  echo "    rclone check ok; retries logged so far: ${retries}"
done

if ((BIG_MB > 0)); then
  echo "==> one file of ${BIG_MB} MiB in ${BIG_PART_MB} MiB parts"
  mkdir -p "${WORK_DIR}/big"
  head -c "$((BIG_MB * 1024 * 1024))" /dev/urandom >"${WORK_DIR}/big/big.bin"
  "${RCLONE}" --config "${WORK_DIR}/rclone.conf" mkdir gono:load-big >>"${CLIENT_LOG}" 2>&1 ||
    fail "rclone mkdir"
  mark="$(lines)"
  start="$(now)"
  "${RCLONE}" --config "${WORK_DIR}/rclone.conf" copyto --s3-chunk-size "${BIG_PART_MB}M" \
    --s3-upload-cutoff "${BIG_PART_MB}M" --s3-upload-concurrency 4 "${WORK_DIR}/big/big.bin" gono:load-big/big.bin \
    >>"${CLIENT_LOG}" 2>&1 || fail "rclone copyto of the big file"
  end="$(now)"
  python3 -c "import sys; s = float(sys.argv[2]) - float(sys.argv[1]); \
print(f'    {sys.argv[3]} MiB in {s:.1f} s: {int(sys.argv[3]) / s:.0f} MiB/s')" \
    "${start}" "${end}" "${BIG_MB}"
  tail -n "+$((mark + 1))" "${LOG_FILE}" | python3 -c '
import re, sys
for line in sys.stdin:
    if "s3 multipart upload completed" in line:
        print("    completion: " + re.search(r"parts=(\d+)", line).group(1) + " parts assembled in "
              + re.search(r"assembled_ms=(\d+)", line).group(1) + " ms, installed in "
              + re.search(r"installed_ms=(\d+)", line).group(1) + " ms")'
  "${RCLONE}" --config "${WORK_DIR}/rclone.conf" check --download "${WORK_DIR}/big" gono:load-big \
    >>"${CLIENT_LOG}" 2>&1 || fail "rclone check of the big file"
  echo "    rclone check --download ok"
fi

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
