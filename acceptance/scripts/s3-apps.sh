#!/usr/bin/env bash
# What the target applications send to their object storage, against the S3 API of the server
# built from this checkout.
#
# The script builds `gono-cloud`, initializes a throwaway installation with the S3 API on
# (anonymous access allowed), creates a bucket whose objects are public by their ACL (`acl`,
# as the applications need) and a key for it, starts `serve` on free loopback ports, and runs
# one scenario per application with the S3 library and version the application uses and the
# parameters of its storage code (see the files in acceptance/s3-apps/):
#
#   mastodon   aws-sdk-s3 1.242.0 (Ruby): upload_file with the public-read ACL, a multipart
#              upload above 15 MB, single-request downloads, ACLs set to private and back
#              (suspension), DeleteObjects
#   misskey    AWS SDK for JavaScript 3.1161.0: Upload (lib-storage) of the original, webpublic
#              and thumbnail variants and a multipart video with public-read, Cache-Control
#              and Content-Disposition; DeleteObject
#   peertube   AWS SDK for JavaScript 3.1161.0 with its default checksums: HLS uploads in one
#              request and in parts, the ACLs of a prefix set to private and back, a copy with
#              new metadata, ranged reads, removal of a prefix
#   picgo      the PicGo-Core command line with picgo-plugin-s3 1.5.2: an image upload with
#              public-read and the URL the plugin builds
#
# Every scenario downloads what it uploaded anonymously and checks status, content and
# headers. The applications' libraries are not part of this repository; install them once
# into APPS_DIR (default ~/.cache/gono/apps):
#
#   npm install --prefix ~/.cache/gono/apps/node-sdk --ignore-scripts \
#     @aws-sdk/client-s3@3.1161.0 @aws-sdk/lib-storage@3.1161.0
#   npm install --prefix ~/.cache/gono/apps/picgo --ignore-scripts picgo-plugin-s3@1.5.2
#   GEM_HOME=~/.cache/gono/apps/mastodon gem install --no-document aws-sdk-s3:1.242.0 \
#     aws-sdk-core:3.268.0 aws-sdk-kms:1.143.0 aws-sigv4:1.12.1 aws-partitions:1.1305.0 \
#     aws-eventstream:1.4.1                        (Ruby 3 or later; Mastodon locks these)
#
# Usage:
#   acceptance/scripts/s3-apps.sh [scenario...]   (default: all of them)
#
# Environment:
#   APPS_DIR=<dir>         where the libraries are installed (default: ~/.cache/gono/apps)
#   RUBY=<path> NODE=<path>   interpreters (default: from PATH)
#   NEW_TARGET_DIR=<dir>   cargo target dir for the server build (default: the repository's)
#   KEEP_WORK_DIR=1        keep the configuration, data and logs
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACCEPT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ACCEPT_DIR}/.." && pwd)"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
APPS_DIR="${APPS_DIR:-${HOME}/.cache/gono/apps}"
RUBY="${RUBY:-ruby}"
NODE="${NODE:-node}"
USER_NAME="gono"
BUCKET="app-media"
ALL_SCENARIOS=(mastodon misskey peertube picgo)

usage() {
  sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

SCENARIOS=()
for arg in "$@"; do
  case "${arg}" in
    -h | --help)
      usage
      exit 0
      ;;
    mastodon | misskey | peertube | picgo)
      SCENARIOS+=("${arg}")
      ;;
    *)
      echo "unknown argument: ${arg}" >&2
      usage >&2
      exit 2
      ;;
  esac
done
if ((${#SCENARIOS[@]} == 0)); then
  SCENARIOS=("${ALL_SCENARIOS[@]}")
fi

fail() {
  echo "FAIL [${CURRENT:-setup}]: $*" >&2
  tail -n 30 "${CLIENT_LOG:-/dev/null}" >&2 || true
  exit 1
}

for cmd in cargo curl python3; do
  command -v "${cmd}" >/dev/null 2>&1 || fail "missing required command: ${cmd}"
done
for scenario in "${SCENARIOS[@]}"; do
  case "${scenario}" in
    mastodon)
      command -v "${RUBY}" >/dev/null 2>&1 || fail "missing ${RUBY} (set RUBY)"
      [[ -d "${APPS_DIR}/mastodon/gems" ]] || fail "aws-sdk-s3 is not installed (see --help)"
      ;;
    misskey | peertube)
      command -v "${NODE}" >/dev/null 2>&1 || fail "missing ${NODE} (set NODE)"
      [[ -d "${APPS_DIR}/node-sdk/node_modules/@aws-sdk/lib-storage" ]] ||
        fail "the AWS SDK for JavaScript is not installed (see --help)"
      ;;
    picgo)
      [[ -x "${APPS_DIR}/picgo/node_modules/.bin/picgo" ]] ||
        fail "PicGo-Core and picgo-plugin-s3 are not installed (see --help)"
      ;;
  esac
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gono-s3-apps.XXXXXX")"
TARGET_DIR="${NEW_TARGET_DIR:-${REPO_ROOT}/target}"
CONFIG_FILE="${WORK_DIR}/config.toml"
LOG_FILE="${WORK_DIR}/server.log"
STDOUT_LOG="${WORK_DIR}/server-stdout.log"
CLIENT_LOG="${WORK_DIR}/client.log"
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

find_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

echo "==> building gono-cloud (target dir: ${TARGET_DIR})"
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --quiet --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p gono-server --bin gono-cloud
BIN="${TARGET_DIR}/debug/gono-cloud"

PORT="$(find_port)"
S3_PORT="$(find_port)"
BASE_URL="http://127.0.0.1:${PORT}"
S3_URL="http://127.0.0.1:${S3_PORT}"

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
allow_anonymous = true
EOF

gono() {
  "${BIN}" --config "${CONFIG_FILE}" "$@"
}

echo "==> initializing a fresh installation in ${WORK_DIR}"
python3 -c 'import secrets; print(secrets.token_urlsafe(18))' |
  gono init --admin "${USER_NAME}" --password-stdin >/dev/null
KEY_OUTPUT="$(gono s3 key create "${USER_NAME}" --label s3-apps 2>&1)"
ACCESS_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Access key id: \([^[:space:]]*\)$/\1/p')"
SECRET_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Secret key: *\([^[:space:]]*\)$/\1/p')"
[[ -n "${ACCESS_KEY}" && -n "${SECRET_KEY}" ]] || fail "s3 key create did not print a key"
# Objects are public by their ACL, as the applications set it.
gono s3 bucket create "${USER_NAME}" "${BUCKET}" >/dev/null
gono s3 bucket set "${USER_NAME}" "${BUCKET}" --anonymous acl >/dev/null

echo "==> starting gono-cloud on ${BASE_URL}, S3 on ${S3_URL}"
"${BIN}" --config "${CONFIG_FILE}" serve >"${STDOUT_LOG}" 2>&1 &
SERVER_PID="$!"
for _ in $(seq 1 200); do
  curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1 && break
  kill -0 "${SERVER_PID}" 2>/dev/null || fail "the server exited: $(tail -n 5 "${STDOUT_LOG}")"
  sleep 0.1
done
curl -fsS "${BASE_URL}/healthz" >/dev/null || fail "the server did not become ready"

scenario_mastodon() {
  GEM_HOME="${APPS_DIR}/mastodon" GEM_PATH="${APPS_DIR}/mastodon" "${RUBY}" \
    "${ACCEPT_DIR}/s3-apps/mastodon.rb" "${S3_URL}" "${ACCESS_KEY}" "${SECRET_KEY}" \
    "${BUCKET}" "${WORK_DIR}/mastodon" >>"${CLIENT_LOG}" 2>&1 || fail "see the client log"
}

scenario_node() {
  "${NODE}" "${ACCEPT_DIR}/s3-apps/node-apps.cjs" "$1" "${APPS_DIR}/node-sdk" "${S3_URL}" \
    "${ACCESS_KEY}" "${SECRET_KEY}" "${BUCKET}" "${WORK_DIR}/$1" >>"${CLIENT_LOG}" 2>&1 ||
    fail "see the client log"
}

scenario_picgo() {
  local dir="${WORK_DIR}/picgo" config out url
  # PicGo loads its plugins from the folder of its configuration.
  config="${APPS_DIR}/picgo/gono-s3-apps-${PORT}.json"
  python3 - "${config}" "${S3_URL}" "${ACCESS_KEY}" "${SECRET_KEY}" "${BUCKET}" <<'PY'
import json, sys
path, endpoint, key, secret, bucket = sys.argv[1:]
json.dump({
    "picBed": {"current": "aws-s3", "uploader": "aws-s3", "aws-s3": {
        "accessKeyID": key, "secretAccessKey": secret, "bucketName": bucket,
        "uploadPath": "picgo/{year}/{month}/{md5}.{extName}", "region": "us-east-1",
        "endpoint": endpoint, "pathStyleAccess": True, "rejectUnauthorized": False,
        "acl": "public-read"}},
    "picgoPlugins": {"picgo-plugin-s3": True},
}, open(path, "w"))
PY
  python3 - "${dir}/image.png" <<'PY'
import os, struct, sys, zlib
os.makedirs(os.path.dirname(sys.argv[1]), exist_ok=True)
def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
raw = b"".join(b"\0" + os.urandom(3 * 16) for _ in range(16))
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0)) \
    + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
PY
  out="$(cd "${APPS_DIR}/picgo" && ./node_modules/.bin/picgo -c "${config}" upload \
    "${dir}/image.png" 2>&1)" || {
    rm -f "${config}"
    printf '%s\n' "${out}" >>"${CLIENT_LOG}"
    fail "picgo upload"
  }
  rm -f "${config}"
  printf '%s\n' "${out}" >>"${CLIENT_LOG}"
  url="$(printf '%s\n' "${out}" | grep -o "${S3_URL}/[^[:space:]]*" | tail -n 1)"
  [[ -n "${url}" ]] || fail "picgo printed no URL of the server: ${out}"
  [[ "$(curl -sS -o "${dir}/back.png" -w '%{http_code}' "${url}")" == "200" ]] ||
    fail "anonymous GET ${url}"
  cmp -s "${dir}/image.png" "${dir}/back.png" || fail "${url}: other content"
  [[ "$(curl -sS -o /dev/null -w '%{content_type}' "${url}")" == "image/png" ]] ||
    fail "${url}: content type"
}

for scenario in "${SCENARIOS[@]}"; do
  CURRENT="${scenario}"
  mkdir -p "${WORK_DIR}/${scenario}"
  echo "==> ${scenario}"
  echo "==== ${scenario}" >>"${CLIENT_LOG}"
  case "${scenario}" in
    mastodon) scenario_mastodon ;;
    misskey | peertube) scenario_node "${scenario}" ;;
    picgo) scenario_picgo ;;
  esac
  echo "    ok"
done
echo "==> all application scenarios passed: ${SCENARIOS[*]}"
