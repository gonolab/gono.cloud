#!/usr/bin/env bash
# Scenarios with real S3 clients against the S3 API of the server built from this checkout.
#
# The script builds `gono-cloud`, initializes a throwaway installation in a temporary directory
# with the S3 API on (anonymous access allowed, virtual-hosted style under s3.localhost), starts
# `serve` on free loopback ports, mints an S3 access key and an app password, and runs these
# scenarios, one after another:
#
#   aws-s3      AWS CLI `s3` in virtual-hosted style: mb, sync (a second sync uploads
#               nothing), a multipart cp, ls, download, mv, rm, rb
#   aws-s3api   AWS CLI `s3api` in path style: metadata, listings with continuation tokens and
#               common prefixes, CopyObject, DeleteObjects, a presigned URL, CORS rules and a
#               preflight, the anonymous-download bucket policy, a multipart upload with
#               UploadPartCopy
#   app-public  an application-style upload with `x-amz-acl: public-read` into an `acl`
#               bucket, then anonymous downloads in both styles; private and missing objects,
#               an ACL set back to private and a WebDAV overwrite are refused; a public-read
#               upload into a private bucket fails
#   rclone      copy with modification times (`X-Amz-Meta-Mtime`, checked over WebDAV), an
#               mtime-only change, multipart, check, a sync that transfers nothing, deletion,
#               virtual-hosted style, purge
#   mc          mb, cp, mirror, diff, ls, cat, stat, `anonymous set download` and `none`
#               (`upload` refused), virtual-hosted style, rm, rb
#   restic      init (creates the bucket), two backups, check --read-data, restore, forget
#               --prune
#   nfd         a tree with names in Unicode NFD (as older macOS writes them) through the AWS
#               CLI's sync, rclone and mc mirror: keys keep their spelling in listings, WebDAV
#               shows the NFC names, and a second sync transfers nothing
#
# WebDAV checks that what the clients wrote is what the file tree holds. The script exits
# non-zero when a scenario fails. Everything is removed again on exit; the clients' own
# configuration and caches live in the work directory, not in $HOME.
#
# Usage:
#   acceptance/scripts/s3-clients.sh [scenario...]   (default: all of them)
#
# Environment:
#   AWS=<path> RCLONE=<path> MC=<path> RESTIC=<path>   client binaries (default: from PATH)
#   NEW_TARGET_DIR=<dir>   cargo target dir for the server build (default: the repository's)
#   KEEP_WORK_DIR=1        keep the temporary config, data, client files and logs
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
AWS="${AWS:-aws}"
RCLONE="${RCLONE:-rclone}"
MC="${MC:-mc}"
RESTIC="${RESTIC:-restic}"
USER_NAME="gono"
ALL_SCENARIOS=(aws-s3 aws-s3api app-public rclone mc restic nfd)

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

SCENARIOS=()
for arg in "$@"; do
  case "${arg}" in
    -h | --help)
      usage
      exit 0
      ;;
    aws-s3 | aws-s3api | app-public | rclone | mc | restic | nfd)
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

# Reports a problem as a GitHub Actions error annotation (see run-new.sh).
annotate() {
  local title="$1" message="$2"
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    message="${message//'%'/'%25'}"
    message="${message//$'\r'/'%0D'}"
    message="${message//$'\n'/'%0A'}"
    title="${title//'%'/'%25'}"
    title="${title//$'\r'/'%0D'}"
    title="${title//$'\n'/'%0A'}"
    title="${title//':'/'%3A'}"
    title="${title//','/'%2C'}"
    echo "::error title=${title}::${message:-${title}}"
  fi
}

trap '[[ $- == *e* ]] && annotate "s3-clients.sh" "command failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    annotate "s3-clients.sh" "missing required command: $1"
    exit 1
  fi
}

require_cmd cargo
require_cmd curl
require_cmd python3
for scenario in "${SCENARIOS[@]}"; do
  case "${scenario}" in
    aws-s3 | aws-s3api | app-public) require_cmd "${AWS}" ;;
    rclone) require_cmd "${RCLONE}" ;;
    mc) require_cmd "${MC}" ;;
    restic) require_cmd "${RESTIC}" ;;
    nfd)
      require_cmd "${AWS}"
      require_cmd "${RCLONE}"
      require_cmd "${MC}"
      ;;
  esac
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gono-s3-clients.XXXXXX")"
TARGET_DIR="${NEW_TARGET_DIR:-${REPO_ROOT}/target}"
CONFIG_FILE="${WORK_DIR}/config.toml"
LOG_FILE="${WORK_DIR}/server.log"
STDOUT_LOG="${WORK_DIR}/server-stdout.log"
CLIENT_LOG="${WORK_DIR}/client.log"
FILES="${WORK_DIR}/files"
SERVER_PID=""
CURRENT="setup"

cleanup() {
  local status=$?
  if [[ "${status}" != "0" ]]; then
    local tails=""
    for log in "${CLIENT_LOG}" "${STDOUT_LOG}" "${LOG_FILE}"; do
      if [[ -s "${log}" ]]; then
        tails+="== ${log##*/}"$'\n'"$(tail -n 20 "${log}")"$'\n'
      fi
    done
    annotate "S3 client scenario '${CURRENT}' failed (exit ${status})" "${tails}"
  fi
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
  echo "FAIL [${CURRENT}]: $*" >&2
  echo "---- last client output" >&2
  tail -n 30 "${CLIENT_LOG}" >&2 || true
  exit 1
}

# --- Server -------------------------------------------------------------------------------------

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
DAV_URL="${BASE_URL}/remote.php/dav/files/${USER_NAME}"
# Path style through the loopback address; virtual-hosted style through <bucket>.s3.localhost,
# which resolves to the loopback addresses without DNS set up (RFC 6761: glibc with
# systemd-resolved, macOS, and the Go resolver alike).
S3_URL="http://127.0.0.1:${S3_PORT}"
VHOST_DOMAIN="s3.localhost"
VHOST_URL="http://${VHOST_DOMAIN}:${S3_PORT}"

# `info` so that the request log shows which requests the clients made.
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
public_url = "${VHOST_URL}"
bind = "127.0.0.1:${S3_PORT}"
allow_anonymous = true
virtual_host_domain = "${VHOST_DOMAIN}"
EOF

gono() {
  "${BIN}" --config "${CONFIG_FILE}" "$@"
}

echo "==> initializing a fresh installation in ${WORK_DIR}"
python3 -c 'import secrets; print(secrets.token_urlsafe(18))' |
  gono init --admin "${USER_NAME}" --password-stdin >/dev/null
PASSWORD="$(gono app-password add "${USER_NAME}" --label s3-clients 2>&1 |
  sed -n 's/^App password: \([^[:space:]]*\)$/\1/p' | tail -n 1)"
[[ -n "${PASSWORD}" ]] || fail "app-password add did not print a password"
KEY_OUTPUT="$(gono s3 key create "${USER_NAME}" --label s3-clients 2>&1)"
ACCESS_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Access key id: \([^[:space:]]*\)$/\1/p')"
SECRET_KEY="$(printf '%s\n' "${KEY_OUTPUT}" | sed -n 's/^Secret key: *\([^[:space:]]*\)$/\1/p')"
[[ -n "${ACCESS_KEY}" && -n "${SECRET_KEY}" ]] || fail "s3 key create did not print a key"
# The bucket an application publishes media in: objects are public by their ACL.
gono s3 bucket create "${USER_NAME}" app-media >/dev/null
gono s3 bucket set "${USER_NAME}" app-media --anonymous acl >/dev/null

echo "==> starting gono-cloud on ${BASE_URL}, S3 on ${S3_URL} and ${VHOST_URL}"
"${BIN}" --config "${CONFIG_FILE}" serve >"${STDOUT_LOG}" 2>&1 &
SERVER_PID="$!"
for _ in $(seq 1 200); do
  curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1 && break
  kill -0 "${SERVER_PID}" 2>/dev/null || fail "the server exited: $(tail -n 5 "${STDOUT_LOG}")"
  sleep 0.1
done
curl -fsS "${BASE_URL}/healthz" >/dev/null || fail "the server did not become ready"

if ! python3 -c '
import socket, sys
addresses = {info[4][0] for info in socket.getaddrinfo(sys.argv[1], 80, proto=socket.IPPROTO_TCP)}
sys.exit(0 if "127.0.0.1" in addresses else 1)' "app-media.${VHOST_DOMAIN}" 2>/dev/null; then
  fail "app-media.${VHOST_DOMAIN} does not resolve to 127.0.0.1; virtual-hosted style needs it"
fi

# --- Helpers ------------------------------------------------------------------------------------

# Runs a client command, keeping its output in the client log; fails the scenario when it fails.
run() {
  echo "\$ $*" >>"${CLIENT_LOG}"
  "$@" >>"${CLIENT_LOG}" 2>&1 || fail "command failed: $*"
}

# Runs a client command that must fail.
run_refused() {
  echo "\$ (must fail) $*" >>"${CLIENT_LOG}"
  if "$@" >>"${CLIENT_LOG}" 2>&1; then
    fail "command succeeded but should have failed: $*"
  fi
}

# Runs a client command and prints its standard output (also kept in the client log).
capture() {
  local out
  echo "\$ $*" >>"${CLIENT_LOG}"
  out="$("$@" 2>>"${CLIENT_LOG}")" || fail "command failed: $*"
  printf '%s\n' "${out}" >>"${CLIENT_LOG}"
  printf '%s' "${out}"
}

# Like capture, with the standard error output as well (rclone logs there).
capture_all() {
  local out
  echo "\$ $*" >>"${CLIENT_LOG}"
  out="$("$@" 2>&1)" || { printf '%s\n' "${out}" >>"${CLIENT_LOG}"; fail "command failed: $*"; }
  printf '%s\n' "${out}" >>"${CLIENT_LOG}"
  printf '%s' "${out}"
}

expect_eq() {
  local actual="$1" expected="$2" what="$3"
  [[ "${actual}" == "${expected}" ]] || fail "${what}: expected '${expected}', got '${actual}'"
}

expect_contains() {
  local haystack="$1" needle="$2" what="$3"
  [[ "${haystack}" == *"${needle}"* ]] || fail "${what}: '${needle}' not in: ${haystack}"
}

# Percent-encodes a relative path, segment by segment.
encode() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@" | cut -d' ' -f1
  else
    shasum -a 256 "$@" | cut -d' ' -f1
  fi
}

mtime_of() {
  python3 -c 'import os, sys; print(int(os.stat(sys.argv[1]).st_mtime))' "$1"
}

curl_dav() {
  curl -sS -u "${USER_NAME}:${PASSWORD}" "$@"
}

# The HTTP status of a WebDAV PROPFIND (depth 0) of a path below the files root: 207 or 404.
dav_status() {
  curl_dav -o /dev/null -w '%{http_code}' -X PROPFIND -H 'Depth: 0' "${DAV_URL}/$(encode "$1")"
}

dav_sha256() {
  curl_dav -f "${DAV_URL}/$(encode "$1")" | sha256
}

# The modification time WebDAV reports for a path, in UNIX seconds.
dav_mtime() {
  curl_dav -f -X PROPFIND -H 'Depth: 0' "${DAV_URL}/$(encode "$1")" | python3 -c '
import email.utils, re, sys
match = re.search(r"getlastmodified>([^<]+)<", sys.stdin.read())
print(int(email.utils.parsedate_to_datetime(match.group(1)).timestamp()) if match else "")'
}

# The HTTP status of an anonymous request (no signature).
anon_status() {
  curl -sS -o /dev/null -w '%{http_code}' "$@"
}

# A small tree with nested folders, a space and CJK in names, and fixed modification times.
make_tree() {
  local dir="$1"
  mkdir -p "${dir}/sub/deeper" "${dir}/中文"
  printf 'alpha\n' >"${dir}/a.txt"
  printf 'with a space\n' >"${dir}/with space.txt"
  printf 'beta\n' >"${dir}/sub/b.txt"
  printf 'gamma\n' >"${dir}/sub/deeper/c.txt"
  printf '名字\n' >"${dir}/中文/名字.txt"
  for i in $(seq 1 20); do
    printf 'small file %s\n' "${i}" >"${dir}/sub/small-${i}.txt"
  done
  touch -t 202001021530.45 "${dir}/a.txt"
  touch -t 201912312359.59 "${dir}/sub/b.txt"
  touch -t 200802291200.00 "${dir}/中文/名字.txt"
}

random_file() {
  head -c "$2" /dev/urandom >"$1"
}

mkdir -p "${FILES}"

# --- AWS CLI ------------------------------------------------------------------------------------

# The CLI reads nothing from $HOME: credentials from the environment, the addressing style from
# a config file of the work directory.
export AWS_ACCESS_KEY_ID="${ACCESS_KEY}" AWS_SECRET_ACCESS_KEY="${SECRET_KEY}"
export AWS_REGION="us-east-1" AWS_SHARED_CREDENTIALS_FILE="${WORK_DIR}/aws-credentials"
export AWS_EC2_METADATA_DISABLED="true" AWS_PAGER=""
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_SESSION_TOKEN AWS_ENDPOINT_URL AWS_ENDPOINT_URL_S3
: >"${AWS_SHARED_CREDENTIALS_FILE}"
printf '[default]\ns3 =\n    addressing_style = path\n' >"${WORK_DIR}/aws-path.conf"
printf '[default]\ns3 =\n    addressing_style = virtual\n' >"${WORK_DIR}/aws-virtual.conf"

# Path style through the loopback address.
aws_path() {
  AWS_CONFIG_FILE="${WORK_DIR}/aws-path.conf" "${AWS}" --endpoint-url "${S3_URL}" "$@"
}

# Virtual-hosted style: <bucket>.s3.localhost. With --endpoint-url the CLI uses path style
# unless told otherwise.
aws_virtual() {
  AWS_CONFIG_FILE="${WORK_DIR}/aws-virtual.conf" "${AWS}" --endpoint-url "${VHOST_URL}" "$@"
}

scenario_aws_s3() {
  local bucket="cli-s3" tree="${FILES}/aws-tree" out
  make_tree "${tree}"
  run aws_virtual s3 mb "s3://${bucket}"
  expect_eq "$(dav_status "Buckets/${bucket}")" "207" "mb created the bucket folder"

  run aws_virtual s3 sync "${tree}" "s3://${bucket}/tree/"
  out="$(capture aws_virtual s3 ls --recursive "s3://${bucket}/tree/")"
  expect_eq "$(printf '%s\n' "${out}" | grep -c .)" "25" "objects after sync"
  expect_eq "$(dav_sha256 "Buckets/${bucket}/tree/中文/名字.txt")" "$(sha256 "${tree}/中文/名字.txt")" \
    "a CJK name through WebDAV"
  expect_eq "$(dav_sha256 "Buckets/${bucket}/tree/with space.txt")" \
    "$(sha256 "${tree}/with space.txt")" "a name with a space through WebDAV"
  out="$(capture aws_virtual s3 sync "${tree}" "s3://${bucket}/tree/")"
  expect_eq "${out}" "" "a second sync uploads nothing"

  # Above the CLI's multipart threshold (8 MiB): three parts.
  random_file "${FILES}/big.bin" 20000000
  run aws_virtual s3 cp "${FILES}/big.bin" "s3://${bucket}/big.bin"
  out="$(capture aws_virtual s3api head-object --bucket "${bucket}" --key big.bin --query ETag --output text)"
  [[ "${out}" =~ -3\"?$ ]] || fail "multipart ETag: ${out}"
  run aws_virtual s3 cp "s3://${bucket}/big.bin" "${FILES}/big.back"
  expect_eq "$(sha256 "${FILES}/big.back")" "$(sha256 "${FILES}/big.bin")" "multipart download"
  expect_eq "$(dav_sha256 "Buckets/${bucket}/big.bin")" "$(sha256 "${FILES}/big.bin")" \
    "multipart object through WebDAV"

  run aws_virtual s3 mv "s3://${bucket}/tree/a.txt" "s3://${bucket}/moved/a.txt"
  expect_eq "$(dav_status "Buckets/${bucket}/tree/a.txt")" "404" "mv removed the source"
  expect_eq "$(dav_sha256 "Buckets/${bucket}/moved/a.txt")" "$(sha256 "${tree}/a.txt")" "mv target"

  run aws_virtual s3 rm --recursive "s3://${bucket}/"
  out="$(capture aws_virtual s3 ls --recursive "s3://${bucket}/")"
  expect_eq "${out}" "" "rm --recursive left objects"
  run aws_virtual s3 rb "s3://${bucket}"
  expect_eq "$(dav_status "Buckets/${bucket}")" "404" "rb removed the bucket folder"
}

scenario_aws_s3api() {
  local bucket="cli-s3api" out etag1 etag2 upload_id parts origin="https://app.example.com" url
  run aws_path s3api create-bucket --bucket "${bucket}"
  run aws_path s3api head-bucket --bucket "${bucket}"
  out="$(capture aws_path s3api list-buckets --query 'Buckets[].Name' --output text)"
  expect_contains "${out}" "${bucket}" "list-buckets"

  # Stored metadata comes back.
  printf 'metadata\n' >"${FILES}/meta.txt"
  run aws_path s3api put-object --bucket "${bucket}" --key docs/meta.txt --body "${FILES}/meta.txt" \
    --content-type "text/x-gono" --cache-control "max-age=60" --metadata "author=acceptance"
  out="$(capture aws_path s3api head-object --bucket "${bucket}" --key docs/meta.txt \
    --query '[ContentType, CacheControl, Metadata.author]' --output text)"
  expect_eq "${out}" $'text/x-gono\tmax-age=60\tacceptance' "head-object metadata"

  # Listings: the CLI follows continuation tokens with a page size of 2.
  for i in 1 2 3 4 5; do
    run aws_path s3api put-object --bucket "${bucket}" --key "many/${i}.txt" --body "${FILES}/meta.txt"
  done
  out="$(capture aws_path s3api list-objects-v2 --bucket "${bucket}" --prefix many/ --page-size 2 \
    --query 'Contents[].Key' --output text)"
  expect_eq "$(printf '%s' "${out}" | tr '\t' '\n' | grep -c .)" "5" "paged listing"
  out="$(capture aws_path s3api list-objects-v2 --bucket "${bucket}" --delimiter / \
    --query 'CommonPrefixes[].Prefix' --output text)"
  expect_eq "${out}" $'docs/\tmany/' "common prefixes"
  out="$(capture aws_path s3api list-objects --bucket "${bucket}" --prefix many/ --max-items 10 \
    --query 'Contents[].Key' --output text)"
  expect_eq "$(printf '%s' "${out}" | tr '\t' '\n' | grep -c .)" "5" "ListObjects v1"

  # CopyObject with new metadata, then DeleteObjects with a missing key.
  run aws_path s3api copy-object --bucket "${bucket}" --key docs/copy.txt \
    --copy-source "${bucket}/docs/meta.txt" --metadata-directive REPLACE \
    --content-type text/plain --metadata "copied=yes"
  out="$(capture aws_path s3api head-object --bucket "${bucket}" --key docs/copy.txt \
    --query '[ContentType, Metadata.copied]' --output text)"
  expect_eq "${out}" $'text/plain\tyes' "copy-object REPLACE"
  out="$(capture aws_path s3api delete-objects --bucket "${bucket}" \
    --delete '{"Objects":[{"Key":"docs/copy.txt"},{"Key":"docs/missing.txt"}]}' \
    --query 'length(Deleted)' --output text)"
  expect_eq "${out}" "2" "delete-objects (a missing key counts as deleted)"
  expect_eq "$(dav_status "Buckets/${bucket}/docs/copy.txt")" "404" "delete-objects removed the file"

  # A presigned URL works without credentials; with CORS rules, a browser on the allowed
  # origin may read it.
  url="$(capture aws_path s3 presign "s3://${bucket}/docs/meta.txt" --expires-in 300)"
  expect_eq "$(curl -fsS "${url}" | sha256)" "$(sha256 "${FILES}/meta.txt")" "presigned GET"
  cat >"${FILES}/cors.json" <<JSON
{"CORSRules": [{"AllowedOrigins": ["${origin}"], "AllowedMethods": ["GET", "PUT"],
  "AllowedHeaders": ["*"], "ExposeHeaders": ["ETag"], "MaxAgeSeconds": 3000}]}
JSON
  run aws_path s3api put-bucket-cors --bucket "${bucket}" --cors-configuration "file://${FILES}/cors.json"
  out="$(capture aws_path s3api get-bucket-cors --bucket "${bucket}" \
    --query 'CORSRules[0].AllowedOrigins[0]' --output text)"
  expect_eq "${out}" "${origin}" "get-bucket-cors"
  out="$(curl -sS -D - -o /dev/null -X OPTIONS -H "Origin: ${origin}" \
    -H "Access-Control-Request-Method: PUT" -H "Access-Control-Request-Headers: content-type" \
    "${S3_URL}/${bucket}/upload.txt" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  expect_contains "${out}" "access-control-allow-origin: ${origin}" "preflight"
  expect_contains "${out}" "access-control-allow-methods: get, put" "preflight methods"
  expect_eq "$(anon_status -X OPTIONS -H "Origin: https://other.example" \
    -H "Access-Control-Request-Method: PUT" "${S3_URL}/${bucket}/upload.txt")" "403" \
    "preflight from another origin"
  out="$(curl -sS -D - -o /dev/null -H "Origin: ${origin}" "${url}" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  expect_contains "${out}" "access-control-expose-headers: etag" "CORS headers on a GET"
  run aws_path s3api delete-bucket-cors --bucket "${bucket}"
  run_refused aws_path s3api get-bucket-cors --bucket "${bucket}"

  # The anonymous-download policy (as `mc anonymous set download` writes it) publishes the
  # bucket; deleting it makes the bucket private again.
  cat >"${FILES}/policy.json" <<JSON
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Principal": {"AWS": ["*"]},
   "Action": ["s3:GetBucketLocation", "s3:ListBucket"], "Resource": ["arn:aws:s3:::${bucket}"]},
  {"Effect": "Allow", "Principal": {"AWS": ["*"]},
   "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::${bucket}/*"]}]}
JSON
  expect_eq "$(anon_status "${S3_URL}/${bucket}/docs/meta.txt")" "403" "anonymous GET before the policy"
  run aws_path s3api put-bucket-policy --bucket "${bucket}" --policy "file://${FILES}/policy.json"
  out="$(capture aws_path s3api get-bucket-policy-status --bucket "${bucket}" \
    --query PolicyStatus.IsPublic --output text)"
  expect_eq "${out}" "True" "policy status"
  expect_eq "$(anon_status "${S3_URL}/${bucket}/docs/meta.txt")" "200" "anonymous GET with the policy"
  expect_eq "$(anon_status "${S3_URL}/${bucket}?list-type=2")" "200" "anonymous listing with the policy"
  run aws_path s3api delete-bucket-policy --bucket "${bucket}"
  expect_eq "$(anon_status "${S3_URL}/${bucket}/docs/meta.txt")" "403" "anonymous GET after delete"
  run_refused aws_path s3api get-bucket-policy --bucket "${bucket}"

  # A multipart upload with one uploaded part and one part copied from a range of an object.
  random_file "${FILES}/part1.bin" 5242880
  random_file "${FILES}/source.bin" 3000000
  run aws_path s3api put-object --bucket "${bucket}" --key source.bin --body "${FILES}/source.bin"
  upload_id="$(capture aws_path s3api create-multipart-upload --bucket "${bucket}" --key joined.bin \
    --query UploadId --output text)"
  etag1="$(capture aws_path s3api upload-part --bucket "${bucket}" --key joined.bin \
    --upload-id "${upload_id}" --part-number 1 --body "${FILES}/part1.bin" --query ETag --output text)"
  etag2="$(capture aws_path s3api upload-part-copy --bucket "${bucket}" --key joined.bin \
    --upload-id "${upload_id}" --part-number 2 --copy-source "${bucket}/source.bin" \
    --copy-source-range bytes=0-1048575 --query CopyPartResult.ETag --output text)"
  out="$(capture aws_path s3api list-parts --bucket "${bucket}" --key joined.bin \
    --upload-id "${upload_id}" --query 'length(Parts)' --output text)"
  expect_eq "${out}" "2" "list-parts"
  parts="$(python3 -c 'import json, sys; print(json.dumps({"Parts": [
    {"PartNumber": 1, "ETag": sys.argv[1]}, {"PartNumber": 2, "ETag": sys.argv[2]}]}))' \
    "${etag1}" "${etag2}")"
  run aws_path s3api complete-multipart-upload --bucket "${bucket}" --key joined.bin \
    --upload-id "${upload_id}" --multipart-upload "${parts}"
  out="$(capture aws_path s3api head-object --bucket "${bucket}" --key joined.bin --query ETag --output text)"
  [[ "${out}" =~ -2\"?$ ]] || fail "multipart ETag: ${out}"
  { cat "${FILES}/part1.bin"; head -c 1048576 "${FILES}/source.bin"; } >"${FILES}/joined.expected"
  run aws_path s3api get-object --bucket "${bucket}" --key joined.bin "${FILES}/joined.back"
  expect_eq "$(sha256 "${FILES}/joined.back")" "$(sha256 "${FILES}/joined.expected")" \
    "multipart upload with a copied part"
  # An aborted upload leaves nothing behind.
  upload_id="$(capture aws_path s3api create-multipart-upload --bucket "${bucket}" --key aborted.bin \
    --query UploadId --output text)"
  run aws_path s3api abort-multipart-upload --bucket "${bucket}" --key aborted.bin --upload-id "${upload_id}"
  # shellcheck disable=SC2016 # a JMESPath literal, not a shell expansion
  out="$(capture aws_path s3api list-multipart-uploads --bucket "${bucket}" \
    --query 'length(Uploads || `[]`)' --output text)"
  expect_eq "${out}" "0" "list-multipart-uploads after abort"

  run aws_path s3 rm --recursive "s3://${bucket}/"
  run aws_path s3api delete-bucket --bucket "${bucket}"
}

scenario_app_public() {
  local bucket="app-media" key="accounts/avatars/original/avatar.png" headers
  random_file "${FILES}/avatar.png" 4096
  # What media servers (Mastodon, PeerTube, Misskey) send: a canned ACL and a content type.
  run aws_path s3api put-object --bucket "${bucket}" --key "${key}" --body "${FILES}/avatar.png" \
    --acl public-read --content-type image/png --cache-control "public, max-age=315576000, immutable"
  expect_eq "$(curl -fsS "${S3_URL}/${bucket}/${key}" | sha256)" "$(sha256 "${FILES}/avatar.png")" \
    "anonymous download, path style"
  expect_eq "$(curl -fsS "http://${bucket}.${VHOST_DOMAIN}:${S3_PORT}/${key}" | sha256)" \
    "$(sha256 "${FILES}/avatar.png")" "anonymous download, virtual-hosted style"
  headers="$(curl -fsS -D - -o /dev/null "${S3_URL}/${bucket}/${key}" | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  expect_contains "${headers}" "content-type: image/png" "content type of a public object"
  expect_contains "${headers}" "x-content-type-options: nosniff" "nosniff on anonymous responses"
  # The AWS CLI's `s3 cp --acl` as well.
  run aws_path s3 cp "${FILES}/avatar.png" "s3://${bucket}/cache/thumb.png" --acl public-read
  expect_eq "$(anon_status "${S3_URL}/${bucket}/cache/thumb.png")" "200" "s3 cp --acl public-read"

  run aws_path s3api put-object --bucket "${bucket}" --key private/secret.png --body "${FILES}/avatar.png"
  expect_eq "$(anon_status "${S3_URL}/${bucket}/private/secret.png")" "403" "a private object"
  expect_eq "$(anon_status "${S3_URL}/${bucket}/missing.png")" "403" "a missing object"
  expect_eq "$(anon_status "${S3_URL}/${bucket}?list-type=2")" "403" "anonymous listing"

  # The ACL can be taken back, and a WebDAV overwrite makes an object private again.
  run aws_path s3api put-object-acl --bucket "${bucket}" --key cache/thumb.png --acl private
  expect_eq "$(anon_status "${S3_URL}/${bucket}/cache/thumb.png")" "403" "ACL set back to private"
  curl_dav -f -o /dev/null -T "${FILES}/avatar.png" "${DAV_URL}/Buckets/${bucket}/$(encode "${key}")" ||
    fail "WebDAV overwrite"
  expect_eq "$(anon_status "${S3_URL}/${bucket}/${key}")" "403" "a WebDAV overwrite is private"

  # A public-read upload into a bucket that publishes nothing fails loudly.
  run aws_path s3api create-bucket --bucket app-private
  run_refused aws_path s3api put-object --bucket app-private --key a.png --body "${FILES}/avatar.png" \
    --acl public-read
  expect_contains "$(tail -n 3 "${CLIENT_LOG}")" "AccessControlListNotSupported" "public-read in a private bucket"
  run aws_path s3api delete-bucket --bucket app-private
}

# --- rclone -------------------------------------------------------------------------------------

scenario_rclone() {
  local bucket="rclone-sync" tree="${FILES}/rclone-tree" conf="${WORK_DIR}/rclone.conf" log file
  cat >"${conf}" <<EOF
[gono]
type = s3
provider = Other
access_key_id = ${ACCESS_KEY}
secret_access_key = ${SECRET_KEY}
endpoint = ${S3_URL}
region = us-east-1
force_path_style = true

[gonovirtual]
type = s3
provider = Other
access_key_id = ${ACCESS_KEY}
secret_access_key = ${SECRET_KEY}
endpoint = ${VHOST_URL}
region = us-east-1
force_path_style = false
EOF
  # shellcheck disable=SC2329 # called through run and capture
  rc() { "${RCLONE}" --config "${conf}" --cache-dir "${WORK_DIR}/rclone-cache" "$@"; }
  make_tree "${tree}"

  run rc mkdir "gono:${bucket}"
  run rc copy "${tree}" "gono:${bucket}"
  run rc check "${tree}" "gono:${bucket}"
  # rclone sends the modification time as X-Amz-Meta-Mtime; the file gets it.
  for file in a.txt sub/b.txt 中文/名字.txt; do
    expect_eq "$(dav_mtime "Buckets/${bucket}/${file}")" "$(mtime_of "${tree}/${file}")" \
      "modification time of ${file} through WebDAV"
  done

  # Only the time changes: rclone updates it with a copy onto the object itself.
  touch -t 202203040506.07 "${tree}/a.txt"
  log="$(capture_all rc sync -v "${tree}" "gono:${bucket}")"
  expect_contains "${log}" "Updated modification time in destination" "mtime-only change"
  expect_eq "$(dav_mtime "Buckets/${bucket}/a.txt")" "$(mtime_of "${tree}/a.txt")" "updated modification time"

  # Multipart (5 MiB chunks), checked by downloading.
  random_file "${tree}/big.bin" 12582912
  run rc copy --s3-upload-cutoff 5M --s3-chunk-size 5M "${tree}" "gono:${bucket}"
  run rc check --download "${tree}" "gono:${bucket}"
  expect_eq "$(dav_mtime "Buckets/${bucket}/big.bin")" "$(mtime_of "${tree}/big.bin")" \
    "modification time of a multipart upload"

  # Nothing changed, nothing is transferred.
  log="$(capture_all rc sync -v "${tree}" "gono:${bucket}")"
  [[ "${log}" != *"Copied"* ]] || fail "a second sync copied files: ${log}"

  # Deletion follows the source.
  rm "${tree}/sub/b.txt"
  run rc sync "${tree}" "gono:${bucket}"
  expect_eq "$(dav_status "Buckets/${bucket}/sub/b.txt")" "404" "sync deleted a removed file"

  # Virtual-hosted style.
  file="$(capture rc lsf "gonovirtual:${bucket}/sub/deeper")"
  expect_eq "${file}" "c.txt" "listing in virtual-hosted style"
  run rc copyto "${tree}/a.txt" "gonovirtual:${bucket}/virtual.txt"
  expect_eq "$(dav_sha256 "Buckets/${bucket}/virtual.txt")" "$(sha256 "${tree}/a.txt")" \
    "upload in virtual-hosted style"

  run rc purge "gono:${bucket}"
  expect_eq "$(dav_status "Buckets/${bucket}")" "404" "purge removed the bucket"
}

# --- mc -----------------------------------------------------------------------------------------

scenario_mc() {
  local bucket="mc-bucket" tree="${FILES}/mc-tree" out
  # shellcheck disable=SC2329 # called through run and capture
  mcc() { "${MC}" --config-dir "${WORK_DIR}/mc" --no-color --quiet "$@"; }
  make_tree "${tree}"
  run mcc alias set gono "${S3_URL}" "${ACCESS_KEY}" "${SECRET_KEY}" --path on
  run mcc alias set gonovirtual "${VHOST_URL}" "${ACCESS_KEY}" "${SECRET_KEY}" --path off

  run mcc mb "gono/${bucket}"
  run mcc cp "${tree}/a.txt" "gono/${bucket}/single/a.txt"
  run mcc mirror "${tree}" "gono/${bucket}/mirror"
  out="$(capture mcc diff "${tree}" "gono/${bucket}/mirror")"
  expect_eq "${out}" "" "mc diff after mirror"
  out="$(capture mcc ls --recursive "gono/${bucket}")"
  expect_eq "$(printf '%s\n' "${out}" | grep -c .)" "26" "objects after mirror"
  expect_eq "$(capture mcc cat "gono/${bucket}/mirror/中文/名字.txt")" "名字" "mc cat"
  out="$(capture mcc stat --json "gono/${bucket}/single/a.txt")"
  expect_contains "${out}" "\"size\":6" "mc stat"

  # The anonymous download policy and back.
  expect_eq "$(anon_status "${S3_URL}/${bucket}/single/a.txt")" "403" "anonymous before the policy"
  run mcc anonymous set download "gono/${bucket}"
  expect_contains "$(capture mcc anonymous get "gono/${bucket}")" "download" "mc anonymous get"
  expect_eq "$(anon_status "${S3_URL}/${bucket}/single/a.txt")" "200" "anonymous with download"
  expect_eq "$(anon_status "http://${bucket}.${VHOST_DOMAIN}:${S3_PORT}/single/a.txt")" "200" \
    "anonymous with download, virtual-hosted style"
  run_refused mcc anonymous set upload "gono/${bucket}"
  run_refused mcc anonymous set public "gono/${bucket}"
  expect_contains "$(capture mcc anonymous get "gono/${bucket}")" "download" "unchanged after refusals"
  run mcc anonymous set none "gono/${bucket}"
  expect_eq "$(anon_status "${S3_URL}/${bucket}/single/a.txt")" "403" "anonymous after none"

  # Virtual-hosted style.
  run mcc cp "${tree}/sub/b.txt" "gonovirtual/${bucket}/virtual/b.txt"
  expect_eq "$(capture mcc cat "gonovirtual/${bucket}/virtual/b.txt")" "beta" "mc in virtual-hosted style"

  run mcc rm --recursive --force "gono/${bucket}"
  run mcc rb "gono/${bucket}"
  expect_eq "$(dav_status "Buckets/${bucket}")" "404" "rb removed the bucket folder"
}

# --- restic -------------------------------------------------------------------------------------

scenario_restic() {
  local bucket="restic-repo" tree="${FILES}/restic-tree" out
  export RESTIC_REPOSITORY="s3:${S3_URL}/${bucket}" RESTIC_PASSWORD="acceptance-only"
  # shellcheck disable=SC2329 # called through run and capture
  rs() { "${RESTIC}" --cache-dir "${WORK_DIR}/restic-cache" "$@"; }
  make_tree "${tree}"
  random_file "${tree}/blob.bin" 3000000

  run rs init
  expect_eq "$(dav_status "Buckets/${bucket}/config")" "207" "init created the bucket and its config"
  run rs backup "${tree}"
  printf 'later\n' >"${tree}/later.txt"
  run rs backup "${tree}"
  out="$(capture rs snapshots --json)"
  expect_eq "$(printf '%s' "${out}" | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))')" \
    "2" "snapshots"
  run rs check --read-data
  run rs restore latest --target "${FILES}/restic-restore"
  diff -r "${tree}" "${FILES}/restic-restore/${tree#/}" >>"${CLIENT_LOG}" 2>&1 ||
    fail "the restored tree differs"
  run rs forget --keep-last 1 --prune
  run rs check
  unset RESTIC_REPOSITORY RESTIC_PASSWORD
}

# --- NFD names ----------------------------------------------------------------------------------

scenario_nfd() {
  local tree="${FILES}/nfd-tree" out conf="${WORK_DIR}/rclone-nfd.conf" keys nfc_name
  # Names in NFD (e + U+0301, i + U+0308), as HFS+ stored them, and one in NFC.
  python3 - "${tree}" <<'PYTHON'
import os, sys, unicodedata
root = sys.argv[1]
for name in ["Café/Résumé.txt", "Café/naïve.txt", "plain.txt"]:
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(name + "\n")
names = [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs]
# The file system must keep the bytes (APFS and ext4 do; HFS+ would decompose anyway).
assert any(not unicodedata.is_normalized("NFC", n) for n in names), names
PYTHON
  nfc_name="$(python3 -c 'print("Café/Résumé.txt")')"

  # The AWS CLI sends the names as they are; the keys keep them.
  run aws_path s3 mb s3://nfd-aws
  run aws_path s3 sync "${tree}" s3://nfd-aws/
  keys="$(capture aws_path s3api list-objects-v2 --bucket nfd-aws --query 'Contents[].Key' --output json)"
  python3 -c '
import json, sys, unicodedata
keys = json.loads(sys.argv[1])
assert len(keys) == 3, keys
assert sum(not unicodedata.is_normalized("NFC", k) for k in keys) == 2, keys' "${keys}" ||
    fail "the AWS CLI's keys lost their spelling: ${keys}"
  expect_eq "$(dav_status "Buckets/nfd-aws/${nfc_name}")" "207" "WebDAV shows the NFC name"
  out="$(capture aws_path s3 sync "${tree}" s3://nfd-aws/)"
  expect_eq "${out}" "" "a second sync uploads nothing"

  # rclone without --local-unicode-normalization: the same, and check finds no difference.
  cat >"${conf}" <<EOF
[gono]
type = s3
provider = Other
access_key_id = ${ACCESS_KEY}
secret_access_key = ${SECRET_KEY}
endpoint = ${S3_URL}
region = us-east-1
force_path_style = true
EOF
  # shellcheck disable=SC2329 # called through run and capture
  rcn() { "${RCLONE}" --config "${conf}" --cache-dir "${WORK_DIR}/rclone-cache" "$@"; }
  run rcn mkdir gono:nfd-rclone
  run rcn copy "${tree}" gono:nfd-rclone
  run rcn check "${tree}" gono:nfd-rclone
  out="$(capture_all rcn sync -v "${tree}" gono:nfd-rclone)"
  [[ "${out}" != *"Copied"* ]] || fail "a second rclone sync copied files: ${out}"
  expect_eq "$(dav_status "Buckets/nfd-rclone/${nfc_name}")" "207" "WebDAV shows the NFC name"

  # mc mirror, compared with mc diff.
  # shellcheck disable=SC2329 # called through run and capture
  mcn() { "${MC}" --config-dir "${WORK_DIR}/mc" --no-color --quiet "$@"; }
  run mcn alias set gononfd "${S3_URL}" "${ACCESS_KEY}" "${SECRET_KEY}" --path on
  run mcn mb gononfd/nfd-mc
  run mcn mirror "${tree}" gononfd/nfd-mc
  out="$(capture mcn diff "${tree}" gononfd/nfd-mc)"
  expect_eq "${out}" "" "mc diff after mirror"
}

# --- Run ----------------------------------------------------------------------------------------

for scenario in "${SCENARIOS[@]}"; do
  CURRENT="${scenario}"
  echo "==> ${scenario}"
  echo "==== ${scenario}" >>"${CLIENT_LOG}"
  "scenario_${scenario//-/_}"
  echo "    ok"
done
CURRENT="done"
echo "==> all S3 client scenarios passed: ${SCENARIOS[*]}"
