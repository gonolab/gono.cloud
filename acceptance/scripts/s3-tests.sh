#!/usr/bin/env bash
# Run a selected subset of Ceph's S3 compatibility tests (s3-tests) against the S3 API of the
# server built from this checkout.
#
# The script builds `gono-cloud`, initializes a throwaway installation in a temporary directory
# with the S3 API on (anonymous access allowed), creates the three users s3-tests needs (main,
# alt and tenant) with an access key each, writes an s3-tests configuration for them, runs the
# tests listed in acceptance/s3-tests/selected.txt with pytest, and compares the failures with
# acceptance/s3-tests/expected-failures.txt. It exits non-zero when a test fails that is not on
# that list, or when a listed test passes. Everything is removed again on exit.
#
# s3-tests is not part of this repository. Check it out at the pinned commit below and install
# its requirements (acceptance/s3-tests/requirements.txt pins them) into a virtualenv:
#
#   git clone https://github.com/ceph/s3-tests.git ~/.cache/gono/s3-tests
#   git -C ~/.cache/gono/s3-tests checkout 5b3987116eca0b4b8fa57d6b10f3db57bab196b6
#   uv venv --python 3.12 ~/.cache/gono/s3-tests/.venv
#   uv pip install --python ~/.cache/gono/s3-tests/.venv/bin/python \
#     -r acceptance/s3-tests/requirements.txt
#
# Usage:
#   acceptance/scripts/s3-tests.sh [-- <extra pytest args>]
#
# Environment:
#   S3_TESTS=<dir>         the s3-tests checkout (default: ~/.cache/gono/s3-tests)
#   S3_TESTS_PYTHON=<path> its Python (default: <S3_TESTS>/.venv/bin/python)
#   S3_TESTS_SELECT=all    run every test of test_s3.py and test_headers.py instead of the
#                          selected ones, and only report (for choosing the selection)
#   NEW_TARGET_DIR=<dir>   cargo target dir for the server build (default: the repository's)
#   KEEP_WORK_DIR=1        keep the temporary config, data, results and logs
set -Eeuo pipefail

# The last commit of ceph/s3-tests before the tests moved into the ceph repository.
S3_TESTS_COMMIT="5b3987116eca0b4b8fa57d6b10f3db57bab196b6"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACCEPT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ACCEPT_DIR}/.." && pwd)"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
S3_TESTS="${S3_TESTS:-${HOME}/.cache/gono/s3-tests}"
S3_TESTS_PYTHON="${S3_TESTS_PYTHON:-${S3_TESTS}/.venv/bin/python}"
S3_TESTS_SELECT="${S3_TESTS_SELECT:-selected}"
SELECTED_FILE="${ACCEPT_DIR}/s3-tests/selected.txt"
EXPECTED_FAILURES_FILE="${ACCEPT_DIR}/s3-tests/expected-failures.txt"
PYTEST_ARGS=()

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while (($#)); do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      PYTEST_ARGS=("$@")
      break
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

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

trap '[[ $- == *e* ]] && annotate "s3-tests.sh" "command failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

fail() {
  echo "$*" >&2
  annotate "s3-tests.sh" "$*"
  exit 1
}

command -v cargo >/dev/null 2>&1 || fail "missing required command: cargo"
command -v curl >/dev/null 2>&1 || fail "missing required command: curl"
command -v python3 >/dev/null 2>&1 || fail "missing required command: python3"
[[ -d "${S3_TESTS}/s3tests/functional" ]] || fail "no s3-tests checkout in ${S3_TESTS} (see --help)"
[[ -x "${S3_TESTS_PYTHON}" ]] || fail "no Python for s3-tests at ${S3_TESTS_PYTHON} (see --help)"
HEAD_COMMIT="$(git -C "${S3_TESTS}" rev-parse HEAD 2>/dev/null || true)"
[[ "${HEAD_COMMIT}" == "${S3_TESTS_COMMIT}" ]] ||
  fail "s3-tests in ${S3_TESTS} is at ${HEAD_COMMIT:-an unknown commit}, not ${S3_TESTS_COMMIT}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gono-s3-tests.XXXXXX")"
TARGET_DIR="${NEW_TARGET_DIR:-${REPO_ROOT}/target}"
CONFIG_FILE="${WORK_DIR}/config.toml"
LOG_FILE="${WORK_DIR}/server.log"
STDOUT_LOG="${WORK_DIR}/server-stdout.log"
TEST_LOG="${WORK_DIR}/pytest.log"
JUNIT="${WORK_DIR}/results.xml"
SERVER_PID=""

# shellcheck disable=SC2329 # the EXIT trap calls it
cleanup() {
  local status=$?
  if [[ "${status}" != "0" ]]; then
    local tails=""
    for log in "${STDOUT_LOG}" "${LOG_FILE}"; do
      if [[ -s "${log}" ]]; then
        tails+="== ${log##*/}"$'\n'"$(tail -n 20 "${log}")"$'\n'
      fi
    done
    annotate "s3-tests.sh exited with ${status}" "${tails}"
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

cat >"${CONFIG_FILE}" <<EOF
[server]
bind = "127.0.0.1:${PORT}"
base_url = "${BASE_URL}"

[storage]
data_dir = "${WORK_DIR}/data"

[db]
path = "${WORK_DIR}/gono-cloud.db"

[logging]
level = "warn"
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

random_password() {
  python3 -c 'import secrets; print(secrets.token_urlsafe(18))'
}

echo "==> initializing a fresh installation in ${WORK_DIR}"
random_password | gono init --admin main --password-stdin >/dev/null
random_password | gono user add alt --display-name "Alt User" --password-stdin >/dev/null
random_password | gono user add tenant --password-stdin >/dev/null

# Creates an access key for every bucket of a user; prints "<access key id> <secret key>".
make_key() {
  local output access secret
  output="$(gono s3 key create "$1" --label s3-tests 2>&1)"
  access="$(printf '%s\n' "${output}" | sed -n 's/^Access key id: \([^[:space:]]*\)$/\1/p')"
  secret="$(printf '%s\n' "${output}" | sed -n 's/^Secret key: *\([^[:space:]]*\)$/\1/p')"
  [[ -n "${access}" && -n "${secret}" ]] || fail "s3 key create did not print a key for $1"
  echo "${access} ${secret}"
}

read -r MAIN_ACCESS MAIN_SECRET <<<"$(make_key main)"
read -r ALT_ACCESS ALT_SECRET <<<"$(make_key alt)"
read -r TENANT_ACCESS TENANT_SECRET <<<"$(make_key tenant)"

# The owner of a bucket is reported with the account's name as its ID and its display name.
# s3-tests reads the IAM sections even when no IAM test runs; they get unused values.
S3TEST_CONF="${WORK_DIR}/s3tests.conf"
cat >"${S3TEST_CONF}" <<EOF
[DEFAULT]
host = 127.0.0.1
port = ${S3_PORT}
is_secure = False
ssl_verify = False

[fixtures]
bucket prefix = gono-{random}-

[s3 main]
display_name = main
user_id = main
email = main@example.com
api_name = default
access_key = ${MAIN_ACCESS}
secret_key = ${MAIN_SECRET}

[s3 alt]
display_name = Alt User
user_id = alt
email = alt@example.com
access_key = ${ALT_ACCESS}
secret_key = ${ALT_SECRET}

[s3 tenant]
display_name = tenant
user_id = tenant
email = tenant@example.com
access_key = ${TENANT_ACCESS}
secret_key = ${TENANT_SECRET}
tenant = testx

[iam]
email = unused@example.com
user_id = unused
access_key = UNUSED
secret_key = unused
display_name = unused

[iam root]
access_key = UNUSED
secret_key = unused
user_id = unused
email = unused@example.com

[iam alt root]
access_key = UNUSED
secret_key = unused
user_id = unused
email = unused@example.com
EOF

echo "==> starting gono-cloud on ${BASE_URL}, S3 on 127.0.0.1:${S3_PORT}"
"${BIN}" --config "${CONFIG_FILE}" serve >"${STDOUT_LOG}" 2>&1 &
SERVER_PID="$!"
for _ in $(seq 1 200); do
  curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1 && break
  kill -0 "${SERVER_PID}" 2>/dev/null || fail "the server exited: $(tail -n 5 "${STDOUT_LOG}")"
  sleep 0.1
done
curl -fsS "${BASE_URL}/healthz" >/dev/null || fail "the server did not become ready"

# The tests to run: node ids relative to the s3-tests checkout.
if [[ "${S3_TESTS_SELECT}" == "all" ]]; then
  TESTS=(s3tests/functional/test_s3.py s3tests/functional/test_headers.py)
else
  TESTS=()
  while IFS= read -r test; do
    TESTS+=("${test}")
  done < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "${SELECTED_FILE}")
  ((${#TESTS[@]})) || fail "no tests selected in ${SELECTED_FILE}"
fi

echo "==> running s3-tests (${S3_TESTS_SELECT}: ${#TESTS[@]} entries) at ${S3_TESTS_COMMIT:0:7}"
set +e
# The AWS SDK must not read the user's own configuration. Some tests compare the server's
# dates with the local clock (`datetime.now()` in the x-amz-expiration tests), so they run in
# UTC, as on Ceph's test hosts.
(
  cd "${S3_TESTS}" &&
    S3TEST_CONF="${S3TEST_CONF}" AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
      AWS_EC2_METADATA_DISABLED=true AWS_DEFAULT_REGION=us-east-1 TZ=UTC \
      "${S3_TESTS_PYTHON}" -m pytest -p no:cacheprovider -q -rN --tb=line \
      --junitxml="${JUNIT}" "${TESTS[@]}" ${PYTEST_ARGS[@]+"${PYTEST_ARGS[@]}"}
) >"${TEST_LOG}" 2>&1
PYTEST_STATUS=$?
set -e
tail -n 3 "${TEST_LOG}"
[[ -s "${JUNIT}" ]] || fail "pytest wrote no results (exit ${PYTEST_STATUS}): $(tail -n 20 "${TEST_LOG}")"

# `<file>::<test>` of every test with the given outcome (passed, failed, skipped) from the
# JUnit report. Errors in setup or teardown count as failures.
results() {
  python3 - "${JUNIT}" "$1" <<'PY'
import sys, xml.etree.ElementTree as ET
path, wanted = sys.argv[1], sys.argv[2]
outcomes = {}
for case in ET.parse(path).iter("testcase"):
    module = case.get("classname", "").replace(".", "/") + ".py"
    name = f"{module}::{case.get('name')}"
    kinds = {child.tag for child in case}
    if kinds & {"failure", "error"}:
        outcome = "failed"
    elif "skipped" in kinds:
        outcome = "skipped"
    else:
        outcome = "passed"
    # A test that passed but failed in teardown appears twice; the failure wins.
    if outcomes.get(name) != "failed":
        outcomes[name] = outcome
for name, outcome in sorted(outcomes.items()):
    if outcome == wanted:
        print(name)
PY
}

FAILED="$(results failed)"
PASSED="$(results passed)"
SKIPPED="$(results skipped)"
count() { printf '%s\n' "$1" | sed '/^$/d' | wc -l | tr -d ' '; }

echo
echo "==> summary"
echo "passed:  $(count "${PASSED}")"
echo "failed:  $(count "${FAILED}")"
echo "skipped: $(count "${SKIPPED}")"

if [[ "${S3_TESTS_SELECT}" == "all" ]]; then
  printf '%s\n' "${PASSED}" >"${WORK_DIR}/passed.txt"
  printf '%s\n' "${FAILED}" >"${WORK_DIR}/failed.txt"
  printf '%s\n' "${SKIPPED}" >"${WORK_DIR}/skipped.txt"
  echo "results: ${WORK_DIR}/{passed,failed,skipped}.txt (set KEEP_WORK_DIR=1 to keep them)"
  exit 0
fi

STATUS=0
EXPECTED="$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "${EXPECTED_FAILURES_FILE}" | sort -u)"
UNEXPECTED_FAILURES="$(comm -23 <(printf '%s\n' "${FAILED}") <(printf '%s\n' "${EXPECTED}") | sed '/^$/d')"
UNEXPECTED_PASSES="$(comm -12 <(printf '%s\n' "${PASSED}") <(printf '%s\n' "${EXPECTED}") | sed '/^$/d')"
if [[ -n "${UNEXPECTED_FAILURES}" ]]; then
  echo "unexpected failures (not in acceptance/s3-tests/expected-failures.txt):"
  printf '%s\n' "${UNEXPECTED_FAILURES}" | sed 's/^/  /'
  grep -E "^(E |FAILED|ERROR)" "${TEST_LOG}" | head -n 40 || true
  annotate "s3-tests: unexpected failures" "${UNEXPECTED_FAILURES}"
  STATUS=1
fi
if [[ -n "${UNEXPECTED_PASSES}" ]]; then
  echo "expected failures that passed (remove them from acceptance/s3-tests/expected-failures.txt):"
  printf '%s\n' "${UNEXPECTED_PASSES}" | sed 's/^/  /'
  annotate "s3-tests: expected failures passed" "${UNEXPECTED_PASSES}"
  STATUS=1
fi
if [[ -n "${SKIPPED}" ]]; then
  echo "skipped (a selected test should run; check the selection):"
  printf '%s\n' "${SKIPPED}" | sed 's/^/  /'
  annotate "s3-tests: selected tests were skipped" "${SKIPPED}"
  STATUS=1
fi
if [[ "${STATUS}" == "0" ]]; then
  echo "all failures match acceptance/s3-tests/expected-failures.txt"
fi
exit "${STATUS}"
