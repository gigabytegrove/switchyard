#!/usr/bin/env bash
# Non-destructive, unauthenticated install acceptance for a freshly built image.
# Usage: SWITCHYARD_URL=http://127.0.0.1:9791 ./scripts/smoke-test.sh
set -Eeuo pipefail
BASE="${SWITCHYARD_URL:-http://127.0.0.1:9791}"
BASE="${BASE%/}"
CURL=(curl --fail --show-error --silent --connect-timeout 4 --max-time 12)
TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT
if [[ ! "$BASE" =~ ^https?://[^/]+$ ]]; then
  echo "ERROR: SWITCHYARD_URL must be an origin, not a path" >&2
  exit 2
fi

check_http() {
  local path="$1" name="$2"
  "${CURL[@]}" "$BASE$path" -o "$TEMP/response" || { echo "FAIL: $name ($path)" >&2; exit 1; }
  [[ -s "$TEMP/response" ]] || { echo "FAIL: $name empty response" >&2; exit 1; }
  printf 'PASS: %s\n' "$name"
}

check_http /healthz 'health endpoint responds'
expected_version="$(tr -d '\r\n' < "$(dirname "${BASH_SOURCE[0]}")/../VERSION")"
[[ "$expected_version" =~ ^[0-9A-Za-z.-]+$ ]] || { echo 'FAIL: invalid VERSION file' >&2; exit 1; }
grep -Fq "\"version\":\"$expected_version\"" "$TEMP/response" || {
  echo "FAIL: running version does not match $expected_version" >&2; exit 1;
}
check_http / 'Switchyard UI responds'
grep -q 'SWITCHYARD' "$TEMP/response" || { echo 'FAIL: expected UI shell missing' >&2; exit 1; }
grep -Fq '0.5.9-dev.1' "$TEMP/response" || { echo 'FAIL: compact SwitchYard interface not installed' >&2; exit 1; }
grep -Fq '/static/switchyard-mark.webp' "$TEMP/response" || { echo 'FAIL: restored original SwitchYard mark missing' >&2; exit 1; }
grep -Fq 'style.css?v=0.5.9-dev.1' "$TEMP/response" || { echo 'FAIL: compact SwitchYard CSS reference missing' >&2; exit 1; }
echo 'PASS: served HTML identifies the new compact SwitchYard interface'
check_http /api/setup/status 'Setup status endpoint responds'
check_http /static/guacamole.js 'Guacamole browser runtime is packaged'
check_http /static/spice/main.js 'SPICE HTML5 browser runtime is packaged'
check_http /static/spice-view.html 'SPICE viewer responds'
check_http '/static/style.css?v=0.5.9-dev.1' 'compact SwitchYard stylesheet is packaged'
grep -Fq -- '--sw-logo-red:#bc293a' "$TEMP/response" || { echo 'FAIL: old stylesheet still served' >&2; exit 1; }
echo 'PASS: verified release-specific compact SwitchYard colors'
"${CURL[@]}" -D "$TEMP/headers" -o /dev/null "$BASE/static/spice-view.html"
grep -Eiq '^x-frame-options:[[:space:]]*SAMEORIGIN' "$TEMP/headers" || {
  echo 'FAIL: SPICE frame policy not configured' >&2; exit 1;
}
status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 "$BASE/api/desktops")"
[[ "$status" == 401 ]] || { echo "FAIL: /api/desktops did not require auth (HTTP $status)" >&2; exit 1; }
echo 'PASS: desktop API rejects unauthenticated access'
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose config --quiet
  echo 'PASS: Docker Compose config resolves'
  # guacd must not have a published host port.
  if docker compose port guacd 4822 >/dev/null 2>&1; then
    echo 'FAIL: private guacd service has a published port' >&2; exit 1
  fi
  echo 'PASS: guacd has no published host port'
fi
echo 'PASS: non-destructive Switchyard v0.5.9-dev.1 smoke checks complete'
