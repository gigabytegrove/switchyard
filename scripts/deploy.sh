#!/usr/bin/env bash
# Switchyard Docker deployment - first install or in-place rebuild.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail 'Docker Engine is not installed'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose plugin is not installed'
command -v openssl >/dev/null 2>&1 || fail 'openssl is not installed'

if [[ ! -f .env ]]; then
  cp .env.example .env
  chmod 600 .env
  printf 'Created .env; configure PUBLIC_ORIGIN and SWITCHYARD_BIND before deployment.\n' >&2
  exit 2
fi

# Enforce explicitly configured browser-facing origin and safe cookies.
origin="$(sed -n 's/^PUBLIC_ORIGIN=//p' .env | tail -n 1)"
secure="$(sed -n 's/^COOKIE_SECURE=//p' .env | tail -n 1)"
[[ "$origin" =~ ^https?://[^/[:space:]]+$ ]] || fail 'PUBLIC_ORIGIN must be a complete origin without a path'
[[ "$origin" != 'https://switchyard.example.net' ]] || fail 'Set PUBLIC_ORIGIN in .env to the browser-facing URL'
if [[ "$origin" == https://* && "$secure" != 'true' ]]; then
  fail 'COOKIE_SECURE must be true when using HTTPS'
fi
if [[ "$origin" == http://* && "$secure" != 'false' ]]; then
  fail 'For isolated local HTTP testing set COOKIE_SECURE=false'
fi

mkdir -p secrets
chmod 700 secrets
if [[ ! -s secrets/admin_password.txt ]]; then
  umask 077
  openssl rand -base64 36 > secrets/admin_password.txt
  chmod 600 secrets/admin_password.txt
  printf 'Generated one-time bootstrap admin password at secrets/admin_password.txt\n'
fi

docker compose config --quiet
docker compose build --pull
docker compose up -d --wait
docker compose ps
printf '\nDeployed. Browser origin: %s\n' "$origin"
printf 'Health check: curl --fail http://127.0.0.1:9791/healthz (for loopback binding)\n'
printf 'Run ./scripts/smoke-test.sh after verifying the host-bound address.\n'
