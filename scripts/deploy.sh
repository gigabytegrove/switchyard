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
  printf 'Created .env; customize LAN_ORIGINS and optional PUBLIC_ORIGIN before deployment.\n' >&2
  exit 2
fi

# LAN works without a public URL. A configured public URL MUST use HTTPS.
origin="$(sed -n 's/^PUBLIC_ORIGIN=//p' .env | tail -n 1)"
secure="$(sed -n 's/^COOKIE_SECURE=//p' .env | tail -n 1)"
if [[ -n "$origin" ]]; then
  [[ "$origin" =~ ^https://[^/[:space:]]+$ ]] || fail 'PUBLIC_ORIGIN must be an HTTPS origin without path'
  [[ "$origin" != 'https://switchyard.example.net' ]] || fail 'Set a real remote PUBLIC_ORIGIN or leave it empty for LAN-only use'
  [[ "$secure" == 'true' ]] || fail 'COOKIE_SECURE must remain true for remote HTTPS'
fi

mkdir -p secrets
chmod 700 secrets
if [[ ! -s secrets/admin_password.txt ]]; then
  umask 077
  openssl rand -base64 36 > secrets/admin_password.txt
  chmod 600 secrets/admin_password.txt
  printf 'Generated one-time bootstrap admin password at secrets/admin_password.txt\n'
fi

if [[ ! -s secrets/mfa_key.txt ]]; then
  if [[ -e secrets/mfa_key.txt ]]; then fail 'MFA key file exists but is empty'; fi
  umask 077
  # Valid Fernet key (32 random bytes, URL-safe base64).
  openssl rand 32 | openssl base64 -A | tr '+/' '-_' > secrets/mfa_key.txt
  chmod 600 secrets/mfa_key.txt
  printf 'Generated persistent TOTP encryption key at secrets/mfa_key.txt\n'
fi

docker compose config --quiet
docker compose build --pull
docker compose up -d --wait
docker compose ps
printf '\nDeployed. LAN: http://YOUR-DOCKER-HOST-LAN-IP:9791\n'
if [[ -n "$origin" ]]; then printf 'Remote HTTPS origin: %s (TOTP required)\n' "$origin"; fi
printf 'Host health: curl --fail http://127.0.0.1:9791/healthz\n'
printf 'Run ./scripts/smoke-test.sh after verifying the host-bound address.\n'
