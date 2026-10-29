#!/usr/bin/env bash
# Zero-configuration deployment. Operator settings are made in the web UI.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail 'Docker Engine is not installed'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'

# Upgrade migration: previous v0.4 builds mounted the Fernet key as a Docker secret.
# Carry it into /data before recreating the container so previously enrolled TOTP
# secrets remain decryptable. Never replace an existing key.
legacy_container="$(docker compose ps -q switchyard 2>/dev/null || true)"
if [[ -n "$legacy_container" ]] && docker exec "$legacy_container" test -s /run/secrets/mfa_key 2>/dev/null; then
  echo 'Migrating existing MFA key from legacy Docker secret into persistent /data.'
  docker exec "$legacy_container" /opt/venv/bin/python -c '
from pathlib import Path
import os
old=Path("/run/secrets/mfa_key")
new=Path("/data/mfa.key")
if not new.exists():
    with os.fdopen(os.open(str(new), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
        file.write(old.read_bytes().strip())
    print("MFA encryption key migrated without replacement")
' || fail 'Could not migrate existing MFA key; old container left running'
fi

# The legacy .env and secrets files are not used by the new Compose file.
# Do not delete automatically: they may be needed for external rollback.
if [[ -f .env || -d secrets ]]; then
  printf 'Note: old .env/secrets files are obsolete; securely remove them after validating upgrade.\n'
fi

docker compose config --quiet
docker compose build --pull
docker compose up -d --wait
docker compose ps
printf '\nSwitchyard LAN: http://DOCKER-HOST-IP:9791\n'
if docker compose logs --no-color switchyard | grep -q 'SWITCHYARD FIRST-RUN CLAIM CODE:'; then
  printf 'First installation: get your one-time claim code with:\n  docker compose logs switchyard\n'
  printf 'Enter the code in the browser setup wizard, set your admin password and save proxy settings there.\n'
fi
printf 'Optional verification: ./scripts/smoke-test.sh\n'
