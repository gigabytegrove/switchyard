#!/usr/bin/env bash
# Zero-configuration deployment. Operator settings are made in the web UI.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail 'Docker Engine is not installed'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'

# Resolve the Compose project name, including COMPOSE_PROJECT_NAME from .env.
# Compose ps can omit an existing container after relocating a Git checkout.
# Identify the installed service from Docker labels rather than directory ancestry.
docker compose config --quiet
compose_project="$(docker compose config | sed -n 's/^name:[[:space:]]*//p' | head -n 1)"
[[ "$compose_project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail 'Could not determine the Compose project identity'

mapfile -t project_services < <(
  docker ps -aq \
    --filter "label=com.docker.compose.project=$compose_project" \
    --filter 'label=com.docker.compose.service=switchyard'
)
[[ "${#project_services[@]}" -le 1 ]] || fail "Multiple Switchyard containers belong to Compose project $compose_project; refusing ambiguous upgrade"
existing_service="${project_services[0]:-}"

# Do not attach a different data volume during a relocated checkout upgrade.
if [[ -n "$existing_service" ]]; then
  existing_data="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}:{{.Name}}{{end}}{{end}}' "$existing_service")"
  [[ "$existing_data" == "volume:${compose_project}_switchyard_data" ]] ||
    fail "Existing Switchyard /data mount ($existing_data) does not match ${compose_project}_switchyard_data. Nothing was changed."
fi

# Matching project/service is the existing installation, not a competitor.
while IFS= read -r running_container; do
  [[ -n "$running_container" && "$running_container" != "$existing_service" ]] || continue
  if docker port "$running_container" 2>/dev/null | grep -Eq ':9791([[:space:]]|$)'; then
    occupied_name="$(docker inspect --format '{{.Name}}' "$running_container" 2>/dev/null || echo "$running_container")"
    occupied_project="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$running_container" 2>/dev/null || echo unknown)"
    fail "TCP 9791 is already published by $occupied_name (Compose project: $occupied_project). Upgrade that original project instead. Nothing was removed."
  fi
done < <(docker ps -q)

# Upgrade migration: previous v0.4 builds mounted the Fernet key as a Docker secret.
# Carry it into /data before recreating the container so previously enrolled TOTP
# secrets remain decryptable. Never replace an existing key.
legacy_container="$existing_service"
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

# Compose .env may store COMPOSE_PROJECT_NAME after moving a checkout.
# All application credentials and settings remain in /data and the web UI.
if [[ -f .env ]]; then
  printf 'Note: preserving Compose .env (including any migrated project name).\n'
fi
if [[ -d secrets ]]; then
  printf 'Note: legacy secrets/ retained for rollback; review after validating upgrade.\n'
fi

docker compose config --quiet
docker compose pull
docker compose up -d --no-build --wait
docker compose ps
printf '\nSwitchyard LAN: http://DOCKER-HOST-IP:9791\n'
if docker compose logs --no-color switchyard | grep -q 'SWITCHYARD FIRST-RUN CLAIM CODE:'; then
  printf 'First installation: get your one-time claim code with:\n  docker compose logs switchyard\n'
  printf 'Enter the code in the browser setup wizard, set your admin password and save proxy settings there.\n'
fi
printf 'Optional verification: ./scripts/smoke-test.sh\n'
