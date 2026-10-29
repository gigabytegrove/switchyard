#!/usr/bin/env bash
# Fail an image build if any mandatory browser protocol runtime is absent.
set -Eeuo pipefail
ROOT="${1:-/app/static}"
required=(
  index.html app.js style.css guacamole.js xterm.js xterm.css addon-fit.js
  spice-view.html spice-view.js spice/main.js spice/spice.css
  spice/spiceconn.js spice/inputs.js spice/display.js
)
for path in "${required[@]}"; do
  if [[ ! -s "$ROOT/$path" ]]; then
    printf 'MISSING: %s\n' "$ROOT/$path" >&2
    exit 1
  fi
done
printf 'PASS: %d mandatory browser protocol assets found\n' "${#required[@]}"
