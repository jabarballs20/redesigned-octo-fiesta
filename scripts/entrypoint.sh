#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/data}"
XRAY_DIR="$DATA_DIR/xray"

mkdir -p "$XRAY_DIR"

if [ ! -f "$XRAY_DIR/config.json" ]; then
  cat >"$XRAY_DIR/config.json" <<'EOF'
{
  "log": { "level": "warning" },
  "inbounds": [],
  "outbounds": [],
  "routing": { "rules": [] }
}
EOF
fi

exec node "$ROOT_DIR/backend.js"
