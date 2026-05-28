#!/usr/bin/env bash
set -euo pipefail

curl -fsS http://localhost:8080/health >/dev/null
