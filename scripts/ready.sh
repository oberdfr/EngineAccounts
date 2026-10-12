#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="$(node --env-file="$ROOT/.env" -p 'process.env.ENGINE_ACCOUNTS_PORT || process.env.PORT || 8080')"
exec "$ROOT/scripts/wait-ready.sh" "$PORT"
