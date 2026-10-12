#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec 9>/run/lock/engineaccounts-rebuild.lock
flock -n 9 || { echo 'Another EngineAccounts rebuild is running.' >&2; exit 1; }
node scripts/check-config.mjs
npm run build
systemctl restart engine-accounts.service
systemctl is-active --quiet engine-accounts.service
./scripts/ready.sh
