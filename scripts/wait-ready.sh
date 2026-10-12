#!/usr/bin/env bash
set -euo pipefail

for port in "$@"; do
  ready=false
  for ((attempt = 0; attempt < 60; attempt++)); do
    if curl --fail --silent --output /dev/null --max-time 2 "http://127.0.0.1:$port/readyz"; then
      ready=true
      break
    fi
    sleep 1
  done
  if [[ "$ready" != true ]]; then
    echo "Readiness failed on port $port" >&2
    exit 1
  fi
done
