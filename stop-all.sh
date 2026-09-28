#!/usr/bin/env bash
# Stop the main platform only. The isolated live demo and data remain untouched.
# Use ./stop-demo.sh for the demo, or pass --include-demo to stop both stacks.
set -Eeuo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is required." >&2
  exit 1
fi

SERVICES=(postgres redis minio backend frontend prometheus grafana loki promtail)
if [ "${1:-}" = "--include-demo" ]; then
  SERVICES+=(demo-backend demo-frontend)
elif [ "${1:-}" != "" ]; then
  echo "Usage: ./stop-all.sh [--include-demo]" >&2
  exit 2
fi

echo "Stopping: ${SERVICES[*]}"
"${COMPOSE[@]}" stop "${SERVICES[@]}"
echo "Stopped. Docker volumes and demo state were preserved."
