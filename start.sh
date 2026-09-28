#!/usr/bin/env bash
# Start the main Predictive Cyber Defence platform only.
# The isolated live demo is intentionally excluded; use ./start-demo.sh for it.
set -Eeuo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker and its Compose plugin first." >&2
  exit 1
fi
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is required." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo "Missing .env. Copy the project environment template or create .env before starting." >&2
  exit 1
fi

MAIN_SERVICES=(postgres redis minio backend frontend prometheus grafana loki promtail)
echo "Starting main platform services (demo excluded)..."
"${COMPOSE[@]}" up -d "${MAIN_SERVICES[@]}"

echo "Waiting for the API..."
for attempt in $(seq 1 30); do
  if curl -fsS http://localhost:8000/health/ready >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "Backend did not become ready. Check: ${COMPOSE[*]} logs backend" >&2
    exit 1
  fi
  sleep 2
done

# Apply versioned database migrations after the backend and database are ready.
"${COMPOSE[@]}" exec -T backend alembic -c /app/alembic.ini upgrade head

echo "Main platform is ready:"
echo "  Frontend:  http://localhost:3000"
echo "  API docs:  http://localhost:8000/api/v1/docs"
echo "  Monitoring: http://localhost:3001"
echo "To stop only the main platform: ./stop-all.sh"
