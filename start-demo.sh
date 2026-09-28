#!/usr/bin/env bash
# Start the isolated live-demo stack only. Main application services are untouched.
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
  echo "Missing .env. Create it before starting the demo." >&2
  exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "Cannot detect wlan0: the ip command is unavailable." >&2
  exit 1
fi
wlan_ip="$(ip -4 -o addr show dev wlan0 scope global 2>/dev/null | sed -n "1{s/.*inet \([0-9.]*\)\/.*/\1/p;}")"
if [ -z "$wlan_ip" ]; then
  echo "No IPv4 address found on wlan0. Connect wlan0 before starting the demo." >&2
  exit 1
fi

export DEMO_HOST_IP="$wlan_ip"
# These values are deliberately overwritten every launch: Wi-Fi DHCP addresses
# change, and a stale shell export must never be encoded into the audience QR.
export DEMO_BASE_URL="http://$DEMO_HOST_IP:8088"
export NEXT_PUBLIC_DEMO_PUBLIC_URL="$DEMO_BASE_URL"
export NEXT_PUBLIC_DEMO_API_URL="http://$DEMO_HOST_IP:8100/api/demo"

echo "Starting Demo-2 live cyber-range on wlan0 ($DEMO_HOST_IP)..."
"${COMPOSE[@]}" up -d --build postgres demo-2-backend demo-2

echo "Waiting for the demo API..."
for attempt in $(seq 1 30); do
  if curl -fsS http://localhost:8100/api/demo/health >/dev/null 2>&1; then
    echo "Demo is ready: $DEMO_BASE_URL"
    echo "QR / audience URL: $DEMO_BASE_URL/join"
    echo "To stop only Demo-2: ./stop-demo.sh"
    exit 0
  fi
  sleep 2
done

echo "Demo-2 API did not become ready. Check: ${COMPOSE[*]} logs demo-2-backend" >&2
exit 1
