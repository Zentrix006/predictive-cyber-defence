#!/bin/bash
# Stop the Demo-2 stack (demo-2-backend + demo-2) only.
# Research services (postgres, backend, frontend, train, grafana, ...) keep running.
#
# Usage:
#   ./stop-demo.sh            stop demo containers
#   ./stop-demo.sh --rm       stop and remove demo containers + demo volumes

set -e
cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

echo -e "${GREEN}Stopping demo stack...${NC}"
if [ "${1:-}" = "--rm" ]; then
  docker compose rm -sf demo-2 demo-2-backend
  docker volume rm -f predictive-cyber-defence_demo2_frontend_next 2>/dev/null || true
  echo -e "${GREEN}Demo containers removed.${NC}"
else
  docker compose stop demo-2 demo-2-backend
  echo -e "${GREEN}Demo-2 containers stopped (use 'docker compose start demo-2 demo-2-backend' to resume).${NC}"
fi
echo "Postgres / research stack untouched."
