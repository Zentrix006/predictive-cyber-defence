# GitHub release setup

## Requirements

- Docker Engine 24+ and Docker Compose v2
- 8 GB RAM minimum; 16 GB recommended
- NVIDIA Container Toolkit only when GPU training/inference is required
- Linux is recommended for LAN Demo-2 edge services

## First run

```bash
cp .env.example .env
# Replace all placeholder secrets before starting.
docker compose up -d
docker compose ps
```

Open the main console at `http://localhost:3000`, Demo-2 at `http://localhost:8088`, API docs at `http://localhost:8000/docs`, and Grafana at `http://localhost:3001`.

## GPU or CPU training

Place an annotated telemetry-v2 CSV at `ml-engine/data/annotated_windows.csv`, then run:

```bash
docker compose --profile training run --rm train \
  python scripts/train_temporal_v2.py \
  --input /ml-engine/data/annotated_windows.csv \
  --out-dir /ml-engine/data/candidate_run \
  --device auto
```

CUDA is preferred and CPU is supported as fallback. Training writes a new candidate directory, quality metadata, calibration temperatures, and history. It never promotes or overwrites the serving model automatically.

## LAN Demo-2

Set `DEMO_HOST_IP` to the host's reachable WLAN address before starting the stack. The join URL and QR code then point to that address instead of localhost. Demo-2 is intended for an isolated, authorized demonstration network.

## Security and data policy

- Never commit `.env`, credentials, JWT secrets, PCAPs, production captures, or runtime databases.
- Keep `DEV_AUTH_BYPASS=false` outside isolated tests.
- The response engine is simulation/audit-first; review containment settings before connecting a real network controller.
- Use only authorized traffic captures and lab attack campaigns.

## Useful commands

```bash
docker compose ps
docker compose logs -f backend frontend demo-2
docker compose down
```

Architecture, API contracts, model evaluation, and telemetry schema are documented under `docs/` and `ml-engine/TELEMETRY_V2.md`.
