<h1 align="center">🛡️ ThreatForage</h1>
<h3 align="center">AI-Based Network Attack Forecasting from Network Traffic Data</h3>

<p align="center">SIH 2026 · Problem Statement SIH26153 · National Technical Research Organisation (NTRO)</p>

<p align="center">
  <a href="https://github.com/Zentrix006/predictive-cyber-defence">Source code on GitHub</a> ·
  <a href="docs/SIH26153_ARCHITECTURE.md">2-page architecture</a> ·
  <a href="docs/SIH26153_DEMO_VIDEO.md">2-minute demo script</a> ·
  <a href="docs/SIH26153_TECHNICAL_PRESENTATION.md">5-slide technical presentation</a>
</p>

---

ThreatForage is a research prototype for temporal network-risk forecasting and analyst decision support. It combines flow/packet analysis, temporal network-state modelling, MITRE ATT&CK stage mapping, investigation evidence, and a controlled LAN demonstration range.

It is not a replacement for an IDS, an incident-response team, or a validated production change-control system. Model forecasts are advisory; do not connect automated containment to production devices without independent evaluation, operator approval, and a tested rollback path.

## What is included

- **FLOWWM forecasting:** learns from time-windowed traffic-state features and predicts future risk/stage trajectories with model explanations and uncertainty/novelty indicators.
- **Passive Analysis:** accepts PCAP/PCAPNG for bounded packet/header, flow, graph, and behaviour analysis; exports reports and supports preserving investigation evidence.
- **Live Telemetry:** reads Zeek JSON and NetFlow/IPFIX through a supervised collector. It reports provenance and only admits fresh, explicitly allowlisted production-source/CIDR records into trusted graph windows. The default lab profile is inspection-only.
- **SOC workspaces:** Command Center, topology, attack forecast, threat actors, deception, forensics, infrastructure, graph analysis, Model Lab, AI Intelligence, and telemetry.
- **Demo-2:** an isolated LAN cyber-range with QR-based device roles, live Demo-2 heartbeats/events, attacker progression, honeynet/deception, and its own topology. Demo-2 telemetry is labelled separately from production packet telemetry.

## Technology

| Layer | Components |
|---|---|
| UI | Next.js 14, React, TypeScript, Tailwind CSS, Zustand |
| API | FastAPI, Pydantic, SQLAlchemy, WebSockets |
| Data | PostgreSQL, Redis; local evidence paths; MinIO service in Compose |
| ML | PyTorch FLOWWM temporal Transformer/state-transition model, belief rollouts, stage/risk/novelty components; CPU fallback and CUDA where available |
| Telemetry/ops | Zeek, PCAP/PCAPNG, flow CSV, NetFlow/IPFIX, Prometheus, Grafana, Loki, Docker Compose |

## Quick start

### Requirements

- Docker Engine and Docker Compose v2
- 8 GB RAM minimum; 16 GB recommended for a full local stack
- Linux recommended for WLAN/LAN Demo-2 and Containerlab workflows
- NVIDIA Container Toolkit only when using an NVIDIA GPU; the inference/training code also supports CPU

### Start the stack

```bash
git clone https://github.com/Zentrix006/predictive-cyber-defence.git
cd predictive-cyber-defence
cp .env.example .env
```

Edit `.env` before starting: replace the PostgreSQL, MinIO, and JWT placeholders and set an operator username/password hash. Keep `DEV_AUTH_BYPASS=false`. Then run:

```bash
docker compose up -d --build
docker compose ps
curl http://localhost:8000/health/ready
```

The readiness response should report database and Redis as `ok`. The main frontend and Demo-2 use development servers inside Compose, which is suitable for a local demonstration, not a hardened public deployment.

### Local service URLs

| Service | URL |
|---|---|
| Main SOC console | <http://localhost:3000> |
| Demo-2 LAN range | <http://localhost:8088> |
| Main API readiness | <http://localhost:8000/health/ready> |
| Main API / Swagger | <http://localhost:8000/api/v1/docs> |
| Demo-2 API | <http://localhost:8100/api/demo/command/health> |
| Grafana | <http://localhost:3001> (localhost-bound) |
| Prometheus | <http://localhost:9090> (localhost-bound) |
| MinIO console | <http://localhost:9001> (localhost-bound) |

To stop services without deleting persistent data, run `docker compose down`. Do not add `-v` unless you intentionally want to delete the local database and service volumes.

### LAN Demo-2

For other devices on the same authorized Wi-Fi/LAN to join, connect the host to `wlan0`, then start/restart Demo-2 using:

```bash
./start-demo.sh
```

The script obtains the current IPv4 address from `wlan0` and configures the QR/join URL for that address. If this machine uses a different interface, update the script/config deliberately rather than publishing a localhost QR. Do not expose the demo range to an untrusted network.

## Live telemetry setup and trust boundary

The collector is **disabled by default**. Production visibility requires an authorized Zeek/SPAN/TAP feed or approved flow exporter. Separate the management plane from passive data capture: management reaches network devices for authenticated read-only discovery; the capture plane receives mirrored server/device-VLAN traffic and must not be used to configure devices.

Before any records become trusted graph input, configure the source profile, source ID allowlist, and protected CIDRs in `.env`:

```env
LIVE_TELEMETRY_ENABLED=true
LIVE_TELEMETRY_PROFILE=production
LIVE_TELEMETRY_APPROVED_SOURCE_IDS=zeek,netflow_ipfix
LIVE_TELEMETRY_APPROVED_CIDRS=<authorized-server-or-device-vlan-cidrs>
FLOW_EXPORT_ENABLED=true
FLOW_EXPORT_ALLOWED_CIDRS=<authorized-exporter-address-cidrs>
```

Replace the examples with values approved by the network owner. Lab-file records and unscoped observations remain inspectable but do not enter trusted graph windows. This collector does not automatically enroll devices or configure switches/routers. The collector-to-model boundary, enablement steps, API checks, production allowlists, and honest model-training limitations are documented in the [Live Telemetry and FLOWWM Runbook](docs/LIVE_TELEMETRY_MODEL_RUNBOOK.md). See also the [architecture and deployment notes](docs/SIH26153_ARCHITECTURE.md). The workspace-level `work status.md` tracks engineering progress but is maintained outside this published project tree.

## Data, evaluation, and limitations

The project contains ingestion, normalization, temporal feature construction, training/evaluation scripts, and public-dataset support. A model score is meaningful only with the dataset/version, campaign-disjoint split, class/stage support, calibration, and baseline reported alongside it. Synthetic Demo-2 traffic demonstrates application behaviour; it is not evidence of real-world generalization or production mitigation efficacy. Do not claim 100% accuracy.

Raw captures may contain personal or sensitive data. Use only authorized telemetry, minimize retention, restrict evidence access, and do not commit PCAPs, credentials, production logs, model checkpoints, or runtime databases to source control.

## Submission package

- [Source code repository](https://github.com/Zentrix006/predictive-cyber-defence)
- [Architecture document — max 2 pages](docs/SIH26153_ARCHITECTURE.md)
- [Demo video plan and timed narration — max 2 minutes](docs/SIH26153_DEMO_VIDEO.md)
- [Technical presentation — exactly 5 proposed slides](docs/SIH26153_TECHNICAL_PRESENTATION.md)

The video and slides are prepared as content/storyboards; capture the actual UI and record the final media from the running authorized environment before submission. Never present simulated Demo-2 activity as a real-world intrusion capture.

## License

The published GitHub release is licensed under Apache-2.0; see the repository [LICENSE](https://github.com/Zentrix006/predictive-cyber-defence/blob/master/LICENSE), [NOTICE](https://github.com/Zentrix006/predictive-cyber-defence/blob/master/NOTICE), and data/dependency terms before redistributing datasets or model artifacts.
