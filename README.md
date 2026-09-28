<h1 align="center">🛡️ ThreatForage</h1>
<h3 align="center">AI-Powered Predictive Cyber Defence • Network Attack Forecasting • World Models</h3>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com/?lines=Predictive+Network+Defence;Temporal+World+Model+Forecasting;Graph+Topology+Intelligence;PCAP+%26+Flow+Investigation;MITRE+ATT%26CK+Mapping;Auditable+Response+Automation&center=true&width=850&height=45&color=58A6FF&vCenter=true" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Problem-SIH26153-58A6FF?style=flat-square" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=flat-square&logo=fastapi" />
  <img src="https://img.shields.io/badge/Next.js-14-black?style=flat-square&logo=nextdotjs" />
  <img src="https://img.shields.io/badge/PyTorch-FLOWWM-EE4C2C?style=flat-square&logo=pytorch" />
  <img src="https://img.shields.io/badge/PostgreSQL-Database-4169E1?style=flat-square&logo=postgresql" />
  <img src="https://img.shields.io/badge/Redis-Cache-DC382D?style=flat-square&logo=redis" />
  <img src="https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat-square&logo=docker" />
  <img src="https://img.shields.io/badge/License-To%20be%20selected-lightgrey?style=flat-square" />
</p>

---

```bash
$ whoami

🛡️ ThreatForage
🔭 Predictive network attack forecasting platform
🧠 Temporal + graph world-model reasoning
📡 PCAP, flow, Zeek and network telemetry ingestion
🎯 MITRE ATT&CK stage forecasting
🧾 Explainable evidence and calibrated uncertainty
⚙️ Simulation-safe, auditable response orchestration
```

## 🚀 What problem does it solve?

Traditional IDS tools classify isolated flows after suspicious activity is visible. ThreatForage models network behaviour as an evolving state:

```text
Network state Sₜ  →  Sₜ₊₁  →  Sₜ₊₂  →  ...  →  Sₜ₊H
```

It learns temporal relationships between flows, packet timing, device identity, VLAN topology, authentication activity, deception telemetry, and attack-stage progression. The result is a defender-oriented forecast rather than a binary packet label.

## 🧩 Core capabilities

```bash
$ ls /features

🌐 Network understanding
▸ Live topology and device inventory
▸ VLAN, zone, interface and relationship context
▸ Identity-aware graph construction
▸ Evidence-backed topology edges

🔬 Passive investigation
▸ PCAP / PCAPNG / flow CSV analysis
▸ Packet and flow feature extraction
▸ Protocol and destination breakdowns
▸ Risk timeline and MITRE progression
▸ Feature attribution and investigation evidence

🧠 FLOWWM intelligence
▸ Temporal network-state forecasting
▸ Graph and lateral-movement reasoning
▸ Calibrated malicious-risk prediction
▸ Novelty and uncertainty boundaries
▸ CPU fallback and CUDA acceleration

🕸️ Deception and response
▸ Controlled honeypot and honeynet workflows
▸ Attacker progression and interaction evidence
▸ Policy decisions with explanations
▸ Containment previews and configuration snapshots
▸ Verification, audit trail and rollback support

📊 Operator experience
▸ SOC command center
▸ Graph Analysis workspace
▸ Passive Analysis workspace
▸ Model Lab and AI Intelligence dashboards
▸ Evidence, logs, files and device context
▸ LAN Demo-2 with QR-based device enrollment
```

## 🏗️ Architecture

```text
                         ┌────────────────────────────┐
                         │ Main SOC / Demo-2 Next.js  │
                         │ Topology • Forecast • PCAP │
                         └──────────────┬─────────────┘
                                        │ REST / WebSocket
                                        ▼
                         ┌────────────────────────────┐
                         │       FastAPI control plane │
                         │ auth • incidents • evidence │
                         │ policy • response • health │
                         └───────┬───────────┬────────┘
                                 │           │
                ┌────────────────┘           └────────────────┐
                ▼                                             ▼
      ┌──────────────────┐                         ┌────────────────────┐
      │ PostgreSQL + Redis│                         │ FLOWWM ML engine   │
      │ state • audit     │                         │ temporal + graph   │
      └──────────────────┘                         │ train • calibrate  │
                                                   │ evaluate • explain │
                                                   └─────────┬──────────┘
                                                             │
             ┌───────────────────────────────────────────────┼─────────────┐
             ▼                                               ▼             ▼
       Zeek / PCAP                                  Demo-2 edge       MinIO evidence
       flow telemetry                               honeynet           object store
```

## 🔬 Intelligence pipeline

```text
[1] Capture PCAP / flows / logs / identity / topology
                      │
                      ▼
[2] Canonical schema + SHA-256 provenance validation
                      │
                      ▼
[3] UTC time-window construction with missingness masks
                      │
                      ▼
[4] Temporal state + identity-aware graph representation
                      │
                      ▼
[5] FLOWWM future-state and attack-stage forecast
                      │
                      ▼
[6] Calibration, novelty and uncertainty assessment
                      │
                      ▼
[7] Explainable decision-support response plan
                      │
                      ▼
[8] Sandbox / policy gate / verification / rollback
```

## ⚙️ Technology stack

```bash
$ tech-stack

🌐 Frontend
▸ Next.js 14 • React • TypeScript
▸ Tailwind CSS • Zustand • Lucide
▸ Interactive topology and SOC workspaces

⚡ Backend
▸ FastAPI • Pydantic • SQLAlchemy 2
▸ PostgreSQL 15 • Redis 7 • Alembic
▸ WebSockets • JWT authentication • audit logging

🤖 AI / ML
▸ PyTorch • temporal Transformer/LSTM branches
▸ Graph-temporal research pipeline
▸ Calibration, focal objectives and quality gates
▸ CPU fallback / NVIDIA CUDA acceleration

📡 Security telemetry
▸ Zeek • tcpdump • PCAP/PCAPNG
▸ NetFlow/IPFIX and flow CSV adapters
▸ DHCP/DNS/authentication telemetry
▸ SNMPv3 • LLDP/CDP • FDB • routing evidence

🧱 Infrastructure
▸ Docker Compose • MinIO • Prometheus • Grafana • Loki
▸ Containerlab enterprise lab topology
▸ FRRouting, VLANs and isolated Demo-2 edge services
```

## 📁 Project structure

```text
predictive-cyber-defence/
├── backend/                 # FastAPI API, services, models and migrations
├── frontend/                # Main SOC console
├── demo-2/                  # LAN cyber-range UI, API, identity and edge
├── ml-engine/               # FLOWWM models, schemas, training and evaluation
├── shared/                  # Shared data models
├── docs/                    # Architecture, API and model documentation
├── config/                  # Prometheus, Loki and Promtail configuration
├── docker-compose.yml       # Full local stack
├── GITHUB_SETUP.md          # Release setup and operational guidance
└── README.md
```

## 🚀 Quick start

```bash
git clone https://github.com/Zentrix006/predictive-cyber-defence.git
cd predictive-cyber-defence
cp .env.example .env
# Replace every placeholder secret in .env
docker compose up -d
docker compose ps
```

### Services

| Service | URL |
|---|---|
| Main SOC console | http://localhost:3000 |
| Demo-2 console | http://localhost:8088 |
| Backend API | http://localhost:8000 |
| Swagger docs | http://localhost:8000/docs |
| Grafana | http://localhost:3001 |
| Prometheus | http://localhost:9090 |
| MinIO console | http://localhost:9001 |

Full GPU/CPU training, LAN QR configuration, security policy, and troubleshooting are documented in [`GITHUB_SETUP.md`](GITHUB_SETUP.md).

## 🧪 Training and evaluation

Place an annotated telemetry-v2 CSV at `ml-engine/data/annotated_windows.csv`:

```bash
docker compose --profile training run --rm train \
  python scripts/train_temporal_v2.py \
  --input /ml-engine/data/annotated_windows.csv \
  --out-dir /ml-engine/data/candidate_run \
  --device auto
```

The pipeline records dataset quality, partition support, loss components, calibration temperatures, and training history. It does not automatically promote a checkpoint.

Evaluation remains campaign-disjoint and evidence-backed. Synthetic topology must not be used to claim real-world graph accuracy.

## 📡 API examples

```text
GET  /health/ready
GET  /api/v1/incidents
GET  /api/v1/topology/world-model/snapshot
GET  /api/v1/topology/world-model/dynamics
POST /api/v1/analyze/upload
GET  /api/v1/defence/actions
POST /api/v1/defence/containment/preview
POST /api/v1/defence/containment/execute
POST /api/v1/defence/actions/{id}/rollback
```

## 🛡️ Safety and responsible use

```bash
$ cat safety.txt

✓ Run only on networks and captures you are authorized to monitor.
✓ Keep DEV_AUTH_BYPASS=false outside isolated tests.
✓ Keep raw PCAPs, credentials and production telemetry out of Git.
✓ Treat model outputs as decision support until independently validated.
✓ Preserve evidence and configuration snapshots before response actions.
✓ Use sandbox verification and rollback before connecting real controllers.
✓ Keep switch/router command execution advisory until vendor workflows are verified.
```

## 🎯 Roadmap

```bash
$ roadmap

[x] Temporal FLOWWM forecasting baseline
[x] PCAP / flow passive analysis
[x] Graph Analysis and topology observability
[x] Evidence, logs, files and device context
[x] Demo-2 LAN enrollment and deception range
[x] Calibration and locked campaign evaluation
[ ] Identity-rich multi-stage enterprise campaign corpus
[ ] Open-set novelty benchmark across unseen attack families
[ ] Outcome-based automated response policy training
[ ] Vendor-verified switch/router advisory templates
[ ] Shadow-mode SIEM and SOAR integrations
[ ] Production Kubernetes deployment profile
```

## 🤝 Contributing

```text
1. Fork the repository.
2. Create a focused feature branch.
3. Add tests and update the relevant documentation.
4. Run the Docker build and applicable model/data checks.
5. Open a pull request with validation evidence.
```

## 📚 Acknowledgements

MITRE ATT&CK • Zeek • PyTorch • FastAPI • PostgreSQL • Redis • Docker • FRRouting • the open cybersecurity research community

## 📜 License

No license has been selected yet. Add the project’s approved license before accepting external contributions or redistributing the repository.

<p align="center"><b>Forecast earlier • Explain clearly • Respond safely</b></p>
<p align="center">Built for authorized cyber defence research and responsible security engineering.</p>
