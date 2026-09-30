# ThreatForage — SIH26153 Architecture

**AI-Based Network Attack Forecasting from Network Traffic Data**
**Organization:** National Technical Research Organisation (NTRO) · **Theme:** Blockchain & Cybersecurity

> Submission-length target: approximately 700 words; designed to fit within two pages at 10–11 pt with normal margins.

## 1. Purpose and system boundary

ThreatForage is a software prototype for learning time-dependent network behaviour and presenting forecasted attack risk, likely MITRE ATT&CK progression, and evidence to a defender. It is designed as decision support. The current release does not claim autonomous production network configuration, perfect detection, or measured efficacy against every attack family. Live device changes require a separately authorized, policy-controlled integration and operator approval.

## 2. Architecture

```text
 PCAP/PCAPNG ──> Passive analyzer ───────────────┐
 Flow CSV / Zeek JSON / NetFlow-IPFIX ─> Collector│
 Auth / discovery / topology evidence ──────────┤
                                                  ▼
                                  Validate provenance + normalize
                                                  │
                       time windows + flow features + graph context
                                                  ▼
                             FLOWWM temporal world-model inference
                             state rollout · risk · attack stage
                             belief/novelty · feature explanations
                                                  │
                                                  ▼
                           FastAPI decision-support and evidence APIs
                                                  │
                        Next.js SOC console / Demo-2 isolated range
                                                  │
                      analyst review · evidence · policy-gated actions
```

The **Next.js/TypeScript** main SOC and Demo-2 interfaces consume the **FastAPI** services over REST and WebSockets. The API uses **PostgreSQL** for durable application state, **Redis** for supporting cache/session or event functions, and bounded in-memory buffers for the live telemetry stream. Local evidence bundles are separated by class (`evidence/live` and `evidence/passive`); Prometheus, Grafana and Loki provide operational observability. Docker Compose runs the local stack. Demo-2 has a separate LAN-range API/state path and is visually explicit that its simulated attack events are not production sensor evidence.

## 3. Telemetry and state construction

The passive investigation path accepts authorized PCAP/PCAPNG and supported flow inputs. It extracts packet/header attributes (for example protocol, ports, TCP flags, TTL/hop limit, packet and payload sizes, timing, and fragmentation), aggregates directional flows, identifies scan/retransmission or unusual-volume patterns, and returns a graph/report with feature-level evidence. The live collector accepts Zeek JSON files and JSON or binary NetFlow/IPFIX, normalizes records, tracks freshness, bounded-buffer drops, and parse errors, and exposes source and graph status.

Temporal model inputs are normalized feature vectors grouped into ordered windows; graph context uses endpoint/identity/topology evidence where it is present. Unknown identities remain unknown rather than being fabricated. Dataset preparation and evaluation preserve capture/campaign partition boundaries and record provenance. The system distinguishes missing telemetry from benign activity.

**Trust gate:** collection is disabled by default. The `lab` profile is inspection-only. To enter the trusted graph stream, a record must be fresh and satisfy all configured production checks: explicit production profile, allowlisted sensor/adapter ID, and an endpoint inside an operator-approved CIDR. Out-of-scope and unverified records remain visible for analyst inspection but do not feed trusted graph windows. Neither telemetry nor discovery silently enrolls a device. SPAN/TAP placement, VLANs, exporter addresses, and retention must be approved and configured for each site.

## 4. FLOWWM forecast and explanation

The serving/research stack models temporal network-state evolution rather than treating each flow as an independent classification. FLOWWM uses a temporal Transformer-based state-transition model with multi-step rollout outputs, risk and attack-stage heads, and a latent belief/imagination component for counterfactual branches; additional graph-temporal and novelty components are available in the ML engine. Forecast responses can include a risk timeline, stage probabilities, novelty/uncertainty signals, and driving features/attention-style explanations. The exact checkpoint, feature contract, dataset, and evaluation split must accompany any quoted score.

The model is trained/evaluated offline from versioned telemetry datasets and candidate checkpoints. Training does not automatically promote a candidate to serving. Model Lab exposes measured benchmarks and experiment history; AI Intelligence focuses on runtime readiness and telemetry-to-decision flow. Baselines and stage-aware gates are used to detect regressions. Synthetic Demo-2 campaigns validate workflow integration, not generalization to real enterprise traffic.

## 5. Response, safety, and deployment

Forecasts are presented with their evidence for analyst triage. Deception, incident workflows, response previews, configuration snapshots, and rollback concepts support controlled exercises. Demo-2 attacker actions are confined to its isolated range. A production deployment should first connect a passive, authorized SPAN/TAP or approved flow exporter and management-plane discovery, validate freshness and scope, run in observe-only mode, then require explicit approval and vendor-specific change/rollback controls before any enforcement integration.

**Current boundary:** the software provides collectors, offline PCAP analysis, model inference/training workflows, and demo operations. A live production sensor/exporter and site-specific source/CIDR policy are not supplied by the repository. Forecast quality and mitigation effectiveness remain dataset-, environment-, and checkpoint-dependent and require independent validation before operational use.
