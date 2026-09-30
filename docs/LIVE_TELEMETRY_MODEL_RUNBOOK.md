# Live telemetry: enablement and model workflow

This runbook separates collection, evidence trust, graph construction, and model training. Enabling the collector does **not** automatically make every observed
record trusted, enroll a device, retrain a checkpoint, or prove that the model is accurate.

## Current local mode

The local Compose environment is enabled with `LIVE_TELEMETRY_ENABLED=true`,
`LIVE_TELEMETRY_PROFILE=lab`, empty approved source/scope lists, and
`FLOW_EXPORT_ENABLED=false`. This is intentionally an inspection-only profile:
mounted Zeek JSON files can be tailed and viewed, but these events are not
admitted to trusted graph windows or production inventory. No untrusted UDP
exporter is exposed for ingest.

1. Start or refresh the backend after changing `.env`:

   ```bash
   docker compose up -d --no-deps backend
   docker compose logs --tail=100 backend
   ```

2. Open **Network → Live Telemetry** in the main console. The page distinguishes
   collector health, unverified observations, trusted graph records, and stale
   sources. Lab files are mounted from `ml-engine/dataset/telemetry-capture`.
3. The authenticated read-only API is under `/api/v1/telemetry`:
   `GET /status`, `GET /sources`, `GET /records?limit=100`, and `GET /graph`.
   The records endpoint is bounded; it is not a durable evidence store.
4. A record may appear in the observation table while the graph remains empty.
   That is expected in lab profile: inspection is allowed, trust promotion is
   not. A graph snapshot is generated only from fresh, trusted records.

## Connect an authorized real sensor

Use only a network and sensor for which the organization has authorized
monitoring. Prefer a dedicated passive SPAN/TAP sensor (Zeek or an approved
NetFlow/IPFIX exporter). Keep the capture plane passive and separate from the
management plane. Do not configure inline blocking from this telemetry feature.

1. Establish the sensor/exporter identity and its fixed source address from
   the network owner. Validate timestamp synchronization, interface/VLAN scope,
   packet-loss counters, sampling settings, and exporter version before use.
2. Configure the collector's environment, replacing the example placeholders
   with the approved sensor identity and monitored CIDRs:

   ```dotenv
   LIVE_TELEMETRY_ENABLED=true
   LIVE_TELEMETRY_PROFILE=production
   LIVE_TELEMETRY_APPROVED_SOURCE_IDS=zeek-prod-east
   LIVE_TELEMETRY_APPROVED_CIDRS=10.20.0.0/16,10.40.0.0/16
   ```

   The source ID must match the record's `sensor_id`, `source_id`, or
   `exporter_id`; where absent, it falls back to the adapter source name. At
   least one flow endpoint must fall inside an approved CIDR. The allowlist is
   a provenance gate, not authentication: isolate the sensor path and enforce
   host/network ACLs as well.
3. For NetFlow/IPFIX only, enable UDP ingest after identifying exporter
   addresses and restricting them at the host/network firewall:

   ```dotenv
   FLOW_EXPORT_ENABLED=true
   FLOW_EXPORT_LISTEN_ADDR=0.0.0.0
   FLOW_EXPORT_LISTEN_PORT=2055
   FLOW_EXPORT_ALLOWED_CIDRS=10.20.1.12/32
   ```

   `FLOW_EXPORT_ALLOWED_CIDRS` filters UDP senders. It is separate from the
   endpoint scopes and source IDs above. Never use `0.0.0.0/0` as an allowlist.
   Ensure the installed optional NetFlow/IPFIX parser is available before
   expecting binary exporter formats; JSON flow records have their own parser.
4. Restart the backend and review `/status` and `/sources`. Confirm the
   expected source counts, `trusted_graph_ready`, freshness, parse errors, and
   buffer utilization. First use a small authorized test VLAN; compare exporter
   counters to collector counts and Zeek/tcpdump loss statistics. Stop and
   investigate if provenance, timestamps, or loss do not reconcile.

Do not place real passwords, SNMP communities, exporter secrets, or customer
addresses in committed files. `.env` is local configuration and must remain
untracked. Keep the approved CIDRs and source identifiers in your secret/config
management process where appropriate.

## How telemetry relates to FLOWWM

The collector normalizes observed records and attaches provenance. Only events
that pass the explicit production-profile, source-allowlist, and endpoint-scope
checks enter the bounded streaming buffer; stale or unverified events remain
visible for inspection but do not become trusted graph state. The stream worker
can expose graph-window snapshots at `/api/v1/telemetry/graph`.

This is a live observability/graph feed, **not online model training**. The
collector currently does not automatically update model weights or guarantee
that a graph snapshot is consumed by the forecasting checkpoint. Use the
existing Model Lab / reproducible ML training pipeline for curated, labeled,
campaign-separated training and evaluation. Before claiming live forecasting
from this feed, an explicit inference adapter must map the graph/window into
the checkpoint's exact feature schema and publish calibrated forecasts with
timestamps, model version, provenance, and explanations. Do not mix unlabeled
production traffic into supervised training; preserve it as separately
governed candidate data, validate/label it, then re-run locked evaluations.

For accuracy claims, report independent campaign/site split metrics (precision,
recall, F1, false-positive rate, stage macro-F1, calibration/ECE, lead time,
and transition prediction error), compare with the same-feature baseline, and
include capture loss, class balance, and provenance coverage. A collector
status of “running” is not evidence of model quality.
