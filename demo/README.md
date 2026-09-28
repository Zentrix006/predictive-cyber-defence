# Predictive Cyber-Defence — Live Demo

A live cyber-range where **the network is discovered, not pre-seeded**. Nothing
is created ahead of time: devices appear as people open the range, and the
THREAT ZONE / CONTAINED / HONEYNET segments plus decoy nodes are minted only as
a consequence of incidents and the real world-model forecast.

## Architecture at a glance

- **Empty start.** No assets, infrastructure nodes or scenarios are pre-created
  (`config/demo.yaml` only carries the safe challenge bank + decoy questions +
  admin PIN). An idempotent `_migrations` step (`app/core/db.py`) extends the
  kept-alive `demo` schema on boot.
- **Device discovery.** `POST /join?role=server|host|client|other` registers the
  browser as a physical device, returns `asset_id` + `page_endpoint`, and
  redirects to `/device/{asset_id}`. That page heartbeats every 4 s; a device
  that stops heartbeating for `DEMO_HEARTBEAT_TIMEOUT` (20 s) is marked offline.
  `attacker` and `observer` are participants, not devices.
- **Live targets only.** `POST /attacker/start` accepts a target from the set of
  *connected* (registered + recently heartbeating) physical devices — anything
  else is rejected with 409. Attacker/observer sees the live device list.
- **Predictive deception.** Answering a safe challenge advances the simulation
  (level 1–6 → kill-chain stage → deterministic risk). The demo runs the real
  `flow-wm-v3.0.0` world model on a feature ramp; only when a prediction exists
  (`predicted_target_id`) is a decoy twin `{target}-DECOY` staged and the
  incident set to `deception`. The decoy twin of a predicted target is never
  pre-staged — `admin/deception` returns 409 before a prediction exists.
- **Honeypot farm & steering.** Two server-shaped honeypot replicas
  (`replica-*`, role `decoy`, asset_type `application-server`) are poised in the
  backend the moment an engagement opens — still zero before any device joins,
  removed on reset. When a node is infected the segment route to the other
  *real* production servers is severed (`lateral_targets`); the only
  server-class hosts the attacker can reach are the honeypot replicas, so their
  lateral movement is funneled into the deception farm while the production
  servers stay untouched. The attacker UI stays fully realistic — no
  steering / deception labels.
- **Attacker intel capture.** Every handshake answer the attacker submits
  (`attacker_intel` evidence) and every touchpoint inside a honeypot
  (`attacker_telemetry` with browser, platform, screen, language, timing and
  per-question answers) is collected and stored with the device context that
  produced it — attribution data for the defender, never exposed to the attacker.
- **Dynamic zones.** `build_topology` derives the graph purely from live state:
  base segments `INTERNET → FIREWALL → CORE-SWITCH`, plus `THREAT-ZONE`,
  `CONTAINED` and `HONEYNET` nodes minted from incident state (compromise →
  containment, predicted target → decoy → deception edge).
- **Isolation & reset.** All demo state lives in the `demo` schema (research data
  untouched). `admin/reset` closes any live incident, deletes decoys, and resets
  devices to HEALTHY on `lan`; `clear_logs=true` additionally wipes events /
  predictions / evidence. Devices stay registered across resets.
- **Multi-actor incidents.** Each attacker runs their *own* engagement — one live
  incident per attacker participant (`attacker/start` only rejects (409) if *that
  attacker* already has a live one). `overview.incidents[]`, `overview.actors[]`
  and `attacker/state` are per-actor; the primary `incident`/`forecast` keys stay
  as the single-attacker compatibility surface. Concurrent attackers are
  discovered through real joins — nothing is pre-seeded.
- **HA service continuity.** Server replicas serve a shared domain
  `app.payg.in` (`config.py → DEMO_DOMAIN`). When a server origin is contained
  (or abandoned), `_service_failover` reroutes traffic to the next continuity
  replica — a healthy real server, or (when none is left) a server-shaped
  honeypot replica, or a minted mirror of the lost server — and emits
  `traffic_rerouted`. The shared domain **never falls** at any point in the demo
  (`service.status`, with `service.continuity.real_serving` / `.honeypot`).
- **Attacker pivot.** At level ≥ 3 the attacker can hop from the current origin
  to any host surfaced by the network sweep (`/attacker/pivot-options` →
  `/attacker/pivot`). Production servers are walled off (pivot → 409 "route
  segmented"); the sweep leads straight to the honeypot replicas. The abandoned
  origin is contained (accumulated in `contained_asset_ids`), any decoy is
  retired, a fresh handshake is minted, and `pivot_count` tracks hops.
- **Convergence.** When two live trajectories predict the same node, their risk
  is fused (`risk_policy.fusion_risk`, 1 − Π(1 − p)) and surfaced in
  `overview.convergence[]` / `command/threats` as `converging`. Actor snapshots,
  trajectories (`threat_actors` / `threat_trajectories`) and
  `actor_correlations` rows are persisted in the `demo` schema (`/threat/actors`,
  `/threat/actors/{id}`, `/threat/trajectories/{actor_id}`).

## Run it

```bash
./start-demo.sh

# Manual alternative: set DEMO_HOST_IP to the active wlan0 IPv4 address first.
# DEMO_HOST_IP=192.168.1.10 docker compose up -d demo-backend demo-frontend
# API:    http://<presenter-host>:8100/api/demo (browser clients derive this host dynamically)
# UI:     http://<LAN_IP>:8088
# Admin:  admin.tsx -> DEMO_ADMIN_PIN from .env (header x-demo-admin-pin)
```

## Demo flow

1. Presenter opens the **Command Center** on the projector — empty range,
   four base segments. Optionally open the Admin tab and confirm
   `/admin/devices` + `/admin/health` (`model_version: flow-wm-v3.0.0`).
2. Audience members scan the QR / open `/join` and pick **Server / Host /
   Client / Other** — each lands on `/device/{asset}` which begins heartbeating;
   devices stream onto the Command Center as they connect.
3. Attacker joins, sees the **live connected targets**, picks one, answers the
   safe challenge. The world model forecasts the next target (terminal →
   kill-chain bridge picks the most-likely connected device).
4. Command Center shows risk + forecast; on high/critical risk the origin is
   contained into THREAT ZONE and the predicted target's decoy twin is staged
   in HONEYNET with a deception edge. The attacker's console stays realistic
   ("Open service console" → `/target`), where the honeypot quietly captures
   browser/platform/screen/language, handshake answers and timing. If an origin
   server is contained, traffic fails over to a healthy replica or a honeypot
   replica (`traffic_rerouted`) — the domain **never falls**.
5. A second attacker joins and opens their own engagement — the Command Center
   tracks every trajectory separately; when two trajectories predict the same
   node its risk is **fused** (convergence, purple ring + panel). At level ≥ 3
   the attacker runs a **network sweep** and hops; the real production servers
   show as segmented/unreachable and the sweep feeds the honeypot replicas
   (which look like ordinary `server` hosts).
6. Presenter uses **Reset / Clear** (admin) — decoys vanish, devices return to
   HEALTHY, incidents close.

## Verification snapshot (all passing)

- `py_compile` clean on all demo backend modules; `tsc --noEmit` clean.
- `/command/overview` starts at `assets: 0`, `threats: 0`, `decoys: 0`.
- 4 devices register + heartbeat → `/assets` lists them; attacker `options`
  shows the connected list.
- Correct deep answer (level ≥ 5) → `lateral_movement`, origin `contained`
  (zone `threat`), real-model forecast (`flow-wm-v3.0.0`, genuine confidence),
  decoy `{target}-DECOY` created plus the honeypot replica farm, topology nodes
  `INTERNET FIREWALL CORE-SWITCH THREAT-ZONE CONTAINED HONEYNET ...` with a
  `kind: deception` edge, and a `traffic_rerouted` event when the contained
  origin is a server replica.
- Honeypot intel captured: `attacker_intel` (per handshake, with device context)
  and `attacker_telemetry` (per `/target` session, with screen/language/timing)
  rows persist in `/forensics/evidence`.
- Lateral movement stays clean: `attacker/pivot-options` lists honeypot
  `server` replicas + endpoints; pivoting (or starting) against a real
  production server is rejected — the route is segmented.
- Multi-actor E2E (phase 2): two attackers run concurrent incidents
  (`overview.incidents` = 2, tracked per actor); a second server replica keeps
  `service.status = serving` after one is contained; both actors converge on the
  same predicted target (identical scenario → identical model output) with fused
  risk > the individual risks; pivot moves the origin to a fresh host, bumps
  `pivot_count` and appends the foothold to the actor's trajectory
  (`/threat/trajectories/{actor_id}`).
- `admin/reset` → 0 decoys, devices healthy, incident `null`; zones gone.
- `attacker/start` on an unknown asset → 409.
- `admin/deception` before any prediction → 409.
- `admin/health` → `model_version: flow-wm-v3.0.0`.

## Demoing against a real second screen

Open `/join` on a second machine/browser so the device's real hostname and
browser fingerprint are recorded (`device_context`), then keep tabs open — the
range reflects live presence.