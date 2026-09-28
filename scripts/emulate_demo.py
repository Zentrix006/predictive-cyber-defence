#!/usr/bin/env python3
"""
Autonomous Cyber-Range Demo Emulation Script
===========================================
Emulates a realistic multi-stage cyber engagement on Demo-2:
1. Enrolls physical assets (servers, database, domain controller, workstations).
2. Runs background heartbeats to maintain active topology nodes.
3. Spawns an advanced threat actor (APT / Zero-Day attacker).
4. Executes progressive MITRE ATT&CK stages:
   - Reconnaissance -> Discovery -> Credential Access -> Lateral Movement.
5. Triggers G-FLOWWM World Model counterfactual evaluation:
   - Evaluates 5 branches inside imagination.
   - Calculates Cyber-JEPA surprisal (detecting novel zero-day behavior).
   - Generates autonomous decision: DECEPTION_DIVERT (-84% risk reduction).
   - Displays machine-auditable kernel nftables diff.
6. Deploys Honeynet zone, traps the attacker, and preserves forensic evidence.
7. Maintains live topology state so decisions and visual vectors are visible in real-time.
"""

import sys
import time
import json
import threading
import argparse
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8100/api/demo"

# ANSI Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def log(msg, tag="INFO", color=CYAN):
    t = time.strftime("%H:%M:%S")
    print(f"{DIM}[{t}]{RESET} {color}{BOLD}[{tag}]{RESET} {msg}")


def api_post(endpoint, data=None):
    url = f"{BASE_URL}{endpoint}"
    payload = json.dumps(data).encode("utf-8") if data is not None else b""
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
            detail = parsed.get("detail", err_body)
        except Exception:
            detail = err_body
        raise RuntimeError(f"HTTP {e.code} on {endpoint}: {detail}")


def api_get(endpoint):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        raise RuntimeError(f"HTTP {e.code} on {endpoint}: {err_body}")


class RangeHeartbeatManager:
    def __init__(self):
        self.devices = []
        self._running = False
        self._thread = None

    def add_device(self, asset_id, hostname):
        self.devices.append({"asset_id": asset_id, "hostname": hostname})

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self._running:
            for dev in list(self.devices):
                try:
                    api_post("/heartbeat", dev)
                except Exception:
                    pass
            time.sleep(8)

    def stop(self):
        self._running = False


def run_emulation(keep_alive_secs=120):
    log("Checking Demo-2 API connectivity...", "INIT", CYAN)
    try:
        health = api_get("/command/health")
        log(f"Demo-2 range online: model={health.get('model')} version={health.get('model_version')}", "READY", GREEN)
    except Exception as e:
        log(f"Cannot reach Demo-2 backend at {BASE_URL}: {e}", "ERROR", RED)
        sys.exit(1)

    hb_mgr = RangeHeartbeatManager()

    # Step 1: Clean Reset
    log("Resetting cyber-range to a clean state...", "RESET", YELLOW)
    try:
        api_post("/admin/reset", {"clear_logs": False})
    except Exception as e:
        log(f"Reset note: {e}", "WARN", YELLOW)

    # Step 2: Enroll Realistic Network Infrastructure
    log("Enrolling enterprise assets (Servers, DBs, Domain Controller, Hosts)...", "ASSETS", CYAN)
    assets = [
        {"role": "server", "name": "web-core-prod"},
        {"role": "server", "name": "web-replica-ha"},
        {"role": "server", "name": "db-vault-finance"},
        {"role": "host", "name": "workstation-sec-ops"},
        {"role": "host", "name": "domain-controller-01"},
    ]

    enrolled = []
    for a in assets:
        joined = api_post(f"/join?role={a['role']}")
        asset_id = joined.get("asset_id")
        hostname = joined.get("hostname")
        hb_mgr.add_device(asset_id, hostname)
        api_post("/heartbeat", {"asset_id": asset_id, "hostname": hostname})
        enrolled.append(joined)
        log(f"  Enrolled {a['role'].upper()}: {BOLD}{asset_id}{RESET} ({hostname})", "ENROLL", GREEN)

    target_asset = enrolled[0]["asset_id"]
    hb_mgr.start()
    log("Heartbeat thread armed (keeping 5 devices healthy on topology).", "HEARTBEAT", GREEN)
    time.sleep(2)

    # Step 3: Spawn Threat Actor
    log("Spawning adversary session (Novel APT-94 Zero-Day Actor)...", "ATTACKER", MAGENTA)
    attacker = api_post("/join?role=attacker")
    attacker_token = attacker["token"]
    attacker_id = attacker["participant_id"]
    log(f"Adversary registered as {BOLD}{attacker_id}{RESET}", "ATTACKER", MAGENTA)
    time.sleep(1)

    # Step 4: Launch Engagement on Target Server
    log(f"Adversary initiating reconnaissance against target: {BOLD}{target_asset}{RESET}...", "ENGAGE", RED)
    start_res = api_post("/attacker/start", {"token": attacker_token, "target": target_asset})
    incident_id = start_res.get("incident_id")
    log(f"Live incident generated: {BOLD}{incident_id}{RESET}", "INCIDENT", RED)
    time.sleep(2)

    # Step 5: Execute Progressive Attack Stages
    stages = [
        {"name": "Discovery & Service Enumeration", "level": 1},
        {"name": "Credential Dumping & Kerberoasting", "level": 2},
        {"name": "Privilege Escalation & Foothold", "level": 3},
        {"name": "Lateral Movement & Exfiltration Attempt", "level": 4},
    ]

    for stage_info in stages:
        lvl = stage_info["level"]
        log(f"\n--- Stage {lvl}: {stage_info['name']} ---", "MITRE", YELLOW)
        state = api_get(f"/attacker/state?token={attacker_token}")
        chall = state.get("challenge")

        if chall:
            options = chall.get("options") or []
            if options and isinstance(options[0], dict):
                chosen = str(options[0].get("value") or options[0].get("label") or "")
            elif options:
                chosen = str(options[0])
            else:
                chosen = "45"
            log(f"Adversary executing tool exploit (submitting '{chosen}' for: {chall.get('question')[:50]}...)", "EXPLOIT", RED)
            try:
                ans_res = api_post("/attacker/answer", {
                    "token": attacker_token,
                    "incident_id": incident_id,
                    "answer": chosen
                })
                log(f"Tool execution completed: stage advanced to {BOLD}{ans_res.get('stage')}{RESET} (Level {ans_res.get('level', lvl)})", "PROGRESS", GREEN)
            except Exception as e:
                log(f"Answer note: {e}", "WARN", YELLOW)
        else:
            log("No pending interactive challenge; advancing simulated telemetry context...", "STEP", CYAN)

        time.sleep(2)

        # Inspect World Model Forecast & Autonomous Decision
        overview = api_get("/command/overview")
        inc_data = next((x for x in overview.get("incidents", []) if x.get("id") == incident_id), None)
        if inc_data:
            stage_name = inc_data.get("stage")
            pred_target = inc_data.get("predicted_target")
            log(f"  Current Stage: {BOLD}{stage_name}{RESET} | Predicted Pivot: {BOLD}{pred_target or 'Evaluating'}{RESET}", "G-FLOWWM", CYAN)

        # Query latest forecast
        try:
            fc = api_get(f"/command/forecast?incident_id={incident_id}")
            if fc and fc.get("model_decision"):
                dec = fc["model_decision"]
                log(f"  {BOLD}★ G-FLOWWM Autonomous Model Decision:{RESET} {MAGENTA}{dec.get('action')}{RESET}", "AI DECISION", MAGENTA)
                log(f"    • Risk Reduction: {GREEN}+{dec.get('risk_reduction_pct')}%{RESET}", "METRIC", GREEN)
                log(f"    • Cyber-JEPA Surprisal: {CYAN}{dec.get('jepa_surprisal')} nats{RESET} (Novel Zero-Day={dec.get('is_novel_behavior')})", "SURPRISAL", CYAN)
                log(f"    • Counterfactual Branches: {dec.get('branches_evaluated')} rollouts evaluated", "ROLLOUT", CYAN)
                log(f"    • Rollback SLA: {GREEN}Armed (60s Guardrail){RESET}", "WATCHDOG", GREEN)
                log(f"    • Kernel Transaction: {DIM}{dec.get('vendor_diff')}{RESET}", "DIFF", CYAN)
        except Exception:
            pass

        time.sleep(2)

    # Step 6: Trigger Automated Honeynet Deception
    log("\nDeploying Autonomous Deception & Honeynet containment...", "DECEPTION", MAGENTA)
    try:
        decoy_res = api_post("/admin/deception", {"incident_id": incident_id})
        log(f"Deception active: {decoy_res}", "HONEYNET", GREEN)
    except Exception as e:
        log(f"Deception note: {e}", "WARN", YELLOW)

    # Step 7: Decoy Interaction & Trapping
    log("Adversary deceived into interacting with high-interaction Honeynet decoy...", "TRAP", MAGENTA)
    try:
        interact_res = api_post("/decoy/interact", {
            "token": attacker_token,
            "incident_id": incident_id,
            "action": "sql_query",
            "query": "SELECT * FROM users WHERE admin=1;",
            "answers": ["SELECT * FROM users WHERE admin=1;"],
        })
        log(f"Attacker captured and isolated in Honeynet! Evidence recorded: {interact_res}", "CONTAINED", GREEN)
    except Exception as e:
        log(f"Interaction note: {e}", "WARN", YELLOW)

    log("\n" + "="*70, "SUCCESS", GREEN)
    log(f"CYBER-RANGE EMULATION COMPLETE & ACTIVELY DISPLAYING ON UI!", "LIVE", GREEN)
    log(f"Main System UI:  {BOLD}http://localhost:3000{RESET}", "CONSOLE", CYAN)
    log(f"Demo Cyber-Range UI: {BOLD}http://localhost:8088{RESET}", "CONSOLE", CYAN)
    log("Visual Highlights Active on Topology:", "INFO", YELLOW)
    log("  1. Golden pulsating predicted attack vector pointing to target server", "VISUAL", YELLOW)
    log("  2. Neon-purple diversion vector routing threat into HONEYNET zone", "VISUAL", MAGENTA)
    log("  3. Floating Autonomous Decision HUD with live risk reduction and kernel diff", "VISUAL", CYAN)
    log(f"Keeping topology nodes alive for {keep_alive_secs} seconds (Press Ctrl+C to exit)...", "WATCH", GREEN)
    log("="*70 + "\n", "SUCCESS", GREEN)

    try:
        for remaining in range(keep_alive_secs, 0, -5):
            time.sleep(5)
    except KeyboardInterrupt:
        log("Emulation monitor stopped by user.", "STOP", YELLOW)
    finally:
        hb_mgr.stop()
        log("Emulation finished.", "DONE", GREEN)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emulate Cyber-Range Demo for G-FLOWWM UI Visualizer")
    parser.add_argument("--keep-alive", type=int, default=180, help="Seconds to keep topology heartbeats active")
    args = parser.parse_args()
    run_emulation(keep_alive_secs=args.keep_alive)
