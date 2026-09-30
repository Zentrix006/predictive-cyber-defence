# ThreatForage — 2-Minute Demo Video Plan

**Maximum runtime:** 02:00. This is a storyboard and narration, not a rendered video. Record the actual application from an authorized local environment. Never present Demo-2 activity as a real external attacker or production sensor capture.

| Time | Screen / shot | Narration |
|---|---|---|
| 00:00–00:08 | Title: ThreatForage · SIH26153 · “Forecast network attack progression” | “ThreatForage explores how AI can forecast evolving network attack behaviour from traffic telemetry.” |
| 00:08–00:22 | Main SOC Command Center; show topology, forecast area, and timeline. | “Rather than classify each flow in isolation, the system organizes observations into time windows and network context. The console brings forecasts, topology, and investigation evidence into one analyst workflow.” |
| 00:22–00:42 | Passive Analysis; select a sanitized PCAP/PCAPNG approved for this demo. Show packet/flow summaries and graph. | “For offline investigation, Passive Analysis extracts packet headers and directional-flow behaviour, then highlights patterns such as scans, retransmissions, and unusual traffic volume. An analyst can inspect the underlying flows instead of relying on a score alone.” |
| 00:42–00:58 | Open a finding; show packet/flow detail, explanation, and report/evidence export controls. | “Findings remain tied to capture evidence. Reports can be exported and captures preserved separately from live evidence, with provenance for later review.” |
| 00:58–01:16 | Attack Forecast and AI Intelligence; show a forecast and runtime readiness. | “FLOWWM rolls the observed state forward to estimate near-future risk and likely attack progression. Feature evidence and uncertainty help an analyst decide what to investigate. Model Lab reports evaluation; AI Intelligence reports runtime readiness.” |
| 01:16–01:32 | Model Lab; show current checkpoint, baseline, and evaluation support. Do not alter values. | “We compare against a baseline and report stage-aware metrics, calibration, and dataset support. Results apply to the displayed checkpoint and split; they do not guarantee performance on every enterprise network.” |
| 01:32–01:50 | Demo-2; show controlled-range banner, topology, and a pre-recorded isolated scenario/event timeline. | “Demo-2 is a separate, controlled LAN range. Its devices, attacker progression, and honeynet interactions demonstrate the workflow without being represented as production telemetry.” |
| 01:50–02:00 | Return to Command Center; end card with source URL and deployment boundary. | “A real deployment starts with an authorized passive sensor, verified source and VLAN scope, and operator approval with rollback. ThreatForage: forecast earlier, explain clearly, respond safely.” |

## Recording checklist

- Target 1920×1080 at 30 fps, legible browser zoom (90–100%), steady cursor movement, and clear narration.
- Use the running main console and Demo-2; avoid showing credentials, personal device names, real public IPs, or unapproved captures.
- Choose a sanitized PCAP and a stable completed Demo-2 scenario before recording. If no authorized production sensor is connected, show the inspection-only provenance state or omit live telemetry; do not imply a production feed exists.
- Display **CONTROLLED DEMO / SIMULATED ACTIVITY** during Demo-2 footage.
- Verify the final recording is at most 02:00. Match every displayed benchmark value to the exact evaluation report being submitted.
