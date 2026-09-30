# ThreatForage — 5-Slide Technical Presentation

**SIH26153 · AI-Based Network Attack Forecasting from Network Traffic Data**
**Organization:** NTRO · **Theme:** Blockchain & Cybersecurity
**Source:** <https://github.com/Zentrix006/predictive-cyber-defence>

Exactly five slides are outlined below. Do not add a sixth title or thank-you slide. Keep citations/source notes in slide footers.

## Slide 1 — From detection to forecasting

**Title:** ThreatForage: Forecasting network attack progression

- Traditional flow-by-flow alerts often describe activity after it appears.
- ThreatForage represents traffic as an evolving sequence of network states.
- Objective: estimate near-future infiltration risk and likely attack stage, with evidence for a defender.
- Output is analyst decision support—not perfect prediction or autonomous production defence.

**Visual:** `Sₜ → Sₜ₊₁ → … → Sₜ₊ₖ`, observed telemetry on the left and a risk/stage timeline on the right.

**Speaker note:** “Our question is not only whether a flow looks suspicious, but how observed behaviour may evolve over the next windows—and what evidence supports that forecast.”

## Slide 2 — Evidence-to-state pipeline

**Title:** Two telemetry paths, one evidence-aware state model

```text
PCAP / PCAPNG ─> packet + flow investigation ─┐
Zeek / NetFlow / IPFIX ─> live normalization ─┼─> ordered windows + graph context
Identity / topology evidence ────────────────┘
```

- Packet path: headers, flags, timing, sizes, fragments, flow summaries, and behaviour findings.
- Live path: bounded collector, freshness/drop/parse counters, explicit source provenance.
- Unknown identity remains unknown; missing data is not treated as benign.
- Lab data is inspection-only. Trusted graph input requires production profile, allowlisted source, and approved CIDR.

**Visual:** three input cards through a provenance gate into “temporal state + graph context.”

**Speaker note:** “The offline investigation and live sensor paths are separate. Provenance checks prevent stale lab artifacts from silently becoming trusted production graph input.”

## Slide 3 — FLOWWM world-model forecast

**Title:** Learn transitions, roll forward, explain the result

- Temporal Transformer-based state-transition model with multi-step rollout.
- Risk and stage predictions map supported labels to MITRE ATT&CK.
- Latent belief/imagination branches explore alternate futures; novelty and uncertainty signals flag unfamiliar observations.
- Forecasts can expose a risk timeline, stage probabilities, and driving-feature evidence.
- CPU execution is supported; CUDA is used when available and configured.

**Visual:** observed windows → FLOWWM → multi-step risk ribbon + stage labels + top contributing features.

**Speaker note:** “The world-model framing produces a future trajectory, not only a per-flow label. Review each forecast with its feature evidence, calibration, and uncertainty.”

## Slide 4 — Evaluation that can be trusted

**Title:** Measure temporal value and generalization—not one accuracy number

Show results from the **same current locked evaluation report** for:

- Binary risk: precision, recall, F1, false-positive rate, calibration/ECE.
- Stage forecasting: macro-F1 and independent test support by stage.
- Dynamics: next-state error versus persistence baseline; lead time where labels support it.
- Baseline: logistic regression on the same inputs and split.
- Novelty: held-out attack-family evaluation without campaign/family leakage.

**Evidence callout:** “Results are checkpoint- and dataset-specific. Report split, provenance, and sample support. Never fill an unmeasured result with an estimate.”

**Visual:** one measured table from Model Lab/locked benchmark. Display “not measured” when a gate lacks adequate support.

**Speaker note:** “A high binary score alone does not establish stage awareness, calibration, or unseen-attack performance. We show the full scorecard and its limits.”

## Slide 5 — Defender workflow and deployment boundary

**Title:** Explain → investigate → approve → verify

1. Observe an authorized passive feed or upload a capture.
2. Inspect the forecast, stage, feature evidence, and topology context.
3. Preserve PCAP analysis/evidence and review a response preview.
4. Exercise attacker progression and deception in isolated Demo-2.
5. In real networks: start observe-only; require site approval, vendor-specific policy, operator confirmation, audit, and rollback before enforcement.

**Visual:** main SOC beside Demo-2 with a prominent **SIMULATION** label; a four-step guarded-response path below.

**Speaker note:** “The demo shows a defender workflow while keeping simulation separate from production telemetry. Real deployment requires an authorized sensor/exporter and independently validated change controls.”

## Presenter checklist

- Replace Slide 4 with a screenshot/table from the exact submitted checkpoint and locked evaluation run.
- Show dataset version, split, sample support, baseline, and missing-stage disclosures.
- Capture screenshots from the running app; mask identities, IPs, credentials, and customer information.
- Keep the presentation at five slides and preserve the distinction between simulated and real telemetry.
