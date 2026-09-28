# Corrected temporal candidate pipeline

This research pipeline isolates corrected preprocessing and temporal training from
the existing 35-feature serving model. Its artifacts are deliberately incompatible
with legacy checkpoints. It does not automatically promote models.

## Input contract

`train_temporal_v2.py` accepts CSV rows that are **already aggregated into 10-second
network segment observations**. Required columns: `capture_id`, `segment_id`,
`timestamp` (UTC), `partition`, `malicious`, `stage`. Partitions are `train`,
`development`, `calibration`, `test`. Every capture belongs to exactly one partition.
Annotate `malicious` as 0 or 1 from evidence, and `stage` as -1 when unlabelled or
benign; otherwise use the first 13 indices of `features.mitre_map.MITRE_STAGES`.
Absence of a label must not be interpreted as absence of malicious activity.

Measured optional columns and units are declared in `features/telemetry_v2.py`.
Unobserved fields remain missing and receive explicit masks. Never fill TTL with
packet lengths or TCP window values with header lengths. Source adapters still
need to produce this contract from raw PCAP/flow/authentication data.

One example uses 12 observed windows (120 seconds) and 6 future windows (60 seconds).
Missing intervals split the sequence. Capture/segment boundaries are respected.
Arrays store observations once; examples are indexed slices, not materialized copies.

## Run inside the backend container

```sh
python /ml-engine/scripts/train_temporal_v2.py --sanity-check --device cpu
python /ml-engine/scripts/train_temporal_v2.py --sanity-check --device cuda
python /ml-engine/scripts/train_temporal_v2.py --input /ml-engine/data/annotated_windows.csv --out-dir /ml-engine/data/temporal_candidate_42 --seed 42
```

An output directory must be new, so experiments cannot overwrite one another.
The checkpoint embeds train-fitted preprocessing, feature order, input hash and
base-branch semantics. `inference.temporal_v2.TemporalPredictor` validates these
before inference and uses the identical transformation. It requires real observed
history; no padding or invented timestamps are used.

## What has and has not been verified

Small-batch overfitting tests optimizer/gradient correctness only. It does not
measure detection accuracy. Full-data training requires independently annotated
captures in all four partitions; the script never fabricates them. Calibration
and test partitions are not used for model selection.

Still required for deployment: source adapters, independent campaign annotations,
baseline comparisons, calibration, campaign-level confidence intervals, novelty
training, analyst review UI, promotion/rollback orchestration and CPU/GPU parity.
Current candidates explicitly carry `promotion_eligible=false`. No claim that the
entire forecasting upgrade is complete or that accuracy has increased is made.
