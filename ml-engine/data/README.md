# ML data and checkpoints

Large captures, raw public datasets, runtime telemetry, and model checkpoints are intentionally not committed to the GitHub source package.

For training, place an annotated telemetry-v2 CSV at `ml-engine/data/annotated_windows.csv` and use the training command documented in `GITHUB_SETUP.md`.

Keep raw PCAPs and downloaded datasets outside Git. Record SHA-256 hashes and provenance in a campaign manifest before using them for training.
