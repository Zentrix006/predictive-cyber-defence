# Data, model, and third-party notices

The Apache-2.0 license in `LICENSE` applies to the original ThreatForage
source code and documentation unless a file states otherwise. It does not
relicense external data, model weights, or dependencies.

## Datasets and captures

- Public datasets must retain their original license and attribution.
- PCAPs, Zeek logs, authentication logs, and topology captures must only be
  collected and distributed with explicit authorization.
- Raw captures and downloaded datasets are excluded from this repository.
- Before training, record source URLs, license, collection scope, SHA-256,
  and campaign provenance in the dataset manifest.

## MITRE ATT&CK

ThreatForage maps behavior to MITRE ATT&CK concepts for defensive research.
MITRE ATT&CK and its contents are maintained by The MITRE Corporation. Review
the current MITRE terms before redistributing ATT&CK-derived content.

## Dependencies

Run the package manager license tools for the applicable environment before
redistribution. Do not remove copyright or license notices from dependencies.

## Model artifacts

Model checkpoints are research artifacts and may have separate dataset or
training-data restrictions. A checkpoint must not be redistributed unless its
training-data provenance and applicable licenses are documented.
