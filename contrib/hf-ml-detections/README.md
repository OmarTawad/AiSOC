# Hugging Face ML detections for AiSOC

This contribution will ingest sampled Hugging Face security telemetry and evaluate
three approaches: supervised XGBoost with SHAP, unsupervised Isolation Forest,
and per-user login z-scores compared with AiSOC UEBA.

See [AiSOC integration notes](docs/aisoc-notes.md) for the Day 1 ingest and
detection controls and [Codespaces workarounds](docs/codespaces-fixes.md) for
local stack setup. Dataset sampling and push ingestion are implemented.
Model evaluation is pending.

## Sample and push

From this directory, install the dependencies into a virtual environment,
then run the sampler for each dataset. The samples and their label counts
are written to the ignored `data/` directory.

```bash
python connector/sample.py --dataset precinct6
python connector/sample.py --dataset advanced-siem
python connector/push.py --dataset precinct6 --limit 5000 --dry-run
python connector/push.py --dataset advanced-siem --limit 5000 --dry-run
```

With the approved HF classes deployed, export `AISOC_INGEST_TOKEN` from
`make -s ingest-token ARGS=--quiet` at the repository root. Remove
`--dry-run` to send to the ingest worker. The CLI batches each connector
type separately and prints accepted and rejected counts. The limit applies
to mapped rows. See [dataset scope and mappings](docs/datasets.md).

## UC1 — Supervised Precinct6 scoring

See [methods](docs/methods.md) for the input allowlist and
[evaluation](docs/evaluation.md) for chronological and organization holdouts,
baseline comparisons, SHAP, and live-rule evidence.
