# Hugging Face ML detections for AiSOC

This contribution will ingest sampled Hugging Face security telemetry and evaluate
three approaches: supervised XGBoost with SHAP, unsupervised Isolation Forest,
and per-user login z-scores compared with AiSOC UEBA.

See [AiSOC integration notes](docs/aisoc-notes.md) for the Day 1 ingest and
detection spike and [Codespaces workarounds](docs/codespaces-fixes.md) for local
stack setup. Connector implementation, model evaluation, and results are pending.
