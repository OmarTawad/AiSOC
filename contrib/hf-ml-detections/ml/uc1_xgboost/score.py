"""Score mapped test-window events and attach per-event Tree SHAP explanations."""

import argparse
from collections import Counter
from hashlib import sha256
import json
import os

import joblib
import numpy as np
import requests
import xgboost as xgb

from features import dataset, event_features, windows
from mapper import map_precinct6
from source import disk_check
from train import ARTIFACTS, HERE
from push import push_batch


def explain(contributions, names, values):
    indices = np.argsort(-np.abs(contributions), kind="stable")[:3]
    notes = []
    for index in indices:
        name = str(names[index])
        if "=" in name:
            description = name if values.get(name.split("=", 1)[0]) == name.split("=", 1)[1] else f"{name} (absent)"
        else:
            description = f"{name}={values.get(name, 0)}"
        notes.append(f"{description} ({contributions[index]:+.3f})")
    return "; ".join(notes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true")
    parser.add_argument("--ingest-url", default="http://127.0.0.1:8081")
    parser.add_argument("--batch-size", type=int, default=250)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 1000:
        parser.error("--batch-size must be between 1 and 1000")
    token = os.environ.get("AISOC_INGEST_TOKEN")
    if args.send and not token:
        parser.error("Set AISOC_INGEST_TOKEN before using --send")

    disk_check()
    report = json.loads((HERE / "metrics.json").read_text())
    threshold = report["models"]["xgboost"]["threshold"]
    rows = dataset()
    features = event_features(rows)
    split, _ = windows(rows, boundaries=report["split_boundaries_epoch"])
    model_path = ARTIFACTS / "model.ubj"
    version = "uc1-xgb-" + sha256(model_path.read_bytes()).hexdigest()[:12]
    encoder = joblib.load(ARTIFACTS / "vectorizer.joblib")
    model = xgb.Booster({"nthread": 2})
    model.load_model(model_path)
    names = encoder.get_feature_names_out()
    families = Counter()
    expected = Counter()
    accepted = rejected = 0
    endpoint = args.ingest_url.rstrip("/") + "/v1/ingest/batch"
    ledger = ARTIFACTS / ("sent.jsonl" if args.send else "preview.jsonl")
    with requests.Session() as session, ledger.open("w", encoding="utf-8") as evidence:
        if token and args.send:
            session.headers["Authorization"] = "Bearer " + token
        for connector_type in ("hf_auth", "hf_network"):
            selected = []
            for i in np.flatnonzero(split == 2):
                mapped = map_precinct6(rows[i][0])
                if mapped and mapped[0] == connector_type:
                    selected.append((i, mapped[1]))
            for start in range(0, len(selected), args.batch_size):
                disk_check()
                chunk = selected[start:start + args.batch_size]
                inputs = [features[i] for i, _ in chunk]
                matrix = xgb.DMatrix(encoder.transform(inputs), nthread=2)
                scores = model.predict(matrix)
                shap_values = model.predict(matrix, pred_contribs=True)[:, :-1]
                events = []
                for item, score, shap_row, values in zip(chunk, scores, shap_values, inputs, strict=True):
                    i, event = item
                    raw = event["raw_event"]
                    raw.update(
                        ml_xgb_score=float(score), ml_xgb_model_version=version,
                        ml_xgb_top_features=explain(shap_row, names, values),
                    )
                    events.append(event)
                    label = rows[i][0]["label_binary"]
                    families[rows[i][3], label] += 1
                    qualifies = float(score) >= threshold
                    if qualifies:
                        expected[label] += 1
                    evidence.write(json.dumps({
                        "external_id": event["external_id"], "label": label, "family": rows[i][3],
                        "score": float(score), "expected": qualifies,
                        "top_features": raw["ml_xgb_top_features"],
                    }) + "\n")
                good, bad = push_batch(session, endpoint, connector_type, events, dry_run=not args.send)
                accepted += good
                rejected += bad
    results = {
        "model_version": version, "threshold": threshold, "events": sum(families.values()),
        "families": {family: {label: n for (key, label), n in families.items() if key == family}
                     for family in sorted({key for key, _ in families})},
        "expected_by_label": dict(expected), "accepted": accepted, "rejected": rejected,
    }
    ledger.with_suffix(".json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results), flush=True)
    if rejected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
