"""Attach frozen Isolation Forest scores and benign-median deviations."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

import joblib
import numpy as np
import requests

from train import deviations

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "cicids"), str(HERE.parents[1] / "connector")]
from evaluation import ARTIFACTS, chronological, load
from source import FEATURES, disk_check
from mapper import map_cicids
from push import push_batch


def explain(row, values):
    indices = np.argsort(-np.abs(values), kind="stable")[:3]
    return "; ".join(f"{FEATURES[i]}={row[FEATURES[i]]:.4g} ({values[i]:+.2f} scaled deviation)" for i in indices)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true")
    parser.add_argument("--ingest-url", default="http://localhost:8081")
    args = parser.parse_args()
    protocol = json.loads((HERE / "metrics.json").read_text())["benign_fpr_protocol"]
    if args.send and not protocol["friday"]["deployment_gate_passed"]:
        raise SystemExit("CIC replay exceeds the frozen Friday benign-FPR deployment gate")
    token = os.environ.get("AISOC_INGEST_TOKEN")
    if args.send and not token:
        raise SystemExit("Set AISOC_INGEST_TOKEN before replay")
    rows, matrix, _, target, _ = load()
    _, _, test = chronological(rows)
    model_path = ARTIFACTS / "uc2.joblib"
    version = "uc2-cic-" + sha256(model_path.read_bytes()).hexdigest()[:12]
    if version != protocol["model_version"]:
        raise ValueError("Model digest differs from the frozen calibration")
    with np.load(ARTIFACTS / "fpr-friday.npz") as archive:
        scores = archive["iforest"]
    records = rows.loc[test].to_dict("records")
    if len(scores) != len(records):
        raise ValueError("Frozen scores differ in size from the Friday cohort")
    values = deviations(joblib.load(model_path), matrix[test])
    accepted = rejected = 0
    endpoint = args.ingest_url.rstrip("/") + "/v1/ingest/batch"
    with requests.Session() as session:
        if args.send:
            session.headers["Authorization"] = "Bearer " + token
        for start in range(0, len(records), 250):
            disk_check()
            batch = []
            for i in range(start, min(start + 250, len(records))):
                _, event = map_cicids(records[i])
                event["raw_event"].update(
                    ml_iforest_score=float(scores[i]), ml_iforest_model_version=version,
                    ml_iforest_top_features=explain(records[i], values[i]),
                )
                batch.append(event)
            good, bad = push_batch(session, endpoint, "hf_network", batch, dry_run=not args.send)
            accepted += good
            rejected += bad
    flags = scores >= protocol["calibration"]["threshold"]
    print(json.dumps({"flows": len(scores), "expected_matches": int(flags.sum()),
                      "benign_fpr": float(flags[target[test] == 0].mean()),
                      "accepted": accepted, "rejected": rejected}), flush=True)
    if rejected:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
