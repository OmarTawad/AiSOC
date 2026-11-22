"""Score and optionally replay the held CIC-IDS2017 day through HTTP ingest."""

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

import numpy as np
import requests
import xgboost as xgb

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "cicids"), str(HERE.parents[1] / "connector")]
from evaluation import ARTIFACTS, chronological, load, save
from source import FEATURES, disk_check
from mapper import map_cicids
from push import push_batch

DEPLOYMENT_CEILING = 0.05


def prepare():
    rows, matrix, _, target, _ = load()
    _, _, test = chronological(rows)
    rows = rows.loc[test].reset_index(drop=True)
    data = xgb.DMatrix(matrix[test], nthread=2)
    path = ARTIFACTS / "uc1b.ubj"
    model = xgb.Booster({"nthread": 2})
    model.load_model(path)
    version = "uc1b-cic-" + sha256(path.read_bytes()).hexdigest()[:12]
    threshold = json.loads((HERE / "metrics.json").read_text())["day_test"]["xgboost"]["threshold"]
    scores = model.predict(data).astype(np.float64)
    flags = scores >= threshold
    labels = rows["attack_label"].tolist()
    report = {
        "model_version": version, "threshold": threshold, "flows": len(rows),
        "benign": int((target[test] == 0).sum()), "expected_matches": int(flags.sum()),
        "expected_by_label": dict(Counter(label for label, hit in zip(labels, flags, strict=True) if hit)),
        "alert_rate": float(flags.mean()),
    }
    return rows, model, data, scores, flags, report


def send(rows, model, matrix, scores, flags, report, args):
    if report["benign"] <= report["flows"] / 2 or report["alert_rate"] > DEPLOYMENT_CEILING:
        raise SystemExit("CIC replay is outside the approved benign-majority alert-volume gate")
    token = os.environ.get("AISOC_INGEST_TOKEN")
    if not token:
        raise SystemExit("Set AISOC_INGEST_TOKEN before replay")
    contributions = model.predict(matrix, pred_contribs=True)[:, :-1]
    records = rows.to_dict("records")
    endpoint = args.ingest_url.rstrip("/") + "/v1/ingest/batch"
    ledger = ARTIFACTS / "uc1b-sent.jsonl"
    accepted = rejected = 0
    with requests.Session() as session, ledger.open("w") as stream:
        session.headers["Authorization"] = "Bearer " + token
        for start in range(0, len(records), args.batch_size):
            disk_check()
            batch = []
            end = min(start + args.batch_size, len(records))
            for i in range(start, end):
                _, event = map_cicids(records[i])
                indices = np.argsort(-np.abs(contributions[i]), kind="stable")[:3]
                explanation = "; ".join(
                    f"{FEATURES[j]}={records[i][FEATURES[j]]:.4g} ({contributions[i,j]:+.3f})"
                    for j in indices
                )
                event["raw_event"].update(
                    ml_xgb_score=float(scores[i]), ml_xgb_model_version=report["model_version"],
                    ml_xgb_top_features=explanation,
                )
                batch.append(event)
            good, bad = push_batch(session, endpoint, "hf_network", batch, dry_run=False)
            accepted += good
            rejected += bad
            if bad:
                raise RuntimeError("Ingest rejected flows during replay")
            for i, event in zip(range(start, end), batch, strict=True):
                stream.write(json.dumps({
                    "external_id": event["external_id"], "label": records[i]["attack_label"],
                    "expected": bool(flags[i]), "score": float(scores[i]),
                }) + "\n")
    return {**report, "accepted": accepted, "rejected": rejected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true")
    parser.add_argument("--ingest-url", default="http://localhost:8081")
    parser.add_argument("--batch-size", type=int, default=250)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 1000:
        parser.error("--batch-size must be between 1 and 1000")
    *details, report = prepare()
    if args.send:
        report = send(*details, report, args)
    save(ARTIFACTS / ("uc1b-sent.json" if args.send else "uc1b-preview.json"), report)
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
