"""Push supported HF telemetry to AiSOC with bounded batches."""

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import time

import pyarrow.parquet as pq
import requests

from mapper import CONNECTOR_ID, MAPPERS

DATA = Path(__file__).resolve().parents[1] / "data"


def push_batch(session, url, connector_type, events, *, dry_run):
    payload = {
        "connector_id": CONNECTOR_ID,
        "connector_type": connector_type,
        "source_format": "json",
        "events": events,
    }
    if dry_run:
        json.dumps(payload, allow_nan=False)
        return 0, 0
    for attempt in range(5):
        response = session.post(url, json=payload, timeout=(5, 30))
        if response.status_code != 429 and not 500 <= response.status_code < 600:
            break
        if attempt < 4:
            retry_after = response.headers.get("Retry-After", "")
            time.sleep(max(2**attempt, min(60, int(retry_after)) if retry_after.isdecimal() else 0))
    if not response.ok:
        raise RuntimeError(f"Ingest HTTP {response.status_code}")
    result = response.json()
    accepted, rejected = result["accepted"], result["rejected"]
    if accepted + rejected != len(events):
        raise RuntimeError("Ingest response counts did not reconcile with batch size")
    print(json.dumps({"connector_type": connector_type, "accepted": accepted, "rejected": rejected,
                      "request_id": result.get("request_id")}), flush=True)
    return accepted, rejected


def send(args, token):
    totals = Counter(selected=0, accepted=0, rejected=0, skipped=0)
    by_type = Counter()
    batches = defaultdict(list)
    endpoint = args.ingest_url.rstrip("/") + "/v1/ingest/batch"
    parquet = pq.ParquetFile(DATA / f"{args.dataset}.parquet")
    with requests.Session() as session:
        if token:
            session.headers["Authorization"] = f"Bearer {token}"

        def flush(connector_type, batch):
            accepted, rejected = push_batch(session, endpoint, connector_type, batch, dry_run=args.dry_run)
            totals["accepted"] += accepted
            totals["rejected"] += rejected
            batch.clear()

        for rows in parquet.iter_batches(batch_size=2048):
            for row in rows.to_pylist():
                if totals["selected"] == args.limit:
                    break
                mapped = MAPPERS[args.dataset](row)
                if mapped is None:
                    totals["skipped"] += 1
                    continue
                connector_type, event = mapped
                batch = batches[connector_type]
                batch.append(event)
                totals["selected"] += 1
                by_type[connector_type] += 1
                if len(batch) >= args.batch_size:
                    flush(connector_type, batch)
            if totals["selected"] == args.limit:
                break
        for connector_type, batch in batches.items():
            if batch:
                flush(connector_type, batch)

    print(json.dumps({"dataset": args.dataset, "dry_run": args.dry_run, **totals, "by_type": by_type}), flush=True)
    return int(bool(totals["rejected"]) or totals["selected"] < args.limit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=MAPPERS, required=True)
    parser.add_argument("--limit", type=int, default=5000, help="Maximum number of mapped events")
    parser.add_argument("--batch-size", type=int, default=250)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--ingest-url", default="http://localhost:8081")
    args = parser.parse_args()
    if args.limit < 1 or args.batch_size < 1:
        parser.error("--limit and --batch-size must be positive")
    token = os.environ.get("AISOC_INGEST_TOKEN")
    if not token and not args.dry_run:
        parser.error("Set AISOC_INGEST_TOKEN or use --dry-run")
    return send(args, token)


if __name__ == "__main__":
    raise SystemExit(main())
