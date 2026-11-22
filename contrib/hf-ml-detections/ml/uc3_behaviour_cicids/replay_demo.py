"""Replay label-free frozen summaries and reconcile them to the local ledger."""

import argparse
from collections import Counter
import json
import subprocess
import sys
import time

import requests

from delivery import HERE, OUTPUT

sys.path.insert(0, str(HERE.parents[1] / "connector"))
from push import push_batch

RULE_SEARCH = "det-hf-ml-005"


def token(command):
    return subprocess.check_output(["make", "-s", command, "ARGS=--quiet"], text=True).strip()


def assert_label_free(item):
    if isinstance(item, dict):
        for key, value in item.items():
            if key.casefold().startswith("hf_label") or key.casefold() in {"label", "attack_label", "label_binary"}:
                raise ValueError("Ground-truth field in the replay event")
            assert_label_free(value)
    elif isinstance(item, list):
        for value in item:
            assert_label_free(value)


def fetch(session, path, **params):
    response = session.get("http://127.0.0.1:8000/api/v1/" + path, params=params, timeout=15)
    response.raise_for_status()
    return response.json()


def reconcile(api, ledger):
    matched = {}
    found = fetch(api, "alerts", search=RULE_SEARCH, limit=200)
    if found["total"] > 200:
        raise ValueError("Unexpected pre-existing alert volume for demo rules")
    for row in found["items"]:
        result = fetch(api, "alerts/" + row["id"])
        normalized = result.get("raw_event") or {}
        if not normalized.get("raw_data"):
            continue
        raw = json.loads(normalized["raw_data"])
        event_id = raw.get("external_id")
        if event_id not in ledger:
            continue
        assert_label_free(raw)
        if event_id in matched:
            raise ValueError("Multiple alerts from one summary event")
        if result["severity"] != ledger[event_id]["expected_severity"]:
            raise ValueError("Unexpected severity for summary event")
        matched[event_id] = {"alert_id": result["id"], "severity": result["severity"],
                             "event_id": normalized["event_id"]}
    return matched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true")
    args = parser.parse_args()
    events = json.loads((OUTPUT / "events.json").read_text())
    ledger = json.loads((OUTPUT / "ledger.json").read_text())
    assert 0 < len(events) <= 150 and {event["external_id"] for event in events} == set(ledger)
    assert_label_free(events)
    if not args.send:
        text = [{"summary_id": key, **value} for key, value in ledger.items()]
        print(json.dumps(text, indent=2), flush=True)
        return
    evidence = OUTPUT / "reconciliation.json"
    if evidence.exists():
        raise SystemExit("Demo already reconciled; use its existing stable alert IDs")
    with requests.Session() as api, requests.Session() as ingest:
        api.headers["Authorization"] = "Bearer " + token("api-token")
        ingest.headers["Authorization"] = "Bearer " + token("ingest-token")
        prior = reconcile(api, ledger)
        if prior:
            print(f"Found {len(prior)} pre-existing demo alerts; reconciling the stable IDs", flush=True)
        missing = [event for event in events if event["external_id"] not in prior]
        accepted = rejected = 0
        if missing:
            accepted, rejected = push_batch(ingest, "http://127.0.0.1:8081/v1/ingest/batch",
                                           "hf_network", missing, dry_run=False)
        for _ in range(30):
            matched = reconcile(api, ledger)
            if len(matched) == len(ledger):
                break
            time.sleep(3)
    evidence.write_text(json.dumps({"accepted": accepted, "rejected": rejected, "expected": len(ledger),
                                    "matched": matched, "label_free_payloads": len(matched)}, indent=2) + "\n")
    print(json.dumps({"expected": len(ledger), "accepted": accepted, "rejected": rejected,
                      "matched": len(matched), "by_severity": dict(Counter(a["severity"] for a in matched.values()))}),
          flush=True)
    if rejected or len(matched) != len(ledger):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
