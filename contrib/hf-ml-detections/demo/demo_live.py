"""Replay CIC-IDS2017 through the frozen AiSOC demo detectors."""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import numpy as np
import pyarrow.parquet as pq
import requests
import xgboost as xgb
from demo_source import CACHE, FEATURES, ROOT, SCENARIOS, SLICES, baseline_cache, disk_check, load_remote, minute_features, prepare

sys.path.insert(0, str(ROOT / "connector"))

from behaviour import top_reasons  # noqa: E402
from benign_fpr import xgb_scores  # noqa: E402
from delivery import ARTIFACTS  # noqa: E402
from mapper import json_value  # noqa: E402
from replay_demo import assert_label_free  # noqa: E402

CONFIG = json.loads((ROOT / "ml/uc3_behaviour_cicids/prereg_v2.json").read_text())
INGEST = os.environ.get("AISOC_DEMO_INGEST_URL", "http://127.0.0.1:8081").rstrip("/")
API = os.environ.get("AISOC_DEMO_API_URL", "http://127.0.0.1:8000").rstrip("/")
CONSOLE = os.environ.get("AISOC_DEMO_CONSOLE_URL", "http://127.0.0.1:3000").rstrip("/")
CAP = 15
MODEL = ARTIFACTS / "uc1b.ubj"
CLOCK_NOTE = "Approximate CIC capture clock; timestamps shifted to the replay timeline"


def stamp(seconds):
    return f"{seconds // 3600:02}:{seconds // 60 % 60:02}"


def allowlist(detector):
    return {row["source_sha256"] for row in CONFIG["frozen"][detector]["monday_source_allowlist"]}


def matrix(rows):
    result = np.array([[row[name] for name in FEATURES] for row in rows], dtype=np.float32)
    result[~np.isfinite(result)] = np.nan
    return result


class Detector:
    def __init__(self, baselines, model):
        self.baselines = baselines
        self.model = model
        self.rule = CONFIG["frozen"]["uc3"]
        self.uc1b = CONFIG["frozen_flow_operating_points"]["uc1b"]
        self.uc3_blocked = allowlist("uc3")
        self.uc1b_blocked = allowlist("uc1b")
        self.window_minutes = CONFIG["window_seconds"] // 60
        self.streaks = {}
        self.flow_hits = Counter()
        self.flow_counts = Counter()
        self.pending = {}
        self.truth = set()
        self.seen = set()

    def score(self, minute, rows):
        window = minute // self.window_minutes
        groups = defaultdict(list)
        scores = xgb_scores(self.model, matrix(rows)) if rows else []
        for row, score in zip(rows, scores, strict=True):
            ip = row["source_ip"]
            if not ip:
                continue
            groups[ip].append(row)
            key = (ip, window)
            self.flow_counts[key] += 1
            if row["attack_label"] != "BENIGN":
                self.truth.add(key)
            if float(score) >= self.uc1b["threshold"]:
                self.flow_hits[key] += 1
        newest, suspicious = [], []
        for ip, group in groups.items():
            if sha256(ip.encode()).hexdigest() in self.uc3_blocked:
                continue
            values = minute_features(group)
            median, scale = self.baselines.get(ip, self.baselines["global"])
            z = (values - median) / scale
            score = float(z.max())
            if score < CONFIG["uc3_robust_score_threshold"] or len(group) < self.rule["min_flows_per_minute"]:
                continue
            last, count = self.streaks.get(ip, (-2, 0))
            count = count + 1 if last == minute - 1 else 1
            self.streaks[ip] = minute, count
            explanation = top_reasons(values, median, z)
            persistence = self.rule["persistence"]
            progress = f"{min(count, persistence)}/{persistence}"
            suspicious.append((score, f"{ip} {explanation.split(';', 1)[0]} suspicious {progress}"))
            key = ip, window
            if count < self.rule["persistence"]:
                continue
            if key not in self.seen:
                self.seen.add(key)
                newest.append(key)
            if key in self.pending or key in newest:
                if key not in self.pending or score > self.pending[key][0]:
                    self.pending[key] = score, explanation
        return scores, newest, max(suspicious, default=(0, ""))[1]

    def ready(self, minute, end):
        for key, (score, explanation) in list(self.pending.items()):
            ip, window = key
            # Wait for the whole current window and its following window.
            if not end and minute + 1 < (window + 2) * self.window_minutes:
                continue
            del self.pending[key]
            confirmed = sha256(ip.encode()).hexdigest() not in self.uc1b_blocked and any(
                self.flow_hits[ip, window + adj] >= self.uc1b["min_matching_flows"] for adj in (-1, 0, 1)
            )
            yield key, score, explanation, confirmed


class Replay:
    def __init__(self, args, ingest, api):
        self.args = args
        self.ingest = ingest
        self.api = api
        self.run_id = uuid4().hex[:12]
        self.rng = np.random.default_rng(2017)
        self.counts = Counter()
        self.waiting = {}
        self.slow = set()
        self.alerts = {}
        self.truth = {}

    def send(self, events):
        assert_label_free(events)
        payload = {"connector_id": "hf-datasets", "connector_type": "hf_network", "source_format": "json", "events": events}
        json.dumps(payload, allow_nan=False)
        if self.args.dry_run or not events:
            return 0
        accepted = 0
        for start in range(0, len(events), 100):
            disk_check()
            chunk = events[start : start + 100]
            response = self.ingest.post(INGEST + "/v1/ingest/batch", json={**payload, "events": chunk}, timeout=(5, 20))
            response.raise_for_status()
            result = response.json()
            if result["accepted"] != len(chunk) or result["rejected"]:
                raise RuntimeError("AiSOC did not accept every event in the batch")
            accepted += result["accepted"]
        return accepted

    def poll(self):
        for event_id, (expected, sent_at) in list(self.waiting.items()):
            response = self.api.get(API + "/api/v1/alerts", params={"hostname": event_id, "limit": 2}, timeout=5)
            response.raise_for_status()
            result = response.json()
            if result["total"] > 1:
                raise RuntimeError(f"More than one alert for {event_id}")
            if not result["items"]:
                if time.monotonic() - sent_at >= 45 and event_id not in self.slow:
                    print(f"       {event_id} accepted, still waiting for Fusion…", flush=True)
                    self.slow.add(event_id)
                continue
            item = result["items"][0]
            detail = self.api.get(API + "/api/v1/alerts/" + item["id"], timeout=5)
            detail.raise_for_status()
            raw = json.loads(detail.json()["raw_event"]["raw_data"])
            assert_label_free(raw)
            if raw["external_id"] != event_id or item["severity"] != expected:
                raise RuntimeError(f"Alert ID or severity mismatch for {event_id}")
            del self.waiting[event_id]
            link = f"{CONSOLE}/alerts/{item['id']}"
            self.alerts[event_id] = link
            print(f"       {expected.upper()} alert ({time.monotonic() - sent_at:.1f}s) → {link}", flush=True)

    def summary(self, detector, key, score, reasons, boost, shift):
        ip, window = key
        start = shift + timedelta(minutes=window * detector.window_minutes)
        end = start + timedelta(minutes=detector.window_minutes)
        event_id = f"demo-{self.run_id}-summary-{self.counts['summaries'] + 1}"
        raw = {
            "method": "uc3-v2",
            "ml_entity_mode": "controlled-demo",
            "ml_entity_score": score,
            "flow_count": detector.flow_counts[key],
            "top_reasons": reasons,
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "clock_note": CLOCK_NOTE,
            "corroborated_by": "uc1b" if boost else "none",
        }
        if boost:
            raw["corroboration_note"] = "matches a known-attack model"
        expected = "high" if boost else "medium"
        self.send(
            [
                {
                    "source": "hf-datasets",
                    "external_id": event_id,
                    "hostname": event_id,
                    "src_ip": ip,
                    "timestamp": start.isoformat(),
                    "severity": "low",
                    "title": "CIC entity behavioural demo",
                    "description": reasons,
                    "raw_event": raw,
                }
            ]
        )
        if not self.args.dry_run:
            self.waiting[event_id] = expected, time.monotonic()
        self.truth[event_id] = key in detector.truth
        self.counts.update({"summaries": 1, "boosted": int(boost)})
        destination = "dry-run" if self.args.dry_run else "AiSOC"
        note = "XGBoost agrees → HIGH" if boost else "MEDIUM"
        print(f"       {ip} z={score:.1f} ALERT → {destination} ({note})", flush=True)

    def slice(self, name, table, baselines, model, replay_start):
        day = SCENARIOS[name]
        start, end = SLICES[day]
        shift = replay_start - timedelta(minutes=start)
        detector = Detector(baselines, model)
        slice_cap = (CAP // 2 if name == "patator" else CAP - CAP // 2) if self.args.scenario == "mixed" else CAP
        starting_count = self.counts["summaries"]
        cap_noted = False
        clock = table["capture_second"].to_numpy()
        for minute in range(start, end):
            tick = time.monotonic()
            disk_check()
            left, right = np.searchsorted(clock, [minute * 60, (minute + 1) * 60])
            rows = table.slice(int(left), int(right - left)).to_pylist()
            scores, newest, activity = detector.score(minute, rows)
            indexes = self.rng.choice(len(rows), min(len(rows), self.args.telemetry_rate), replace=False)
            telemetry = [self.telemetry(rows[i], float(scores[i]), shift) for i in sorted(indexes)]
            accepted = self.send(telemetry)
            self.counts.update({"flows": len(rows), "pushed": accepted})
            status = f"{len(telemetry)} selected (dry-run)" if self.args.dry_run else f"{accepted} → AiSOC ✓"
            print(f"{stamp(minute * 60)}  {len(rows):,} flows | {status}" + (f" | {activity}" if activity else ""), flush=True)
            for ip, _ in newest:
                if self.counts["summaries"] - starting_count < slice_cap:
                    print(f"       {ip} ALERT pending, checking XGBoost corroboration…", flush=True)
            for key, score, reasons, boost in detector.ready(minute, end=minute == end - 1):
                if self.counts["summaries"] - starting_count < slice_cap:
                    self.summary(detector, key, score, reasons, boost, shift)
                elif not cap_noted:
                    print(f"       {name} cap of {slice_cap} reached. Skipping remaining summaries in this slice.", flush=True)
                    cap_noted = True
            self.poll()
            time.sleep(max(0, self.args.speed - (time.monotonic() - tick)))

    def telemetry(self, row, score, shift):
        raw = {f"hf_{name}": json_value(row[name]) for name in FEATURES}
        raw.update(
            hf_dataset="cicids",
            hf_destination_port=row["destination_port"],
            hf_protocol=row["protocol"],
            ml_xgb_score=score,
            ml_xgb_model_version=MODEL_VERSION,
        )
        event = {
            "source": "hf-datasets",
            "external_id": f"demo-{self.run_id}-flow-{row['row_id']}",
            "timestamp": (shift + timedelta(seconds=row["capture_second"])).isoformat(),
            "severity": "low",
            "title": "CIC-IDS2017 network flow",
            "event_type": "hf.cicids.network-flow",
            "raw_event": raw,
        }
        for key, source in (("src_ip", "source_ip"), ("dst_ip", "destination_ip")):
            if row[source]:
                event[key] = row[source]
        return event

    def footer(self, elapsed):
        c = self.counts
        print(
            f"Run {self.run_id} | {elapsed:.1f}s | {c['flows']:,} flows processed | {c['pushed']:,} pushed | "
            f"{len(self.alerts)} alerts confirmed | {c['summaries']} summaries "
            f"({'simulated' if self.args.dry_run else 'sent'}, {c['boosted']} corroborated)",
            flush=True,
        )
        for link in self.alerts.values():
            print(f"  {link}", flush=True)
        if self.args.presenter_notes:
            keys = self.truth if self.args.dry_run else self.alerts
            true = sum(self.truth[key] for key in keys)
            print(f"Presenter notes | {true} true / {len(keys) - true} false", flush=True)


def session(stack, name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Set {name} or use --dry-run")
    client = stack.enter_context(requests.Session())
    client.headers["Authorization"] = "Bearer " + value
    return client


MODEL_VERSION = json.loads((ROOT / "ml/uc1b_xgboost_cicids/metrics.json").read_text())["benign_fpr_protocol"]["model_version"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=(*SCENARIOS, "mixed"), nargs="?")
    parser.add_argument("--source", choices=("cache", "hf"), default="cache")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--speed", type=float, default=0.2, help="real seconds per replayed minute (default 0.2)")
    parser.add_argument("--telemetry-rate", type=int, default=8, help="maximum telemetry flows per replayed minute (default 8)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--presenter-notes", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        prepare()
        return 0
    if not args.scenario or not np.isfinite(args.speed) or args.speed < 0 or args.telemetry_rate < 0:
        parser.error("Specify a scenario, nonnegative speed, and nonnegative telemetry rate")
    started = time.monotonic()
    with ExitStack() as stack:
        ingest = None if args.dry_run else session(stack, "AISOC_INGEST_TOKEN")
        api = None if args.dry_run else session(stack, "AISOC_API_TOKEN")
        replay = Replay(args, ingest, api)
        try:
            disk_check()
            if not MODEL_VERSION.endswith(sha256(MODEL.read_bytes()).hexdigest()[:12]):
                raise ValueError("UC1b model does not match its frozen digest")
            model = xgb.Booster({"nthread": 2})
            model.load_model(MODEL)
            names = tuple(SCENARIOS) if args.scenario == "mixed" else (args.scenario,)
            baselines = baseline_cache()
            if args.source == "hf":
                tables, fitted = load_remote(names, need_baselines=baselines is None)
                if fitted is not None:
                    baselines = fitted
            else:
                if baselines is None:
                    raise ValueError("No demo cache. Run --prepare first.")
                tables = {name: pq.read_table(CACHE / f"{name}.parquet") for name in names}
            ranges = [(name, SCENARIOS[name], *SLICES[SCENARIOS[name]]) for name in names]
            label = " + ".join(f"{day} {stamp(start * 60)}–{stamp(end * 60)}" for _, day, start, end in ranges)
            print(
                f"CIC-IDS2017 | {args.scenario} | {label} (capture clock) | {sum(map(len, tables.values())):,} flows | run {replay.run_id}",
                flush=True,
            )
            replay_start = datetime.now(UTC) - timedelta(minutes=sum(end - start for _, _, start, end in ranges))
            for name, _, start, end in ranges:
                replay.slice(name, tables[name], baselines, model, replay_start)
                replay_start += timedelta(minutes=end - start)
            deadline = time.monotonic() + 120
            while replay.waiting:
                disk_check()
                replay.poll()
                if replay.waiting:
                    if time.monotonic() >= deadline:
                        missing = ", ".join(replay.waiting)
                        raise RuntimeError(f"Alert confirmation timed out for {missing}")
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\nReplay stopped. Accepted events may still be processing.", flush=True)
            return 130
        except (ValueError, RuntimeError, OSError, requests.RequestException) as error:
            print(f"Replay failed: {error}", file=sys.stderr, flush=True)
            return 1
        finally:
            replay.footer(time.monotonic() - started)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
