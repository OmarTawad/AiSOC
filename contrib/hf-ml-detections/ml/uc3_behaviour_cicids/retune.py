"""Tune a fixed CIC entity candidate grid, then run the frozen Friday retest."""

import argparse
from collections import Counter, defaultdict
import gzip
from hashlib import sha256
import json
import subprocess

import numpy as np

from behaviour import robust_fit
from clock import DATA, HERE, PREREG, disk_check, parse_clock, remote_parquet
from evaluate import AUTH, measure
from source import FEATURES

MON = "2017-07-03"
DEVELOPMENT = ("2017-07-04", "2017-07-05", "2017-07-06")
FRIDAY = "2017-07-07"
FROZEN = HERE / "prereg_v2.json"
AGGREGATE = DATA / "cicids-entity-aggregates.jsonl.gz"
COUNTS = (0, 5, 10, 25)
MINUTE_VARIANTS = ((2, 1), (3, 1), (3, 5), (3, 10))
MINUTES_COLUMNS = [
    "Timestamp", "source_ip", "destination_ip", "destination_port", *FEATURES[:3],
]


def json_save(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def digest(value):
    return sha256(value.encode()).hexdigest()


def window_data(days):
    prefixes = tuple(f'["{date}"' for date in days)
    result = {}
    with gzip.open(AGGREGATE, "rt") as source:
        for line in source:
            if not line.startswith(prefixes):
                continue
            date, ip, bucket, flows, labels, matches, explanation = json.loads(line)
            result[date, ip, bucket] = (flows, labels, matches, explanation)
    return result


def minute_data(days):
    """Stream projected columns; exclude dates before building minute features."""
    date_prefixes = tuple(
        f"{day_number}/{month}/"
        for day in days for day_number in {day[-2:], str(int(day[-2:]))} for month in ("07", "7")
    )
    minute_rows = {}
    with remote_parquet(PREREG["dataset_revision"]) as parquet:
        for batch in parquet.iter_batches(batch_size=32768, columns=MINUTES_COLUMNS, use_threads=False):
            disk_check()
            for stamp, ip, dst, port, duration, forward, backward in zip(
                *(col.to_pylist() for col in batch.columns), strict=True
            ):
                if not stamp or not stamp.startswith(date_prefixes):
                    continue
                clock = parse_clock(stamp)
                if not clock or clock[0] not in days or not ip:
                    continue
                day, second = clock
                record = minute_rows.setdefault((day, ip, second // 60), [0, set(), set(), 0, 0])
                record[0] += 1
                if port is not None:
                    record[1].add(port)
                if dst:
                    record[2].add(dst)
                record[3] += port in AUTH
                record[4] += (
                    duration is not None and duration <= PREREG["uc3"]["short_flow_max_microseconds"]
                    and forward is not None and backward is not None
                    and forward + backward <= PREREG["uc3"]["short_flow_max_packets"]
                )
    return {
        key: np.array([flows, len(ports), len(hosts), auth, short / flows])
        for key, (flows, ports, hosts, auth, short) in minute_rows.items()
    }


def robust_candidates(minutes, variants):
    training = defaultdict(list)
    for (day, ip, _), values in minutes.items():
        if day == MON:
            training[ip].append(values)
    personal = {ip: robust_fit(observations) for ip, observations in training.items()}
    pooled = robust_fit([row for rows in training.values() for row in rows])
    sets = {variant: set() for variant in variants}
    previous = {variant: {} for variant in variants}
    for (day, ip, minute), feature in sorted(minutes.items()):
        if day == MON:
            continue
        median, scale = personal.get(ip, pooled)
        score = max((feature - median) / scale)
        key = day, ip
        for variant in variants:
            persistence, floor = variant
            last, streak = previous[variant].get(key, (-2, 0))
            qualifies = score >= PREREG["uc3"]["threshold"] and feature[0] >= floor
            streak = (streak + 1 if last == minute - 1 else 1) if qualifies else 0
            previous[variant][key] = minute, streak
            if streak >= persistence:
                sets[variant].add((day, ip, minute // 5))
    return sets


def flow_sets(windows):
    return {name: {key for key, (_, _, hits, _) in windows.items()
                   if hits.get(name, 0) >= PREREG[name]["min_matching_flows"]}
            for name in ("uc1b", "uc2")}


def candidate_hits(config, flow, robust, blocked):
    method = config["detector"]
    if method == "uc3":
        hits = robust[config["persistence"], config["min_flows_per_minute"]]
        if config["require_flow_confirmation"]:
            confirm = flow["uc1b"] | flow["uc2"]
            hits = {key for key in hits if any((key[0], key[1], key[2] + delta) in confirm
                                                for delta in (-1, 0, 1))}
    else:
        hits = flow[method]
    return {key for key in hits if digest(key[1]) not in blocked}


def meets(metrics):
    return (metrics["false_entity_alerts"] <= PREREG["evaluation"]["max_false_entity_alerts"]
            and metrics["precision"] is not None
            and metrics["precision"] >= PREREG["evaluation"]["min_entity_precision"])


def source_ranking(windows):
    flow_count = Counter()
    for (day, ip, _), record in windows.items():
        if day == MON:
            flow_count[ip] += record[0]
    return [{"rank": i, "source_sha256": digest(ip), "monday_flows": count,
             "reason": "Monday benign top talker by cumulative observed flows; infrastructure role unverified"}
            for i, (ip, count) in enumerate(sorted(flow_count.items(), key=lambda item: (-item[1], item[0]))[:max(COUNTS)], 1)]


def tune():
    if FROZEN.exists():
        raise SystemExit("A final v2 selection already exists")
    windows = window_data((MON, *DEVELOPMENT))
    monday_rank = source_ranking(windows)
    flow = flow_sets(windows)
    robust = robust_candidates(minute_data((MON, *DEVELOPMENT)), MINUTE_VARIANTS)
    original = {key for key, rec in windows.items() if rec[3] is not None}
    if robust[(2, 1)] != original:
        raise ValueError(f"UC3 parity mismatch: {Counter(key[0] for key in robust[(2, 1)] - original)} extra, "
                         f"{Counter(key[0] for key in original - robust[(2, 1)])} missing")
    by_day = {date: [key for key in windows if key[0] == date] for date in DEVELOPMENT}
    configs = []
    for count in COUNTS:
        for method in ("uc1b", "uc2"):
            configs.append({"detector": method, "monday_top_n": count})
        for persistence, floor in MINUTE_VARIANTS:
            for layer in (False, True):
                configs.append({"detector": "uc3", "monday_top_n": count, "persistence": persistence,
                                "min_flows_per_minute": floor, "require_flow_confirmation": layer})
    records = []
    for config in configs:
        dates = DEVELOPMENT if config["detector"] == "uc3" and not config["require_flow_confirmation"] else DEVELOPMENT[-1:]
        blocked = {row["source_sha256"] for row in monday_rank[:config["monday_top_n"]]}
        hits = candidate_hits(config, flow, robust, blocked)
        records.append({"config": config, "days": {
            day: measure(windows, hits, by_day[day]) for day in dates
        }})

    def rank(record):
        common = record["days"][DEVELOPMENT[-1]]
        false = common["false_entity_alerts"]
        families = common["families"].values()
        recall = sum(r["recall"] for r in families) / max(1, len(common["families"]))
        # Rank on the common Thursday cohort. Reward family recall among gate
        # passers, otherwise prefer a smaller false-alert excess before recall.
        return (not meets(common), max(0, false - 25), -recall, false,
                -(common["precision"] or 0), record["config"]["monday_top_n"])

    winners = {}
    for name in ("uc1b", "uc2", "uc3"):
        best = min((row for row in records if row["config"]["detector"] == name), key=rank)
        config = best["config"]
        winners[name] = {
            **config,
            "monday_source_allowlist": monday_rank[:config["monday_top_n"]],
            "tuning_days": best["days"],
        }
    frozen = {
        "prior_prereg_sha256": sha256((HERE / "prereg.json").read_bytes()).hexdigest(),
        "evaluation_day": FRIDAY,
        "entity": PREREG["entity"],
        "window_seconds": PREREG["evaluation"]["window_seconds"],
        "frozen_flow_operating_points": {name: PREREG[name] for name in ("uc1b", "uc2")},
        "uc3_robust_score_threshold": PREREG["uc3"]["threshold"],
        "evidence": "Friday was examined in earlier rounds; this is a pre-registered re-test, weaker evidence than a fresh day.",
        "selection": "Compare all candidates on common Thursday: gate pass first, then excess false alerts, descending macro family recall, false alerts, precision and allowlist size. Tue/Wed are additional UC3 evidence. Flow confirmation is unavailable on Tue/Wed because frozen flow scores were only computed for Thu/Fri.",
        "gate": {"false_entity_alerts_max": 25, "precision_min": .5, "requires_validated_clock": True},
        "frozen": winners,
    }
    json_save(HERE / "tuning_v2.json", {"monday_top_sources": monday_rank, "candidates": records})
    json_save(FROZEN, frozen)
    print(json.dumps(winners), flush=True)


def friday():
    report = HERE / "friday_v2.json"
    if report.exists():
        raise SystemExit("Friday v2 has already been evaluated")
    frozen = json.loads(FROZEN.read_text())
    # Before opening Friday, require that the exact preregistration is tracked
    # in HEAD and unmodified. No threshold or allowlist fitting follows.
    relative = FROZEN.relative_to(HERE.parents[3])
    tracked = subprocess.check_output(["git", "show", f"HEAD:{relative}"], cwd=HERE.parents[3])
    if tracked != FROZEN.read_bytes():
        raise SystemExit("Commit the exact preregistration before evaluating Friday")
    windows = window_data((FRIDAY,))
    flow = flow_sets(windows)
    uc3 = frozen["frozen"]["uc3"]
    robust = robust_candidates(minute_data((MON, FRIDAY)), ((uc3["persistence"], uc3["min_flows_per_minute"]),))
    validated = json.loads((HERE / "clock-validation.json").read_text())["validated"]
    outcomes = {}
    for name, config in frozen["frozen"].items():
        blocked = {row["source_sha256"] for row in config["monday_source_allowlist"]}
        result = measure(windows, candidate_hits(config, flow, robust, blocked), list(windows))
        outcomes[name] = {**result, "numeric_gate_passed": meets(result),
                          "clock_validated": validated, "eligible_to_deploy": meets(result) and validated}
    json_save(report, outcomes)
    print(json.dumps(outcomes), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["tune", "friday"])
    if parser.parse_args().stage == "tune":
        tune()
    else:
        friday()
