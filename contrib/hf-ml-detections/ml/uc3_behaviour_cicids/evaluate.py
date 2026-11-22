"""Full-stream entity aggregation for frozen CICIDS detectors and baselines."""

from collections import Counter, defaultdict
from functools import lru_cache
import gzip
from hashlib import blake2b, sha256
import json
from time import monotonic

import joblib
import numpy as np
import xgboost as xgb

from clock import HERE, PREREG, parse_clock
from behaviour import evaluate_minutes
from benign_fpr import UC1B, UC2, fit_xgb, freeze, module_at, xgb_scores
from evaluation import ARTIFACTS, attack_family, load, save
from source import DATA, FEATURES, disk_check, remote_parquet

DAYS = tuple(f"2017-07-0{day}" for day in range(3, 8))
FROZEN_DAYS = DAYS[-2:]
CLOCK = HERE / "clock-validation.json"
RESULTS = HERE / "metrics.json"
FEATURES_AND_KEYS = [
    "Timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "attack_label", *FEATURES,
]
AUTH = frozenset(PREREG["uc3"]["auth_ports"])


@lru_cache(maxsize=262144)
def fold(day, ip, bucket):
    value = f"{day}|{ip}|{bucket}".encode()
    return int.from_bytes(blake2b(value, digest_size=8).digest(), "big") % 10


def diagnostic_models(isolation):
    rows, matrix, family, target, _ = load()
    partitions = np.array([
        fold(clock[0], ip, clock[1] // PREREG["evaluation"]["window_seconds"]) if clock and ip else -1
        for stamp, ip in zip(rows["Timestamp"], rows["source_ip"], strict=True)
        for clock in [parse_clock(stamp)]
    ])
    train = (partitions >= 0) & (partitions < 6)
    validation = (partitions >= 6) & (partitions < 8) & (target == 0)
    models = {}
    thresholds = {}
    did_train = Counter(family[train])
    for group in ("all", *sorted(set(family) - {"benign"})):
        use = train if group == "all" else train & (family != group)
        if not (target[use] == 1).any():
            continue
        model = fit_xgb(matrix[use], target[use])
        models[group] = model
        thresholds[group] = freeze(xgb_scores(model, matrix[validation]))
    diagnostic_iforest = isolation.fit_benign(matrix[train & (target == 0)])
    thresholds["isolation_forest"] = freeze(isolation.score(diagnostic_iforest, matrix[validation]))
    return models, thresholds, {str(key): value for key, value in did_train.items()}, diagnostic_iforest


def verify_model(path, expected_version):
    if not expected_version.endswith(sha256(path.read_bytes()).hexdigest()[:12]):
        raise ValueError(f"Model digest does not match frozen threshold: {path.name}")


def scan(models, thresholds, versions, isolation, diagnostic_iforest):
    windows = {}
    minutes = {}
    counts = Counter()
    start = monotonic()
    xgb_cutoff = PREREG["uc1b"]["threshold"]
    iforest_cutoff = PREREG["uc2"]["threshold"]
    chrono_xgb, chrono_iforest = versions
    with remote_parquet(PREREG["dataset_revision"]) as parquet:
        for number, batch in enumerate(parquet.iter_batches(batch_size=32768, columns=FEATURES_AND_KEYS, use_threads=False)):
            disk_check()
            def read(name):
                return batch.column(batch.schema.get_field_index(name))

            stamps = [parse_clock(value) for value in read("Timestamp").to_pylist()]
            ips = read("source_ip").to_pylist()
            targets = read("destination_ip").to_pylist()
            ports = read("destination_port").to_pylist()
            families = [attack_family(label) for label in read("attack_label").to_pylist()]
            used = np.array([clock is not None and bool(ip) for clock, ip in zip(stamps, ips, strict=True)])
            day = np.array([stamp[0] if stamp else "" for stamp in stamps])
            scores = np.column_stack([read(name).to_numpy(zero_copy_only=False) for name in FEATURES]).astype(np.float32)
            scores[~np.isfinite(scores)] = np.nan
            packets = np.nan_to_num(scores[:, 1] + scores[:, 2], nan=np.inf)
            short = (scores[:, 0] <= PREREG["uc3"]["short_flow_max_microseconds"]) & (packets <= PREREG["uc3"]["short_flow_max_packets"])
            buckets = [
                (clock[0], ip, clock[1] // 300) if keep else None
                for clock, ip, keep in zip(stamps, ips, used, strict=True)
            ]
            indexes = np.flatnonzero(used & np.isin(day, FROZEN_DAYS))
            diagnostic = np.array([bool(key and key[0] != DAYS[0] and fold(*key) >= 8) for key in buckets])
            test_idx = np.flatnonzero(diagnostic)
            counts["invalid_clock_or_missing_source"] += int((~used).sum())
            counts["flows"] += len(batch)
            matches = defaultdict(list)
            if len(indexes):
                for method, predicate in (
                    ("uc1b", xgb_scores(chrono_xgb, scores[indexes]).astype(np.float64) >= xgb_cutoff),
                    ("uc2", isolation.score(chrono_iforest, scores[indexes]) >= iforest_cutoff),
                ):
                    matches[method].extend(indexes[predicate])
            if len(test_idx):
                diagnostic_matrix = xgb.DMatrix(scores[test_idx], nthread=2)
                for method, model in models.items():
                    score = model.predict(diagnostic_matrix).astype(np.float64)
                    matches[f"diagnostic_{method}"].extend(test_idx[score >= thresholds[method]["threshold"]])
                iforest = isolation.score(diagnostic_iforest, scores[test_idx])
                matches["diagnostic_isolation_forest"].extend(
                    test_idx[iforest >= thresholds["isolation_forest"]["threshold"]]
                )
            for i, key in enumerate(buckets):
                if key is None:
                    continue
                counts[key[0]] += 1
                window = windows.setdefault(key, [0, set(), Counter()])
                window[0] += 1
                if families[i] != "benign":
                    window[1].add(families[i])
                minute = stamps[i][1] // 60
                flow = minutes.setdefault((key[0], key[1], minute), [0, set(), set(), 0, 0])
                flow[0] += 1
                if ports[i] is not None:
                    flow[1].add(ports[i])
                if targets[i]:
                    flow[2].add(targets[i])
                flow[3] += ports[i] in AUTH
                flow[4] += bool(short[i])
            for method, matching in matches.items():
                for index in matching:
                    windows[buckets[index]][2][method] += 1
            if number % 16 == 15:
                print(f"Scanned {counts['flows']:,} flows in {monotonic()-start:.1f}s", flush=True)
    minutes = {
        key: np.array([n, len(ports), len(hosts), auth, short / n])
        for key, (n, ports, hosts, auth, short) in minutes.items()
    }
    return windows, minutes, dict(counts)


def measure(windows, alarms, subset):
    labels = Counter()
    caught = Counter()
    total = attacks = false = true = 0
    for key in subset:
        total += 1
        families = windows[key][1]
        hit = key in alarms
        if families:
            attacks += 1
            true += hit
            labels.update(families)
            if hit:
                caught.update(families)
        elif hit:
            false += 1
    return {
        "source_windows": total, "malicious_windows": attacks, "entity_alerts": true + false,
        "false_entity_alerts": false, "true_entity_alerts": true,
        "precision": true / (true + false) if true + false else None,
        "recall": true / attacks if attacks else None,
        "families": {
            name: {"windows": n, "detected": caught[name], "recall": caught[name] / n}
            for name, n in sorted(labels.items())
        },
    }


def evaluate(windows, minutes, diagnostic, clock):
    robust, ueba, baseline_summary = evaluate_minutes(minutes)
    alarms = {"uc3": set(robust), "ueba_reference": ueba}
    for method in ("uc1b", "uc2"):
        alarms[method] = {key for key, value in windows.items()
                          if value[2][method] >= PREREG[method]["min_matching_flows"]}
    for method in (*diagnostic, "isolation_forest"):
        alarms[f"diagnostic_{method}"] = {key for key, value in windows.items()
                                            if value[2][f"diagnostic_{method}"] >= PREREG["uc1b"]["min_matching_flows"]}
    by_day = {}
    for day in DAYS[1:]:
        subset = [key for key in windows if key[0] == day]
        by_day[day] = {name: measure(windows, alarms[name], subset) for name in
                       (("uc1b", "uc2", "uc3", "ueba_reference") if day in FROZEN_DAYS else ("uc3", "ueba_reference"))}
    gates = {}
    cfg = PREREG["evaluation"]
    for method in ("uc1b", "uc2", "uc3", "ueba_reference"):
        result = by_day[cfg["gate_day"]][method]
        numbers_pass = (result["false_entity_alerts"] <= cfg["max_false_entity_alerts"]
                        and result["precision"] is not None and result["precision"] >= cfg["min_entity_precision"])
        gates[method] = {"numeric_gate_passed": numbers_pass, "clock_validated": clock,
                         "eligible_to_deploy": numbers_pass and clock and method != "ueba_reference"}
    matched = {}
    cohort = [key for key in windows if key[0] != DAYS[0] and fold(*key) >= 8]
    for family in sorted(set(diagnostic) - {"all"}):
        subset = [key for key in cohort if not windows[key][1] or family in windows[key][1]]
        rows = {}
        for method in ("diagnostic_all", f"diagnostic_{family}", "diagnostic_isolation_forest", "uc3", "ueba_reference"):
            rows[method] = {
                "overall": measure(windows, alarms[method], subset),
                "by_day": {day: measure(windows, alarms[method], [key for key in subset if key[0] == day])
                           for day in DAYS[1:]},
            }
        matched[family] = rows
    return by_day, gates, baseline_summary, matched, robust


def main():
    clock_result = json.loads(CLOCK.read_text())
    isolation = module_at("isolation", UC2 / "train.py")
    diag, thresholds, support, diagnostic_iforest = diagnostic_models(isolation)
    xgb_file = ARTIFACTS / "uc1b.ubj"
    iforest_file = ARTIFACTS / "uc2.joblib"
    for record, path, key in [(UC1B, xgb_file, "uc1b"), (UC2, iforest_file, "uc2")]:
        frozen = json.loads((record / "metrics.json").read_text())["benign_fpr_protocol"]
        verify_model(path, frozen["model_version"])
        if PREREG[key]["threshold"] != frozen["calibration"]["threshold"]:
            raise ValueError("Frozen threshold differs from the preregistration")
    chrono = xgb.Booster({"nthread": 2})
    chrono.load_model(xgb_file)
    windows, minutes, flow_counts = scan(
        diag, thresholds, (chrono, joblib.load(iforest_file)), isolation, diagnostic_iforest
    )
    by_day, gates, baseline, matched, explanations = evaluate(windows, minutes, diag, clock_result["validated"])
    disk_check()
    with gzip.open(DATA / "cicids-entity-aggregates.jsonl.gz", "wt", encoding="utf-8") as evidence:
        for key, (flows, families, matches) in sorted(windows.items()):
            evidence.write(json.dumps([*key, flows, sorted(families), matches, explanations.get(key)]) + "\n")
    save(RESULTS, {
        "flow_counts": flow_counts, "timestamp_approximate": not clock_result["validated"],
        "by_day": by_day, "deployment_gates": gates, "baseline": baseline,
        "matched_comparison": matched, "diagnostic_thresholds": thresholds,
        "diagnostic_all_family_training_counts": support,
    })
    scores = {day: {method: (v["entity_alerts"], v["false_entity_alerts"], v["precision"], v["recall"])
                    for method, v in methods.items()} for day, methods in by_day.items()}
    print(json.dumps({"days": scores, "gate": gates, "counts": flow_counts, "baseline": baseline}), flush=True)


if __name__ == "__main__":
    main()
