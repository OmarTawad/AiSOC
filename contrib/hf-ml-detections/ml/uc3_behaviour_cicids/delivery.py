"""Build the frozen UC3 demonstration and descriptive CIC audits."""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import csv
import json

import joblib
import numpy as np
import xgboost as xgb

from behaviour import robust_fit, top_reasons
from clock import DATA, HERE, PREREG, disk_check, parse_clock, remote_parquet
from retune import DEVELOPMENT, FRIDAY, MON, digest, flow_sets, minute_data, robust_candidates, window_data
from source import FEATURES
from benign_fpr import UC2, module_at, xgb_scores
from evaluation import ARTIFACTS

DAYS = (MON, *DEVELOPMENT, FRIDAY)
SLICES = {DEVELOPMENT[0]: (13 * 60 + 50, 15 * 60 + 20),
          DEVELOPMENT[1]: (9 * 60 + 17, 11 * 60 + 32)}
SERVICES = {21, 22, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 464, 636, 3268, 3389, 5353, 5355, 8080}
COLUMNS = ["Timestamp", "source_ip", "destination_ip", "destination_port", "attack_label", *FEATURES]
REPORTS = HERE.parents[1] / "reports"
OUTPUT = DATA / "day6"
RULE_FAMILY = "uc3-v2"


def capture_sources(windows, allowed):
    return {ip for (day, ip, _) in windows if day == MON and digest(ip) in allowed}


def slice_bucket(day, bucket, margin=0):
    if day not in SLICES:
        return False
    start, end = SLICES[day]
    return start - margin <= bucket * 5 < end + margin


def role(ip, incoming):
    if ip in {"172.16.0.1", "205.174.165.80"}:
        return "Firewall / NAT (published)"
    if ip == "192.168.10.3":
        return "DNS and domain controller (published)"
    if ip in {"192.168.10.50", "192.168.10.51"}:
        return "Web / Ubuntu server (published)"
    if ip == "192.168.10.8":
        return "Windows workstation; simulated lateral-movement source"
    if ip.startswith("192.168.10."):
        return "Workstation-like client (lab inventory)"
    if sum(incoming[p] for p in (80, 443, 8080)) >= 10:
        return "Web service-like (observed)"
    return "Role uncertain"


def analyze(allowed):
    isolation = module_at("isolation", UC2 / "train.py")
    iforest = joblib.load(ARTIFACTS / "uc2.joblib")
    xgb_model = xgb.Booster({"nthread": 2})
    xgb_model.load_model(ARTIFACTS / "uc1b.ubj")
    cutoff = PREREG["uc1b"]["threshold"]
    incoming = defaultdict(Counter)
    in_peers = defaultdict(set)
    out_peers = defaultdict(set)
    outgoing = Counter()
    hunts = {}
    truth = set()
    demo_hits = Counter()
    with remote_parquet(PREREG["dataset_revision"]) as parquet:
        for batch in parquet.iter_batches(batch_size=32768, columns=COLUMNS, use_threads=False):
            disk_check()
            fields = {name: batch.column(batch.schema.get_field_index(name)).to_pylist()
                      for name in ("Timestamp", "source_ip", "destination_ip", "destination_port", "attack_label")}
            clocks = [parse_clock(value) for value in fields["Timestamp"]]
            matrix = np.column_stack([batch.column(batch.schema.get_field_index(name)).to_numpy(zero_copy_only=False)
                                      for name in FEATURES]).astype(np.float32)
            matrix[~np.isfinite(matrix)] = np.nan
            scores = isolation.score(iforest, matrix)
            keys = []
            demo_idx = []
            for i, (clock, src, dst, port, label) in enumerate(zip(
                clocks, fields["source_ip"], fields["destination_ip"], fields["destination_port"], fields["attack_label"],
                strict=True,
            )):
                if clock is None or not src:
                    keys.append(None)
                    continue
                day, second = clock
                entity = day, src
                key = day, src, second // 300
                keys.append(key)
                if label != "BENIGN":
                    truth.add(entity)
                current = hunts.get(entity)
                if current is None or scores[i] > current[0]:
                    hunts[entity] = float(scores[i]), matrix[i].copy()
                if day == MON:
                    if src in allowed:
                        outgoing[src] += 1
                        if dst:
                            out_peers[src].add(dst)
                    if dst in allowed:
                        in_peers[dst].add(src)
                        if port in SERVICES:
                            incoming[dst][port] += 1
                if slice_bucket(day, key[2], margin=5):
                    demo_idx.append(i)
            if demo_idx:
                values = xgb_scores(xgb_model, matrix[demo_idx]).astype(np.float64)
                for index, score in zip(demo_idx, values, strict=True):
                    if score >= cutoff:
                        demo_hits[keys[index]] += 1
    audit = []
    for ip in sorted(allowed, key=lambda value: (-outgoing[value], value)):
        audit.append({
            "source_ip": ip, "likely_role": role(ip, incoming[ip]),
            "monday_outbound_flows": outgoing[ip], "distinct_outbound_peers": len(out_peers[ip]),
            "distinct_inbound_peers": len(in_peers[ip]), "top_inbound_service_ports": incoming[ip].most_common(4),
        })
    hunting = {}
    REPORTS.mkdir(exist_ok=True)
    for day in DAYS:
        selected = sorted(((ip, value) for (date, ip), value in hunts.items() if date == day),
                          key=lambda item: (-item[1][0], item[0]))[:20]
        rows = []
        for rank, (ip, (score, values)) in enumerate(selected, 1):
            z = isolation.deviations(iforest, values.reshape(1, -1))[0]
            top = np.argsort(-np.abs(z), kind="stable")[:3]
            reasons = "; ".join(f"{FEATURES[i]} ({z[i]:+.2f} scaled deviation)" for i in top)
            rows.append({"rank": rank, "source_ip": ip, "score": f"{score:.8f}", "top_deviations": reasons,
                         "attack_entity": (day, ip) in truth})
        hunting[day] = {"listed": len(rows), "attack_entities": sum(row["attack_entity"] for row in rows)}
        path = REPORTS / f"hunting_{day}"
        with path.with_suffix(".csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        text = [f"# CIC-IDS2017 hunting — {day}", "",
                "Ranked by each source's highest frozen Isolation Forest flow score. Deviations describe the highest-scoring flow.",
                f"Attack-labeled sources among the top {len(rows)}: {hunting[day]['attack_entities']}.",
                "", "| Rank | Source IP | Score | Top deviations | Attack-labeled source |", "|---:|---|---:|---|---|"]
        text.extend("| " + " | ".join(map(str, row.values())) + " |" for row in rows)
        path.with_suffix(".md").write_text("\n".join(text) + "\n")
    return audit, hunting, {key for key, hits in demo_hits.items() if hits >= PREREG["uc1b"]["min_matching_flows"]}


def flagged_reasons(minutes, variant, demo):
    run, floor = variant
    monday = defaultdict(list)
    for (day, ip, _), values in minutes.items():
        if day == MON:
            monday[ip].append(values)
    fit = {ip: robust_fit(values) for ip, values in monday.items()}
    pool = robust_fit([row for values in monday.values() for row in values])
    preceding = {}
    explanation = {}
    for (day, ip, minute), values in sorted(minutes.items()):
        if day not in SLICES:
            continue
        median, scale = fit.get(ip, pool)
        z = (values - median) / scale
        key, bucket = (day, ip), (day, ip, minute // 5)
        last, streak = preceding.get(key, (-2, 0))
        qualifies = z.max() >= PREREG["uc3"]["threshold"] and values[0] >= floor
        streak = (streak + 1 if last == minute - 1 else 1) if qualifies else 0
        preceding[key] = minute, streak
        if streak >= run and bucket in demo:
            score = float(z.max())
            if bucket not in explanation or score > explanation[bucket][0]:
                explanation[bucket] = score, top_reasons(values, median, z)
    assert set(explanation) == demo
    return explanation


def corroborated(key, flow):
    day, ip, bucket = key
    return any((day, ip, bucket + step) in flow for step in (-1, 0, 1))



def write_allowlist_report(audit):
    lines = [
        "# CIC-IDS2017 Monday allowlist audit", "",
        "The allowlist is the frozen top 25 by Monday source flow count. The inbound port",
        "column counts flow rows whose destination was that IP and an audited service port.",
        "A missing port is no evidence of a listening socket. Peer counts are distinct",
        "opposite endpoints per direction. Observed roles are hypotheses.",
        "", "| Source IP | Likely role | Monday source flows | Inbound peers | Outbound peers | Inbound ports (flows) |",
        "|---|---|---:|---:|---:|---|",
    ]
    for row in audit:
        ip = row["source_ip"]
        incoming = Counter(dict(row["top_inbound_service_ports"]))
        ports = ", ".join(f"{port} ({count:,})" for port, count in incoming.items()) or "—"
        lines.append(
            f"| {ip} | {role(ip, incoming)} | {row['monday_outbound_flows']:,} | "
            f"{row['distinct_inbound_peers']:,} | {row['distinct_outbound_peers']:,} | {ports} |"
        )
    lines.extend([
        "", "Neither published firewall address (172.16.0.1 or 205.174.165.80),",
        "nor 172.16.0.11 or the published external attacker addresses, is on the list.",
        "Windows host 192.168.10.8 is on the list and is also the published simulated",
        "source of one Thursday lateral-movement scenario.",
        "[UNB network inventory and capture schedule](https://www.unb.ca/cic/datasets/ids-2017.html)",
    ])
    (REPORTS / "allowlist-audit.md").write_text("\n".join(lines) + "\n")


def main():
    prereg = json.loads((HERE / "prereg_v2.json").read_text())
    config = prereg["frozen"]["uc3"]
    blocked = {record["source_sha256"] for record in config["monday_source_allowlist"]}
    windows = window_data(DAYS)
    ips = capture_sources(windows, blocked)
    assert len(ips) == len(blocked) == 25
    minutes = minute_data(DAYS)
    variant = config["persistence"], config["min_flows_per_minute"]
    raw = robust_candidates(minutes, (variant,))[variant]
    assert not config["require_flow_confirmation"]
    final = {key for key in raw if key[1] not in ips}
    suppressed = defaultdict(Counter)
    for key in raw - final:
        suppressed[key[0]].update(windows[key][1])
    flow = flow_sets(windows)["uc1b"]
    uc1b_blocked = {record["source_sha256"] for record in prereg["frozen"]["uc1b"]["monday_source_allowlist"]}
    flow = {key for key in flow if digest(key[1]) not in uc1b_blocked}
    friday = defaultdict(Counter)
    for key in final:
        if key[0] == FRIDAY:
            friday["boosted" if corroborated(key, flow) else "medium"]["attack" if windows[key][1] else "benign"] += 1
    assert sum(sum(row.values()) for row in friday.values()) == 25
    audit, hunts, demo_flow = analyze(ips)
    write_allowlist_report(audit)
    demo = {key for key in final if slice_bucket(key[0], key[2])}
    assert len(demo) <= 150
    reasons = flagged_reasons(minutes, variant, demo)
    events = []
    ledger = {}
    for key in sorted(demo):
        day, ip, bucket = key
        start = datetime.fromisoformat(day) + timedelta(minutes=5 * bucket)
        end = start + timedelta(minutes=5)
        identifier = "cic-uc3-v2-demo-" + digest("|".join(map(str, key)))[:24]
        boost = corroborated(key, demo_flow)
        score, explanation = reasons[key]
        raw = {"method": RULE_FAMILY, "ml_entity_mode": "controlled-demo", "ml_entity_score": score,
               "flow_count": windows[key][0], "top_reasons": explanation, "window_start": start.isoformat(),
               "window_end": end.isoformat(), "clock_note": "approximate capture clock; time zone unverified",
               "corroborated_by": "uc1b" if boost else "none"}
        if boost:
            raw["corroboration_note"] = "matches a known-attack model"
        events.append({"source": "hf-datasets", "external_id": identifier, "hostname": identifier,
                       "src_ip": ip, "timestamp": start.isoformat() + "Z", "severity": "low",
                       "title": "CIC entity behavioural demo", "description": explanation, "raw_event": raw})
        ledger[identifier] = {"families": windows[key][1], "expected_severity": "high" if boost else "medium",
                              "capture_day": day, "window_start": start.isoformat()}
    expected = defaultdict(Counter)
    for row in ledger.values():
        expected[row["capture_day"], row["expected_severity"]].update(row["families"] or ["benign"])
    OUTPUT.mkdir(exist_ok=True)
    for name, content in (
        ("events.json", events), ("ledger.json", ledger), ("allowlist-audit.json", audit),
        ("summary.json", {"suppressed": {day: dict(row) for day, row in sorted(suppressed.items())},
                          "friday_boost": friday, "hunting": hunts,
                          "demo_expected": [{"day": day, "severity": severity, "counts": counts}
                                            for (day, severity), counts in sorted(expected.items())],
                          "demo_events": len(events)}),
    ):
        (OUTPUT / name).write_text(json.dumps(content, indent=2, allow_nan=False) + "\n")
    print((OUTPUT / "summary.json").read_text(), flush=True)


if __name__ == "__main__":
    main()
