"""Project the pinned CIC-IDS2017 capture and materialize bounded demo slices."""

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml" / "uc3_behaviour_cicids"))
from behaviour import robust_fit  # noqa: E402
from delivery import FEATURES, MON, PREREG, SLICES, disk_check, parse_clock, remote_parquet  # noqa: E402

CACHE = ROOT / "data" / "demo"
SCENARIOS = dict(zip(("patator", "dos"), SLICES, strict=True))
COLUMNS = ["Timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "attack_label", *FEATURES]
CACHE_LIMIT = 100_000_000
AUTH_PORTS = set(PREREG["uc3"]["auth_ports"])


def minute_features(rows):
    ports = {row["destination_port"] for row in rows if row["destination_port"] is not None}
    peers = {row["destination_ip"] for row in rows if row["destination_ip"]}
    auth = sum(row["destination_port"] in AUTH_PORTS for row in rows)
    short = sum(is_short(row) for row in rows)
    return np.array([len(rows), len(ports), len(peers), auth, short / len(rows)])


def is_short(row):
    duration, forward, backward = (row[name] for name in FEATURES[:3])
    return (
        duration is not None
        and duration <= PREREG["uc3"]["short_flow_max_microseconds"]
        and forward is not None
        and backward is not None
        and forward + backward <= PREREG["uc3"]["short_flow_max_packets"]
    )


def load_remote(names, need_baselines):
    tables = {name: [] for name in names}
    dates = {SCENARIOS[name]: name for name in names}
    monday = defaultdict(list)
    row_index = 0
    print("Reading projected columns from the pinned Hugging Face parquet…", flush=True)
    with remote_parquet(PREREG["dataset_revision"]) as parquet:
        for batch in parquet.iter_batches(batch_size=32768, columns=COLUMNS, use_threads=False):
            disk_check()
            stamps = batch.column(0).to_pylist()
            indexes = defaultdict(list)
            seconds = defaultdict(list)
            for index, stamp in enumerate(stamps):
                clock = parse_clock(stamp)
                if clock is None:
                    continue
                day, second = clock
                if day == MON and need_baselines:
                    name = MON
                elif day in dates and SLICES[day][0] <= second // 60 < SLICES[day][1]:
                    name = dates[day]
                else:
                    continue
                indexes[name].append(index)
                seconds[name].append(second)
            for name, selected in indexes.items():
                subset = batch.take(pa.array(selected, type=pa.int64()))
                if name == MON:
                    keep = ["source_ip", "destination_ip", "destination_port", *FEATURES[:3]]
                    for second, row in zip(seconds[name], subset.select(keep).to_pylist(), strict=True):
                        if row["source_ip"]:
                            monday[row["source_ip"], second // 60].append(row)
                else:
                    table = pa.Table.from_batches([subset]).drop(["Timestamp"])
                    tables[name].append(
                        table.append_column("capture_second", pa.array(seconds[name])).append_column(
                            "row_id", pa.array([row_index + i for i in selected])
                        )
                    )
            row_index += len(batch)
    output = {
        name: pa.concat_tables(parts).sort_by([("capture_second", "ascending"), ("row_id", "ascending")]) for name, parts in tables.items()
    }
    return output, fit_baselines(monday) if need_baselines else None


def fit_baselines(monday):
    by_host = defaultdict(list)
    for (ip, _), rows in monday.items():
        by_host[ip].append(minute_features(rows))
    rows = [values for group in by_host.values() for values in group]
    baselines = {ip: robust_fit(values) for ip, values in by_host.items()}
    baselines["global"] = robust_fit(rows)
    return baselines


def prepare():
    disk_check()
    tables, baselines = load_remote(SCENARIOS, need_baselines=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    baseline_json = {ip: [median.tolist(), scale.tolist()] for ip, (median, scale) in baselines.items()}
    manifest = {"revision": PREREG["dataset_revision"], "baselines": baseline_json}
    paths = []
    try:
        for name, table in tables.items():
            disk_check()
            temp = CACHE / f"{name}.parquet.tmp"
            paths.append(temp)
            pq.write_table(table, temp, compression="zstd")
        metadata = CACHE / "baselines.json.tmp"
        paths.append(metadata)
        metadata.write_text(json.dumps(manifest, allow_nan=False))
        total = sum(path.stat().st_size for path in paths)
        if total > CACHE_LIMIT:
            raise ValueError(f"Demo cache would occupy {total:,} bytes")
        disk_check()
        for path in paths:
            path.replace(path.with_suffix(""))
    finally:
        for path in paths:
            path.unlink(missing_ok=True)
    print(
        f"Prepared {total / 1_000_000:.1f} MB | " + " | ".join(f"{name}: {len(table):,} flows" for name, table in tables.items()),
        flush=True,
    )


def baseline_cache():
    path = CACHE / "baselines.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    if data["revision"] != PREREG["dataset_revision"]:
        raise ValueError("Prepared baseline revision differs from the frozen capture")
    return {ip: (np.array(median), np.array(scale)) for ip, (median, scale) in data["baselines"].items()}


if __name__ == "__main__":
    prepare()
