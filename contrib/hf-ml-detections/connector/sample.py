"""Read projected parquet columns remotely and publish a bounded local sample."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import random
import tempfile

import fsspec
import pyarrow as pa
import pyarrow.parquet as pq

DATA = Path(__file__).resolve().parents[1] / "data"
CAP = 300_000_000
SEED = 42
BASE = "https://huggingface.co/datasets"
SIGNALS = (
    f"{BASE}/witfoo/precinct6-cybersecurity/resolve/"
    "96311c2e29611d8ddbf1c0d59f531f6a362b8233/signals/signals.parquet"
)
SIEM = (
    f"{BASE}/darkknight25/Advanced_SIEM_Dataset/resolve/"
    "76501f045606bc9ec5116b8448430fdb079eea08/default/train/0000.parquet"
)
SIGNALS_FIELDS = (
    "event_time timestamp artifact_id message_type stream_name product_name vendor_name "
    "src_ip dst_ip src_port dst_port protocol src_host dst_host username action severity "
    "vendor_code label_binary label_confidence attack_tactics attack_techniques"
).split()
SIEM_FIELDS = (
    "event_id timestamp event_type source severity user action device_type src_ip dst_ip "
    "alert_type category src_port dst_port protocol bytes duration"
).split()


def day(value):
    if value is None or not math.isfinite(value):
        return "missing"
    return datetime.fromtimestamp(value, timezone.utc).date().isoformat()


def update_range(bounds, values):
    values = [
        datetime.fromtimestamp(value, timezone.utc).isoformat() if isinstance(value, (int, float)) else str(value)
        for value in values
        if value is not None and (not isinstance(value, float) or math.isfinite(value))
    ]
    if values:
        bounds[:] = [min(values + bounds[:1]), max(values + bounds[-1:])]


def allocate(size, strata, rng):
    """Allocate a proportional share by day, retaining one per day when possible."""
    if not strata or size <= 0:
        return {}
    total = sum(map(len, strata.values()))
    size = min(size, total)
    days = sorted(strata)
    quotas = {key: size * len(strata[key]) // total for key in days}
    if size >= len(days):
        for key in days:
            if not quotas[key]:
                donor = max(days, key=quotas.__getitem__)
                if sum(quotas.values()) == size:
                    quotas[donor] -= 1
                quotas[key] = 1
    order = sorted(days, key=lambda key: size * len(strata[key]) / total - quotas[key], reverse=True)
    while sum(quotas.values()) < size:
        for key in order:
            if quotas[key] < len(strata[key]):
                quotas[key] += 1
                if sum(quotas.values()) == size:
                    break
    return {key: rng.sample(strata[key], quotas[key]) for key in days}


def select_signals(parquet, target):
    strata = defaultdict(lambda: defaultdict(list))
    bounds = []
    stride = max(parquet.metadata.row_group(group).num_rows for group in range(parquet.num_row_groups))
    for group in range(parquet.num_row_groups):
        table = parquet.read_row_group(group, columns=["label_binary", "timestamp"])
        times = table["timestamp"].to_pylist()
        update_range(bounds, times)
        for index, (label, when) in enumerate(zip(table["label_binary"].to_pylist(), times, strict=True)):
            strata[label][day(when)].append(group * stride + index)
    full = {str(label): sum(map(len, months.values())) for label, months in strata.items()}
    if set(full) - {"benign", "suspicious", "malicious"}:
        raise ValueError(f"Unexpected Precinct6 labels: {sorted(full)}")
    rng = random.Random(SEED)
    chosen = [index for rows in strata["malicious"].values() for index in rows]
    remaining = max(0, target - len(chosen))
    suspicious = allocate(remaining // 2, strata["suspicious"], rng)
    chosen.extend(index for rows in suspicious.values() for index in rows)
    benign = allocate(max(0, target - len(chosen)), strata["benign"], rng)
    chosen.extend(index for rows in benign.values() for index in rows)
    selected = defaultdict(list)
    for item in sorted(chosen):
        group, index = divmod(item, stride)
        selected[group].append(index)
    return selected, full, bounds


def sample(dataset, target):
    precinct = dataset == "precinct6"
    url = SIGNALS if precinct else SIEM
    fields = SIGNALS_FIELDS if precinct else SIEM_FIELDS
    label_field = "label_binary" if precinct else "alert_type"
    destination = DATA / f"{dataset}.parquet"
    DATA.mkdir(exist_ok=True)
    existing_bytes = sum(path.stat().st_size for path in DATA.iterdir() if path.is_file() and path != destination)
    with fsspec.open(url, block_size=262144, cache_type="none") as remote, tempfile.TemporaryDirectory(dir=DATA) as tmp:
        parquet = pq.ParquetFile(remote, pre_buffer=True)
        selected, full, full_bounds = select_signals(parquet, target) if precinct else (None, {}, [])
        output = Path(tmp) / "sample.parquet"
        columns = [parquet.schema_arrow.field(name) for name in fields]
        schema = pa.schema([*columns, pa.field("hf_row_index", pa.int64())])
        counts = Counter()
        category_counts = Counter()
        bounds = []
        offset = 0
        with pq.ParquetWriter(output, schema, compression="zstd") as writer:
            for group in range(parquet.num_row_groups):
                size = parquet.metadata.row_group(group).num_rows
                indices = selected.get(group, []) if precinct else range(size)
                if indices:
                    table = parquet.read_row_group(group, columns=fields).select(fields)
                    if precinct:
                        table = table.take(indices)
                    table = table.append_column("hf_row_index", pa.array((offset + index for index in indices), type=pa.int64()))
                    writer.write_table(table)
                    counts.update(str(label) for label in table[label_field].to_pylist())
                    if not precinct:
                        category_counts.update(str(label) for label in table["category"].to_pylist())
                    update_range(bounds, table["timestamp"].to_pylist())
                    if existing_bytes + output.stat().st_size >= CAP:
                        raise ValueError("Local sample budget exceeded")
                offset += size
        if existing_bytes + output.stat().st_size > CAP:
            raise ValueError("Local sample budget exceeded")
        output.replace(destination)
    report = {
        "dataset": dataset,
        "seed": SEED,
        "full_rows": parquet.metadata.num_rows,
        "full_labels": full if precinct else dict(counts),
        "full_time_range": full_bounds if precinct else bounds,
        "sample_rows": sum(counts.values()),
        "sample_labels": dict(counts),
        "sample_time_range": bounds,
        "categories": dict(category_counts),
        "label_field": label_field,
        "sample_bytes": destination.stat().st_size,
    }
    (DATA / f"{dataset}-sample.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=["precinct6", "advanced-siem"], required=True)
    parser.add_argument("--target", type=int, default=200_000, help="Precinct6 target including every malicious row")
    args = parser.parse_args()
    if args.target < 1:
        parser.error("--target must be positive")
    sample(args.dataset, args.target)


if __name__ == "__main__":
    main()
