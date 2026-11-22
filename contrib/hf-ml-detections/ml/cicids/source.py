"""Read the CIC-IDS2017 flows with bounded remote parquet projections."""

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import date
import json
from pathlib import Path
import re
import shutil

import fsspec
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import requests

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
REPO = "rdpahalavan/CIC-IDS2017"
FILE = "Network-Flows/CICIDS_Flow.parquet"
FLOOR = int(1.5 * 1024**3)
FEATURES = (
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Mean", "Bwd IAT Mean",
    "Packet Length Mean", "Packet Length Std", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "Down/Up Ratio",
    "Active Mean", "Idle Mean",
)
PATTERN = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AP]M))?$", re.I)


def disk_check():
    if shutil.disk_usage(ROOT).free < FLOOR:
        raise SystemExit("Disk floor reached: less than 1.5 GiB free")


def timestamp_parts(value):
    match = PATTERN.fullmatch((value or "").strip())
    if match is None:
        return None, "invalid"
    day, month, year, hour, minute, second = (int(v or 0) for v in match.groups()[:6])
    meridiem = match[7]
    if year < 100:
        year += 2000
    try:
        capture_day = date(year, month, day)
    except ValueError:
        return None, "invalid"
    if minute > 59 or second > 59 or (meridiem and not 1 <= hour <= 12) or (not meridiem and hour > 23):
        return None, "invalid"
    style = "AM/PM" if meridiem else "24h-evidence" if hour == 0 or hour > 12 else "ambiguous-1-to-12"
    return capture_day.isoformat(), style


def revision():
    response = requests.get(f"https://huggingface.co/api/datasets/{REPO}", timeout=20)
    response.raise_for_status()
    return response.json()["sha"]


@contextmanager
def remote_parquet(sha):
    url = f"https://huggingface.co/datasets/{REPO}/resolve/{sha}/{FILE}"
    with fsspec.open(url, block_size=262144, cache_type="none") as stream:
        yield pq.ParquetFile(stream)


def census(parquet):
    day_counts = Counter()
    formats = Counter()
    full = Counter()
    invalid = 0
    for group in range(parquet.num_row_groups):
        disk_check()
        table = parquet.read_row_group(group, columns=["Timestamp", "attack_label"])
        for timestamp, label in zip(table["Timestamp"].to_pylist(), table["attack_label"].to_pylist(), strict=True):
            day, style = timestamp_parts(timestamp)
            full[label] += 1
            if day is None:
                invalid += 1
                continue
            day_counts[label, day] += 1
            formats[day, style] += 1
    return {
        "rows": parquet.metadata.num_rows, "groups": parquet.num_row_groups,
        "schema": {field.name: str(field.type) for field in parquet.schema_arrow},
        "labels": dict(full), "label_days": [[k, d, n] for (k, d), n in sorted(day_counts.items())],
        "timestamp_styles": [[d, style, n] for (d, style), n in sorted(formats.items())],
        "invalid_timestamps": invalid,
    }


def sample(parquet, report):
    rng = np.random.default_rng(42)
    counts = {(label, day): n for label, day, n in report["label_days"]}
    totals = Counter()
    for (label, _), count in counts.items():
        totals[label] += count
    selected = {}
    for key, n in sorted(counts.items()):
        label, _ = key
        cap = 10000 if label == "BENIGN" else 3000 if totals[label] > 3000 else n
        selected[key] = set(rng.choice(n, size=min(n, cap), replace=False).tolist())
    occurrences = Counter()
    columns = ["flow_id", "Timestamp", "attack_label", "source_ip", "destination_ip", *FEATURES]
    final = DATA / "cicids.parquet"
    temporary = DATA / "cicids.partial"
    offset = 0
    schema = pa.schema([*(parquet.schema_arrow.field(name) for name in columns), pa.field("capture_day", pa.string()), pa.field("hf_row_index", pa.int64())])
    try:
        with pq.ParquetWriter(temporary, schema, compression="zstd") as writer:
            for group in range(parquet.num_row_groups):
                disk_check()
                index = parquet.read_row_group(group, columns=["Timestamp", "attack_label"])
                keep = []
                days = []
                for row, (timestamp, label) in enumerate(zip(index["Timestamp"].to_pylist(), index["attack_label"].to_pylist(), strict=True)):
                    day, _ = timestamp_parts(timestamp)
                    if day is None:
                        continue
                    key = label, day
                    if occurrences[key] in selected[key]:
                        keep.append(row)
                        days.append(day)
                    occurrences[key] += 1
                if keep:
                    table = parquet.read_row_group(group, columns=columns).select(columns).take(keep)
                    table = table.append_column("capture_day", pa.array(days, type=pa.string()))
                    table = table.append_column("hf_row_index", pa.array([offset + i for i in keep], type=pa.int64()))
                    writer.write_table(table)
                offset += len(index)
                if temporary.stat().st_size > 150_000_000:
                    raise ValueError("CIC sample exceeds 150 MB")
        if temporary.stat().st_size > 150_000_000:
            raise ValueError("CIC sample exceeds 150 MB")
        temporary.replace(final)
    finally:
        temporary.unlink(missing_ok=True)
    print("sample", pq.ParquetFile(final).metadata.num_rows, final.stat().st_size, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["census", "sample"])
    args = parser.parse_args()
    disk_check()
    report_path = DATA / "cicids-census.json"
    if args.operation == "census":
        sha = revision()
        with remote_parquet(sha) as parquet:
            report = {"revision": sha, **census(parquet)}
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "schema"}), flush=True)
    else:
        report = json.loads(report_path.read_text())
        with remote_parquet(report["revision"]) as parquet:
            sample(parquet, report)


if __name__ == "__main__":
    main()
