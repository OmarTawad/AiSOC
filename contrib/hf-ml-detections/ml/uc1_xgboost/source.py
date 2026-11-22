"""Scan the VPC label population or enrich the fixed Day 2 row selection."""

import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import sys

import fsspec
import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "connector"))
from sample import DATA, SIGNALS

MIN_FREE = int(1.5 * 1024**3)
SAMPLE = DATA / "precinct6.parquet"
RECOVERED = DATA / "uc1-source.parquet"


def disk_check():
    if shutil.disk_usage(ROOT).free < MIN_FREE:
        raise SystemExit("Disk floor reached: less than 1.5 GiB is free")


def scan_population(parquet):
    counts = Counter()
    for group in range(parquet.num_row_groups):
        disk_check()
        table = parquet.read_row_group(group, columns=["stream_name", "label_binary"])
        labels = table["label_binary"].filter(pc.equal(table["stream_name"], "aws_vpc_flow_log"))
        counts.update(labels.to_pylist())
    return {"rows_scanned": parquet.metadata.num_rows, "vpc_labels": dict(counts)}


def recover(parquet):
    indices = pq.read_table(SAMPLE, columns=["hf_row_index"])["hf_row_index"].to_numpy()
    if not len(indices) or np.any(indices[1:] <= indices[:-1]):
        raise ValueError("Expected a non-empty, strictly ordered sample index")
    offset = 0
    columns = ["org_id", "message_sanitized"]
    batches = []
    for group in range(parquet.num_row_groups):
        disk_check()
        size = parquet.metadata.row_group(group).num_rows
        left, right = indices.searchsorted([offset, offset + size])
        if right > left:
            # Parquet transfers column chunks for the intersecting row groups.
            # Retain only the fixed sample's row indexes and these two columns.
            selected = indices[left:right]
            table = parquet.read_row_group(group, columns=columns).take(selected - offset)
            batches.append(table.append_column("hf_row_index", pa.array(selected)))
        offset += size
    result = pa.concat_tables(batches)
    if result.num_rows != len(indices):
        raise ValueError("Remote projection did not recover every sample row")
    temp = RECOVERED.with_suffix(".tmp")
    try:
        pq.write_table(result, temp, compression="zstd")
        disk_check()
        if temp.stat().st_size > 50_000_000:
            raise ValueError("Recovered columns exceed the 50 MB budget")
        temp.replace(RECOVERED)
    finally:
        temp.unlink(missing_ok=True)
    return {"recovered_rows": len(indices), "bytes": RECOVERED.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["population", "recover"])
    args = parser.parse_args()
    with fsspec.open(SIGNALS, block_size=262144, cache_type="none") as remote:
        parquet = pq.ParquetFile(remote)
        result = scan_population(parquet) if args.operation == "population" else recover(parquet)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
