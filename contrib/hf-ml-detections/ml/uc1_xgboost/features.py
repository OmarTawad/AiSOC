"""Build event-time inputs from the fixed Precinct6 sample."""

from collections import defaultdict, deque
from datetime import datetime, timezone
from hashlib import blake2b
from ipaddress import ip_address
from itertools import groupby
import math
import re

import numpy as np
import pyarrow.parquet as pq

from source import RECOVERED, SAMPLE
from mapper import map_precinct6

TOKENS = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,31}")
SOURCE_FIELDS = ("stream_name", "message_type", "vendor_name", "product_name")
PAYLOAD_FIELDS = (
    "hf_row_index", "timestamp", "event_time", "artifact_id", "message_type",
    "stream_name", "action", "protocol", "src_ip", "dst_ip", "src_port", "dst_port",
    "src_host", "dst_host", "username", "product_name", "vendor_name", "severity",
    "label_binary", "label_confidence", "attack_tactics", "attack_techniques", "vendor_code",
)


def internal(value):
    try:
        address = ip_address(value)
    except ValueError:
        return -1
    return int(address.is_private)


def port(value):
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        return -1
    return result if 0 <= result <= 65535 else -1


def category(value):
    return str(value or "missing").strip().casefold() or "missing"


def dataset():
    local = pq.read_table(SAMPLE, columns=list(PAYLOAD_FIELDS)).to_pylist()
    extra = pq.read_table(RECOVERED).to_pylist()
    if len(local) != len(extra):
        raise ValueError("Recovered rows do not match the sample size")
    rows = []
    for record, recovered in zip(local, extra, strict=True):
        if record["hf_row_index"] != recovered["hf_row_index"]:
            raise ValueError("Recovered columns are not aligned to the sample")
        timestamp = record["timestamp"]
        if timestamp is None or not math.isfinite(timestamp):
            continue
        mapped = map_precinct6(record)
        family = mapped[0] if mapped else "skipped"
        if record["stream_name"] == "aws_vpc_flow_log":
            family = "vpc"
        rows.append((record, str(recovered["org_id"]), recovered["message_sanitized"], family))
    return sorted(rows, key=lambda row: (row[0]["timestamp"], row[0]["hf_row_index"]))


def hour_counts(rows):
    counts = np.zeros(len(rows), dtype=np.int32)
    history = defaultdict(deque)
    # First score all events at one instant, then expose that instant to later events.
    for now, timed in groupby(enumerate(rows), key=lambda item: item[1][0]["timestamp"]):
        pending = []
        for index, (record, organization, _, _) in timed:
            source = record["src_ip"]
            if not source:
                continue
            queue = history[organization, source]
            while queue and queue[0] < now - 3600:
                queue.popleft()
            counts[index] = len(queue)
            pending.append(queue)
        for queue in pending:
            queue.append(now)
    return counts


def event_features(rows, *, with_source=False):
    counts = hour_counts(rows)
    vectors = []
    for (row, _, text, _), prior in zip(rows, counts, strict=True):
        when = datetime.fromtimestamp(row["timestamp"], timezone.utc)
        values = {
            "src_port": port(row["src_port"]),
            "dst_port": port(row["dst_port"]),
            "protocol": category(row["protocol"]),
            "action": category(row["action"]),
            "hour": when.hour,
            "weekday": when.weekday(),
            "src_internal": internal(row["src_ip"]),
            "dst_internal": internal(row["dst_ip"]),
            "username_present": int(bool(row["username"])),
            "src_prior_hour_count": int(prior),
        }
        if with_source:
            values.update({name: category(row[name]) for name in SOURCE_FIELDS})
        for token in set(TOKENS.findall((text or "")[:512].casefold())):
            bucket = int.from_bytes(blake2b(token.encode(), digest_size=2).digest(), "big") % 512
            values[f"text_hash_{bucket:03d}"] = 1
        vectors.append(values)
    return vectors


def windows(rows, cohort=None, boundaries=None):
    timestamps = np.array([row[0]["timestamp"] for row in rows])
    if boundaries is None:
        selected = timestamps if cohort is None else timestamps[cohort]
        boundaries = [float(selected[int(len(selected) * ratio)]) for ratio in (0.70, 0.85)]
    return np.searchsorted(boundaries, timestamps, side="right"), boundaries
