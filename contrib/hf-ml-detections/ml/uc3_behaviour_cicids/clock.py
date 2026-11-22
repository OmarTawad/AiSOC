"""Validate candidate 24-hour timestamps against source order and capture schedule."""

from collections import Counter
from datetime import date
from functools import lru_cache
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "cicids"))
from source import DATA, PATTERN, disk_check, remote_parquet

PREREG = json.loads((HERE / "prereg.json").read_text())


@lru_cache(maxsize=32768)
def parse_clock(value):
    match = PATTERN.fullmatch((value or "").strip())
    if not match:
        return None
    day, month, year, hour, minute, second = (int(v or 0) for v in match.groups()[:6])
    if year < 100:
        year += 2000
    meridiem = match[7]
    if meridiem:
        if not 1 <= hour <= 12:
            return None
        hour = hour % 12 + (12 if meridiem.upper() == "PM" else 0)
    elif hour < 8:
        hour += 12
    if hour > 23 or minute > 59 or second > 59:
        return None
    try:
        return date(year, month, day).isoformat(), hour * 3600 + minute * 60 + second
    except ValueError:
        return None


def hhmmss(seconds):
    return f"{seconds // 3600:02}:{(seconds // 60) % 60:02}:{seconds % 60:02}"


def run():
    schedule = dict(zip(
        ("FTP-Patator", "SSH-Patator"),
        (PREREG["clock"]["ftp_minutes_from_midnight"], PREREG["clock"]["ssh_minutes_from_midnight"]),
        strict=True,
    ))
    previous = {}
    counts = Counter()
    bounds = {}
    inversions = Counter()
    largest_reverse = Counter()
    invalid = 0
    attacks = {label: {"rows": 0, "inside": 0, "minimum": 86400, "maximum": 0} for label in schedule}
    with remote_parquet(PREREG["dataset_revision"]) as parquet:
        for batch in parquet.iter_batches(batch_size=32768, columns=["Timestamp", "attack_label"], use_threads=False):
            disk_check()
            for time, label in zip(*[col.to_pylist() for col in batch.columns], strict=True):
                clock = parse_clock(time)
                if clock is None:
                    invalid += 1
                    continue
                day, sec = clock
                counts[day] += 1
                lo, hi = bounds.get(day, (86400, 0))
                bounds[day] = min(lo, sec), max(hi, sec)
                if day in previous and sec < previous[day]:
                    inversions[day] += 1
                    largest_reverse[day] = max(largest_reverse[day], previous[day] - sec)
                previous[day] = sec
                if day != "2017-07-04" or label not in schedule:
                    continue
                lo, hi = schedule[label]
                record = attacks[label]
                record["rows"] += 1
                record["inside"] += (lo - 5) * 60 <= sec <= (hi + 5) * 60
                record["minimum"] = min(record["minimum"], sec)
                record["maximum"] = max(record["maximum"], sec)
    for record in attacks.values():
        record["share_inside"] = record["inside"] / record["rows"] if record["rows"] else 0
        record["minimum"] = hhmmss(record["minimum"]) if record["rows"] else None
        record["maximum"] = hhmmss(record["maximum"]) if record["rows"] else None
    valid = invalid == 0 and not any(inversions.values()) and all(a["share_inside"] >= .95 for a in attacks.values())
    report = {
        "validated": valid, "invalid_rows": invalid,
        "days": {day: {"rows": counts[day], "range": [hhmmss(sec) for sec in bounds[day]],
                        "backsteps": inversions[day], "max_backstep_seconds": largest_reverse[day]} for day in sorted(counts)},
        "tuesday_schedule": attacks,
    }
    (HERE / "clock-validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    run()
