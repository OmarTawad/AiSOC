"""Shared CICIDS cohort, splits and alert-budget metrics."""

from collections import Counter
import json

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from source import DATA, FEATURES, disk_check

SEED = 42
ARTIFACTS = DATA / "cicids-models"
FAMILIES = ("dos", "portscan", "patator", "web")


def attack_family(label):
    key = label.casefold()
    if key in {"benign", "normal"}:
        return "benign"
    if "web attack" in key:
        return "web"
    if "patator" in key or key in {"brute force", "bruteforce"}:
        return "patator"
    if "portscan" in key:
        return "portscan"
    if "dos" in key or "heartbleed" in key:
        return "dos"
    return key


def load():
    disk_check()
    original = pd.read_parquet(DATA / "cicids.parquet")
    original = original.sort_values(["capture_day", "hf_row_index"], kind="stable").reset_index(drop=True)
    features = original[list(FEATURES)].astype("float64")
    values = features.to_numpy()
    counts = Counter({"sample_rows": len(original), "nan_cells": int(np.isnan(values).sum()),
                      "infinite_cells": int(np.isinf(values).sum())})
    features = features.replace([np.inf, -np.inf], np.nan)
    # Group identically observed numeric feature vectors across days and labels.
    # Conflicting fingerprints are not suitable supervised examples.
    fingerprint = pd.util.hash_pandas_object(features, index=False)
    conflicts = original["attack_label"].groupby(fingerprint).transform("nunique") > 1
    duplicates = fingerprint.duplicated()
    keep = ~(conflicts | duplicates)
    rows = original.loc[keep].reset_index(drop=True)
    numeric = features.loc[keep].to_numpy(dtype=np.float32)
    counts.update({"conflicting_rows_removed": int(conflicts.sum()),
                   "duplicate_rows_removed": int((duplicates & ~conflicts).sum()), "clean_rows": len(rows)})
    family = rows["attack_label"].map(attack_family).to_numpy()
    target = (family != "benign").astype(np.int8)
    return rows, numeric, family, target, dict(counts)


def chronological(rows):
    days = np.sort(rows["capture_day"].unique())
    if len(days) < 3:
        raise ValueError("Expected separate chronological training, validation and test days")
    day = rows["capture_day"].to_numpy()
    return np.isin(day, days[:-2]), day == days[-2], day == days[-1]


def family_split(rows):
    rng = np.random.default_rng(SEED)
    partitions = np.zeros(len(rows), dtype=np.int8)
    for indices in rows.groupby(["capture_day", "attack_label"], sort=True).indices.values():
        indices = rng.permutation(indices)
        if len(indices) < 3:
            partitions[indices] = 2
            continue
        val = max(1, int(len(indices) * .2))
        test = max(1, int(len(indices) * .2))
        partitions[indices[:val]] = 1
        partitions[indices[val:val + test]] = 2
    return [partitions == group for group in range(3)]


def tune(labels, scores, budget, *, optimize_f1=True):
    order = np.argsort(-scores, kind="stable")
    ranks = scores[order]
    ends = np.r_[np.flatnonzero(ranks[1:] != ranks[:-1]), len(ranks) - 1]
    feasible = ends[ends + 1 <= len(labels) * budget]
    if not len(feasible):
        return float(np.nextafter(float(ranks[0]), np.inf))
    if optimize_f1:
        positives = np.cumsum(labels[order])
        best = feasible[np.argmax(2 * positives[feasible] / (feasible + 1 + max(1, labels.sum())))]
    else:
        best = feasible[-1]
    return float(ranks[best])


def metrics(labels, scores, threshold):
    alert = scores.astype(np.float64) >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, alert, labels=[0, 1]).ravel().tolist()
    mixed = len(np.unique(labels)) == 2
    return {
        "rows": len(labels), "attack_rows": tp + fn, "alerts": tp + fp,
        "average_precision": float(average_precision_score(labels, scores)) if mixed else None,
        "roc_auc": float(roc_auc_score(labels, scores)) if mixed else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fn + fp) if 2 * tp + fn + fp else None,
        "alerts_per_10k": 10000 * (tp + fp) / len(labels) if len(labels) else None,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def result(labels, scores, threshold, family):
    groups = {}
    for name in sorted(set(family) - {"benign"}):
        use = family == name
        group = metrics(labels[use], scores[use], threshold)
        groups[str(name)] = {"rows": group["rows"], "recall": group["recall"]}
    return {"threshold": threshold, **metrics(labels, scores, threshold), "families": groups}


def save(path, payload):
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n")
