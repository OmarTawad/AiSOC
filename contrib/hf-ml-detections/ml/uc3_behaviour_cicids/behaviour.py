"""Minute-level baselines and offline reproduction of the UEBA scoring core."""

from collections import defaultdict
import math

import numpy as np

from clock import PREREG

SETTINGS = PREREG["uc3"]
UEBA = PREREG["ueba_reference"]


def robust_fit(samples):
    values = np.asarray(samples)
    median = np.median(values, axis=0)
    mad = np.median(np.abs(values - median), axis=0)
    scale = np.maximum(mad * SETTINGS["mad_multiplier"], SETTINGS["minimum_scales"])
    return median, scale


class RunningBaseline:
    """Equivalent to UEBA's Welford update and personal deviation score."""

    def __init__(self):
        self.n = 0
        self.mean = np.zeros(5)
        self.m2 = np.zeros(5)

    def update(self, values):
        self.n += 1
        diff = values - self.mean
        self.mean += diff / self.n
        self.m2 += diff * (values - self.mean)

    def score(self, values):
        if self.n < UEBA["min_samples"]:
            return 0.0
        std = np.sqrt(np.maximum(self.m2, 0) / (self.n - 1))
        keep = std >= UEBA["zero_variance_epsilon"]
        z = (values[keep] - self.mean[keep]) / std[keep]
        return min(math.sqrt(float(np.dot(z, z))), 10.0)


def top_reasons(values, median, z):
    order = np.argsort(-z, kind="stable")[:3]
    return "; ".join(
        f"{SETTINGS['features'][i]} {values[i]:.3g} vs baseline {median[i]:.3g} (z={z[i]:.2f})"
        for i in order
    )


def evaluate_minutes(minute_features):
    monday = SETTINGS["baseline_day"]
    training = defaultdict(list)
    ueba = defaultdict(RunningBaseline)
    for (day, source, minute), metrics in sorted(minute_features.items()):
        if day == monday:
            training[source].append(metrics)
            ueba[source].update(metrics)
    personal = {source: robust_fit(samples) for source, samples in training.items()}
    fallback = robust_fit([values for samples in training.values() for values in samples])
    previous = {}
    robust_alerts = {}
    ueba_alerts = set()
    fallback_minutes = 0
    counts = 0
    for (day, source, minute), values in sorted(minute_features.items()):
        if day == monday:
            continue
        key = day, source
        median, scale = personal.get(source, fallback)
        fallback_minutes += source not in personal
        counts += 1
        z = (values - median) / scale
        score = float(z.max())
        start, length = previous.get(key, (-2, 0))
        length = (length + 1 if start == minute - 1 else 1) if score >= SETTINGS["threshold"] else 0
        previous[key] = minute, length
        bucket = day, source, minute // 5
        if length >= SETTINGS["consecutive_minutes"]:
            existing = robust_alerts.get(bucket)
            if existing is None or score > existing[0]:
                robust_alerts[bucket] = (score, top_reasons(values, median, z))
        if ueba[source].score(values) >= UEBA["threshold"]:
            ueba_alerts.add(bucket)
        ueba[source].update(values)
    return robust_alerts, ueba_alerts, {
        "monday_entities": len(training),
        "monday_active_minutes": sum(map(len, training.values())),
        "evaluation_active_minutes": counts,
        "global_fallback_minutes": fallback_minutes,
    }
