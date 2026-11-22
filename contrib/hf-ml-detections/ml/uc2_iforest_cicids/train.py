"""Isolation Forest fitted on benign flow telemetry only."""

from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer

HERE = Path(__file__).resolve().parent


def transform(matrix):
    return np.sign(matrix) * np.log1p(np.abs(matrix))


def fit_benign(matrix):
    if not len(matrix):
        raise ValueError("Isolation Forest needs benign training flows")
    transformed = transform(matrix)
    imputer = SimpleImputer(strategy="median", keep_empty_features=True).fit(transformed)
    clean = imputer.transform(transformed)
    model = IsolationForest(n_estimators=160, max_samples=256, random_state=42, n_jobs=2).fit(clean)
    q1, median, q3 = np.quantile(clean, [.25, .5, .75], axis=0)
    return {"imputer": imputer, "model": model, "median": median, "scale": np.maximum(q3 - q1, .1)}


def score(model, matrix):
    return 1.0 - model["model"].score_samples(model["imputer"].transform(transform(matrix)))


def deviations(model, matrix):
    transformed = model["imputer"].transform(transform(matrix))
    return (transformed - model["median"]) / model["scale"]
