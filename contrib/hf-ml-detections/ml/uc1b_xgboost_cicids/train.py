"""Train and evaluate supervised CIC-IDS2017 flow detectors."""

import json
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import RobustScaler
import xgboost as xgb

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "cicids"))
from evaluation import ARTIFACTS, FAMILIES, chronological, family_split, load, result, save, tune
from source import FEATURES, disk_check

BUDGET = .03


def log_features(matrix):
    return np.sign(matrix) * np.log1p(np.abs(matrix))


def fit_scores(matrix, target, train):
    model = xgb.XGBClassifier(
        n_estimators=150, max_depth=4, learning_rate=.08, min_child_weight=3,
        subsample=.9, colsample_bytree=.85, tree_method="hist",
        n_jobs=2, random_state=42, objective="binary:logistic",
    ).fit(matrix[train], target[train])
    transformed = log_features(matrix)
    imputer = SimpleImputer(strategy="median", keep_empty_features=True).fit(transformed[train])
    transformed = imputer.transform(transformed)
    scale = RobustScaler().fit(transformed[train])
    linear_input = scale.transform(transformed)
    linear = LogisticRegression(max_iter=400, random_state=42).fit(linear_input[train], target[train])
    # Score only unusually high rates/durations against benign training quantiles.
    benign = transformed[train & (target == 0)]
    columns = [FEATURES.index(name) for name in ("Flow Duration", "Flow Bytes/s", "Flow Packets/s")]
    median, limit = np.quantile(benign[:, columns], [.5, .99], axis=0)
    heuristic = np.max((transformed[:, columns] - median) / np.maximum(limit - median, .1), axis=1)
    return model, {
        "heuristic": heuristic, "logistic": linear.predict_proba(linear_input)[:, 1],
        "xgboost": model.predict_proba(matrix)[:, 1],
    }


def compare(matrix, target, family, train, val, test):
    model, scores = fit_scores(matrix, target, train)
    comparisons = {}
    for name, values in scores.items():
        cutoff = tune(target[val], values[val], BUDGET)
        comparisons[name] = result(target[test], values[test], cutoff, family[test])
        comparisons[name]["validation_alerts_per_10k"] = float((values[val].astype("float64") >= cutoff).mean() * 10000)
    return model, comparisons


def shap_plot(model, matrix):
    selected = matrix[np.random.default_rng(42).choice(len(matrix), min(len(matrix), 750), replace=False)]
    shap = model.get_booster().predict(xgb.DMatrix(selected, nthread=2), pred_contribs=True)
    importance = np.mean(np.abs(shap[:, :-1]), axis=0)
    top = np.argsort(importance)[-15:]
    fig, ax = plt.subplots(figsize=(8, 5), layout="constrained")
    ax.barh(np.array(FEATURES)[top], importance[top], color="#146b72")
    ax.set_xlabel("Mean absolute Tree SHAP (log-odds)")
    ax.set_title("CIC-IDS2017 flow feature contributions")
    fig.savefig(HERE / "shap-top15.png", dpi=150)
    plt.close(fig)


def main():
    rows, matrix, family, target, cleanup = load()
    train, val, test = chronological(rows)
    model, baseline = compare(matrix, target, family, train, val, test)
    partitions = family_split(rows)
    holdouts = {}
    for name in FAMILIES:
        development = family != name
        held = partitions[2] & np.isin(family, ["benign", name])
        if not (family[held] == name).any():
            holdouts[name] = {"status": "unavailable"}
            continue
        _, scores = compare(matrix, target, family, partitions[0] & development, partitions[1] & development, held)
        holdouts[name] = scores
    disk_check()
    ARTIFACTS.mkdir(exist_ok=True)
    model.save_model(ARTIFACTS / "uc1b.ubj")
    shap_plot(model, matrix[test])
    report = {
        "cleanup": cleanup, "feature_allowlist": FEATURES, "threshold_budget": BUDGET,
        "class_days_after_cleanup": rows.groupby(["capture_day", "attack_label"]).size().unstack(fill_value=0).to_dict(),
        "split_days": {name: sorted(set(rows.loc[use, "capture_day"])) for name, use in zip(("train", "validation", "test"), (train, val, test), strict=True)},
        "test_families_absent_from_train": sorted(set(family[test]) - set(family[train])),
        "test_labels_absent_from_train": sorted(set(rows.loc[test, "attack_label"]) - set(rows.loc[train, "attack_label"])),
        "day_test": baseline, "family_holdouts": holdouts,
    }
    save(HERE / "metrics.json", report)
    print(json.dumps({k: report[k] for k in ("cleanup", "test_families_absent_from_train", "day_test", "family_holdouts")}), flush=True)


if __name__ == "__main__":
    main()
