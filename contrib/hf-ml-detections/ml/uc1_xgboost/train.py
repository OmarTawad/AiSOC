"""Train UC1 and evaluate the fixed chronological and organization holdouts."""

import argparse
from collections import Counter
import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score
from sklearn.preprocessing import MaxAbsScaler
import xgboost as xgb

from features import dataset, event_features, windows
from source import DATA, disk_check

HERE = Path(__file__).resolve().parent
ARTIFACTS = DATA / "uc1_xgboost"
POPULATION_PREVALENCE = 0.0038
SAMPLE_PREVALENCE = 0.0386
ALERT_BUDGET = 0.05
ELIGIBLE = ("hf_auth", "hf_network")
SEED = 42


def divide(a, b):
    return float(a / b) if b else None


def metrics(labels, scores, threshold):
    if not len(labels):
        return {"rows": 0}
    predicted = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel().tolist()
    tpr, fpr = divide(tp, tp + fn), divide(fp, tn + fp)
    has_both = tpr is not None and fpr is not None
    result = {
        "rows": len(labels), "malicious": tp + fn, "alert_count": tp + fp,
        "pr_auc_average_precision": float(average_precision_score(labels, scores)) if has_both else None,
        "roc_auc": float(roc_auc_score(labels, scores)) if has_both else None,
        "precision": divide(tp, tp + fp), "recall": tpr,
        "f1": divide(2 * tp, 2 * tp + fp + fn),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "score_quantiles": np.quantile(scores, [0, .25, .5, .75, 1]).tolist(),
    }
    for name, prevalence in (("sample", SAMPLE_PREVALENCE), ("population", POPULATION_PREVALENCE)):
        result[f"precision_at_{name}_prevalence"] = (
            divide(tpr * prevalence, tpr * prevalence + fpr * (1 - prevalence)) if has_both else None
        )
    return result


def choose_threshold(labels, scores):
    if len(np.unique(labels)) != 2:
        raise ValueError("Threshold tuning requires both classes in validation")
    order = np.argsort(-scores, kind="stable")
    sorted_scores = scores[order]
    indices = np.r_[np.flatnonzero(sorted_scores[1:] != sorted_scores[:-1]), len(scores) - 1]
    positives = np.cumsum(labels[order])[indices]
    negatives = indices + 1 - positives
    weights = POPULATION_PREVALENCE * positives / labels.sum()
    weights += (1 - POPULATION_PREVALENCE) * negatives / (len(labels) - labels.sum())
    f1 = 2 * positives / (labels.sum() + indices + 1)
    feasible = np.flatnonzero(weights <= ALERT_BUDGET)
    if not len(feasible):
        return float(np.nextafter(1.0, 2.0)), 0.0
    best = feasible[np.argmax(f1[feasible])]
    return float(sorted_scores[indices[best]]), float(weights[best])


def classifier(matrix, labels):
    model = xgb.XGBClassifier(
        n_estimators=180, max_depth=4, learning_rate=0.08, min_child_weight=3,
        subsample=0.9, colsample_bytree=0.85, tree_method="hist",
        objective="binary:logistic", n_jobs=2, random_state=SEED,
    )
    model.fit(matrix, labels)
    return model


def heuristic(features):
    actions = {"action=block", "action=deny", "action=denied", "action=drop", "action=failed", "action=failure"}
    return np.array([
        0.65 * (f"action={row['action']}" in actions)
        + 0.35 * (row["dst_port"] in {22, 135, 139, 445, 3389})
        for row in features
    ])


def summary_plot(model, matrix, names):
    subset = matrix[np.random.default_rng(SEED).choice(matrix.shape[0], min(700, matrix.shape[0]), replace=False)]
    # XGBoost pred_contribs computes exact Tree SHAP values for its tree ensemble.
    contributions = model.get_booster().predict(xgb.DMatrix(subset), pred_contribs=True)[:, :-1]
    values = np.abs(contributions).mean(axis=0)
    top = np.argsort(values)[-15:]
    fig, ax = plt.subplots(figsize=(8, 5.5), layout="constrained")
    ax.barh(names[top], values[top], color="#17677b")
    ax.set_xlabel("Mean absolute Tree SHAP contribution (log-odds)")
    ax.set_title("Precinct6 XGBoost feature contributions")
    fig.savefig(HERE / "shap-top15.png", dpi=150)
    plt.close(fig)
    return [{"feature": str(names[i]), "mean_abs_shap": float(values[i])} for i in reversed(top)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-vpc", action="store_true", help="Use only after verifying VPC has meaningful benign coverage")
    args = parser.parse_args()
    disk_check()
    rows = dataset()
    features = event_features(rows)
    family = np.array([r[3] for r in rows])
    organization = np.array([r[1] for r in rows])
    labels_text = np.array([r[0]["label_binary"] for r in rows])
    binary = np.isin(labels_text, ["benign", "malicious"])
    label = (labels_text == "malicious").astype(int)
    eligible = binary & np.isin(family, [*ELIGIBLE, "vpc"] if args.include_vpc else ELIGIBLE)
    initial_split, _ = windows(rows)
    initial_test = eligible & (initial_split == 2)
    split, boundaries = windows(rows, cohort=eligible)
    train, val, test = (eligible & (split == number) for number in range(3))
    encoder = DictVectorizer(dtype=np.float32)
    encoder.fit([item for item, use in zip(features, train, strict=True) if use])
    matrix = encoder.transform(features)
    model = classifier(matrix[train], label[train])
    xgb_scores = model.predict_proba(matrix)[:, 1]
    scaler = MaxAbsScaler().fit(matrix[train])
    linear = LogisticRegression(C=1, max_iter=400, random_state=SEED).fit(scaler.transform(matrix[train]), label[train])
    linear_scores = linear.predict_proba(scaler.transform(matrix))[:, 1]
    alternate = event_features(rows, with_source=True)
    other_encoder = DictVectorizer(dtype=np.float32).fit([item for item, use in zip(alternate, train, strict=True) if use])
    other_matrix = other_encoder.transform(alternate)
    ablation_scores = classifier(other_matrix[train], label[train]).predict_proba(other_matrix)[:, 1]
    all_mapped = binary & (family != "skipped") & (split == 2)
    methods = {}
    for name, scores in (
        ("heuristic", heuristic(features)), ("logistic", linear_scores),
        ("xgboost", xgb_scores), ("xgboost_with_source", ablation_scores),
    ):
        threshold, alert_rate = choose_threshold(label[val], scores[val])
        methods[name] = {
            "threshold": threshold, "validation_alerts_per_10k": alert_rate * 10000,
            "validation": metrics(label[val], scores[val], threshold),
            "test": metrics(label[test], scores[test], threshold),
            "all_mapped_test": metrics(label[all_mapped], scores[all_mapped], threshold),
            "families": {
                group: metrics(label[mask], scores[mask], threshold)
                for group in (*ELIGIBLE, "vpc")
                for mask in [binary & (split == 2) & (family == group)]
            },
        }
    threshold = methods["xgboost"]["threshold"]
    holdouts = {}
    for org in sorted(set(organization[eligible])):
        dev = eligible & (organization != org) & (split == 0)
        tune = eligible & (organization != org) & (split == 1)
        held = eligible & (organization == org) & (split == 2)
        if not held.any() or len(np.unique(label[dev])) < 2 or len(np.unique(label[tune])) < 2:
            holdouts[org] = {"rows": int(held.sum()), "status": "insufficient class support"}
            continue
        enc = DictVectorizer(dtype=np.float32).fit([item for item, keep in zip(features, dev, strict=True) if keep])
        trained = classifier(enc.transform([item for item, keep in zip(features, dev, strict=True) if keep]), label[dev])
        tune_scores = trained.predict_proba(enc.transform([item for item, keep in zip(features, tune, strict=True) if keep]))[:, 1]
        cutoff, _ = choose_threshold(label[tune], tune_scores)
        held_scores = trained.predict_proba(enc.transform([item for item, keep in zip(features, held, strict=True) if keep]))[:, 1]
        holdouts[org] = {"threshold": cutoff, **metrics(label[held], held_scores, cutoff)}
    fp = np.flatnonzero(test & (label == 0) & (xgb_scores >= threshold))
    fp = fp[np.argsort(-xgb_scores[fp], kind="stable")[:20]]
    fp_groups = Counter((rows[i][0]["vendor_name"], rows[i][0]["message_type"]) for i in fp)
    suspicious = {}
    for group in ("all", *ELIGIBLE, "vpc", "skipped"):
        use = (labels_text == "suspicious") & (split == 2)
        if group != "all":
            use &= family == group
        values = xgb_scores[use]
        suspicious[group] = {
            "rows": len(values), "over_threshold": int((values >= threshold).sum()),
            "score_quantiles": np.quantile(values, [0, .25, .5, .75, 1]).tolist() if len(values) else [],
        }
    disk_check()
    ARTIFACTS.mkdir(exist_ok=True)
    model.save_model(ARTIFACTS / "model.ubj")
    joblib.dump(encoder, ARTIFACTS / "vectorizer.joblib")
    names = encoder.get_feature_names_out()
    top = summary_plot(model, matrix[test], names)
    report = {
        "evaluation": "mapped, binary, non-VPC" if not args.include_vpc else "mapped, binary",
        "split_boundaries_epoch": boundaries,
        "all_sample_split_headline_test": {"rows": int(initial_test.sum()), "malicious": int(label[initial_test].sum())},
        "all_rows_by_time_window": [int((split == i).sum()) for i in range(3)],
        "headline_rows_by_time_window": [int(mask.sum()) for mask in (train, val, test)],
        "sample_prevalence": SAMPLE_PREVALENCE, "population_prevalence": POPULATION_PREVALENCE,
        "models": methods, "organization_holdouts": holdouts, "suspicious_test": suspicious,
        "top_false_positive_groups": [
            {"vendor": v, "message_type": t, "count": count} for (v, t), count in fp_groups.most_common()
        ],
        "top15_shap": top,
    }
    (HERE / "metrics.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"threshold": threshold, "test": methods["xgboost"]["test"], "holdouts": holdouts}), flush=True)


if __name__ == "__main__":
    main()
