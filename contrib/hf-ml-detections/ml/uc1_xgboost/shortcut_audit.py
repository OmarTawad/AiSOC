"""Rerun the existing Precinct6 split without action or ports."""

import json

import numpy as np
from sklearn.feature_extraction import DictVectorizer

from features import dataset, event_features, windows
from train import ELIGIBLE, HERE, choose_threshold, classifier, metrics


def run():
    rows = dataset()
    inputs = event_features(rows)
    for features in inputs:
        for name in ("src_port", "dst_port", "action"):
            del features[name]
    base = json.loads((HERE / "metrics.json").read_text())
    split, _ = windows(rows, boundaries=base["split_boundaries_epoch"])
    labels = np.array([r[0]["label_binary"] for r in rows])
    truth = (labels == "malicious").astype(int)
    orgs = np.array([r[1] for r in rows])
    eligible = np.isin([r[3] for r in rows], ELIGIBLE) & np.isin(labels, ["benign", "malicious"])
    results = {}
    for org in (None, *sorted(set(orgs[eligible]))):
        development = eligible if org is None else eligible & (orgs != org)
        train, validation = (development & (split == i) for i in (0, 1))
        held = eligible & (split == 2)
        if org is not None:
            held &= orgs == org
        if not held.any() or len(np.unique(truth[train])) < 2 or len(np.unique(truth[validation])) < 2:
            results[org or "overall"] = {"rows": int(held.sum()), "status": "insufficient class support"}
            continue
        train_rows = [inputs[i] for i in np.flatnonzero(train)]
        encoder = DictVectorizer(dtype=np.float32)
        model = classifier(encoder.fit_transform(train_rows), truth[train])
        validation_scores = model.predict_proba(encoder.transform([inputs[i] for i in np.flatnonzero(validation)]))[:, 1]
        threshold, _ = choose_threshold(truth[validation], validation_scores)
        held_scores = model.predict_proba(encoder.transform([inputs[i] for i in np.flatnonzero(held)]))[:, 1]
        results[org or "overall"] = {"threshold": threshold, **metrics(truth[held], held_scores, threshold)}
    (HERE / "shortcut-audit.json").write_text(json.dumps(results, indent=2, allow_nan=False) + "\n")
    print({org: (m.get("pr_auc_average_precision"), m.get("recall")) for org, m in results.items()}, flush=True)


if __name__ == "__main__":
    run()
