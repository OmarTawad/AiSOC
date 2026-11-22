"""Freeze CICIDS benign operating points, then run the single test evaluation."""

from hashlib import sha256
import importlib.util
import json
from pathlib import Path

import joblib
import numpy as np
import xgboost as xgb

from evaluation import ARTIFACTS, FAMILIES, chronological, family_split, load, result, save, tune

ML = Path(__file__).resolve().parents[1]
UC1B = ML / "uc1b_xgboost_cicids"
UC2 = ML / "uc2_iforest_cicids"
CAP = .01
GATE = .02


def module_at(name, location):
    spec = importlib.util.spec_from_file_location(name, location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def freeze(benign_scores):
    if not len(benign_scores):
        raise ValueError("Missing benign validation flows")
    threshold = tune(np.zeros(len(benign_scores), dtype=int), benign_scores, CAP, optimize_f1=False)
    fp = int((benign_scores.astype(np.float64) >= threshold).sum())
    assert fp / len(benign_scores) <= CAP
    return {"threshold": threshold, "benign_validation": len(benign_scores),
            "validation_false_positives": fp, "validation_benign_fpr": fp / len(benign_scores)}


def assess(truth, scores, frozen, family):
    metrics = result(truth, scores, frozen["threshold"], family)
    tn, fp = metrics["confusion_matrix"][0]
    fpr = fp / (fp + tn)
    return {**metrics, "benign_fpr": fpr, "alerts_per_10k_benign": fpr * 10000,
            "deployment_gate_passed": fpr <= GATE}


def xgb_scores(model, matrix):
    return model.predict(xgb.DMatrix(matrix, nthread=2))


def fit_xgb(matrix, truth):
    return xgb.XGBClassifier(
        n_estimators=150, max_depth=4, learning_rate=.08, min_child_weight=3,
        subsample=.9, colsample_bytree=.85, tree_method="hist",
        n_jobs=2, random_state=42, objective="binary:logistic",
    ).fit(matrix, truth).get_booster()


def main():
    uc1_path = UC1B / "metrics.json"
    uc2_path = UC2 / "metrics.json"
    if ARTIFACTS.joinpath("fpr-friday.npz").exists():
        raise SystemExit("The frozen Friday evaluation has already run")
    rows, matrix, family, target, cleanup = load()
    train, validation, friday = chronological(rows)
    ftrain, fval, ftest = family_split(rows)
    isolation = module_at("isolation", UC2 / "train.py")
    xgb_path = ARTIFACTS / "uc1b.ubj"
    chronological_xgb = xgb.Booster({"nthread": 2})
    chronological_xgb.load_model(xgb_path)
    chronological_iforest = isolation.fit_benign(matrix[train & (target == 0)])
    all_family_xgb = fit_xgb(matrix[ftrain], target[ftrain])
    family_iforest = isolation.fit_benign(matrix[ftrain & (target == 0)])
    family_xgb = {name: fit_xgb(matrix[ftrain & (family != name)], target[ftrain & (family != name)])
                  for name in FAMILIES}
    benign_val = matrix[validation & (target == 0)]
    benign_family_val = matrix[fval & (target == 0)]
    calibration_xgb = {
        "cap": CAP, "gate": GATE, "calibration": freeze(xgb_scores(chronological_xgb, benign_val)),
        "family_reference_calibration": freeze(xgb_scores(all_family_xgb, benign_family_val)),
        "family_holdout_calibration": {name: freeze(xgb_scores(model, benign_family_val))
                                       for name, model in family_xgb.items()},
        "model_version": "uc1b-cic-" + sha256(xgb_path.read_bytes()).hexdigest()[:12],
    }
    iforest_path = ARTIFACTS / "uc2.joblib"
    joblib.dump(chronological_iforest, iforest_path)
    calibration_iforest = {
        "cap": CAP, "gate": GATE, "calibration": freeze(isolation.score(chronological_iforest, benign_val)),
        "family_reference_calibration": freeze(isolation.score(family_iforest, benign_family_val)),
        "model_version": "uc2-cic-" + sha256(iforest_path.read_bytes()).hexdigest()[:12],
    }
    uc1 = json.loads(uc1_path.read_text())
    uc1["benign_fpr_protocol"] = calibration_xgb
    uc2 = {"cleanup": cleanup, "benign_training_count": int((train & (target == 0)).sum()),
           "family_benign_training_count": int((ftrain & (target == 0)).sum()),
           "benign_fpr_protocol": calibration_iforest}

    # The frozen records are written before either Friday test score is computed.
    save(uc1_path, uc1)
    save(uc2_path, uc2)
    print("Frozen validation thresholds", calibration_xgb["calibration"], calibration_iforest["calibration"], flush=True)
    xgb_test = xgb_scores(chronological_xgb, matrix[friday])
    iforest_test = isolation.score(chronological_iforest, matrix[friday])
    np.savez_compressed(ARTIFACTS / "fpr-friday.npz", xgb=xgb_test, iforest=iforest_test)
    for report, scores in ((calibration_xgb, xgb_test), (calibration_iforest, iforest_test)):
        report["friday"] = assess(target[friday], scores, report["calibration"], family[friday])
    family_reference = xgb_scores(all_family_xgb, matrix[ftest])
    family_unsupervised = isolation.score(family_iforest, matrix[ftest])
    comparisons = {}
    for name in FAMILIES:
        compare = np.isin(family[ftest], ["benign", name])
        held_xgb = xgb_scores(family_xgb[name], matrix[ftest][compare])
        evaluations = (
            ("xgboost_all_families", family_reference[compare], calibration_xgb["family_reference_calibration"]),
            ("xgboost_held_out", held_xgb, calibration_xgb["family_holdout_calibration"][name]),
            ("isolation_forest", family_unsupervised[compare], calibration_iforest["family_reference_calibration"]),
        )
        comparisons[name] = {key: assess(target[ftest][compare], scores, frozen, family[ftest][compare])
                             for key, scores, frozen in evaluations}
    uc2["family_comparison"] = comparisons
    save(uc1_path, uc1)
    save(uc2_path, uc2)
    print(json.dumps({"xgb": calibration_xgb["friday"], "iforest": calibration_iforest["friday"]}), flush=True)


if __name__ == "__main__":
    main()
