#!/usr/bin/env python3
# scripts/run_inference.py
import os, json, pickle, logging, argparse
from datetime import datetime, timezone
import numpy as np, pandas as pd
from tqdm import tqdm
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report
from catboost import CatBoostClassifier

from catlyst import config, utils

def main():
    utils.setup_logging(config.LOG_LEVEL)
    log = logging.getLogger("main")

    p = argparse.ArgumentParser(description="Two-stage inference + metrics")
    p.add_argument("--model",          default=config.MODEL_PATH_DEFAULT,
                   help="CatBoost model (.cbm)")
    p.add_argument("--meta",           default=config.META_PATH_DEFAULT,
                   help="Pickled metadata (feat_order,cat_cols,lookup)")
    p.add_argument("--input-json",     default=config.INPUT_JSON_DEFAULT,
                   help="Test JSON (exported_at + threats)")
    p.add_argument("--output",         default=config.OUTPUT_JSON_DEFAULT,
                   help="Where to write inference + metrics JSON")
    p.add_argument("--novelty-train",  default=config.NOVELTY_TRAIN_DEFAULT,
                   help="Train JSON to fit IsolationForest (None to disable)")
    p.add_argument("--iso-contamination", type=float, default=config.ISO_CONT_DEFAULT,
                   help="IF contamination fraction")
    p.add_argument("--iso-estimators",    type=int,   default=config.ISO_EST_DEFAULT,
                   help="IsolationForest n_estimators")
    p.add_argument("--novelty-threshold", type=float, default=config.NOVELTY_THRESHOLD_DEFAULT,
                   help="Threshold on IF score to flag outlier")
    p.add_argument("--prob-threshold",    type=float, default=config.PROB_THRESHOLD_DEFAULT,
                   help="Cut-off for labeling model prob as false positive")
    args = p.parse_args()

    log.info("Loading model + metadata")
    model, feat_order, cat_cols, lookup = utils.load_model_and_meta(
        args.model, args.meta
    )

    if args.novelty_train:
        log.info("Training IsolationForest for novelty")
        iso, iso_enc_meta = utils.build_isolation_forest(
            args.novelty_train, feat_order, cat_cols,
            args.iso_contamination, args.iso_estimators
        )
    else:
        iso = None
        iso_enc_meta = None

    log.info("Loading input JSON: %s", args.input_json)
    doc     = json.load(open(args.input_json, "r", encoding="utf-8"))
    threats = doc.get("threats", [])

    results  = []
    y_true   = []
    y_pred   = []
    y_prob   = []

    bar = tqdm(threats, desc="Scoring threats", unit="thr")
    for th in bar:
        flat       = utils.flatten_threat(th)
        true_label = flat.pop("true_label", None)
        sha        = flat.get("threatInfo_sha256")

        # 1) fast lookup
        if sha and sha in lookup:
            prob       = float(lookup[sha])
            pred_label = int(lookup[sha])
            source     = "lookup"
            novel      = False
            nov_score  = None
        else:
            # 2) general CatBoost
            dfX        = utils.prepare_features(pd.DataFrame([flat]), feat_order, cat_cols)
            prob       = model.predict_proba(dfX)[:,1][0]
            pred_label = 1 if prob >= args.prob_threshold else 0
            source     = "model"
            # 3) novelty with encoded IF features
            if iso:
                dfX_iso = utils._apply_iso_encoders(
                            dfX,
                            iso_enc_meta['num_cols'],
                            iso_enc_meta['low_card'],
                            iso_enc_meta['high_card'],
                            iso_enc_meta['freq_map'],
                            iso_enc_meta['ohe_columns']
                )
                nov_score = float(iso.decision_function(dfX_iso)[0])
                novel     = nov_score < args.novelty_threshold
            else:
                novel     = False
                nov_score = None

        # accumulate for metrics
        if true_label is not None:
            y_true.append(true_label)
            y_pred.append(pred_label)
            y_prob.append(prob)

        results.append({
            "id":            flat.get("thr_id"),
            "sha256":        sha,
            "true_label":    true_label,
            "prob_falsep":   prob,
            "pred_label":    pred_label,
            "source":        source,
            "is_novel":      novel,
            "novelty_score": nov_score
        })

    # ───── Compute overall metrics if we have any ground truth ──────────
    if y_true:
        acc    = accuracy_score(y_true, y_pred)
        auc    = roc_auc_score(y_true, y_prob)
        creport= classification_report(y_true, y_pred, output_dict=True)
        log.info("Accuracy = %.4f, AUC = %.4f", acc, auc)
    else:
        acc = auc = None
        creport = {}

    # ───── Write output JSON ─────────────────────────────────────────────
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    out = {
        "scored_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "metrics": {
            "accuracy":             acc,
            "roc_auc":              auc,
            "classification_report": creport
        },
        "results": results
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    log.info("Wrote %d scored threats + metrics → %s",
             len(results), args.output)
    log.info("Inference complete")

if __name__ == "__main__":
    main()
    pass