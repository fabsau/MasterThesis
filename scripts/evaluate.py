# scripts/evaluate.py
import os
import argparse
import json
import pickle
from pathlib import Path

import numpy  as np
import pandas as pd
from sklearn.metrics      import roc_auc_score, classification_report
from catboost             import CatBoostClassifier

import sys, os
import pickle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from s1_pipeline import config
from etl   import load_raw_records, featurize

def build_test_features(
    test_json: Path,
    ignore_notes: bool,
    ignore_verdict: bool
):
    """
    Load raw threats from JSON, strip notes/verdict if requested,
    featurize each with your ETL, and return:
      - DataFrame of features (numeric + notes_text + label)
      - true_labels array
    """
    # 1) load raw records (now test_json is a Path)
    recs = load_raw_records(test_json)
    print(f"[i] Loaded {len(recs)} raw records from {test_json}")

    feats = []
    true_labels = []
    for r in recs:
        # pull true label BEFORE stripping
        v = r.get("threatInfo", {}).get("analystVerdict", "")
        lbl = 1 if v.lower() == "true_positive" else (0 if v.lower() == "false_positive" else None)
        true_labels.append(lbl)

        # strip notes if requested
        if ignore_notes:
            r["notes"] = []

        # strip analystVerdict so featurize cannot see it
        if ignore_verdict:
            r.get("threatInfo", {}).pop("analystVerdict", None)

        try:
            feats.append(featurize(r))
        except Exception as e:
            print(f"⚠️  featurize error skipping record: {e}")
            true_labels.pop()

    if not feats:
        raise RuntimeError("No test features created – aborting")

    df = pd.DataFrame(feats)
    # fill numeric NaNs
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(0.0)

    # reorder so label is last
    cols = [c for c in df.columns if c != "label"] + ["label"]
    df = df[cols]

    # our canonical true labels
    y_true = np.array(true_labels, dtype=int)
    return df, y_true


def main():
    p = argparse.ArgumentParser(
        description="Evaluate CatBoost+TFIDF model on raw test JSON"
    )
    p.add_argument(
        "--test-json", "-t",
        type=Path,
        default=Path(config.DEFAULT_TEST_JSON),
        help="Raw test JSON (contains notes & analystVerdict)"
    )
    p.add_argument(
        "--model", "-m",
        default=config.DEFAULT_MODEL_OUT,
        help="Trained CatBoost .cbm file"
    )
    p.add_argument(
        "--tfidf", "-f",
        default=config.DEFAULT_TFIDF_OUT,
        help="TFIDF pickle file (.tfidf.pkl) from train"
    )
    p.add_argument(
        "--results", "-r",
        default=config.DEFAULT_RESULTS_DIR,
        help="Directory to write metrics.json & feature_importance.txt"
    )
    p.add_argument(
        "--top-k", "-k",
        type=int,
        default=getattr(config, "EVAL_TOP_K", 20),
        help="How many top features to save"
    )
    p.add_argument(
        "--ignore-notes",
        action="store_true",
        help="Drop notes before featurizing (simulate prod missing-notes)"
    )
    p.add_argument(
        "--ignore-verdict",
        action="store_true",
        help="Drop analystVerdict before featurizing (simulate prod missing-label)"
    )
    args = p.parse_args()

    # 1) build DataFrame + true labels
    df_test, y_true = build_test_features(
        args.test_json,
        ignore_notes   = args.ignore_notes,
        ignore_verdict = args.ignore_verdict
    )

    # 2) split out numeric + notes_text
    notes = df_test["notes_text"].fillna("").astype(str).values
    X_num = df_test.drop(columns=["notes_text", "label"]).values
    num_feats = list(df_test.drop(columns=["notes_text", "label"]).columns)
    print(f"[i] Test set: {X_num.shape[0]} rows × {X_num.shape[1]} numeric features")

    # 3) load TF-IDF & transform notes
    print(f"[i] Loading TF-IDF from {args.tfidf}")
    with open(args.tfidf, "rb") as f:
        tfv = pickle.load(f)
    X_txt = tfv.transform(notes).toarray()
    txt_feats = list(tfv.get_feature_names_out())
    print(f"[i] Notes → TF-IDF → {X_txt.shape[1]} features")

    # 4) stack numeric + text
    X_test = np.hstack([X_num, X_txt])
    all_feats = num_feats + txt_feats

    # 5) load CatBoost model
    print(f"[i] Loading CatBoost model from {args.model}")
    model = CatBoostClassifier()
    model.load_model(args.model)

    # 6) predict + metrics
    proba = model.predict_proba(X_test)[:,1]
    thresh = getattr(config, "PROB_THRESHOLD_DEFAULT", 0.5)
    preds  = (proba >= thresh).astype(int)

    auc        = roc_auc_score(y_true, proba)
    report_dict= classification_report(y_true, preds, output_dict=True, digits=4)
    report_txt = classification_report(y_true, preds, digits=4)

    print(f"\n=== Test AUC: {auc:.4f}  (threshold={thresh}) ===\n")
    print("=== Classification Report ===\n", report_txt)

    # 7) feature importances
    fi_vals = model.get_feature_importance(type="FeatureImportance")
    fi      = list(zip(all_feats, fi_vals))
    fi_sorted = sorted(fi, key=lambda x: -x[1])[: args.top_k]

    # 8) save outputs
    os.makedirs(args.results, exist_ok=True)

    metrics = {
        "test_auc":             auc,
        "threshold":            thresh,
        "classification_report": report_dict
    }
    mfile = os.path.join(args.results, "metrics.json")
    with open(mfile, "w", encoding="utf-8") as mf:
        json.dump(metrics, mf, indent=2)
    print(f"[✔] Wrote metrics → {mfile}")

    fpath = os.path.join(args.results, "feature_importance.txt")
    with open(fpath, "w", encoding="utf-8") as ff:
        ff.write(f"{'Feature':<40} Importance\n")
        ff.write(f"{'-'*60}\n")
        for name, val in fi_sorted:
            ff.write(f"{name[:40]:<40} {val:8.3f}\n")
    print(f"[✔] Wrote top-{args.top_k} features → {fpath}")


if __name__ == "__main__":
    main()