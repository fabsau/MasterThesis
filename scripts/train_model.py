#!/usr/bin/env python3
import os, json, logging, argparse, pickle
from datetime import datetime, timezone
import pandas as pd, numpy as np
from tqdm import tqdm
from catboost import CatBoostClassifier, Pool
from sklearn.metrics import roc_auc_score, classification_report

from s1_pipeline import config, utils

def flatten_dict(d: dict, prefix: str, out: dict):
    """
    Recursively flatten nested dicts/lists into a single-level map.
    Lists of primitives become pipe-delimited strings; complex lists get JSON-encoded.
    """
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            flatten_dict(v, key + "_", out)
        elif isinstance(v, list):
            if all(not isinstance(x, (dict, list)) for x in v):
                out[key] = "|".join(map(str, v))
            else:
                out[key] = "|".join(json.dumps(x, default=str) for x in v)
        else:
            out[key] = v

def load_and_flatten(path: str) -> pd.DataFrame:
    """
    Load a SentinelOne export JSON and flatten each 'threat' into a feature dict.
    Returns a DataFrame with one row per threat.
    """
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    recs = []
    for th in tqdm(doc.get("threats", []),
                   desc=f"Flattening {os.path.basename(path)}",
                   unit="thr", ncols=80):
        r = {}
        flatten_dict(th.get("agentDetectionInfo", {}), "agent_", r)
        flatten_dict(th.get("threatInfo",       {}), "threatInfo_", r)

        # top-level id
        r["thr_id"] = th.get("id")

        # indicators → categories, descriptions, tactics, techniques
        inds = th.get("indicators", [])
        r["ind_count"]       = len(inds)
        r["ind_cats"]        = "|".join(i.get("category","") for i in inds)
        r["ind_desc"]        = "|".join(i.get("description","") for i in inds)
        tacs, techs = [], []
        for i in inds:
            for tac in i.get("tactics", []):
                tacs.append(tac.get("name",""))
                for te in tac.get("techniques", []):
                    techs.append(te.get("name",""))
        r["tactic_names"]    = "|".join(tacs)
        r["technique_names"] = "|".join(techs)

        # label: false_positive=1, malicious/true_positive=0, else None
        v = r.get("threatInfo_analystVerdict", "undefined")
        r["label"] = 1 if v == "false_positive" else (0 if v == "true_positive" else None)
        # DROP RAW VERDICT FEATURES TO PREVENT LABEL LEAKAGE
        r.pop("threatInfo_analystVerdict", None)
        
        recs.append(r)

    return pd.DataFrame(recs)

def prepare_train(df: pd.DataFrame):
    """
    - Drop rows with undefined label
    - Capture lookup mapping
    - Drop ID columns
    - Split off y
    - Detect categorical
    - Fill & cast
    """
    # 1) restrict to 0/1 labels
    df = df[df["label"].isin([0, 1])].copy()

    # 2) BUILD lookup: sha256 → label
    lookup = {}
    for _, row in df.iterrows():
        sha = row.get("threatInfo_sha256")
        if sha:
            lookup[sha] = int(row["label"])

    # 3) extract y and X
    y = df["label"].astype(int)
    X = df.drop(columns=["label"] + config.ID_COLS)

    # 4) detect cats, fill & cast
    cat_cols = X.select_dtypes(include="object").columns.tolist()
    for c in X.columns:
        if c in cat_cols:
            X[c] = X[c].fillna("NA").astype(str)
        else:
            X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0).astype(float)

    feat_order = X.columns.tolist()
    return X, y, cat_cols, feat_order, lookup

def prepare_test(df: pd.DataFrame, feat_order, cat_cols):
    """
    - Drop undefined labels
    - Drop ID cols, align to feat_order, fill & cast
    """
    df = df[df["label"].isin([0, 1])].copy()
    y  = df["label"].astype(int)
    X  = df.drop(columns=["label"] + config.ID_COLS)

    # add missing, drop extras, reorder
    for c in feat_order:
        if c not in X.columns:
            X[c] = np.nan
    X = X[feat_order]

    # fill & cast
    for c in feat_order:
        if c in cat_cols:
            X[c] = X[c].fillna("NA").astype(str)
        else:
            X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0).astype(float)

    return X, y

def train_and_evaluate(X_tr, y_tr, X_te, y_te, cat_cols, params, results_dir):
    """
    Fit CatBoost, evaluate on test set, print & save metrics & feature importances.
    Returns the trained model.
    """
    os.makedirs(results_dir, exist_ok=True)

    tr_pool = Pool(data=X_tr, label=y_tr, cat_features=cat_cols)
    te_pool = Pool(data=X_te, label=y_te, cat_features=cat_cols)

    model = CatBoostClassifier(**params)
    model.fit(tr_pool, eval_set=te_pool)

    # test‐set metrics
    proba = model.predict_proba(X_te)[:,1]
    auc   = roc_auc_score(y_te, proba)
    preds = model.predict(X_te)
    report_dict = classification_report(y_te, preds, output_dict=True)
    report_txt  = classification_report(y_te, preds)

    logging.getLogger("main").info("Test AUC = %.4f", auc)
    print("\n=== Test Classification Report ===\n", report_txt)

    # save metrics JSON
    metrics = {
        "test_auc": auc,
        "classification_report": report_dict,
        "trained_at": datetime.now(timezone.utc).isoformat()
    }
    with open(os.path.join(results_dir, "metrics.json"), "w") as jf:
        json.dump(metrics, jf, indent=2)

    # feature importance
    fi_vals  = model.get_feature_importance(tr_pool)
    fi_tuples= sorted(zip(X_tr.columns, fi_vals), key=lambda x: -x[1])
    with open(os.path.join(results_dir, "feature_importance.txt"), "w") as ff:
        ff.write("Feature                          Importance\n")
        ff.write("---------------------------------------------\n")
        for name, val in fi_tuples[:50]:
            ff.write(f"{name[:30]:<30}  {val:7.3f}\n")

    return model

def main():
    utils.setup_logging(config.LOG_LEVEL)
    log = logging.getLogger("main")

    # ─── Parse CLI args ───────────────────────────────────────────────────────
    p = argparse.ArgumentParser(
        description="CatBoost trainer & scorer for SentinelOne FP detection"
    )
    p.add_argument("--train-json",  "-t", default=config.DEFAULT_TRAIN_JSON,
                   help="Path to training JSON")
    p.add_argument("--test-json",   "-e", default=config.DEFAULT_TEST_JSON,
                   help="Path to test JSON")
    p.add_argument("--model-out",   "-m", default=config.DEFAULT_MODEL_OUT,
                   help="Where to save the CatBoost model (.cbm)")
    p.add_argument("--results-dir", "-r", default=config.DEFAULT_RESULTS_DIR,
                   help="Directory to write metrics & feature‐importances")
    p.add_argument("--threads",     "-T", type=int, default=config.DEFAULT_THREADS,
                   help="Number of CPU threads for CatBoost")
    p.add_argument("--use-gpu",     action="store_true",
                   help="Run CatBoost on GPU if available")
    args = p.parse_args()

    # ─── Finalize CatBoost params ────────────────────────────────────────────
    params = config.CATBOOST_PARAMS.copy()
    if args.use_gpu:
        params["task_type"] = "GPU"
    else:
        params["task_type"]    = "CPU"
        params["thread_count"] = args.threads

    log.info("=== CatBoost START ===")
    log.info(" Train JSON : %s", args.train_json)
    log.info("  Test JSON : %s", args.test_json)
    log.info("Model output: %s", args.model_out)
    log.info("Results dir : %s", args.results_dir)

    # ─── 1) Load & flatten JSON → DataFrames ─────────────────────────────────
    df_tr = load_and_flatten(args.train_json)
    df_te = load_and_flatten(args.test_json)

    # ─── 2) Prepare train & test (dropping ID_COLS) ───────────────────────────
    X_tr, y_tr, cat_cols, feat_order, lookup = prepare_train(df_tr)
    X_te, y_te                            = prepare_test(df_te, feat_order, cat_cols)

    log.info("Train rows: %d, Test rows: %d", len(X_tr), len(X_te))
    log.info("Features: %d  |  Categorical: %d", len(feat_order), len(cat_cols))

    # ─── 3) Train & evaluate ─────────────────────────────────────────────────
    model = train_and_evaluate(
        X_tr, y_tr, X_te, y_te,
        cat_cols, params, args.results_dir
    )

    # ─── 4) Persist model + lookup‐meta ───────────────────────────────────────
    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    model.save_model(args.model_out)
    log.info("Saved CatBoost model → %s", args.model_out)

    # Save feature‐order, categorical cols & sha256→label lookup
    meta = {
      "feat_order": feat_order,
      "cat_cols":   cat_cols,
      "lookup":     lookup
    }
    meta_path = os.path.join(os.path.dirname(args.model_out), "meta.pkl")
    with open(meta_path, "wb") as mf:
        pickle.dump(meta, mf)
    log.info("Saved training metadata → %s", meta_path)

    log.info("=== CatBoost COMPLETE ===")

if __name__ == "__main__":
    main()
    pass