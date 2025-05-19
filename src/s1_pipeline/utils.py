# utils.py

import os
import json
import logging
import random
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from collections import defaultdict
from sklearn.preprocessing import OneHotEncoder

def setup_logging(level):
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=level
    )

def load_threats(path):
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    return doc.get("threats", []), doc.get("exported_at")

def random_split(threats, test_size, seed):
    random.seed(seed)
    random.shuffle(threats)
    split_idx = int(len(threats) * (1 - test_size))
    return threats[:split_idx], threats[split_idx:]

def group_split(threats, test_size, seed, group_fields):
    random.seed(seed)
    groups = defaultdict(list)
    for t in threats:
        key = tuple(t.get(f, None) for f in group_fields)
        groups[key].append(t)
    group_list = list(groups.values())
    random.shuffle(group_list)
    split_idx = int(len(group_list) * (1 - test_size))
    train = [t for g in group_list[:split_idx] for t in g]
    test = [t for g in group_list[split_idx:] for t in g]
    return train, test

def time_split(test_size, cutoff_date, time_field, iso_format, threats):
    cutoff = datetime.strptime(cutoff_date, iso_format)
    train = [t for t in threats if datetime.strptime(t[time_field], iso_format) < cutoff]
    test = [t for t in threats if datetime.strptime(t[time_field], iso_format) >= cutoff]
    return train, test

def temporal_group_split(test_size, cutoff_date, time_field, iso_format, group_fields, threats):
    cutoff = datetime.strptime(cutoff_date, iso_format)
    groups = defaultdict(list)
    for t in threats:
        key = tuple(t.get(f, None) for f in group_fields)
        groups[key].append(t)
    train, test = [], []
    for g in groups.values():
        g_train = [t for t in g if datetime.strptime(t[time_field], iso_format) < cutoff]
        g_test = [t for t in g if datetime.strptime(t[time_field], iso_format) >= cutoff]
        train.extend(g_train)
        test.extend(g_test)
    return train, test

def get_by_path(d, path):
    keys = path.split(".")
    for k in keys:
        d = d.get(k, {})
    return d

def write_dataset(threats, exported_at, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"exported_at": exported_at, "threats": threats}, f, indent=2)

def flatten_threat(threat):
    flat = {}
    for k, v in threat.items():
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                flat[f"{k}_{sub_k}"] = sub_v
        else:
            flat[k] = v
    return flat

def prepare_features(df, feat_order, cat_cols):
    for c in feat_order:
        if c not in df.columns:
            df[c] = np.nan
    df = df[feat_order]
    for c in feat_order:
        if c in cat_cols:
            df[c] = df[c].fillna("NA").astype(str)
        else:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0).astype(float)
    return df

def build_isolation_forest(train_json, feat_order, cat_cols, contamination, n_estimators):
    with open(train_json, "r", encoding="utf-8") as f:
        doc = json.load(f)
    threats = doc.get("threats", [])
    df = pd.DataFrame([flatten_threat(t) for t in threats])
    df = prepare_features(df, feat_order, cat_cols)
    num_cols = df.select_dtypes(include="number").columns.tolist()
    low_card = [c for c in cat_cols if df[c].nunique() <= 10]
    high_card = [c for c in cat_cols if c not in low_card]
    freq_map = {c: df[c].value_counts(normalize=True).to_dict() for c in high_card}
    ohe = OneHotEncoder(sparse=False, handle_unknown="ignore")
    ohe.fit(df[low_card])
    ohe_columns = ohe.get_feature_names_out(low_card)
    df_encoded = _apply_iso_encoders(df, num_cols, low_card, high_card, freq_map, ohe_columns)
    iso = IsolationForest(contamination=contamination, n_estimators=n_estimators, random_state=42)
    iso.fit(df_encoded)
    return iso, {"num_cols": num_cols, "low_card": low_card, "high_card": high_card, "freq_map": freq_map, "ohe_columns": ohe_columns}

def _apply_iso_encoders(df, num_cols, low_card, high_card, freq_map, ohe_columns):
    df_num = df[num_cols]
    df_low_card = pd.DataFrame(ohe.transform(df[low_card]), columns=ohe_columns)
    df_high_card = df[high_card].applymap(lambda x: freq_map.get(x, 0.0))
    return pd.concat([df_num, df_low_card, df_high_card], axis=1)