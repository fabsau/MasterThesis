# ./src/utils.py

import os
import json
import logging
import random
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from collections import defaultdict
from sklearn.preprocessing import OneHotEncoder
from . import config

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
    """
    Cluster threats by any shared value on group_fields (union-find),
    then split clusters into train/test.
    """
    random.seed(seed)
    n = len(threats)
    parent = list(range(n))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # map each field value to list of threat indices
    val2idx = defaultdict(list)
    for idx, t in enumerate(threats):
        for field in group_fields:
            # changed: support nested paths
            val = get_by_path(t, field)
            if val:
                val2idx[val].append(idx)

    # union all indices sharing the same value
    for idxs in val2idx.values():
        for other in idxs[1:]:
            union(idxs[0], other)

    # build clusters
    clusters = defaultdict(list)
    for idx in range(n):
        clusters[find(idx)].append(threats[idx])
    group_list = list(clusters.values())

    # shuffle and split clusters
    random.shuffle(group_list)
    split = int(len(group_list) * (1 - test_size))
    train = [t for grp in group_list[:split] for t in grp]
    test  = [t for grp in group_list[split:] for t in grp]
    return train, test

def time_split(test_size, cutoff_date, time_field, iso_format, threats):
    """
    If cutoff_date is 'YYYY-MM-DD', split by date part only:
      date_part >= cutoff_date → test, else → train.
    Otherwise fallback to frac-based split on full timestamp ordering.
    Ensures test set matches requested test_size fraction (downsampling if needed).
    """
    if cutoff_date:
        train, test = [], []
        for t in threats:
            ts = get_by_path(t, time_field) or ""
            date_part = ts.split("T", 1)[0]
            if date_part >= cutoff_date:
                test.append(t)
            else:
                train.append(t)
        # Downsample test set if too large
        target_test_size = int(round(len(threats) * test_size))
        if len(test) > target_test_size:
            random.shuffle(test)
            test = test[:target_test_size]
        return train, test

    # fraction-based fallback on datetime ordering
    recs = []
    for t in threats:
        ts = get_by_path(t, time_field) or ""
        try:
            dt = datetime.strptime(ts, iso_format)
        except:
            dt = datetime.min
        recs.append((dt, t))
    recs.sort(key=lambda x: x[0])
    n = int(len(recs) * test_size)
    train = [r for (_, r) in recs[:-n]]
    test  = [r for (_, r) in recs[-n:]]
    return train, test

def temporal_group_split(test_size, cutoff_date, time_field, iso_format, group_fields, threats):
    """
    1) Perform a time_split
    2) From the test set, drop any record whose group key appears in train
    3) Downsample filtered test set to match test_size fraction if needed
    """
    raw_train, raw_test = time_split(test_size, cutoff_date, time_field, iso_format, threats)
    # gather all individual group-field values from the train split
    seen_vals = set()
    for t in raw_train:
        for f in group_fields:
            v = get_by_path(t, f)
            if v:
                seen_vals.add(v)
    # keep only those test records that share none of these values
    filtered = [
        t for t in raw_test
        if all(get_by_path(t, f) not in seen_vals for f in group_fields)
    ]
    # Downsample filtered test set to match requested test_size
    target_test_size = int(round(len(threats) * test_size))
    if len(filtered) > target_test_size:
        random.shuffle(filtered)
        filtered = filtered[:target_test_size]
    # Optionally, could log if filtered is much smaller than target
    return raw_train, filtered

def get_by_path(d, path):
    keys = path.split(".")
    for k in keys:
        d = d.get(k, {})
    return d

def filter_by_whitelist(obj, whitelist):
    """
    Return a new dict containing only the nested keys in whitelist,
    e.g. "threatInfo.sha1" → {'threatInfo': {'sha1': ...}}
    """
    out = {}
    for path in whitelist:
        val = get_by_path(obj, path)
        if val is not None:
            keys = path.split(".")
            d = out
            for k in keys[:-1]:
                d = d.setdefault(k, {})
            d[keys[-1]] = val
    return out

def get_column_clause():
    # Use string or join list
    cols = config.DV_COLUMNS if isinstance(config.DV_COLUMNS, str) else ", ".join(config.DV_COLUMNS)
    clause = f"| columns {cols}"
    if hasattr(config, 'DV_SORT') and config.DV_SORT:
        clause += f" | sort {config.DV_SORT}"
    return clause

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

def drop_nested_keys(obj, paths):
    for path in paths:
        _drop(obj, path.split("."))

def _drop(current, keys):
    if not keys: return
    k, rest = keys[0], keys[1:]
    if k == "*" and isinstance(current, list):
        for item in current: _drop(item, rest)
    elif isinstance(current, dict) and k in current:
        if not rest: del current[k]
        else: _drop(current[k], rest)