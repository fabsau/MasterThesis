# scripts/etl.py
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from s1_pipeline import config

import json
from pathlib import Path
from typing import List, Dict, Any

import numpy as np
import pandas as pd
from dateutil import parser as dateparser
from tqdm import tqdm

def load_raw_records(path: Path) -> List[Dict[str, Any]]:
    """
    Load 'threats' from either a single JSON file or a directory of JSONs.
    """
    if path.is_file():
        j = json.load(path.open(encoding="utf-8"))
        # Top‐level envelope with metadata + threats list?
        if isinstance(j, dict) and "threats" in j:
            return j["threats"]
        # Plain list?
        if isinstance(j, list):
            return j
        # Single-record fallback
        return [j]
    else:
        recs = []
        for f in path.glob("*.json"):
            try:
                j = json.load(f.open(encoding="utf-8"))
                if isinstance(j, dict) and "threats" in j:
                    recs.extend(j["threats"])
                elif isinstance(j, list):
                    recs.extend(j)
                else:
                    recs.append(j)
            except Exception as e:
                print(f"⚠️ Could not load {f}: {e}")
        return recs


def agg_deep_visibility(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Numeric aggregation for process‐fields, plus low‐cardinality one‐hot for strings.
    """
    if not events:
        return {}

    df = pd.DataFrame(events)
    out: Dict[str, Any] = {}

    # 1) count per event.category
    if "event.category" in df:
        for cat, grp in df.groupby("event.category"):
            out[f"dv_cat_{cat}_count"] = len(grp)

    # 2) for each configured process field...
    for fld in config.ETL_PROC_NUMERIC:
        if fld not in df:
            continue
        col = df[fld]
        safe = fld.replace("src.process.", "").replace(".", "_")

        # attempt numeric
        num = pd.to_numeric(col, errors="coerce")
        if num.notna().any():
            out[f"{safe}_sum"] = float(num.sum())
            out[f"{safe}_max"] = float(num.max())
            continue

        # boolean‐like
        if col.dropna().astype(str).str.lower().isin({"true","false"}).all():
            b = col.dropna().astype(str).str.lower()=="true"
            out[f"{safe}_sum"] = int(b.sum())
            out[f"{safe}_max"] = int(b.any())
            continue

        # low‐cardinality string → one‐hot count
        uniq = col.dropna().unique()
        if 1 < len(uniq) <= 5:
            for v in uniq:
                vn = str(v).replace(" ","_")
                out[f"{safe}_{vn}_count"] = int((col==v).sum())
        # else skip high‐cardinality strings

    # 3) unique event types
    if "event.type" in df:
        out["dv_event_type_unique"] = int(df["event.type"].nunique())

    return out


def agg_indicators(inds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Count per indicator category + unique tactic/technique counts.
    """
    if not inds:
        return {}

    out: Dict[str, Any] = {}
    cats = [i.get("category","") for i in inds]
    for c in set(cats):
        out[f"ind_cat_{c}_count"] = cats.count(c)

    tactics = []
    techs   = []
    for i in inds:
        for tac in i.get("tactics", []):
            tactics.append(tac.get("name",""))
            for tech in tac.get("techniques", []):
                techs.append(tech.get("name",""))

    out["ind_unique_tactic_count"]    = len(set(tactics))
    out["ind_unique_technique_count"] = len(set(techs))
    return out


def featurize(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten one threat record into features + label.
    """
    out: Dict[str, Any] = {}
    ti = rec.get("threatInfo", {})

    # Label
    out["label"] = 1 if ti.get("analystVerdict","").lower()=="true_positive" else 0

    # Time features
    try:
        dt = dateparser.parse(ti.get("createdAt",""))
        out["hour"]    = dt.hour
        out["weekday"] = dt.weekday()
    except:
        out["hour"] = np.nan
        out["weekday"] = np.nan

    # Engines one‐hot
    for eng in ti.get("detectionEngines", []):
        key = eng.get("key","").replace("-","_")
        out[f"eng_{key}"] = 1

    # Hash presence
    out["sha1_present"]   = int(bool(ti.get("sha1")))
    out["sha256_present"] = int(bool(ti.get("sha256")))
    out["md5_present"]    = int(bool(ti.get("md5")))

    # DV + indicators
    out.update(agg_deep_visibility(rec.get("deepVisibilityEvents", [])))
    out.update(agg_indicators(rec.get("indicators", [])))

    # Notes text (cap length)
    notes = rec.get("notes", [])
    txt   = " ".join(notes)
    out["notes_text"] = txt[:config.ETL_NOTES_MAX_LEN]

    return out


def run_etl():
    raw_path = Path(config.RAW_JSON_PATH)
    recs     = load_raw_records(raw_path)
    print(f"ℹ️ Loaded {len(recs)} threats from {raw_path}")

    feats = []
    for r in tqdm(recs, desc="Featurizing"):
        try:
            feats.append(featurize(r))
        except Exception as e:
            print(f"⚠️ featurize error: {e}")

    if not feats:
        print("❌ No features extracted, aborting.")
        return

    df = pd.DataFrame(feats)
    # fill numeric nans
    nums = df.select_dtypes(include=[np.number]).columns
    df[nums] = df[nums].fillna(0.0)

    # label last
    cols = [c for c in df.columns if c!="label"] + ["label"]
    df = df[cols]

    outp = Path(config.FEATURES_OUTPUT_CSV)
    outp.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(outp, index=False)
    print(f"✅ Wrote features {df.shape} → {outp}")


if __name__=="__main__":
    run_etl()