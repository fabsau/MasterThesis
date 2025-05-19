import logging, json, pandas as pd, numpy as np

def setup_logging(level):
    fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%SZ"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)

def drop_nested_keys(obj, paths):
    for path in paths:
        _drop(obj, path.split("."))

def _drop(current, keys):
    if not keys: return
    k, rest = keys[0], keys[1:]
    if k=="*" and isinstance(current, list):
        for item in current: _drop(item, rest)
    elif isinstance(current, dict) and k in current:
        if not rest: del current[k]
        else: _drop(current[k], rest)

def get_by_path(d, path):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict): return None
        cur = cur.get(p)
    return cur

def flatten_dict(d: dict, prefix: str, out: dict):
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
