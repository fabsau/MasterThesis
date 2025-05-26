#!/usr/bin/env python3
# scripts/fetch_data.py
import json, argparse, requests, logging, time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tqdm import tqdm
import sys, os

proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
src_path  = os.path.join(proj_root, "src")
if src_path not in sys.path:    sys.path.insert(0, src_path)
if proj_root not in sys.path:   sys.path.insert(0, proj_root)

from s1_pipeline import config, utils, fetcher
import MySecrets

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--since-days", type=int, default=config.LOOKBACK_DAYS)
    p.add_argument("--workers",    type=int, default=config.MAX_WORKERS)
    p.add_argument("--output",     type=str, default=config.OUTPUT_FILE)
    p.add_argument("--log-level",  type=str, default=None,
                   help="DEBUG/INFO/etc")
    p.add_argument("--verdicts",   type=str,
                   default="false_positive,true_positive")
    args = p.parse_args()

    # clamp since-days to maximum allowed incident look-back
    args.since_days = min(args.since_days, config.MAX_INCIDENT_LOOKBACK_DAYS)

    # Logging
    level = getattr(logging, args.log_level.upper(), config.LOG_LEVEL) \
            if args.log_level else config.LOG_LEVEL
    utils.setup_logging(level)
    log = logging.getLogger("main")

    # Time window for fetching threats
    since_iso = (datetime.now(timezone.utc)
                 - timedelta(days=args.since_days)) \
                .strftime(config.ISO_FORMAT)
    log.info("=== EXPORT START (since %s) ===", since_iso)

    # HTTP setup
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=args.workers,
                          pool_maxsize=args.workers)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # API endpoints
    mgmt        = MySecrets.MANAGEMENT_URL.rstrip("/")
    threat_url  = f"{mgmt}/web/api/v2.1/threats"
    pq_url      = f"{mgmt}/web/api/v2.1/dv/events/pq"
    pq_ping_url = f"{mgmt}/web/api/v2.1/dv/events/pq-ping"
    headers     = {
        "Authorization": f"ApiToken {MySecrets.API_TOKEN}",
        "Content-Type":  "application/json",
    }
    verdicts = args.verdicts.split(",")

    # 1) Fetch all threats
    all_threats = list(fetcher.fetch_all_threats(
        session, threat_url, headers, since_iso, verdicts))
    log.info("Fetched %d threats", len(all_threats))

    # 2) Drop unwanted fields
    for t in all_threats:
        for fld in config.IGNORE_FIELDS:
            t.pop(fld, None)
        utils.drop_nested_keys(t, config.IGNORE_NESTED_FIELDS)
    log.info("Dropped ignore-fields")

    # 3) Fetch notes in parallel
    log.info("Fetching notes…")
    note_bar = tqdm(total=len(all_threats), desc="Notes", unit="thr", ncols=80)
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        fut2th = {}
        for t in all_threats:
            tid = t.get("id") or t.get("threatInfo", {}).get("threatId")
            fut2th[exe.submit(fetcher.fetch_notes,
                              session, threat_url, headers, tid)] = t
        for fut in as_completed(fut2th):
            t = fut2th[fut]
            try:
                t["notes"] = fut.result()
            except Exception:
                log.exception("Note-fetch failed for %s", t.get("id"))
                t["notes"] = []
            note_bar.update(1)
    note_bar.close()

    # 4) Fetch Deep Visibility (Power-Query) in parallel
    log.info("Fetching DeepVis events via Power-Query in parallel…")
    cols_clause = utils.get_column_clause()
    dv_bar = tqdm(total=len(all_threats), desc="DeepVis", unit="thr", ncols=80)

    def _fetch_deepvis_for_threat(t):
        thinfo = t.get("threatInfo") or {}
        story = thinfo.get("storyline")
        # pick best hash
        sha1, sha256, md5 = thinfo.get("sha1"), thinfo.get("sha256"), thinfo.get("md5")
        if sha1:   hash_field, hash_val = "sha1", sha1
        elif sha256: hash_field, hash_val = "sha256", sha256
        elif md5:  hash_field, hash_val = "md5", md5
        else:      hash_field = hash_val = None
        agent_uuid = (t.get("agentRealtimeInfo") or {}).get("agentUuid")
        site_id    = (t.get("agentDetectionInfo") or {}).get("siteId")
        account_id = (t.get("agentDetectionInfo") or {}).get("accountId")
        created = thinfo.get("createdAt")
        if not created:
            return []
        # parse threat timestamp
        try:
            dt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except ValueError:
            dt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

        # skip deep-vis if threat is older than allowed window
        if dt < datetime.now(timezone.utc) - timedelta(days=config.MAX_DEEPVIS_LOOKBACK_DAYS):
            return []

        # parse time window
        from_iso = (dt - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        to_iso   = (dt + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        # build query core
        query_story = f"src.process.storyline.id == '{story}'" if story else None
        if hash_field and hash_val and agent_uuid:
            hf = f"src.process.image.{hash_field}"
            hash_and_agent = f"({hf} == '{hash_val}' and agent.uuid == '{agent_uuid}')"
        else:
            hash_and_agent = None
        if query_story and hash_and_agent:
            query_core = f"{query_story} or {hash_and_agent}"
        elif query_story:
            query_core = query_story
        elif hash_and_agent:
            query_core = hash_and_agent
        else:
            return []
        query = f"{query_core} {cols_clause}"
        # build body
        body = {
            "query": query,
            "fromDate": from_iso,
            "toDate": to_iso,
            "limit": config.PAGE_LIMIT
        }
        if site_id:    body["siteIds"]    = [site_id]
        if account_id: body["accountIds"] = [account_id]
        # run PQ
        return fetcher.deepvis_pq_events_with_body(session, pq_url, pq_ping_url, headers, body)

    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        fut2th = { exe.submit(_fetch_deepvis_for_threat, t): t for t in all_threats }
        for fut in as_completed(fut2th):
            t = fut2th[fut]
            try:
                t["deepVisibilityEvents"] = fut.result()
            except Exception:
                log.exception("DeepVis PQ failed for %s", t.get("id"))
                t["deepVisibilityEvents"] = []
            dv_bar.update(1)
    dv_bar.close()

    # convert raw list‐based deepVisibilityEvents into dicts with titles
    cols = config.DV_COLUMNS if isinstance(config.DV_COLUMNS, list) else config.DV_COLUMNS.split(",")
    # ensure the sort field is included first
    if getattr(config, "DV_SORT", None) and config.DV_SORT not in cols:
        cols.insert(0, config.DV_SORT)
    dv_columns = [c.strip() for c in cols]
    for t in all_threats:
        evts = t.get("deepVisibilityEvents", [])
        if evts and isinstance(evts[0], list):
            t["deepVisibilityEvents"] = [ dict(zip(dv_columns, row)) for row in evts ]

    # drop empty, null, and zero values from deepVisibilityEvents
    for t in all_threats:
        cleaned = []
        for evt in t.get("deepVisibilityEvents", []):
            filtered = {
                k: v
                for k, v in evt.items()
                if v is not None
                   and v != ""
                   and not (isinstance(v, (int, float))
                            and not isinstance(v, bool)
                            and v == 0)
            }
            cleaned.append(filtered)
        t["deepVisibilityEvents"] = cleaned

    # 5) Write out exactly as before
    log.info("Writing %d records → %s", len(all_threats), args.output)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    # --- Format deepVisibilityEvents as list of dicts with column names ---
    cols = config.DV_COLUMNS if isinstance(config.DV_COLUMNS, list) else config.DV_COLUMNS.split(",")
    # ensure the sort field is included first
    if getattr(config, "DV_SORT", None) and config.DV_SORT not in cols:
        cols.insert(0, config.DV_SORT)
    dv_columns = [c.strip() for c in cols]

    def format_deepvis_events(events):
        # If already dicts, return as is
        if not events:
            return []
        if isinstance(events[0], dict):
            return events
        # Otherwise, map each event (list) to dict
        return [
            dict(zip(dv_columns, evt)) if isinstance(evt, list) else evt
            for evt in events
        ]

    out = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc)\
                               .strftime(config.ISO_FORMAT),
            "num_threats":  len(all_threats)
        },
        "threats": [
            (
                utils.filter_by_whitelist(t, config.WHITELIST_FIELDS)
                if config.WHITELIST_FIELDS else {
                    **t,
                    "deepVisibilityEvents": format_deepvis_events(t.get("deepVisibilityEvents", []))
                }
            )
            for t in all_threats
        ]
    }
    with open(args.output, "w", encoding="utf-8") as fd:
        json.dump(out, fd, ensure_ascii=False, indent=2)

    log.info("=== EXPORT COMPLETE ===")

if __name__ == "__main__":
    main()