#!/usr/bin/env python3
import json, argparse, requests, logging, time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tqdm import tqdm

import sys
import os
proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
src_path = os.path.join(proj_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)
from s1_pipeline import config, utils, fetcher
import MySecrets

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--since-days", type=int, default=config.LOOKBACK_DAYS)
    p.add_argument("--workers",    type=int, default=config.MAX_WORKERS)
    p.add_argument("--output",     type=str, default=config.OUTPUT_FILE)
    p.add_argument("--log-level",  type=str, default=None)
    p.add_argument("--verdicts",   type=str, default="false_positive,true_positive")
    args = p.parse_args()

    level = getattr(logging, args.log_level.upper(), config.LOG_LEVEL) \
            if args.log_level else config.LOG_LEVEL
    utils.setup_logging(level)
    log = logging.getLogger("main")

    since_iso = (datetime.now(timezone.utc)
                 - timedelta(days=args.since_days)) \
                .strftime(config.ISO_FORMAT)
    log.info("=== EXPORT START (since %s) ===", since_iso)

    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=args.workers,
                          pool_maxsize=args.workers)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    mgmt_url  = MySecrets.MANAGEMENT_URL.rstrip("/")
    threat_url= f"{mgmt_url}/web/api/v2.1/threats"
    dv_init   = f"{mgmt_url}/web/api/v2.1/dv/init-query"
    dv_events = f"{mgmt_url}/web/api/v2.1/dv/events"
    headers   = {
        "Authorization": f"ApiToken {MySecrets.API_TOKEN}",
        "Content-Type":  "application/json",
    }
    verdicts  = args.verdicts.split(",")

    # 1) Fetch threats
    all_threats = list(fetcher.fetch_all_threats(
        session, threat_url, headers, since_iso, verdicts))
    log.info("Fetched %d threats", len(all_threats))

    # 2) Drop unneeded fields
    for t in all_threats:
        for fld in config.IGNORE_FIELDS:
            t.pop(fld, None)
        utils.drop_nested_keys(t, config.IGNORE_NESTED_FIELDS)
    log.info("Dropped ignore-fields")

    # 3) Fetch notes…
    log.info("Fetching notes…")
    note_bar = tqdm(total=len(all_threats), desc="Notes", unit="thr", ncols=80)
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        fut2th = {}
        for t in all_threats:
            tid = t.get("id") or t.get("threatId")
            fut2th[exe.submit(fetcher.fetch_notes, session, threat_url, headers, tid)] = t
        for fut in as_completed(fut2th):
            t = fut2th[fut]
            try:
                t["notes"] = fut.result()
            except Exception as e:
                log.error("Note-fetch for %s failed: %s", t.get("id"), e)
                t["notes"] = []
            note_bar.update(1)
    note_bar.close()

    # 4) Deep Visibility
    # since_dt = datetime.now(timezone.utc) - timedelta(days=args.since_days)
    # to_dt    = datetime.now(timezone.utc)
    # log.info("Querying DeepVis from %s to %s …", since_dt, to_dt)
    # try:
    #     dv_qid = fetcher.init_deepvis_query(
    #         session, dv_init, headers, since_dt, to_dt)
    # except Exception as e:
    #     log.error("Failed to init-query DeepVis: %s", e)
    #     dv_qid = None

    # dv_events_all = []
    # if dv_qid:
    #     cursor   = None
    #     dv_bar   = tqdm(desc="DV pages", unit="page", ncols=80)
    #     while True:
    #         params = {"queryId": dv_qid, "limit": config.PAGE_LIMIT}
    #         if cursor:
    #             params["cursor"] = cursor
    #         resp = session.get(dv_events, headers=headers,
    #                            params=params,
    #                            timeout=config.DV_TIMEOUT,
    #                            verify=config.VERIFY_SSL)
    #         if resp.status_code == 429:
    #             logging.warning("DV/events 429, sleeping 5s")
    #             time.sleep(5)
    #             continue
    #         resp.raise_for_status()
    #         js = resp.json()
    #         dv_events_all.extend(js.get("data", []))
    #         dv_bar.update(1)
    #         cursor = js.get("pagination", {}).get("nextCursor")
    #         if not cursor:
    #             break
    #     dv_bar.close()

    # log.info("Fetched %d DeepVis events", len(dv_events_all))

    # 5) Attach events to threats
    dv_events_all = []
    dv_map = {}
    for e in dv_events_all:
        pg = e.get("processGroupId")
        if pg:
            dv_map.setdefault(pg, []).append(e)
    for t in all_threats:
        sl = t.get("threatInfo", {}).get("storyline")
        t["deepVisibilityEvents"] = dv_map.get(sl, [])

    # 6) Write out
    log.info("Writing %d records → %s", len(all_threats), args.output)
    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fd:
        json.dump({
            "exported_at": datetime.now(timezone.utc)
                                       .strftime(config.ISO_FORMAT),
            "threats":     all_threats
        }, fd, ensure_ascii=False, indent=2)
    log.info("=== EXPORT COMPLETE ===")

if __name__ == "__main__":
    main()
    pass