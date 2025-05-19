import time, logging, requests
from tqdm import tqdm
from . import config

def fetch_all_threats(session, url, headers, since_iso, verdicts):
    params = {
        "limit": config.PAGE_LIMIT,
        "createdAt__gte": since_iso,
        "analystVerdicts": ",".join(verdicts),
    }
    cursor, bar = None, None
    while True:
        if cursor: params["cursor"] = cursor
        r = session.get(url, headers=headers, params=params, verify=config.VERIFY_SSL)
        r.raise_for_status()
        js = r.json()
        data = js.get("data", [])
        pag  = js.get("pagination", {})
        if bar is None:
            bar = tqdm(total=pag.get("totalItems", 0),
                       desc="Threats", unit="thr", ncols=80)
        bar.update(len(data))
        for t in data: yield t
        cursor = pag.get("nextCursor")
        if not cursor: break
    if bar: bar.close()

def fetch_notes(session, base_url, headers, threat_id):
    url, notes, cursor = f"{base_url}/{threat_id}/notes", [], None
    while True:
        params = {"limit": config.NOTE_PAGE}
        if cursor: params["cursor"] = cursor
        r = session.get(url, headers=headers, params=params, verify=config.VERIFY_SSL)
        r.raise_for_status()
        jb = r.json()
        for n in jb.get("data", []):
            txt = n.get("text", "").strip()
            if txt: notes.append(txt)
        cursor = jb.get("pagination", {}).get("nextCursor")
        if not cursor: break
    return notes

def init_deepvis_query(session, url, headers,
                       since_dt, until_dt,
                       query_str="SELECT *",
                       max_retry=None):
    max_retry = max_retry or config.MAX_INIT_RETRY
    body = {
        "fromDate": since_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "toDate":   until_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "query":    query_str,
    }
    for attempt in range(1, max_retry + 1):
        resp = session.post(url, json=body,
                            headers=headers,
                            timeout=config.DV_TIMEOUT,
                            verify=config.VERIFY_SSL)
        if resp.status_code == 429:
            wait = 2 ** attempt
            logging.warning("DV init-query 429, backoff %ds (try %d/%d)",
                            wait, attempt, max_retry)
            time.sleep(wait)
            continue
        if not resp.ok:
            detail = None
            try:
                detail = resp.json().get("errors", [{}])[0].get("detail")
            except:
                pass
            logging.error("DV init-query failed (%d): %s", resp.status_code,
                          detail or resp.text)
            resp.raise_for_status()
        qid = resp.json().get("data", {}).get("queryId")
        if not qid:
            raise RuntimeError(f"No queryId in response: {resp.text}")
        logging.info("DV init-query succeeded, queryId=%s", qid)
        return qid
    raise RuntimeError(f"Could not init DeepVis after {max_retry} attempts")