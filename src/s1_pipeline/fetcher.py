# ./fetcher.py
import time, logging, json
from requests.exceptions import HTTPError
from tqdm import tqdm
from . import config

def fetch_all_threats(session, url, headers, since_iso, verdicts):
    params = {
        "limit":           config.PAGE_LIMIT,
        "createdAt__gte":  since_iso,
        "analystVerdicts": ",".join(verdicts),
    }
    cursor, bar = None, None

    while True:
        if cursor:
            params["cursor"] = cursor

        r = session.get(url, headers=headers, params=params,
                        verify=config.VERIFY_SSL)
        r.raise_for_status()
        js   = r.json()
        data = js.get("data", [])
        pag  = js.get("pagination", {})

        if bar is None:
            bar = tqdm(total=pag.get("totalItems", 0),
                       desc="Threats", unit="thr", ncols=80)

        bar.update(len(data))
        for t in data:
            yield t

        cursor = pag.get("nextCursor")
        if not cursor:
            break

    if bar:
        bar.close()

def fetch_notes(session, base_url, headers, threat_id):
    url, notes, cursor = f"{base_url}/{threat_id}/notes", [], None

    while True:
        params = {"limit": config.NOTE_PAGE}
        if cursor:
            params["cursor"] = cursor

        r = session.get(url, headers=headers, params=params,
                        verify=config.VERIFY_SSL)
        r.raise_for_status()

        jb = r.json()
        for n in jb.get("data", []):
            txt = n.get("text", "").strip()
            if txt:
                notes.append(txt)

        cursor = jb.get("pagination", {}).get("nextCursor")
        if not cursor:
            break

    return notes

def deepvis_pq_events_with_body(session, pq_url, pq_ping_url, headers, body):
    """
    Run a Deep Visibility PowerQuery using a user-constructed JSON body.
    """
    log = logging.getLogger("deepvis")
    log.debug("PQ REQUEST URL:     %s", pq_url)
    log.debug("PQ REQUEST HEADERS: %s", json.dumps(dict(headers), indent=2))
    log.debug("PQ REQUEST BODY:\n%s", json.dumps(body, indent=2))

    # 1) kick off PQ
    resp = session.post(pq_url,
                        headers=headers,
                        json=body,
                        timeout=config.DV_TIMEOUT,
                        verify=config.VERIFY_SSL)
    resp.raise_for_status()
    pj = resp.json().get("data", {})
    log.debug("PQ INIT RESPONSE DATA:\n%s", json.dumps(pj, indent=2))

    qid = pj.get("queryId")
    status = pj.get("status") or pj.get("progress")
    log.debug("PQ started id=%s status=%s", qid, status)
    # 2) poll if not already done
    if status not in ("FINISHED", "SUCCEEDED", 100):
        params = {"queryId": qid}
        while True:
            ping = session.get(pq_ping_url,
                               headers=headers,
                               params=params,
                               timeout=config.DV_TIMEOUT,
                               verify=config.VERIFY_SSL)
            ping.raise_for_status()
            pd = ping.json().get("data", {})
            log.debug("PQ PING RESPONSE DATA:\n%s", json.dumps(pd, indent=2))
            status = pd.get("status") or pd.get("progress")
            if status in ("FINISHED", "SUCCEEDED", 100):
                pj = pd
                break
            if str(status).startswith("FAILED"):
                raise RuntimeError(f"Power-Query {qid} FAILED: {ping.text}")
            time.sleep(5)
    data = pj.get("data", [])
    log.debug("PQ FINAL data count=%d", len(data))
    return data