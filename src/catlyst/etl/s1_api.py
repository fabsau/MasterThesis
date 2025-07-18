# src/catlyst/etl/s1_api.py

import time
import logging
import json
from datetime import datetime, timedelta, timezone
from typing import Iterator, Dict, Any, List
from tqdm import tqdm

import backoff
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from catlyst.settings import get_settings

LOG = logging.getLogger(__name__)

class SentinelOneAPI:
    """SentinelOne HTTP client, fully driven by Pydantic Settings."""

    def __init__(self,
                 base_url:    str = None,
                 token:       str = None,
                 max_workers: int = None):
        s1 = get_settings().s1
        self.base_url    = (base_url    or s1.s1_management_url).rstrip("/")
        self.api_token   = token        or s1.s1_api_token
        self.pool_size   = max_workers  or s1.s1_max_workers
        self.verify_ssl  = s1.s1_verify_ssl
        self.page_limit  = s1.s1_page_limit
        self.note_page   = s1.s1_note_page
        self.retry_total = s1.s1_max_init_retry
        self.dv_timeout  = s1.s1_dv_timeout
        self.dv_lookback = s1.s1_max_deepvis_lookback_days

        # If api_prefix is a property on Settings, use that (patch it if not):
        if hasattr(s1, "api_prefix"):
            self.api_prefix = s1.api_prefix
        else:
            # fallback: build from current fields if needed
            self.api_prefix = f"{self.base_url}/web/api/{s1.s1_api_version}"

        self.session = self._build_session()
        LOG.debug("SentinelOneAPI initialized: base_url=%s with pool_size=%d", self.base_url, self.pool_size)

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_maxsize=self.pool_size,
            pool_connections=self.pool_size,
            max_retries=Retry(
                total=self.retry_total,
                backoff_factor=0.3,
                status_forcelist=[429,500,502,503,504]
            )
        )
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        session.headers.update({
            "Authorization": f"ApiToken {self.api_token}",
            "Content-Type":  "application/json",
        })
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        LOG.debug("HTTP session built with headers: %s", session.headers)
        return session

    @backoff.on_exception(
        backoff.expo,
        (requests.HTTPError, requests.RequestException),
        max_time=60
    )
    def _get(self, url: str, **kwargs) -> requests.Response:
        LOG.debug("Sending GET request to: %s with kwargs: %s", url, kwargs)
        resp = self.session.get(
            url,
            verify=self.verify_ssl,
            timeout=self.dv_timeout,
            **kwargs
        )
        LOG.debug("Received response: %s from GET %s", resp.status_code, url)
        resp.raise_for_status()
        return resp

    def fetch_all_threats(self,
                        since_iso: str,
                        verdicts: List[str],
                        show_progress: bool = False
                        ) -> Iterator[Dict[str, Any]]:
        url = f"{self.api_prefix}/threats"
        params = {
            "createdAt__gte": since_iso,
            "analystVerdicts": ",".join(verdicts),
            "limit": self.page_limit,
        }
        LOG.debug("Starting threat fetch with params: %s", params)
        bar = None
        while True:
            resp = self._get(url, params=params)
            js = resp.json()
            data = js.get("data", [])
            pag = js.get("pagination", {}) or {}
            LOG.debug("Fetched %d threats; pagination: %s", len(data), pag)
            if show_progress and bar is None:
                total = pag.get("totalItems", len(data))
                bar = tqdm(total=total, desc="threats", unit="thr")
            # yield each threat and advance progress bar
            for t in data:
                if bar:
                    bar.update(1)
                yield t
            # handle pagination token (v2.1 returns `nextCursor` or sometimes `nextPageToken`)
            next_token = pag.get("nextCursor") or js.get("nextPageToken")
            if not next_token:
                break
            # Use "cursor" for the next page query param (instead of "pageToken")
            params["cursor"] = next_token
            LOG.debug("Advancing to next page with cursor: %s", next_token)

    @backoff.on_exception(
        backoff.expo,
        (requests.HTTPError, requests.RequestException),
        max_time=30
    )
    def fetch_notes(self, threat_id: str) -> List[str]:
        url    = f"{self.api_prefix}/threats/{threat_id}/notes"
        notes  = []
        params = {"limit": self.note_page}
        LOG.debug("Starting fetch_notes for threat_id: %s", threat_id)
        while True:
            resp = self._get(url, params=params)
            js   = resp.json()
            for rec in js.get("data", []):
                txt = (rec.get("body","") or rec.get("text","")).strip()
                if txt:
                    notes.append(txt)

            pag    = js.get("pagination", {})
            cursor = pag.get("nextCursor") or js.get("nextPageToken")
            if not cursor:
                break
            params["cursor"] = cursor
            LOG.debug("Advancing to next notes page with cursor: %s", cursor)
        LOG.debug("Completed fetch_notes: Total notes fetched: %d", len(notes))
        return notes

    @backoff.on_exception(
        backoff.expo,
        (requests.HTTPError, requests.RequestException),
        max_time=60
    )
    def fetch_deepvis(self,
                      threat:      Dict[str,Any],
                      cols_clause: str = ""
                     ) -> List[Dict[str,Any]]:
        LOG.info("==== DeepVis fetch for threat_id=%s ====", threat.get("id", "unknown"))
        LOG.debug("Starting fetch_deepvis for threat %s with cols_clause=%s", threat.get("id", "unknown"), cols_clause)
        thinfo = threat.get("threatInfo", {}) or {}
        created = thinfo.get("createdAt")
        LOG.info("Threat info: id=%s, createdAt=%s", threat.get("id", "unknown"), created)
        if not created:
            LOG.warning("Skipping DV; no createdAt for threat ID: %s", threat.get("id", "unknown"))
            return []

        try:
            dt = datetime.fromisoformat(created.replace("Z","+00:00"))
        except Exception:
            LOG.debug("Invalid timestamp %s", created)
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.dv_lookback)
        if dt < cutoff:
            LOG.debug("Skipping DV; threat ID: %s older than lookback", threat.get("id", "unknown"))
            return []

        start = dt - timedelta(minutes=1)
        end   = dt + timedelta(minutes=1)
        LOG.debug("DeepVis time window: %s to %s", start, end)

        # Try with only storyline id, then with only agent.uuid if no results
        ti = threat.get("threatInfo", {}) or {}
        story = ti.get("storyline")
        agent = (threat.get("agentRealtimeInfo") or {}).get("agentUuid")

        queries = []
        if story:
            queries.append(f"src.process.storyline.id == '{story}'")
        if agent:
            queries.append(f"agent.uuid == '{agent}'")

        for query_core in queries:
            full_query = query_core + cols_clause
            body = {
                "query": full_query,
                "fromDate": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "toDate":   end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "limit":    self.page_limit,
            }
            det = threat.get("agentDetectionInfo", {}) or {}
            # if det.get("siteId"):    body["siteIds"]    = [det["siteId"]]
            # if det.get("accountId"): body["accountIds"] = [det["accountId"]]
            LOG.debug("DeepVis PQ body: %s", json.dumps(body))

            pq_url   = f"{self.api_prefix}/dv/events/pq"
            ping_url = f"{self.api_prefix}/dv/events/pq-ping"

            # submit PQ
            r = self.session.post(pq_url, json=body,
                                  verify=self.verify_ssl,
                                  timeout=self.dv_timeout)
            LOG.debug("DeepVis PQ POST status: %s", r.status_code)
            if r.status_code == 400:
                LOG.warning("DV PQ bad request for threat %s: %s", threat.get("id", "unknown"), r.text)
                continue
            r.raise_for_status()
            resp_json = r.json()
            LOG.debug("DeepVis PQ POST response: %s", resp_json)
            pq_data = resp_json.get("data", {})
            query_id = pq_data.get("queryId")
            status = pq_data.get("status") or pq_data.get("progress")
            LOG.info("PQ started id=%s status=%s", query_id, status)
            if not query_id:
                LOG.error("DV PQ returned no queryId")
                continue

            # poll
            if status not in ("FINISHED", "SUCCEEDED", 100):
                params = {"queryId": query_id}
                poll_count = 0
                while True:
                    poll_count += 1
                    LOG.debug("Polling PQ status (attempt %d) for queryId=%s", poll_count, query_id)
                    ping = self.session.get(ping_url,
                                            params=params,
                                            verify=self.verify_ssl,
                                            timeout=self.dv_timeout)
                    LOG.debug("PQ PING status: %s", ping.status_code)
                    ping.raise_for_status()
                    ping_json = ping.json()
                    LOG.debug("PQ PING response: %s", ping_json)
                    pd = ping_json.get("data", {})
                    status = pd.get("status") or pd.get("progress")
                    LOG.debug("PQ PING status value: %s", status)
                    if status in ("FINISHED", "SUCCEEDED", 100):
                        pq_data = pd
                        LOG.debug("PQ finished for queryId=%s", query_id)
                        break
                    if str(status).startswith("FAILED"):
                        LOG.error("Power-Query %s FAILED: %s", query_id, ping.text)
                        raise RuntimeError(f"Power-Query {query_id} FAILED: {ping.text}")
                    time.sleep(5)
            data = pq_data.get("data", [])
            LOG.info("PQ FINAL data count=%d", len(data))
            if data:
                LOG.debug("PQ FINAL data sample: %s", data[0] if isinstance(data, list) and len(data) > 0 else data)
                return data
        return []

    def _build_query_core(self, threat: Dict[str,Any]) -> str:
        ti     = threat.get("threatInfo", {}) or {}
        story  = ti.get("storyline")
        clauses: list[str] = []
        if story:
            clauses.append(f"src.process.storyline.id == '{story}'")

        agent = (threat.get("agentRealtimeInfo") or {}).get("agentUuid")
        for fld in ("sha256","sha1","md5"):
            val = ti.get(fld)
            if agent and val:
                clauses.append(
                    f"(src.process.image.{fld} == '{val}'"
                    f" and agent.uuid == '{agent}')"
                )
                break

        return " or ".join(clauses)
