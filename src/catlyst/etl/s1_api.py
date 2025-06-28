# src/catlyst/etl/s1_api.py
import time
import logging
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
        return session

    @backoff.on_exception(
        backoff.expo,
        (requests.HTTPError, requests.RequestException),
        max_time=60
    )
    def _get(self, url: str, **kwargs) -> requests.Response:
        resp = self.session.get(
            url,
            verify=self.verify_ssl,
            timeout=self.dv_timeout,
            **kwargs
        )
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
        bar = None
        while True:
            resp = self._get(url, params=params)
            js = resp.json()
            data = js.get("data", [])
            pag = js.get("pagination", {}) or {}
            # initialize progress bar once
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

    @backoff.on_exception(
        backoff.expo,
        (requests.HTTPError, requests.RequestException),
        max_time=30
    )
    def fetch_notes(self, threat_id: str) -> List[str]:
        url    = f"{self.api_prefix}/threats/{threat_id}/notes"
        notes  = []
        params = {"limit": self.note_page}

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

        return notes

    @backoff.on_exception(
        backoff.expo,
        (requests.HTTPError, requests.RequestException),
        max_time=60
    )
    def fetch_deepvis(self,
                      threat:      Dict[str,Any],
                      cols_clause: str
                     ) -> List[Dict[str,Any]]:
        thinfo = threat.get("threatInfo", {}) or {}
        created = thinfo.get("createdAt")
        if not created:
            LOG.debug("Skipping DV; no createdAt")
            return []

        try:
            dt = datetime.fromisoformat(created.replace("Z","+00:00"))
        except Exception:
            LOG.debug("Invalid timestamp %s", created)
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.dv_lookback)
        if dt < cutoff:
            LOG.debug("Skipping DV; older than lookback")
            return []

        start = dt - timedelta(minutes=5)
        end   = dt + timedelta(hours=1)
        query_core = self._build_query_core(threat)
        if not query_core:
            LOG.debug("Skipping DV; no valid query core")
            return []

        body = {
            "query":    query_core + cols_clause,
            "fromDate": start.isoformat(timespec="milliseconds")+"Z",
            "toDate":   end  .isoformat(timespec="milliseconds")+"Z",
            "limit":    self.page_limit,
        }
        det = threat.get("agentDetectionInfo", {}) or {}
        if det.get("siteId"):    body["siteIds"]    = [det["siteId"]]
        if det.get("accountId"): body["accountIds"] = [det["accountId"]]

        pq_url   = f"{self.api_prefix}/dv/events/pq"
        ping_url = f"{self.api_prefix}/dv/events/pq-ping"

        # submit
        r = self.session.post(pq_url, json=body,
                              verify=self.verify_ssl,
                              timeout=self.dv_timeout)
        r.raise_for_status()
        report_id = r.json().get("data",{}).get("reportId")
        if not report_id:
            LOG.error("DV PQ returned no reportId")
            return []

        # poll
        while True:
            p = self.session.get(f"{ping_url}/{report_id}",
                                  verify=self.verify_ssl,
                                  timeout=self.dv_timeout)
            p.raise_for_status()
            st = p.json().get("status")
            if   st=="completed": break
            elif st=="failed":
                raise RuntimeError("DV PQ failed: "+p.text)
            time.sleep(1)

        # download
        out = self.session.get(f"{pq_url}/{report_id}/download",
                               verify=self.verify_ssl,
                               timeout=self.dv_timeout)
        out.raise_for_status()
        return out.json()

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