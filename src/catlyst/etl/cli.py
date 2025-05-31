# src/catlyst/etl/cli.py

import sys
import logging
import argparse
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from alembic.config import Config as AlembicConfig
from alembic import command
from sqlalchemy.exc import SQLAlchemyError

from catlyst.settings import get_settings
from catlyst.db.connection import SessionLocal
from catlyst.etl.s1_api import SentinelOneAPI
from catlyst.etl import db as ingest

LOG = logging.getLogger(__name__)

def setup_logging(level: str):
    lvl = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(lvl)
    root.addHandler(handler)


def get_column_clause():
    settings = get_settings()
    cols = settings.deepvis.columns
    sort = getattr(settings.deepvis, "sort", None)

    if isinstance(cols, list):
        cols_list = list(cols)
        if sort and sort not in cols_list:
            cols_list.insert(0, sort)
        cols_str = ", ".join(cols_list)
    else:
        cols_str = cols

    clause = f"| columns {cols_str}"
    if sort:
        clause += f" | sort {sort}"
    return clause


def run_migrations():
    cfg = AlembicConfig("alembic.ini")
    settings = get_settings()
    db = settings.database
    url = db.url
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    LOG.info("✅ Applied migrations")


def parse_args():
    s = get_settings().etl
    p = argparse.ArgumentParser("SentinelOne ETL")
    p.add_argument("--since-days", type=int, default=s.since_days)
    p.add_argument("--workers",    type=int, default=s.workers)
    p.add_argument("--verdicts",   type=str, default=",".join(s.verdicts))
    p.add_argument("--log-level",  type=str, default=s.log_level)
    p.add_argument("--no-progress", action="store_true",
                   help="Disable tqdm progress bar")
    return p.parse_args()


def main():
    args = parse_args()
    settings = get_settings()

    setup_logging(args.log_level)
    LOG.info("🔄 Starting ETL")

    run_migrations()

    client = SentinelOneAPI(
        base_url=settings.s1.s1_management_url,
        token=settings.s1.s1_api_token,
        max_workers=args.workers,
    )

    lookback = min(args.since_days, settings.s1.s1_max_incident_lookback_days)
    since_iso = (
        datetime.now(timezone.utc)
        - timedelta(days=lookback)
    ).strftime(settings.etl.iso_format)

    verdicts = [v.strip() for v in args.verdicts.split(",")]

    LOG.info("Fetching threats since %s verdicts=%s", since_iso, verdicts)
    threats = list(client.fetch_all_threats(
        since_iso, verdicts, show_progress=not args.no_progress
    ))
    LOG.info("Fetched %d threats", len(threats))

    # fetch notes & deepvis in parallel
    cols_clause = get_column_clause()
    with ThreadPoolExecutor(max_workers=args.workers) as exe:
        # NOTES
        note_futs = {exe.submit(client.fetch_notes, t["id"]): t
                     for t in threats}
        for fut in as_completed(note_futs):
            t = note_futs[fut]
            try:
                t["notes"] = fut.result()
            except Exception as e:
                LOG.error("notes(%s) → %s", t["id"], e)
                t["notes"] = []

        # DEEPVIS
        dv_futs = {exe.submit(client.fetch_deepvis, t, cols_clause): t
                   for t in threats}
        for fut in as_completed(dv_futs):
            t = dv_futs[fut]
            try:
                t["deepVisibilityEvents"] = fut.result()
            except Exception as e:
                LOG.error("deepvis(%s) → %s", t["id"], e)
                t["deepVisibilityEvents"] = []

    # write into Postgres
    LOG.info("Writing to Postgres")
    with SessionLocal() as db:
        try:
            for t in threats:
                det = t.get("agentDetectionInfo", {}) or {}
                rt  = t.get("agentRealtimeInfo", {}) or {}

                ingest.upsert_tenant(
                    db,
                    int(det.get("accountId") or 0),
                    det.get("accountName", "")
                )

                ingest.upsert_endpoint(
                    db,
                    endpoint_id=int(rt.get("agentId") or 0),
                    tenant_id=int(det.get("accountId") or 0),
                    agent_uuid=rt.get("agentUuid", ""),
                    computer_name=rt.get("agentComputerName"),
                    os_name=rt.get("agentOsName"),
                    os_type=rt.get("agentOsType"),
                    ip_v4=rt.get("agentLocalIpV4"),
                    ip_v6=rt.get("agentLocalIpV6"),
                    agent_version=rt.get("agentVersion"),
                    scan_started_at=rt.get("scanStartedAt"),
                    scan_finished_at=rt.get("scanFinishedAt"),
                )

                ingest.upsert_threat(db, t)

                tid = int(t["threatInfo"]["threatId"])
                ingest.insert_notes(db, tid, t.get("notes", []))
                ingest.insert_labels(
                    db, tid,
                    t["threatInfo"].get("analystVerdict", "")
                )
                ingest.insert_indicators(
                    db, tid, t.get("indicators", [])
                )

            db.commit()

        except SQLAlchemyError:
            db.rollback()
            LOG.exception("Database error → rollback")
            sys.exit(1)

    LOG.info("✅ ETL completed successfully")


if __name__ == "__main__":
    main()