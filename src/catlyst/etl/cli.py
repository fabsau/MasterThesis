import sys
import logging
import argparse
from datetime import datetime, timedelta, timezone

from alembic.config import Config as AlembicConfig
from alembic import command

from catlyst.settings import get_settings
from catlyst.db.connection import engine, SessionLocal
from catlyst.db.schema import metadata
from catlyst.etl.s1_api import SentinelOneAPI
from catlyst.etl import db as ingest

from tqdm import tqdm

class TqdmLoggingHandler(logging.StreamHandler):
    """
    Logging handler that uses tqdm.write so log messages don't overwrite tqdm bars.
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)

def setup_logging(level: str, use_tqdm: bool = False):
    lvl = getattr(logging, level.upper(), logging.DEBUG)
    if use_tqdm:
        h = TqdmLoggingHandler()
    else:
        h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(lvl)
    root.addHandler(h)

def run_migrations():
    LOG = logging.getLogger(__name__)
    LOG.debug("Initializing Alembic configuration from alembic.ini")
    cfg = AlembicConfig("alembic.ini")
    url = get_settings().database.url
    cfg.set_main_option("sqlalchemy.url", url)
    LOG.debug("Starting Alembic upgrade with URL: %s", url)
    command.upgrade(cfg, "head")
    LOG.info("✅ Alembic migrations applied")

def init_db():
    LOG = logging.getLogger(__name__)
    LOG.debug("Starting DB initialization: calling metadata.create_all()")
    metadata.create_all(bind=engine)
    LOG.info("✅ Database initialized (metadata.create_all completed)")

def parse_args():
    etl = get_settings().etl
    p = argparse.ArgumentParser("SentinelOne ETL")
    p.add_argument("--init-db", action="store_true",
                   help="Create tables (metadata.create_all) and exit")
    p.add_argument("--since-days", type=int, default=etl.since_days,
                   help=f"Lookback (max {etl.max_since_days})")
    p.add_argument("--workers", type=int, default=etl.workers)
    p.add_argument("--verdicts", type=str,
                   default=",".join(etl.verdicts))
    p.add_argument("--log-level", type=str, default=etl.log_level)
    p.add_argument("--no-progress", action="store_true",
                   help="Disable all tqdm progress bars")
    return p.parse_args()

def compute_since_iso(days: int) -> str:
    fmt = get_settings().etl.iso_format
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return since.strftime(fmt)

def main():
    try:
        args = parse_args()
        # SETUP LOGGING before migrations (for early logs and Alembic logs)
        setup_logging(args.log_level, use_tqdm=not args.no_progress)
        LOG = logging.getLogger(__name__)
        LOG.debug("Starting ETL main function")
        LOG.debug("Parsed arguments: %s", args)

        run_migrations()

        # SETUP LOGGING again after Alembic wipes our handlers
        setup_logging(args.log_level, use_tqdm=not args.no_progress)
        LOG = logging.getLogger(__name__)

        if args.init_db:
            LOG.debug("--init-db flag detected; initializing database")
            init_db()
            sys.exit(0)

        settings = get_settings()
        LOG.debug("Fetched settings: %s", settings)
        LOG.debug("Creating SentinelOneAPI client")
        client = SentinelOneAPI(
            base_url=settings.s1.s1_management_url,
            token=settings.s1.s1_api_token,
            max_workers=args.workers
        )
        since_iso = compute_since_iso(args.since_days)
        verdicts = [v.strip() for v in args.verdicts.split(",")]

        LOG.info("🔄 ETL starting – since_days=%d → %s", args.since_days, since_iso)

        # Stage 1: Fetch threats
        threats = list(client.fetch_all_threats(since_iso, verdicts, show_progress=not args.no_progress))
        LOG.info("→ %d threats fetched", len(threats))

        # Stage 2: Fetch notes for each threat
        LOG.info("Stage 2: Fetching notes for each threat")
        for t in threats:
            tid = t.get("id") or t.get("threatInfo", {}).get("threatId")
            t["notes"] = client.fetch_notes(tid)

        # Stage 3: Fetching and mapping deep visibility events
        LOG.info("Stage 3: Fetching and mapping deep visibility events")
        # Build columns clause for DV queries from deepvis settings
        from catlyst.config import DEEPVIS_COLUMN_MAPPINGS, DEEPVIS_SORT_CLAUSE

        # Build the columns clause dynamically
        columns_expr = ", ".join(
            f"{out} = {src}" for out, src in DEEPVIS_COLUMN_MAPPINGS
        )
        deepvis_cols = f" | columns {columns_expr}{DEEPVIS_SORT_CLAUSE}"

        for t in threats:
            tid = t.get("id") or t.get("threatInfo", {}).get("threatId")
            try:
                dv_raw = client.fetch_deepvis(t, deepvis_cols)
            except Exception:
                LOG.exception("Error fetching DeepVis for threat %s", tid)
                dv_raw = []
            LOG.debug("Fetched %d DeepVis events for threat %s", len(dv_raw), tid)
            mapped = []
            for ev in dv_raw:
                mapped.append({
                    out: ev.get(src)
                    for out, src in DEEPVIS_COLUMN_MAPPINGS
                })
            t["deepvis"] = mapped

        # Stage 4: Bulk upsert core objects
        LOG.info("Stage 4: Bulk upsert core objects")
        with SessionLocal() as db:
            LOG.debug("Upserting core objects into DB")
            ingest.batch_upsert_core(db, threats, show_progress=not args.no_progress)
            LOG.debug("Completed upsert of core objects")

        # Stage 5: Bulk insert dependent objects
        LOG.info("Stage 5: Bulk insert dependent objects")
        with SessionLocal() as db:
            LOG.debug("Upserting dependent objects into DB")
            ingest.batch_upsert_dependents(db, threats, show_progress=not args.no_progress)
            LOG.debug("Completed upsert of dependent objects")

        LOG.info("✅ ETL completed successfully")
    except Exception as exc:
        msg = str(exc)[:200]
        LOG = logging.getLogger(__name__)
        LOG.exception("ETL job failed with exception: %s", msg)
        sys.stderr.write(f"ETL job failed: {msg}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
