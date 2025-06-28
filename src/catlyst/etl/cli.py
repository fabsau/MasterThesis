# src/catlyst/etl/cli.py

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

LOG = logging.getLogger(__name__)


def setup_logging(level: str):
    lvl = getattr(logging, level.upper(), logging.INFO)
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(lvl)
    root.addHandler(h)


def run_migrations():
    cfg = AlembicConfig("alembic.ini")
    url = get_settings().database.url
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    LOG.info("✅ Alembic migrations applied")


def init_db():
    LOG.info("⚙️  Initializing DB via metadata.create_all()")
    metadata.create_all(bind=engine)
    LOG.info("✅ Database initialized")


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
        setup_logging(args.log_level)
        run_migrations()

        if args.init_db:
            init_db()
            sys.exit(0)

        settings = get_settings()
        LOG.debug(
            f"S1 URL={settings.s1.s1_management_url}, token(len)={len(settings.s1.s1_api_token)}"
        )

        client = SentinelOneAPI(
            base_url=settings.s1.s1_management_url,
            token=settings.s1.s1_api_token,
            max_workers=args.workers
        )

        since_iso = compute_since_iso(args.since_days)
        verdicts = [v.strip() for v in args.verdicts.split(",")]

        LOG.info("🔄 ETL starting – since_days=%d → %s", args.since_days, since_iso)
        threats = list(client.fetch_all_threats(since_iso, verdicts, show_progress=not args.no_progress))
        LOG.info("→ %d threats fetched", len(threats))

        LOG.info("Stage 2: Bulk upsert core objects")
        with SessionLocal() as db:
            ingest.batch_upsert_core(db, threats)

        LOG.info("Stage 3: Bulk insert dependent objects")
        with SessionLocal() as db:
            ingest.batch_upsert_dependents(db, threats)

        LOG.info("✅ ETL completed successfully")
    except Exception as exc:
        msg = str(exc)[:200]
        sys.stderr.write(f"ETL job failed: {msg}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()