# src/catlyst/db/connection.py

import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from catlyst.settings import get_settings

# Set up logging for this module
LOG = logging.getLogger(__name__)
# On import, this will call get_settings() which loads .env first
cfg = get_settings().database

# Use the url property we defined in the settings
engine = create_engine(
    cfg.url,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True,
)

def get_db():
    db = SessionLocal()
    LOG.debug("Created new DB session")
    try:
        yield db
    finally:
        db.close()
        LOG.debug("Closed DB session")
