# src/catlyst/db/connection.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from catlyst.settings import get_settings

# on import, this will call get_settings() → which loads .env first
cfg = get_settings().database

# use the url property we defined above
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
    try:
        yield db
    finally:
        db.close()