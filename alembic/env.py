# /alembic/env.py
from logging.config import fileConfig

from sqlalchemy import create_engine, pool
from alembic import context

from catlyst.db.schema import metadata as target_metadata
from catlyst.settings import get_settings

# this config object is the Alembic .ini settings
cfg = context.config
if cfg.config_file_name:
    fileConfig(cfg.config_file_name)

if cfg.config_file_name:
    fileConfig(cfg.config_file_name, disable_existing_loggers=False)

# build the same DSN from our DatabaseSettings
settings = get_settings()
db = settings.database
alembic_url = db.url
cfg.set_main_option("sqlalchemy.url", alembic_url)


def run_migrations_offline():
    """Run migrations in 'offline' mode (no DB connection)."""
    url = cfg.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode (connect to the DB)."""
    connectable = create_engine(
        cfg.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
        future=True,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()