import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Make `app` importable when alembic is run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import _normalize_database_url, settings  # noqa: E402
from app.database import Base  # noqa: E402
from app import models  # noqa: E402,F401  (import registers all tables on Base.metadata)

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Always take the DB URL from our own app config (env vars), never from a
# URL hardcoded in alembic.ini -- keeps exactly one source of truth for
# where the database lives, and keeps credentials out of a file that's
# easy to accidentally commit.
#
# Migrations specifically need a DIRECT connection, not the transaction-mode
# pooler (Supavisor/PgBouncer) the running app uses: DDL and multi-statement
# migrations don't play well with transaction-mode pooling. If
# MIGRATION_DATABASE_URL is set, use that for migrations; otherwise fall
# back to the app's normal DATABASE_URL (fine for SQLite / a plain Postgres
# instance with no pooler in front of it).
migration_url_raw = os.environ.get("MIGRATION_DATABASE_URL")
migration_url = _normalize_database_url(migration_url_raw) if migration_url_raw else settings.database_url
config.set_main_option("sqlalchemy.url", migration_url)

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
