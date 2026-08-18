from __future__ import annotations

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings

logger = logging.getLogger("credtrace")


def _uses_transaction_pooler_port(database_url: str) -> bool:
    return ":6543" in database_url


_is_sqlite = settings.database_url.startswith("sqlite")
_is_postgres = settings.database_url.startswith("postgresql")

if _is_sqlite:
    engine = create_engine(
        settings.database_url, connect_args={"check_same_thread": False}, future=True
    )
elif _is_postgres:
    # Supabase (and most managed Postgres-as-a-service providers) expects
    # serverless/short-lived-process clients to connect through their
    # transaction-mode pooler (Supavisor/PgBouncer, typically port 6543)
    # rather than directly to Postgres (port 5432). A handful of settings
    # matter specifically because of that:
    #
    # - NullPool: don't maintain our own connection pool on top of a pool.
    #   On a serverless platform the process itself is short-lived, so an
    #   app-level pool just holds connections open across invocations that
    #   may get frozen/thawed with a stale socket. Let the pooler in front
    #   of Postgres do the pooling.
    # - prepare_threshold=None: PgBouncer/Supavisor transaction mode ties a
    #   session to a different backend connection per transaction, which
    #   breaks server-side prepared statements. psycopg3 will otherwise
    #   start preparing statements automatically after a few repeated
    #   executions; disabling that avoids "prepared statement does not
    #   exist" errors under pooling.
    # - pool_pre_ping: cheap liveness check before reusing a connection,
    #   defense in depth even with NullPool.
    if not _uses_transaction_pooler_port(settings.database_url) and settings.environment == "production":
        logger.warning(
            "DATABASE_URL does not look like it's using a transaction-mode "
            "pooler (port 6543). On a serverless platform (Vercel, etc.) "
            "this risks exhausting Postgres's connection limit under "
            "concurrent load -- see README.md's 'Deploying to Vercel + "
            "Supabase' section."
        )
    engine = create_engine(
        settings.database_url,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args={"prepare_threshold": None},
        future=True,
    )
else:
    engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)

# Enforce FK constraints on SQLite (off by default). Postgres enforces them
# natively, so this is a SQLite-only concern.
if _is_sqlite:
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
