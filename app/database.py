from __future__ import annotations

import logging
import socket

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings

logger = logging.getLogger("credtrace")


def _uses_transaction_pooler_port(database_url: str) -> bool:
    return ":6543" in database_url


def _make_ipv4_only_psycopg_creator(database_url: str):
    """Returns a connection-factory function that forces IPv4, working
    around a real, documented failure mode: Supabase's pooler hostnames can
    resolve to BOTH an IPv4 and an IPv6 address, and Python's default DNS
    resolution can pick the IPv6 one. That's fine on a host with IPv6
    egress -- but Vercel's serverless function runtime has none, so the
    connection fails with `OSError: Cannot assign requested address`
    despite DNS resolving successfully. libpq (which psycopg wraps)
    supports connecting to a specific resolved address (`hostaddr`) while
    still sending the original hostname for TLS certificate verification
    (`host`) -- which is exactly what this does, resolved fresh on every
    connection rather than cached once, so it keeps working if Supabase's
    underlying IPs change.
    """
    import psycopg

    url = make_url(database_url)
    host = url.host
    port = url.port or 5432

    def _creator():
        # AF_INET = IPv4 only. This is the actual fix -- everything else
        # here is just plumbing the resolved address through to psycopg.
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"No IPv4 address found for {host}:{port}")
        ipv4_addr = infos[0][4][0]

        return psycopg.connect(
            host=host,  # kept for TLS SNI / certificate verification
            hostaddr=ipv4_addr,  # the actual address dialed, forced to IPv4
            port=port,
            user=url.username,
            password=url.password,
            dbname=url.database,
            sslmode="require",
            prepare_threshold=None,
        )

    return _creator


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
    # - IPv4-forced connection creator: see _make_ipv4_only_psycopg_creator
    #   above -- fixes a real "Cannot assign requested address" failure
    #   observed connecting from Vercel's serverless runtime to Supabase.
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
        "postgresql+psycopg://",  # placeholder; the creator below supplies real connection params
        creator=_make_ipv4_only_psycopg_creator(settings.database_url),
        poolclass=NullPool,
        pool_pre_ping=True,
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
