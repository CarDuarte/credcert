from __future__ import annotations

from app.config import _normalize_database_url


def test_normalizes_plain_postgresql_url_to_use_psycopg_driver():
    result = _normalize_database_url("postgresql://user:pass@host:5432/db")
    assert result == "postgresql+psycopg://user:pass@host:5432/db"


def test_normalizes_legacy_postgres_scheme_to_use_psycopg_driver():
    # Heroku-style `postgres://` URLs are still common in the wild
    # (Supabase itself may hand you either form depending on where you
    # copy it from).
    result = _normalize_database_url("postgres://user:pass@host:5432/db")
    assert result == "postgresql+psycopg://user:pass@host:5432/db"


def test_leaves_sqlite_url_untouched():
    result = _normalize_database_url("sqlite:///./credtrace.db")
    assert result == "sqlite:///./credtrace.db"


def test_leaves_already_explicit_driver_url_untouched():
    result = _normalize_database_url("postgresql+psycopg://user:pass@host:6543/db")
    assert result == "postgresql+psycopg://user:pass@host:6543/db"


def test_pooler_port_detection():
    from app.database import _uses_transaction_pooler_port

    assert _uses_transaction_pooler_port("postgresql+psycopg://user:pass@host:6543/db") is True
    assert _uses_transaction_pooler_port("postgresql+psycopg://user:pass@host:5432/db") is False
    assert _uses_transaction_pooler_port("sqlite:///./credtrace.db") is False
