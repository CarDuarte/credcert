"""
Centralized configuration.

Security principle: NO secrets or environment-specific values are hardcoded.
Everything is read from environment variables (12-factor app), with safe
defaults only for genuinely non-sensitive local-dev convenience. In
production, SECRET_KEY and DATABASE_URL must be supplied explicitly or the
app refuses to start.
"""
from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Loads variables from a .env file in the current working directory into
# the process environment, if one exists. This is what lets `.env` "just
# work" on every OS -- no manual `export $(cat .env | ...)` shell gymnastics
# needed (which is fragile anyway: it breaks the moment a value contains a
# space, an inline comment, or a character like `|` that the shell treats
# specially). Real environment variables already set (e.g. by Docker,
# Vercel, or your CI) always take precedence -- load_dotenv() does not
# override an existing os.environ value by default.
load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_database_url(url: str) -> str:
    """Supabase (and most providers) hand you a plain `postgresql://...` or
    legacy `postgres://...` connection string. Left as-is, SQLAlchemy
    defaults the dialect to psycopg2, which we don't install (we use
    psycopg v3 instead) -- that would fail at connect time with a
    confusing "no module named psycopg2" error. Normalize both forms to
    explicitly request the psycopg v3 driver.
    """
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


@dataclass(frozen=True)
class Settings:
    app_name: str = "CredTrace"
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    debug: bool = field(default_factory=lambda: _env_bool("DEBUG", False))

    database_url: str = field(
        default_factory=lambda: _normalize_database_url(os.getenv("DATABASE_URL", "sqlite:///./credtrace.db"))
    )

    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))

    session_cookie_name: str = "credtrace_session"
    session_max_age_seconds: int = field(
        default_factory=lambda: int(os.getenv("SESSION_MAX_AGE_SECONDS", "28800"))  # 8h
    )
    session_idle_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "1800"))  # 30m
    )

    # Secure-by-default in production (session cookie gets the `Secure` flag,
    # HTTP->HTTPS redirect is enabled). Defaults OFF outside production so
    # local dev over plain http://localhost works out of the box; set
    # FORCE_HTTPS explicitly to override either direction.
    force_https: bool = field(
        default_factory=lambda: _env_bool("FORCE_HTTPS", os.getenv("ENVIRONMENT", "development") == "production")
    )

    max_failed_logins: int = field(default_factory=lambda: int(os.getenv("MAX_FAILED_LOGINS", "5")))
    lockout_minutes: int = field(default_factory=lambda: int(os.getenv("LOCKOUT_MINUTES", "15")))

    login_rate_limit: str = field(default_factory=lambda: os.getenv("LOGIN_RATE_LIMIT", "10/minute"))

    trusted_hosts: list[str] = field(
        default_factory=lambda: [h for h in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",") if h]
    )


def get_settings() -> Settings:
    settings = Settings()

    if settings.environment == "production":
        if not settings.secret_key or len(settings.secret_key) < 32:
            sys.stderr.write(
                "FATAL: SECRET_KEY must be set to a random value of at least 32 "
                "characters in production (e.g. `openssl rand -hex 32`).\n"
            )
            raise SystemExit(1)
        if settings.database_url.startswith("sqlite") and not _env_bool("ALLOW_SQLITE_IN_PROD", False):
            sys.stderr.write(
                "FATAL: refusing to use SQLite in production. Set DATABASE_URL to a "
                "real database, or explicitly set ALLOW_SQLITE_IN_PROD=true if this "
                "is intentional (e.g. a demo deployment).\n"
            )
            raise SystemExit(1)
    elif not settings.secret_key:
        # Dev convenience only: ephemeral key, regenerated each process start.
        # This deliberately invalidates sessions across restarts in dev so a
        # weak/blank key is never silently reused.
        object.__setattr__(settings, "secret_key", secrets.token_hex(32))

    return settings


settings = get_settings()
