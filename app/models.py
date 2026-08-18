from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp. We deliberately store naive-but-UTC datetimes
    everywhere: SQLite (used in dev/tests) silently drops tzinfo on
    round-trip even when a column is declared timezone-aware, which
    previously caused naive-vs-aware TypeErrors when comparing a freshly
    created (aware) value against one just reloaded from the DB (naive).
    Being consistently naive-UTC end-to-end avoids that whole class of bug
    and works identically across SQLite and Postgres."""
    return datetime.now(UTC).replace(tzinfo=None)


def gen_uuid() -> str:
    return str(uuid.uuid4())


class Role(enum.StrEnum):
    ADMIN = "admin"     # can create/edit/delete credentials, projects, mappings, users
    EDITOR = "editor"   # can create/edit credentials, projects, mappings
    VIEWER = "viewer"   # read-only


class Criticality(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(enum.StrEnum):
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


# ---------------------------------------------------------------------------
# IMPORTANT: This application NEVER stores secret/credential *values*.
# Only metadata about a credential (its name, owner, rotation schedule) and
# WHERE it is used (which projects/systems) is stored. This is a deliberate
# security design choice that removes an entire class of risk (this DB being
# a juicy target for actual secret theft).
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False, default=Role.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)

    sessions: Mapped[list[UserSession]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """Server-side session store, so sessions are instantly revocable (unlike
    stateless JWTs). Only an opaque random token is ever placed in the
    client's cookie -- never any user data."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=gen_uuid, nullable=False)
    csrf_token: Mapped[str] = mapped_column(String(64), default=gen_uuid, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")


class Project(Base):
    """A system/service/repo that CONSUMES credentials."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    repo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    environment: Mapped[Environment] = mapped_column(Enum(Environment), default=Environment.DEV, nullable=False)
    owner_team: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, onupdate=utcnow, nullable=False)

    usages: Mapped[list[CredentialUsage]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Credential(Base):
    """Metadata ABOUT a credential. The actual secret value is never stored
    here -- this table is a pointer/index, not a vault."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    criticality: Mapped[Criticality] = mapped_column(Enum(Criticality), default=Criticality.MEDIUM, nullable=False)

    # Where the actual secret VALUE lives (a vault reference, never the value itself)
    vault_reference: Mapped[str | None] = mapped_column(
        String(512), nullable=True, doc="e.g. vault://secret/prod/db-password or AWS Secrets Manager ARN"
    )

    rotation_period_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, onupdate=utcnow, nullable=False)

    usages: Mapped[list[CredentialUsage]] = relationship(back_populates="credential", cascade="all, delete-orphan")


class CredentialUsage(Base):
    """The mapping: 'this credential is used HERE, in this way'. This is the
    core value of the tool -- it's what answers 'if I rotate credential X,
    what breaks?'"""

    __tablename__ = "credential_usages"
    __table_args__ = (UniqueConstraint("credential_id", "project_id", "usage_location", name="uq_usage"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int] = mapped_column(ForeignKey("credentials.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)

    usage_location: Mapped[str] = mapped_column(
        String(255), nullable=False, doc="e.g. 'env var DB_PASSWORD in docker-compose.yml'"
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    added_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, nullable=False)

    credential: Mapped[Credential] = relationship(back_populates="usages")
    project: Mapped[Project] = relationship(back_populates="usages")


class AuditLog(Base):
    """Append-only audit trail. Never store secret values or session tokens
    here -- only who did what to which entity, and when."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # CREATE/UPDATE/DELETE/LOGIN/LOGIN_FAILED/LOGOUT
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
