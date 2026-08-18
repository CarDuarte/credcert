from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import Criticality, Environment, Role
from app.security import password_policy_errors

# All write endpoints validate through these schemas before touching the DB.
# Pydantic enforces types/lengths; anything free-text is length-capped to
# resist storage-exhaustion / stored-XSS-via-oversized-payload abuse
# (output is still escaped at render time by Jinja2 autoescaping -- this is
# defense in depth, not the only control).


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)
    role: Role = Role.VIEWER

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        errors = password_policy_errors(v)
        if errors:
            raise ValueError(" ".join(errors))
        return v


class ProjectCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    repo_url: str | None = Field(default=None, max_length=512)
    environment: Environment = Environment.DEV
    owner_team: str | None = Field(default=None, max_length=128)

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str | None) -> str | None:
        if v and not (v.startswith("https://") or v.startswith("git@")):
            raise ValueError("repo_url must start with https:// or git@")
        return v


class ProjectUpdate(ProjectCreate):
    pass


class CredentialCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    owner_team: str | None = Field(default=None, max_length=128)
    criticality: Criticality = Criticality.MEDIUM
    vault_reference: str | None = Field(default=None, max_length=512)
    rotation_period_days: int | None = Field(default=None, ge=1, le=3650)

    @field_validator("vault_reference")
    @classmethod
    def reject_looks_like_secret(cls, v: str | None) -> str | None:
        # Defense in depth: refuse to store anything that looks like it
        # might actually BE a secret value rather than a pointer to one.
        if v and len(v) > 8 and " " not in v and any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
            if v.count("-") == 0 and v.count("/") == 0 and v.count(":") == 0 and not v.startswith("arn:"):
                raise ValueError(
                    "vault_reference should be a pointer (e.g. 'vault://secret/prod/db' or an "
                    "ARN), not a raw value. This app never stores secret values."
                )
        return v


class CredentialUpdate(CredentialCreate):
    last_rotated_at: datetime | None = None


class UsageCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    credential_id: int
    project_id: int
    usage_location: str = Field(min_length=1, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)
