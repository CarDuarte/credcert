from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def log_action(
    db: Session,
    *,
    username: str,
    action: str,
    entity_type: str,
    entity_id: str | int | None = None,
    details: str | None = None,
    ip_address: str | None = None,
) -> None:
    """Never pass secret values or session/CSRF tokens into `details` --
    this table is expected to be readable by anyone with the ADMIN role."""
    entry = AuditLog(
        username=username,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
