from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import require_admin
from app.models import AuditLog, User
from app.templating import templates

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def view_audit_log(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    entries = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(500).all()
    return templates.TemplateResponse(request, "audit_log.html", {"request": request, "entries": entries, "user": user})
