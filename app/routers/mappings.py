from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import client_ip, log_action
from app.database import get_db
from app.deps import require_editor, verify_csrf
from app.models import Credential, CredentialUsage, Project, User
from app.schemas import UsageCreate

router = APIRouter(prefix="/mappings", tags=["mappings"])


@router.post("/new")
def create_mapping(
    request: Request,
    credential_id: int = Form(...),
    project_id: int = Form(...),
    usage_location: str = Form(...),
    notes: str = Form(""),
    redirect_to: str = Form("/credentials"),
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    try:
        data = UsageCreate(
            credential_id=credential_id, project_id=project_id, usage_location=usage_location, notes=notes or None
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail="Invalid mapping data") from e

    if not db.get(Credential, data.credential_id) or not db.get(Project, data.project_id):
        raise HTTPException(status_code=404, detail="Credential or project not found")

    usage = CredentialUsage(**data.model_dump(), added_by=user.username)
    db.add(usage)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Duplicate mapping -- treat as a no-op success rather than an error,
        # this is an idempotent "make sure this link exists" action.
        pass
    else:
        log_action(
            db, username=user.username, action="CREATE", entity_type="credential_usage",
            entity_id=usage.id, details=f"credential={data.credential_id} project={data.project_id}",
            ip_address=client_ip(request),
        )

    safe_redirect = redirect_to if redirect_to.startswith("/") and not redirect_to.startswith("//") else "/credentials"
    return RedirectResponse(safe_redirect, status_code=303)


@router.post("/{usage_id}/delete")
def delete_mapping(
    usage_id: int,
    request: Request,
    redirect_to: str = Form("/credentials"),
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    usage = db.get(CredentialUsage, usage_id)
    if usage is None:
        raise HTTPException(status_code=404, detail="Mapping not found")
    db.delete(usage)
    db.commit()
    log_action(
        db, username=user.username, action="DELETE", entity_type="credential_usage",
        entity_id=usage_id, ip_address=client_ip(request),
    )

    safe_redirect = redirect_to if redirect_to.startswith("/") and not redirect_to.startswith("//") else "/credentials"
    return RedirectResponse(safe_redirect, status_code=303)
