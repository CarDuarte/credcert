from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session, selectinload

from app.audit import client_ip, log_action
from app.database import get_db
from app.deps import require_editor, require_login, verify_csrf
from app.models import Credential, CredentialUsage, Criticality, Project, User
from app.schemas import CredentialCreate, CredentialUpdate
from app.templating import templates

router = APIRouter(prefix="/credentials", tags=["credentials"])


@router.get("")
def list_credentials(
    request: Request,
    q: str | None = None,
    user: User = Depends(require_login),
    db: Session = Depends(get_db),
):
    query = db.query(Credential)
    if q:
        query = query.filter(Credential.name.ilike(f"%{q.strip()}%"))
    creds = query.order_by(Credential.name).all()
    return templates.TemplateResponse(request, "credentials_list.html",
        {"request": request, "credentials": creds, "q": q or "", "user": user},
    )


@router.get("/new")
def new_credential_form(request: Request, user: User = Depends(require_editor)):
    return templates.TemplateResponse(request, "credential_form.html",
        {"request": request, "credential": None, "errors": [], "criticalities": list(Criticality), "user": user},
    )


@router.post("/new")
def create_credential(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    owner_team: str = Form(""),
    criticality: str = Form("medium"),
    vault_reference: str = Form(""),
    rotation_period_days: str = Form(""),
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    try:
        data = CredentialCreate(
            name=name,
            description=description or None,
            owner_team=owner_team or None,
            criticality=criticality,
            vault_reference=vault_reference or None,
            rotation_period_days=int(rotation_period_days) if rotation_period_days else None,
        )
    except ValidationError as e:
        return templates.TemplateResponse(request, "credential_form.html",
            {
                "request": request,
                "credential": None,
                "errors": [err["msg"] for err in e.errors()],
                "criticalities": list(Criticality),
                "user": user,
            },
            status_code=400,
        )

    if db.query(Credential).filter(Credential.name == data.name).first():
        return templates.TemplateResponse(request, "credential_form.html",
            {
                "request": request,
                "credential": None,
                "errors": ["A credential with that name already exists."],
                "criticalities": list(Criticality),
                "user": user,
            },
            status_code=409,
        )

    cred = Credential(**data.model_dump())
    db.add(cred)
    db.commit()
    db.refresh(cred)
    log_action(db, username=user.username, action="CREATE", entity_type="credential", entity_id=cred.id, ip_address=client_ip(request))
    return RedirectResponse(f"/credentials/{cred.id}", status_code=303)


@router.get("/{credential_id}")
def credential_detail(
    credential_id: int,
    request: Request,
    user: User = Depends(require_login),
    db: Session = Depends(get_db),
):
    cred = (
        db.query(Credential)
        .options(selectinload(Credential.usages).selectinload(CredentialUsage.project))
        .filter(Credential.id == credential_id)
        .one_or_none()
    )
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    # "Blast radius": every project this credential touches, ranked so
    # production impact is impossible to miss.
    env_rank = {"production": 0, "staging": 1, "dev": 2}
    affected = sorted(cred.usages, key=lambda u: env_rank.get(u.project.environment.value, 9))

    all_projects = db.query(Project).order_by(Project.name).all()

    return templates.TemplateResponse(request, "credential_detail.html",
        {"request": request, "credential": cred, "affected": affected, "all_projects": all_projects, "user": user},
    )


@router.get("/{credential_id}/edit")
def edit_credential_form(
    credential_id: int, request: Request, user: User = Depends(require_editor), db: Session = Depends(get_db)
):
    cred = db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    return templates.TemplateResponse(request, "credential_form.html",
        {"request": request, "credential": cred, "errors": [], "criticalities": list(Criticality), "user": user},
    )


@router.post("/{credential_id}/edit")
def update_credential(
    credential_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    owner_team: str = Form(""),
    criticality: str = Form("medium"),
    vault_reference: str = Form(""),
    rotation_period_days: str = Form(""),
    mark_rotated: str = Form(""),
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    cred = db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    try:
        data = CredentialUpdate(
            name=name,
            description=description or None,
            owner_team=owner_team or None,
            criticality=criticality,
            vault_reference=vault_reference or None,
            rotation_period_days=int(rotation_period_days) if rotation_period_days else None,
        )
    except ValidationError as e:
        return templates.TemplateResponse(request, "credential_form.html",
            {
                "request": request,
                "credential": cred,
                "errors": [err["msg"] for err in e.errors()],
                "criticalities": list(Criticality),
                "user": user,
            },
            status_code=400,
        )

    for field, value in data.model_dump(exclude={"last_rotated_at"}).items():
        setattr(cred, field, value)

    if mark_rotated == "on":
        from app.security import utcnow

        cred.last_rotated_at = utcnow()

    db.commit()
    log_action(db, username=user.username, action="UPDATE", entity_type="credential", entity_id=cred.id, ip_address=client_ip(request))
    return RedirectResponse(f"/credentials/{cred.id}", status_code=303)


@router.post("/{credential_id}/delete")
def delete_credential(
    credential_id: int,
    request: Request,
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    cred = db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    db.delete(cred)
    db.commit()
    log_action(
        db, username=user.username, action="DELETE", entity_type="credential",
        entity_id=credential_id, ip_address=client_ip(request),
    )
    return RedirectResponse("/credentials", status_code=303)
