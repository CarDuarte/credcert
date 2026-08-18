from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session, selectinload

from app.audit import client_ip, log_action
from app.database import get_db
from app.deps import require_editor, require_login, verify_csrf
from app.models import Credential, CredentialUsage, Environment, Project, User
from app.schemas import ProjectCreate, ProjectUpdate
from app.templating import templates

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("")
def list_projects(
    request: Request, q: str | None = None, user: User = Depends(require_login), db: Session = Depends(get_db)
):
    query = db.query(Project)
    if q:
        query = query.filter(Project.name.ilike(f"%{q.strip()}%"))
    projects = query.order_by(Project.name).all()
    context = {"request": request, "projects": projects, "q": q or "", "user": user}
    return templates.TemplateResponse(request, "projects_list.html", context)


@router.get("/new")
def new_project_form(request: Request, user: User = Depends(require_editor)):
    context = {"request": request, "project": None, "errors": [], "environments": list(Environment), "user": user}
    return templates.TemplateResponse(request, "project_form.html", context)


@router.post("/new")
def create_project(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    repo_url: str = Form(""),
    environment: str = Form("dev"),
    owner_team: str = Form(""),
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    try:
        data = ProjectCreate(
            name=name, description=description or None, repo_url=repo_url or None,
            environment=environment, owner_team=owner_team or None,
        )
    except ValidationError as e:
        context = {
            "request": request, "project": None, "errors": [err["msg"] for err in e.errors()],
            "environments": list(Environment), "user": user,
        }
        return templates.TemplateResponse(request, "project_form.html", context, status_code=400)

    if db.query(Project).filter(Project.name == data.name).first():
        context = {
            "request": request, "project": None, "errors": ["A project with that name already exists."],
            "environments": list(Environment), "user": user,
        }
        return templates.TemplateResponse(request, "project_form.html", context, status_code=409)

    project = Project(**data.model_dump())
    db.add(project)
    db.commit()
    db.refresh(project)
    log_action(
        db, username=user.username, action="CREATE", entity_type="project",
        entity_id=project.id, ip_address=client_ip(request),
    )
    return RedirectResponse(f"/projects/{project.id}", status_code=303)


@router.get("/{project_id}")
def project_detail(project_id: int, request: Request, user: User = Depends(require_login), db: Session = Depends(get_db)):
    project = (
        db.query(Project)
        .options(selectinload(Project.usages).selectinload(CredentialUsage.credential))
        .filter(Project.id == project_id)
        .one_or_none()
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    all_credentials = db.query(Credential).order_by(Credential.name).all()
    context = {"request": request, "project": project, "all_credentials": all_credentials, "user": user}
    return templates.TemplateResponse(request, "project_detail.html", context)


@router.get("/{project_id}/edit")
def edit_project_form(
    project_id: int, request: Request, user: User = Depends(require_editor), db: Session = Depends(get_db)
):
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    context = {
        "request": request, "project": project, "errors": [], "environments": list(Environment), "user": user,
    }
    return templates.TemplateResponse(request, "project_form.html", context)


@router.post("/{project_id}/edit")
def update_project(
    project_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    repo_url: str = Form(""),
    environment: str = Form("dev"),
    owner_team: str = Form(""),
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        data = ProjectUpdate(
            name=name, description=description or None, repo_url=repo_url or None,
            environment=environment, owner_team=owner_team or None,
        )
    except ValidationError as e:
        context = {
            "request": request, "project": project, "errors": [err["msg"] for err in e.errors()],
            "environments": list(Environment), "user": user,
        }
        return templates.TemplateResponse(request, "project_form.html", context, status_code=400)

    for field, value in data.model_dump().items():
        setattr(project, field, value)
    db.commit()
    log_action(
        db, username=user.username, action="UPDATE", entity_type="project",
        entity_id=project.id, ip_address=client_ip(request),
    )
    return RedirectResponse(f"/projects/{project.id}", status_code=303)


@router.post("/{project_id}/delete")
def delete_project(
    project_id: int,
    request: Request,
    user: User = Depends(require_editor),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
    log_action(
        db, username=user.username, action="DELETE", entity_type="project",
        entity_id=project_id, ip_address=client_ip(request),
    )
    return RedirectResponse("/projects", status_code=303)
