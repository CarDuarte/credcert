from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.audit import client_ip, log_action
from app.auth import revoke_all_sessions_for_user
from app.database import get_db
from app.deps import require_admin, verify_csrf
from app.models import Role, User
from app.schemas import UserCreate
from app.security import hash_password
from app.templating import templates

router = APIRouter(prefix="/users", tags=["users"])


def would_be_last_active_admin(db: Session, target: User) -> bool:
    """True if deactivating `target` would leave zero active admins.

    Extracted as a standalone, directly-testable function on purpose: when
    the acting admin is blocked from deactivating *themselves* (see the
    separate self-deactivation check below), the acting admin's own active
    session guarantees at least one active admin always remains counted
    here -- so through the ordinary single-actor HTTP flow, this condition
    can only ever be False. It still matters as defense-in-depth against a
    future bulk-deactivate/delete-user feature, or against a race between
    two concurrent requests from two different admins -- which is why it's
    tested directly against this function rather than only through the
    HTTP route (see tests/test_rbac.py).
    """
    if target.role != Role.ADMIN:
        return False
    remaining = (
        db.query(User).filter(User.role == Role.ADMIN, User.is_active.is_(True), User.id != target.id).count()
    )
    return remaining == 0


@router.get("")
def list_users(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.username).all()
    return templates.TemplateResponse(
        request, "users_list.html",
        {"request": request, "users": users, "roles": list(Role), "errors": [], "user": user},
    )


@router.post("/new")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf),
):
    try:
        data = UserCreate(username=username, password=password, role=role)
    except ValidationError as e:
        users = db.query(User).order_by(User.username).all()
        return templates.TemplateResponse(request, "users_list.html",
            {"request": request, "users": users, "roles": list(Role), "errors": [err["msg"] for err in e.errors()], "user": admin},
            status_code=400,
        )

    if db.query(User).filter(User.username == data.username).first():
        users = db.query(User).order_by(User.username).all()
        return templates.TemplateResponse(request, "users_list.html",
            {"request": request, "users": users, "roles": list(Role), "errors": ["Username already taken."], "user": admin},
            status_code=409,
        )

    new_user = User(username=data.username, password_hash=hash_password(data.password), role=data.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    log_action(db, username=admin.username, action="CREATE", entity_type="user", entity_id=new_user.id, ip_address=client_ip(request))
    return RedirectResponse("/users", status_code=303)


@router.post("/{user_id}/deactivate")
def deactivate_user(
    user_id: int, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db), _csrf: None = Depends(verify_csrf)
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")

    if would_be_last_active_admin(db, target):
        raise HTTPException(status_code=400, detail="You cannot deactivate the last active admin.")

    target.is_active = False
    db.commit()
    revoke_all_sessions_for_user(db, target.id)
    log_action(
        db, username=admin.username, action="UPDATE", entity_type="user",
        entity_id=target.id, details="deactivated", ip_address=client_ip(request),
    )
    return RedirectResponse("/users", status_code=303)
