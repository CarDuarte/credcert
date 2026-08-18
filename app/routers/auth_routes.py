from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit import client_ip, log_action
from app.auth import AccountLockedError, authenticate, create_session, revoke_session
from app.config import settings
from app.database import get_db
from app.deps import get_current_session
from app.rate_limit import limiter
from app.templating import templates

router = APIRouter(tags=["auth"])



@router.get("/login")
def login_form(request: Request, next: str = "/", db: Session = Depends(get_db)):
    session = get_current_session(request, db)
    if session:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": None, "next": next}
    )


@router.post("/login")
@limiter.limit(settings.login_rate_limit)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
    db: Session = Depends(get_db),
):
    error = None
    try:
        user = authenticate(db, username, password)
    except AccountLockedError:
        error = "Account temporarily locked due to repeated failed logins. Try again later."
        log_action(db, username=username, action="LOGIN_LOCKED", entity_type="user", ip_address=client_ip(request))
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": error, "next": next}, status_code=429
        )

    if user is None:
        log_action(db, username=username, action="LOGIN_FAILED", entity_type="user", ip_address=client_ip(request))
        return templates.TemplateResponse(request, "login.html",
            {"request": request, "error": "Invalid username or password.", "next": next},
            status_code=401,
        )

    session = create_session(db, user, ip_address=client_ip(request), user_agent=request.headers.get("user-agent"))
    log_action(db, username=user.username, action="LOGIN", entity_type="user", entity_id=user.id, ip_address=client_ip(request))

    safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
    response = RedirectResponse(safe_next, status_code=303)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session.token,
        httponly=True,
        secure=settings.force_https,
        samesite="lax",
        max_age=settings.session_max_age_seconds,
        path="/",
    )
    return response


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(settings.session_cookie_name)
    current_session = get_current_session(request, db)
    if current_session:
        from app.models import User

        user = db.get(User, current_session.user_id)
        if user:
            log_action(db, username=user.username, action="LOGOUT", entity_type="user", entity_id=user.id, ip_address=client_ip(request))
    revoke_session(db, token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(settings.session_cookie_name, path="/")
    return response
