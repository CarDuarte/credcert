from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth import get_valid_session
from app.config import settings
from app.database import get_db
from app.models import Role, User, UserSession
from app.security import constant_time_eq


def get_current_session(request: Request, db: Session = Depends(get_db)) -> UserSession | None:
    token = request.cookies.get(settings.session_cookie_name)
    return get_valid_session(db, token)


def require_login(
    request: Request,
    session: UserSession | None = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> User:
    if session is None:
        # 303 so browsers correctly redirect GET after a POST-triggered check.
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": f"/login?next={request.url.path}"},
        )
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    request.state.current_user = user
    request.state.current_session = session
    return user


def require_role(*roles: Role):
    def _checker(user: User = Depends(require_login)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        return user

    return _checker


require_editor = require_role(Role.ADMIN, Role.EDITOR)
require_admin = require_role(Role.ADMIN)


async def verify_csrf(
    request: Request,
    session: UserSession | None = Depends(get_current_session),
) -> None:
    """Synchronizer-token CSRF protection for all state-changing requests.

    The token is bound to the server-side session (not just a cookie), so an
    attacker who can only make the victim's browser send cookies (the classic
    CSRF setup) still cannot produce a valid token -- they'd need to have
    read it out of the rendered page first, which the browser's
    same-origin policy prevents.
    """
    if session is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed: no session.")

    form = await request.form()
    submitted = form.get("csrf_token")
    if not submitted or not constant_time_eq(str(submitted), session.csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed.")
