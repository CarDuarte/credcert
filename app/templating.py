from __future__ import annotations

from fastapi import Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")


def csrf_token(request: Request) -> str:
    """Reads the CSRF token off the current server-side session (set by
    require_login). Returns '' when there's no session (e.g. login page),
    in which case any form using it simply won't submit successfully --
    which is fine, since those forms require auth anyway."""
    session = getattr(request.state, "current_session", None)
    return session.csrf_token if session else ""


templates.env.globals["csrf_token"] = csrf_token
