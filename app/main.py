from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.database import Base, engine, get_db
from app.deps import require_login
from app.middleware import HTTPSRedirectIfConfigured, SecurityHeadersMiddleware
from app.models import Credential, CredentialUsage, Project, User
from app.rate_limit import limiter
from app.routers import audit_routes, auth_routes, credentials, mappings, projects, users_routes
from app.templating import templates

# Structured logging. Never log request bodies, passwords, tokens, or cookies.
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("credtrace")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # In a real deployment, schema management is via Alembic migrations
    # (see scripts/migrate). create_all() here is only a convenience for
    # local dev / the demo Docker image.
    if settings.environment != "production":
        Base.metadata.create_all(bind=engine)
    logger.info("CredTrace starting in %s mode (debug=%s)", settings.environment, settings.debug)
    yield


app = FastAPI(
    title="CredTrace",
    description="Credential usage / blast-radius tracker (metadata only -- never stores secret values).",
    debug=settings.debug,
    lifespan=lifespan,
    # Hide interactive API docs in production: they're a recon aid for an
    # attacker and this app is UI-driven, not a public API product.
    docs_url="/api/docs" if settings.environment != "production" else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.environment != "production" else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(HTTPSRedirectIfConfigured)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts or ["*"])

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth_routes.router)
app.include_router(credentials.router)
app.include_router(projects.router)
app.include_router(mappings.router)
app.include_router(audit_routes.router)
app.include_router(users_routes.router)


@app.get("/healthz")
def healthz():
    """Liveness probe. Deliberately reveals nothing about internal state."""
    return PlainTextResponse("ok")


@app.get("/")
def dashboard(request: Request, user: User = Depends(require_login), db: Session = Depends(get_db)):
    from datetime import timedelta

    from app.security import utcnow

    total_credentials = db.query(func.count(Credential.id)).scalar()
    total_projects = db.query(func.count(Project.id)).scalar()
    total_mappings = db.query(func.count(CredentialUsage.id)).scalar()

    unmapped = (
        db.query(Credential)
        .outerjoin(CredentialUsage)
        .filter(CredentialUsage.id.is_(None))
        .order_by(Credential.name)
        .all()
    )

    overdue = []
    for cred in db.query(Credential).filter(Credential.rotation_period_days.isnot(None)).all():
        if cred.last_rotated_at is None:
            overdue.append(cred)
        elif cred.last_rotated_at + timedelta(days=cred.rotation_period_days) < utcnow():
            overdue.append(cred)

    return templates.TemplateResponse(request, "dashboard.html",
        {
            "request": request,
            "user": user,
            "total_credentials": total_credentials,
            "total_projects": total_projects,
            "total_mappings": total_mappings,
            "unmapped": unmapped,
            "overdue": overdue,
        },
    )
