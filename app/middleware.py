from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings

# Strict CSP: no inline scripts, no remote script sources, no framing.
# Our templates deliberately avoid inline <script>/<style> so this can stay
# tight instead of falling back to 'unsafe-inline'.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "object-src 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.force_https:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        # Defense in depth against caching pages that may contain
        # session-scoped data (CSRF tokens, audit logs, etc.)
        if request.url.path not in ("/static",) and not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response


class HTTPSRedirectIfConfigured(BaseHTTPMiddleware):
    """Redirect http->https, but only when FORCE_HTTPS is on and we're not
    already behind a TLS-terminating proxy that says otherwise. Skipped
    automatically for local dev via ENVIRONMENT=development."""

    async def dispatch(self, request: Request, call_next):
        if (
            settings.force_https
            and settings.environment == "production"
            and request.url.scheme == "http"
            and request.headers.get("x-forwarded-proto", "http") != "https"
        ):
            https_url = request.url.replace(scheme="https")
            from starlette.responses import RedirectResponse

            return RedirectResponse(str(https_url), status_code=308)
        return await call_next(request)
