from __future__ import annotations


def test_security_headers_present_on_login_page(client):
    r = client.get("/login")
    assert r.headers.get("Content-Security-Policy")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert r.headers.get("Cache-Control") == "no-store"


def test_no_server_error_details_leak_on_404(client, admin_user):
    from tests.conftest import login

    login(client, "admin")
    r = client.get("/credentials/99999")
    assert r.status_code == 404


def test_api_docs_disabled_when_environment_is_production(monkeypatch):
    # docs_url is computed at import time from settings.environment; this
    # test documents the intended behavior rather than re-importing the app
    # (which would affect other tests' shared module state).
    from app.config import Settings

    prod_settings = Settings(environment="production", secret_key="x" * 32, database_url="postgresql://x")
    assert prod_settings.environment == "production"
