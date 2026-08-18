from __future__ import annotations

from tests.conftest import get_csrf_token, login


def test_create_credential_without_csrf_token_is_rejected(client, admin_user):
    login(client, "admin")
    r = client.post("/credentials/new", data={"name": "x", "criticality": "low"})
    assert r.status_code == 403


def test_create_credential_with_wrong_csrf_token_is_rejected(client, admin_user):
    login(client, "admin")
    r = client.post("/credentials/new", data={"name": "x", "criticality": "low", "csrf_token": "forged"})
    assert r.status_code == 403


def test_create_credential_with_valid_csrf_token_succeeds(client, admin_user):
    login(client, "admin")
    token = get_csrf_token(client, "/credentials/new")
    r = client.post("/credentials/new", data={"name": "x", "criticality": "low", "csrf_token": token})
    assert r.status_code == 303


def test_csrf_token_from_a_different_session_is_rejected(client, db_session, admin_user):
    from app.models import Role
    from tests.conftest import make_user

    make_user(db_session, "other-admin", "CorrectHorseBattery99", Role.ADMIN)

    login(client, "admin")
    token = get_csrf_token(client, "/credentials/new")

    # Log out and in as a different user -- gets a fresh session/csrf token.
    logout_token = get_csrf_token(client, "/")
    client.post("/logout", data={"csrf_token": logout_token})
    login(client, "other-admin")

    # The token minted for the FIRST session must not work for the second.
    r = client.post("/credentials/new", data={"name": "y", "criticality": "low", "csrf_token": token})
    assert r.status_code == 403


def test_delete_requires_csrf(client, admin_user):
    login(client, "admin")
    token = get_csrf_token(client, "/credentials/new")
    client.post("/credentials/new", data={"name": "to-delete", "criticality": "low", "csrf_token": token})

    r = client.post("/credentials/1/delete")
    assert r.status_code == 403
