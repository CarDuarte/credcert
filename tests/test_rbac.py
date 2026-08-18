from __future__ import annotations

from app.models import Role
from tests.conftest import get_csrf_token, login, make_user


def test_viewer_cannot_create_credential(client, viewer_user):
    login(client, "viewer")
    r = client.get("/credentials/new")
    assert r.status_code == 403


def test_viewer_can_read_credentials_list(client, viewer_user):
    login(client, "viewer")
    r = client.get("/credentials")
    assert r.status_code == 200


def test_editor_can_create_credential(client, editor_user):
    login(client, "editor")
    token = get_csrf_token(client, "/credentials/new")
    r = client.post("/credentials/new", data={"name": "editor-made", "criticality": "medium", "csrf_token": token})
    assert r.status_code == 303


def test_editor_cannot_view_audit_log(client, editor_user):
    login(client, "editor")
    r = client.get("/audit")
    assert r.status_code == 403


def test_editor_cannot_manage_users(client, editor_user):
    login(client, "editor")
    r = client.get("/users")
    assert r.status_code == 403


def test_admin_can_view_audit_log(client, admin_user):
    login(client, "admin")
    r = client.get("/audit")
    assert r.status_code == 200


def test_admin_can_manage_users(client, admin_user):
    login(client, "admin")
    r = client.get("/users")
    assert r.status_code == 200


def test_admin_cannot_deactivate_self(client, admin_user):
    login(client, "admin")
    token = get_csrf_token(client, "/users")
    r = client.post(f"/users/{admin_user.id}/deactivate", data={"csrf_token": token})
    assert r.status_code == 400


def test_cannot_deactivate_the_last_active_admin(db_session, admin_user):
    """Unit-tests the counting logic directly rather than through the HTTP
    route. Through the ordinary single-actor HTTP flow, the acting admin's
    own active session always keeps the count at >=1 (self-deactivation is
    blocked separately, see the test above), so this condition can't
    actually be reached that way -- it exists as defense-in-depth for a
    future bulk-deactivate feature or a race between two admins' concurrent
    requests. See the docstring on would_be_last_active_admin for the full
    reasoning."""
    from app.routers.users_routes import would_be_last_active_admin

    # admin_user is currently the only admin -> deactivating them would
    # leave zero.
    assert would_be_last_active_admin(db_session, admin_user) is True

    # With a second active admin present, deactivating the first is fine.
    other_admin = make_user(db_session, "second-admin", "CorrectHorseBattery99", Role.ADMIN)
    assert would_be_last_active_admin(db_session, admin_user) is False

    # But once that second admin is (already) inactive, admin_user is once
    # again the last one standing.
    other_admin.is_active = False
    db_session.commit()
    assert would_be_last_active_admin(db_session, admin_user) is True

    # Non-admins never trip this check regardless of admin headcount.
    viewer = make_user(db_session, "some-viewer", "CorrectHorseBattery99", Role.VIEWER)
    assert would_be_last_active_admin(db_session, viewer) is False
