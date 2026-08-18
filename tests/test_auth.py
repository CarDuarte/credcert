from __future__ import annotations

from tests.conftest import get_csrf_token, login


def test_unauthenticated_redirects_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_login_with_bad_password_fails(client, admin_user):
    r = login(client, "admin", "totally-wrong")
    assert r.status_code == 401
    assert "Invalid username or password" in r.text


def test_login_with_unknown_username_fails_same_as_bad_password(client, admin_user):
    r = login(client, "no-such-user", "whatever")
    assert r.status_code == 401
    assert "Invalid username or password" in r.text


def test_successful_login_grants_access(client, admin_user):
    r = login(client, "admin")
    assert r.status_code == 303
    r = client.get("/")
    assert r.status_code == 200
    assert "Dashboard" in r.text


def test_session_cookie_is_httponly(client, admin_user):
    r = login(client, "admin", )
    set_cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie or "SameSite=Lax" in set_cookie


def test_account_locks_after_repeated_failures(client, admin_user):
    for _ in range(5):
        login(client, "admin", "wrong-password")
    r = login(client, "admin", "CorrectHorseBattery99")  # correct password, but locked
    assert r.status_code == 429


def test_logout_invalidates_session(client, admin_user):
    login(client, "admin")
    assert client.get("/").status_code == 200

    token = get_csrf_token(client, "/")
    client.post("/logout", data={"csrf_token": token})

    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_deactivated_user_cannot_access(client, db_session, admin_user):
    admin_user.is_active = False
    db_session.commit()
    r = login(client, "admin")
    # authenticate() rejects inactive users same as bad password
    assert r.status_code == 401
