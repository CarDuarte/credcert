from __future__ import annotations

import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("TRUSTED_HOSTS", "testserver,127.0.0.1,localhost")
os.environ.setdefault("FORCE_HTTPS", "false")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models import Role, User
from app.security import hash_password


@pytest.fixture()
def db_session(tmp_path):
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    session = TestingSessionLocal()
    yield session
    session.close()
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # The login rate limiter's in-memory storage lives for the lifetime of
    # the process, not per-request -- without resetting it between tests,
    # tests that call /login several times exhaust the shared bucket and
    # every later test starts seeing 429s instead of the status codes
    # they're actually testing for.
    from app.rate_limit import limiter

    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture()
def client(db_session):
    # follow_redirects=False deliberately: tests assert on the *exact*
    # redirect target (e.g. catching an open-redirect regression) rather
    # than silently following wherever the app sends them.
    return TestClient(app, base_url="http://127.0.0.1", follow_redirects=False)


def make_user(db_session, username: str, password: str, role: Role) -> User:
    user = User(username=username, password_hash=hash_password(password), role=role)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def admin_user(db_session):
    return make_user(db_session, "admin", "CorrectHorseBattery99", Role.ADMIN)


@pytest.fixture()
def editor_user(db_session):
    return make_user(db_session, "editor", "CorrectHorseBattery99", Role.EDITOR)


@pytest.fixture()
def viewer_user(db_session):
    return make_user(db_session, "viewer", "CorrectHorseBattery99", Role.VIEWER)


def login(client, username: str, password: str = "CorrectHorseBattery99"):
    return client.post("/login", data={"username": username, "password": password, "next": "/"})


def get_csrf_token(client, path: str) -> str:
    import re

    r = client.get(path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert match, f"no csrf token found on {path}"
    return match.group(1)
