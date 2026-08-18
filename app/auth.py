from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, UserSession
from app.security import (
    new_token,
    session_expiry,
    utcnow,
    verify_password,
)


class AccountLockedError(Exception):
    pass


def is_locked(user: User) -> bool:
    return bool(user.locked_until and user.locked_until > utcnow())


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Returns the user on success, None on bad credentials, raises
    AccountLockedError if the account is currently locked out.

    Deliberately takes the same code path (and roughly the same time) for
    'user does not exist' and 'wrong password' so the login endpoint does
    not leak which usernames are valid via a response-content or timing
    oracle.
    """
    user = db.query(User).filter(User.username == username).one_or_none()

    # Always hash something, even for unknown users, so response timing
    # doesn't reveal whether the username exists.
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAA"
    target_hash = user.password_hash if user else dummy_hash

    password_ok = verify_password(password, target_hash)

    if user is None:
        return None

    if is_locked(user):
        raise AccountLockedError()

    if not user.is_active or not password_ok:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.max_failed_logins:
            user.locked_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
        db.commit()
        return None

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    db.commit()
    return user


def create_session(db: Session, user: User, ip_address: str | None, user_agent: str | None) -> UserSession:
    session = UserSession(
        token=new_token(),
        csrf_token=new_token(),
        user_id=user.id,
        expires_at=session_expiry(settings.session_max_age_seconds),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255],
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def get_valid_session(db: Session, token: str | None) -> UserSession | None:
    if not token:
        return None
    session = db.query(UserSession).filter(UserSession.token == token).one_or_none()
    if session is None:
        return None
    now = utcnow()
    if session.expires_at < now:
        db.delete(session)
        db.commit()
        return None
    if (now - session.last_seen_at).total_seconds() > settings.session_idle_timeout_seconds:
        db.delete(session)
        db.commit()
        return None
    session.last_seen_at = now
    db.commit()
    return session


def revoke_session(db: Session, token: str | None) -> None:
    if not token:
        return
    db.query(UserSession).filter(UserSession.token == token).delete()
    db.commit()


def revoke_all_sessions_for_user(db: Session, user_id: int) -> None:
    db.query(UserSession).filter(UserSession.user_id == user_id).delete()
    db.commit()
