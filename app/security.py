"""
Security primitives kept in one small, auditable module on purpose --
in an AppSec review, this is the first file a reviewer should need to read.
"""
from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta

from passlib.context import CryptContext

# Argon2id: OWASP's current recommended default for password hashing
# (memory-hard, resistant to GPU/ASIC cracking, tunable cost).
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # Any malformed-hash / library error is treated as a failed verify,
        # never as an exception that could short-circuit a caller's logic.
        return False


def needs_rehash(password_hash: str) -> bool:
    return pwd_context.needs_update(password_hash)


def new_token() -> str:
    """Cryptographically secure, URL-safe random token (256 bits)."""
    return secrets.token_urlsafe(32)


def constant_time_eq(a: str, b: str) -> bool:
    """Timing-safe string comparison -- used for CSRF token checks so an
    attacker can't use response-time differences to guess the token."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def utcnow() -> datetime:
    """Naive UTC timestamp -- see app.models.utcnow for why this project
    standardizes on naive-but-UTC datetimes throughout."""
    return datetime.now(UTC).replace(tzinfo=None)


def session_expiry(max_age_seconds: int) -> datetime:
    return utcnow() + timedelta(seconds=max_age_seconds)


PASSWORD_MIN_LENGTH = 12


def password_policy_errors(password: str) -> list[str]:
    """NIST 800-63B aligned: prioritize length over composition rules, block
    a short list of the very worst passwords, no arbitrary character-class
    requirements that push users toward predictable patterns."""
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long.")
    if password.lower() in _COMMON_WEAK_PASSWORDS:
        errors.append("This password is too common. Choose something less guessable.")
    return errors


_COMMON_WEAK_PASSWORDS = {
    "password123", "password1234", "letmeinnow", "qwertyuiop12",
    "administrator", "changeme123", "welcome12345",
}
