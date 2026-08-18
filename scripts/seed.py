"""
Creates the first admin user, reading credentials from the environment so
nothing sensitive ever lands in source control or shell history logs.

Usage:
    ADMIN_USERNAME=alice ADMIN_PASSWORD='...' python scripts/seed.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import Role, User  # noqa: E402
from app.security import hash_password, password_policy_errors  # noqa: E402


def main() -> None:
    Base.metadata.create_all(bind=engine)

    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")

    if not username or not password:
        print("ADMIN_USERNAME and ADMIN_PASSWORD environment variables are required.", file=sys.stderr)
        raise SystemExit(1)

    errors = password_policy_errors(password)
    if errors:
        print("Refusing to create admin user: " + " ".join(errors), file=sys.stderr)
        raise SystemExit(1)

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).one_or_none()
        if existing:
            print(f"User '{username}' already exists -- not modifying it.")
            return

        admin = User(username=username, password_hash=hash_password(password), role=Role.ADMIN)
        db.add(admin)
        db.commit()
        print(f"Created admin user '{username}'.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
