"""Command-line administration.

uv run python -m app.cli create-admin --username admin
    Prompts for the password (or reads ST_ADMIN_PASSWORD for non-interactive setup).
"""

import argparse
import getpass
import os
import re
import sys

from sqlalchemy import select

from app.core.security import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, hash_password
from app.db.session import get_sessionmaker
from app.models import Role, User
from app.schemas.auth import USERNAME_PATTERN
from app.services import audit
from app.services.auth import find_user


def _read_password() -> str:
    env = os.environ.get("ST_ADMIN_PASSWORD")
    if env:
        return env
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    return first


def create_admin(username: str) -> int:
    if not re.match(USERNAME_PATTERN, username):
        print("Invalid username (3-64 chars: letters, digits, . _ -).", file=sys.stderr)
        return 2
    password = _read_password()
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        print(
            f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters.",
            file=sys.stderr,
        )
        return 2

    with get_sessionmaker()() as db:
        if find_user(db, username) is not None:
            print(f"User '{username}' already exists.", file=sys.stderr)
            return 1
        role = db.scalar(select(Role).where(Role.name == "admin"))
        if role is None:
            print("Roles missing. Run 'alembic upgrade head' first.", file=sys.stderr)
            return 1
        user = User(username=username, password_hash=hash_password(password), role=role)
        db.add(user)
        db.flush()
        audit.record(
            db,
            "user.create",
            actor_username="cli",
            target_type="user",
            target_id=user.id,
            details={"username": username, "role": "admin"},
        )
        db.commit()
    print(f"Admin user '{username}' created.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    p_admin = sub.add_parser("create-admin", help="Create an administrator account")
    p_admin.add_argument("--username", required=True)
    args = parser.parse_args(argv)
    if args.command == "create-admin":
        return create_admin(args.username)
    return 2


if __name__ == "__main__":
    sys.exit(main())
