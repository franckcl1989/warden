"""Bootstrap the first admin user (platform support carrying PLT-01).

Authentication is local-only with no public registration (docs/SECURITY.md
§2), so a deployment command must create the first admin. This is an
operator command, not an API endpoint: it applies the password policy, writes
an audit row with a NULL actor and forces a password change on first login.

Usage::

    python -m app.tools.bootstrap_admin --username admin --password "..."

Without ``--password`` the command reads WARDEN_BOOTSTRAP_ADMIN_PASSWORD;
when neither is set it generates a strong password and prints it ONCE.
Idempotent: an existing user with the same username is reported and left
untouched.
"""

from __future__ import annotations

import argparse
import os
import secrets
import string
import sys

from sqlalchemy import select

from app.config import get_settings
from app.domain.password_policy import validate_password
from app.infrastructure.audit import AuditLogger
from app.infrastructure.db import create_db_engine, create_session_factory
from app.infrastructure.passwords import hash_password
from app.models.auth import User


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits + "-_+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(20))
        if not validate_password(candidate, ""):
            return candidate


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create the first Warden admin user.")
    parser.add_argument("--username", help="Admin username (WARDEN_BOOTSTRAP_ADMIN_USERNAME)")
    parser.add_argument("--password", help="Initial password (or WARDEN_BOOTSTRAP_ADMIN_PASSWORD)")
    return parser.parse_args(argv)


def run(argv: list[str]) -> int:
    settings = get_settings()
    args = _parse_args(argv)
    username = args.username or settings.bootstrap_admin_username
    if not username:
        print("error: no bootstrap admin username (--username or WARDEN_BOOTSTRAP_ADMIN_USERNAME)", file=sys.stderr)
        return 2
    password = args.password or os.environ.get("WARDEN_BOOTSTRAP_ADMIN_PASSWORD", "")
    generated = False
    if not password:
        password = _generate_password()
        generated = True

    violations = validate_password(password, username)
    if violations:
        print(f"error: password policy violated: {violations[0]}", file=sys.stderr)
        return 2

    engine = create_db_engine(settings.database_url)
    try:
        factory = create_session_factory(engine)
        with factory() as db:
            existing = db.scalar(select(User).where(User.username.ilike(username)).limit(1))
            if existing is not None:
                print(f"info: user '{username}' already exists; nothing to do")
                return 0
            user = User(
                username=username,
                display_name=username,
                role="admin",
                password_hash=hash_password(password),
                must_change_password=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        AuditLogger(factory).record(
            action="users.create",
            actor_user_id=None,
            resource_type="user",
            resource_id=str(user.id),
            requirement_id="PLT-01",
            result="success",
            detail={"method": "bootstrap_cli"},
        )
    finally:
        engine.dispose()

    print(f"created admin user '{username}' (must change password on first login)")
    if generated:
        print(f"generated initial password: {password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
