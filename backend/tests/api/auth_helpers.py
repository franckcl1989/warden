"""Helpers shared by the auth/user integration tests (real PostgreSQL)."""

from __future__ import annotations

from app.infrastructure.passwords import hash_password
from app.models.auth import User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Adm!n-2026-StrongPass"


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    role: str = "operator",
    display_name: str | None = None,
    status: str = "active",
    must_change_password: bool = False,
) -> User:
    user = User(
        username=username,
        display_name=display_name or username,
        role=role,
        status=status,
        password_hash=hash_password(password),
        must_change_password=must_change_password,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_admin(db: Session) -> User:
    return create_user(
        db,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
        role="admin",
        display_name="平台管理员",
    )


def login(client: TestClient, username: str, password: str, *, origin: str | None = None) -> object:
    headers = {"Origin": origin} if origin is not None else {}
    return client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
        headers=headers,
    )


def login_csrf(client: TestClient, username: str, password: str) -> tuple[object, str]:
    """Log in and return (response, csrf_token)."""
    response = login(client, username, password)
    body = response.json()
    return response, str(body.get("csrf_token", ""))
