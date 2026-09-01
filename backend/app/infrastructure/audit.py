"""Audit writer (docs/SECURITY.md §12, DATA_MODEL.md §9.1).

Only appends: rows are created here and never updated or deleted (the model
raises and the database trigger rejects any mutation). The detail JSON is
sanitized recursively before it is stored: keys that look like secrets
(password, token, cookie, authorization, secret, community, auth_key,
privacy_key — SECURITY.md §10) are replaced, so audit rows never contain
passwords or session tokens.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session, sessionmaker

from app.models.auth import AuditLog

SENSITIVE_KEYS: frozenset[str] = frozenset(
    {"password", "token", "authorization", "community", "auth_key", "privacy_key", "cookie", "secret"}
)
REDACTED = "[REDACTED]"


def sanitize_detail(value: object) -> object:
    """Recursively redact sensitive keys from ``value`` (dicts, lists, scalars)."""
    if isinstance(value, dict):
        return {
            key: REDACTED if str(key).lower() in SENSITIVE_KEYS else sanitize_detail(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_detail(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_detail(item) for item in value)
    return value


class AuditLogger:
    """Writes append-only audit rows on its own transaction."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(
        self,
        *,
        action: str,
        actor_user_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        device_id: uuid.UUID | None = None,
        requirement_id: str | None = None,
        request_id: str = "",
        task_id: uuid.UUID | None = None,
        result: str = "success",
        source_ip: str | None = None,
        user_agent_summary: str | None = None,
        detail: object | None = None,
    ) -> AuditLog:
        row = AuditLog(
            actor_user_id=actor_user_id,
            session_id=session_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            device_id=device_id,
            requirement_id=requirement_id,
            request_id=request_id or None,
            task_id=task_id,
            result=result,
            source_ip=source_ip,
            user_agent_summary=user_agent_summary,
            detail_jsonb=sanitize_detail(detail) if detail is not None else {},
        )
        with self._session_factory() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
        return row
