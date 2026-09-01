"""Session lifecycle helpers (docs/SECURITY.md §2, DATA_MODEL.md §3.3).

Encapsulates idle/absolute expiry, reauthentication validity and the
"revoke everything else" pattern so API routes and dependencies share one
implementation. All functions are DB-free (pure computations over model
instances and datetimes); persistence stays in the routes.
"""

from __future__ import annotations

import datetime

from app.models.auth import Session


def session_is_valid(session: Session, now: datetime.datetime, idle_minutes: int) -> bool:
    """True when the session is not revoked and within idle+absolute limits.

    Idle expiry slides from ``last_activity_at``; the absolute limit is
    immutable.
    """
    if session.revoked_at is not None:
        return False
    if now > session.absolute_expires_at:
        return False
    idle_limit = session.last_activity_at + datetime.timedelta(minutes=idle_minutes)
    return now <= idle_limit


def reauthenticated_until(session: Session, now: datetime.datetime, ttl_minutes: int) -> datetime.datetime:
    """The moment the current reauthentication stays valid.

    Validity derives from ``reauthenticated_at`` (docs/SECURITY.md §4: 最近 5
    分钟有效); no separate bearer token is ever issued.
    """
    base = session.reauthenticated_at if session.reauthenticated_at is not None else datetime.datetime.min.replace(
        tzinfo=now.tzinfo
    )
    return base + datetime.timedelta(minutes=ttl_minutes)


def is_reauthenticated(session: Session, now: datetime.datetime, ttl_minutes: int) -> bool:
    """True when the session was reauthenticated within the TTL window."""
    return session.reauthenticated_at is not None and reauthenticated_until(session, now, ttl_minutes) > now


def client_summary(source_ip: str | None, user_agent: str | None) -> str | None:
    """Human-readable client descriptor for ``sessions.client_summary``."""
    ua = (user_agent or "").strip()
    if source_ip and ua:
        return f"{source_ip} {ua[:200]}"
    if source_ip:
        return source_ip
    return ua[:200] or None
