"""Terminal-session use cases (M5T4, API_CONTRACT.md §7/§11, SECURITY.md §8).

The browser terminal flow: ``POST /devices/{id}/launches`` with
``console.ssh.open`` / ``console.telnet.open`` issues a normal one-time
60-second launch ticket (M3T4 machinery, ``application/launches.py`` —
protocol ssh/telnet); ``WS /terminal/sessions/{ticket}`` then claims it:

1. the ticket must be ``issued``, owned by the authenticated user, unexpired
   and of terminal protocol; the DEVICE must still be enabled/ready AND at
   the configuration version the ticket recorded (API_CONTRACT.md §7: 票据绑
   定…设备版本 — a re-configured device needs a fresh probe + launch);
2. Telnet re-checks BOTH gates at connect time: the deployment-wide setting
   and the per-device opt-in (SECURITY.md §6 / ADR-007 — both are required
   for every telnet session; automation never uses Telnet);
3. concurrency caps (API_CONTRACT.md §11: 每用户最多 3、每设备最多 1 交互会话)
   count OPEN terminal rows PLUS issued-unexpired launch tickets of the same
   user/device — the M3T4 ticket caps and the terminal-session caps are ONE
   pool so tickets cannot pile up around open sessions;
4. the claim consumes the ticket and creates the ``terminal_sessions`` row
   (status ``open``) in ONE transaction; then the WS layer dials the device
   (asyncssh / telnet), audits handshake ok/failed and closes the row with a
   reason on every exit — content is never logged or recorded here
   (SECURITY.md §8/§12: this module touches only metadata).

All ticket-level failures are a uniform close code (non-enumerable like the
M3T4 uniform-404 semantics); only the concurrency caps are distinguishable
(they are only reachable with a VALID own ticket).
"""

from __future__ import annotations

import datetime
import ipaddress
import uuid
from dataclasses import dataclass

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from app.config import WardenSettings
from app.domain import auth_errors
from app.domain.adapter import DeviceSession
from app.domain.errors import AppError
from app.domain.operation_plan import execute_permission_for
from app.domain.roles import require_permission as matrix_require
from app.generated.operations import OPERATION_PROFILES
from app.infrastructure.protocols.terminal.telnet import TelnetTarget
from app.infrastructure.protocols.vrp.session import VrpSshConfig, canonical_fingerprint
from app.infrastructure.time import utcnow
from app.models.auth import User
from app.models.devices import Device
from app.models.launch import LaunchSession
from app.models.terminal import TerminalSession

PLT_09 = "PLT-09"

#: WebSocket close codes of the terminal endpoint (client-facing protocol;
#: the browser maps them to Chinese messages — no content ever travels here).
WS_CLOSE_UNAUTHENTICATED = 4401
WS_CLOSE_FORBIDDEN = 4403  # origin rejected / password change required
WS_CLOSE_TICKET_UNAVAILABLE = 4404  # unknown/expired/used/foreign/mismatch
WS_CLOSE_CAPACITY = 4429
WS_CLOSE_HANDSHAKE_FAILED = 4101

#: Terminal protocols (contracts/operations.json launch profiles with
#: conflict_scope terminal_session). Consumed ONLY through the WS endpoint —
#: GET /launches/{id} must never consume a terminal ticket.
TERMINAL_PROTOCOLS = frozenset({"ssh", "telnet"})

#: Uniform ticket-refusal machine codes (all map to 4404).
TICKET_UNAVAILABLE = "ticket_unavailable"
CAPACITY_USER = "capacity_user"
CAPACITY_DEVICE = "capacity_device"

#: Telnet weak-protocol gate keys (SECURITY.md §6 denylist semantics).
TELNET_CONFIG_KEY = "telnet"
TELNET_PORT_CONFIG_KEY = "telnet_port"
SSH_PORT_CONFIG_KEY = "ssh_port"
SSH_FINGERPRINT_CONFIG_KEY = "ssh_host_fingerprint"

#: Max seconds of device dial + handshake before the connect is refused.
CONNECT_TIMEOUT_SECONDS = 10.0

#: Fixed retry hint when an OPEN terminal session blocks a launch/session
#: (the session may last up to its max duration; 60 s is the ticket-window
#: hint of API_CONTRACT.md §7, documented in the M5T4 report).
_CAPACITY_RETRY_AFTER = 60


@dataclass(frozen=True)
class ClaimOutcome:
    """Result of one ticket claim: ok=True carries the open session."""

    ok: bool
    refusal: str = ""
    terminal_session: TerminalSession | None = None
    launch: LaunchSession | None = None
    retry_after_seconds: int = 0

    @classmethod
    def refused(cls, refusal: str, retry_after_seconds: int = 0) -> ClaimOutcome:
        return cls(ok=False, refusal=refusal, retry_after_seconds=retry_after_seconds)


@dataclass(frozen=True)
class CloseOutcome:
    """Result of one terminal close (idempotent conditional close)."""

    closed_now: bool  # this call transitioned open -> closed
    exists: bool  # the row exists and belongs to the caller scope


def _active_counts(
    db: Session,
    *,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
) -> tuple[int, int]:
    """(per-user, per-device) count of active remote interactions.

    Active = issued-unexpired launch tickets + OPEN terminal sessions
    (API_CONTRACT.md §11 pools; M5T4 report documents the unified pool).
    """
    now = utcnow()

    def _user_count() -> int:
        tickets = len(
            db.scalars(
                select(LaunchSession.id).where(
                    LaunchSession.status == "issued",
                    LaunchSession.expires_at > now,
                    LaunchSession.user_id == user_id,
                )
            ).all()
        )
        sessions = len(
            db.scalars(
                select(TerminalSession.id).where(
                    TerminalSession.status == "open",
                    TerminalSession.user_id == user_id,
                )
            ).all()
        )
        return tickets + sessions

    def _device_count() -> int:
        tickets = len(
            db.scalars(
                select(LaunchSession.id).where(
                    LaunchSession.status == "issued",
                    LaunchSession.expires_at > now,
                    LaunchSession.device_id == device_id,
                )
            ).all()
        )
        sessions = len(
            db.scalars(
                select(TerminalSession.id).where(
                    TerminalSession.status == "open",
                    TerminalSession.device_id == device_id,
                )
            ).all()
        )
        return tickets + sessions

    if user_id is not None and device_id is None:
        return _user_count(), 0
    if device_id is not None and user_id is None:
        return 0, _device_count()
    return _user_count(), _device_count()


def _serialize_user(db: Session, user_id: uuid.UUID) -> None:
    """Per-user transaction advisory lock (same fixed order + keys as the
    launch service: user then device — no deadlock cycles). Released
    automatically at commit/rollback."""
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"launch-user:{user_id}"},
    )


def _serialize_device(db: Session, device_id: uuid.UUID) -> None:
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"launch-device:{device_id}"},
    )


def _ticket_unavailable() -> ClaimOutcome:
    return ClaimOutcome.refused(TICKET_UNAVAILABLE)


def _capacity_retry_after(blocking_tickets: list[LaunchSession]) -> int:
    """Seconds until the oldest blocking ticket expires (>= 1); terminal
    sessions bound the retry by the fixed 60 s hint."""
    if blocking_tickets:
        now = utcnow()
        remaining = [ticket.expires_at for ticket in blocking_tickets if ticket.expires_at > now]
        if remaining:
            return max(1, int((min(remaining) - now).total_seconds()) + 1)
    return _CAPACITY_RETRY_AFTER


def claim_terminal_session(
    db: Session,
    *,
    ticket: str,
    user: User,
    settings: WardenSettings,
    now: datetime.datetime | None = None,
) -> ClaimOutcome:
    """Claim one terminal ticket: consume it + open the session row.

    Runs inside the CALLER's transaction (the route commits on ok and rolls
    back on refusal — a refused claim never consumes the ticket). All
    validations re-run AFTER the advisory locks inside the transaction the
    claim commits in, so two concurrent claims cannot double-consume or
    exceed a cap.
    """
    current = now if now is not None else utcnow()
    try:
        key = uuid.UUID(ticket)
    except ValueError:
        return _ticket_unavailable()
    row = db.get(LaunchSession, key)
    if row is None:
        return _ticket_unavailable()
    if (
        row.user_id != user.id
        or row.protocol not in TERMINAL_PROTOCOLS
        or row.status != "issued"
        or row.expires_at <= current
    ):
        return _ticket_unavailable()
    device = db.get(Device, row.device_id)
    if device is None or not device.enabled or device.readiness != "ready":
        return _ticket_unavailable()
    if row.device_version is not None and device.version != row.device_version:
        return _ticket_unavailable()
    profile = OPERATION_PROFILES.get(f"{row.requirement_id}:{row.capability_key}")
    if profile is None or not matrix_require(user.role, execute_permission_for(profile.risk)):
        # M3T4 consume semantics: a permission failure is a uniform
        # "not claimable" (non-enumerable); the ticket is not consumed.
        return _ticket_unavailable()
    if user.must_change_password:
        return ClaimOutcome.refused("password_change_required")
    if row.protocol == "telnet" and not settings.telnet_enabled:
        return _ticket_unavailable()
    if row.protocol == "telnet" and device.connection_config.get(TELNET_CONFIG_KEY) is not True:
        return _ticket_unavailable()
    if row.protocol == "ssh" and not device.connection_config.get(SSH_FINGERPRINT_CONFIG_KEY):
        # Pin-or-refuse (SECURITY.md §8, M5T3 report): a terminal ticket for
        # an unpinned device is not claimable — re-probe + pin first.
        return _ticket_unavailable()

    _serialize_user(db, user.id)
    _serialize_device(db, device.id)
    # Re-claim under the locks (conditional UPDATE; race-safe single-use).
    claimed = db.execute(
        update(LaunchSession)
        .where(
            LaunchSession.id == key,
            LaunchSession.user_id == user.id,
            LaunchSession.status == "issued",
            LaunchSession.expires_at > current,
        )
        .values(status="consumed", consumed_at=current, version=LaunchSession.version + 1)
        .returning(LaunchSession)
    ).scalar_one_or_none()
    if claimed is None:
        return _ticket_unavailable()

    blocking_tickets = list(
        db.scalars(
            select(LaunchSession).where(
                LaunchSession.status == "issued",
                LaunchSession.expires_at > current,
                LaunchSession.id != key,
                LaunchSession.user_id == user.id,
            )
        ).all()
    )
    user_count, _ = _active_counts(db, user_id=user.id)
    if user_count >= 3:
        return ClaimOutcome.refused(CAPACITY_USER, _capacity_retry_after(blocking_tickets))
    _, device_count = _active_counts(db, device_id=device.id)
    if device_count >= 1:
        return ClaimOutcome.refused(CAPACITY_DEVICE, _capacity_retry_after(blocking_tickets))

    session_row = TerminalSession(
        launch_session_id=claimed.id,
        device_id=device.id,
        user_id=user.id,
        protocol=claimed.protocol,
        capability_key=claimed.capability_key,
        requirement_id=claimed.requirement_id,
        status="open",
        opened_at=current,
        last_activity_at=current,
    )
    db.add(session_row)
    db.flush()
    return ClaimOutcome(ok=True, terminal_session=session_row, launch=claimed)


def close_terminal_session(
    db: Session,
    *,
    session_id: str,
    user_id: uuid.UUID | None,
    reason: str,
    now: datetime.datetime | None = None,
) -> CloseOutcome:
    """Conditional close of one terminal session row.

    ``user_id`` scopes ownership (None = system/maintenance close). Returns
    ``closed_now`` only when THIS call transitioned open -> closed; a second
    close is a no-op (idempotent — exactly one actor audits per session).
    """
    current = now if now is not None else utcnow()
    try:
        key = uuid.UUID(session_id)
    except ValueError:
        return CloseOutcome(closed_now=False, exists=False)
    conditions = [TerminalSession.id == key]
    if user_id is not None:
        conditions.append(TerminalSession.user_id == user_id)
    row = db.scalar(select(TerminalSession).where(*conditions))
    if row is None:
        return CloseOutcome(closed_now=False, exists=False)
    # The conditional UPDATE returns the row ONLY when THIS call performed
    # the open -> closed transition (a second close matches zero rows). The
    # returned row is the unambiguous signal — rowcount is not relied on.
    closed_id = db.execute(
        update(TerminalSession)
        .where(TerminalSession.id == key, TerminalSession.status == "open")
        .values(status="closed", closed_at=current, close_reason=reason)
        .returning(TerminalSession.id)
    ).scalar_one_or_none()
    return CloseOutcome(closed_now=closed_id is not None, exists=True)


def touch_terminal_session(
    db: Session, *, session_id: uuid.UUID, at: datetime.datetime
) -> None:
    """Best-effort last-activity refresh (open rows only)."""
    db.execute(
        update(TerminalSession)
        .where(TerminalSession.id == session_id, TerminalSession.status == "open")
        .values(last_activity_at=at)
    )


# ---------------------------------------------------------------------------
# Transport targets (device-side connect configuration)
# ---------------------------------------------------------------------------


def _require_ip_literal(endpoint: str) -> str:
    """SECURITY.md §7 boundary rule (mirror of the M5T3 ops path): the
    connect target must be a resolved policy IP or an IP literal — the
    platform never resolves hostnames at connect time (no DNS rebinding).
    """
    try:
        return str(ipaddress.ip_address(endpoint))
    except ValueError as exc:
        raise AppError(
            "not_configured",
            "未提供经 SSRF 策略解析的管理地址（resolved_ip）",
            details={"field": "management_endpoint"},
        ) from exc


def _credentials_section(device_session: DeviceSession, section: str) -> dict[str, object]:
    credentials = dict(device_session.credentials)
    value = credentials.get(section)
    if not isinstance(value, dict) or not value.get("username") or not value.get("password"):
        raise AppError(
            "not_configured",
            f"设备未配置 {section} 账号（credentials.{section}）",
            details={"field": f"credentials.{section}"},
        )
    return value


def ssh_target_from(device_session: DeviceSession) -> VrpSshConfig:
    """The SSH target of one terminal session (pin-or-refuse enforced)."""
    config = dict(device_session.connection_config)
    credentials = _credentials_section(device_session, "ssh")
    raw_port = config.get(SSH_PORT_CONFIG_KEY)
    if not isinstance(raw_port, int):
        raise AppError(
            "not_configured",
            f"设备未配置 SSH 端口（connection_config.{SSH_PORT_CONFIG_KEY}）",
            details={"field": SSH_PORT_CONFIG_KEY},
        )
    raw_fingerprint = config.get(SSH_FINGERPRINT_CONFIG_KEY)
    if not isinstance(raw_fingerprint, str) or not raw_fingerprint:
        raise AppError(
            "not_configured",
            f"未固定 SSH 主机指纹（connection_config.{SSH_FINGERPRINT_CONFIG_KEY}）；"
            "终端连接拒绝首次信任（host_key_missing）",
            details={"field": SSH_FINGERPRINT_CONFIG_KEY},
        )
    try:
        fingerprint = canonical_fingerprint(raw_fingerprint)
    except ValueError as exc:
        raise AppError(
            "validation_failed", f"SSH 主机指纹格式非法：{exc}", details={"field": SSH_FINGERPRINT_CONFIG_KEY}
        ) from None
    return VrpSshConfig(
        host=_require_ip_literal(device_session.management_endpoint),
        port=raw_port,
        username=str(credentials["username"]),
        password=str(credentials["password"]),
        fingerprint=fingerprint,
    )


def telnet_target_from(device_session: DeviceSession) -> TelnetTarget:
    """The Telnet target of one terminal session.

    Called only after the claim re-verified BOTH gates (global setting +
    device opt-in); this builds the connect target and never weakens them.
    """
    config = dict(device_session.connection_config)
    if config.get(TELNET_CONFIG_KEY) is not True:
        raise auth_errors.validation_failed(
            "telnet", "设备未启用 Telnet（connection_config.telnet）"
        )
    credentials = _credentials_section(device_session, "telnet")
    raw_port = config.get(TELNET_PORT_CONFIG_KEY)
    if not isinstance(raw_port, int):
        raise AppError(
            "not_configured",
            f"设备未配置 Telnet 端口（connection_config.{TELNET_PORT_CONFIG_KEY}）",
            details={"field": TELNET_PORT_CONFIG_KEY},
        )
    return TelnetTarget(
        host=_require_ip_literal(device_session.management_endpoint),
        port=raw_port,
        username=str(credentials["username"]),
        password=str(credentials["password"]),
    )
