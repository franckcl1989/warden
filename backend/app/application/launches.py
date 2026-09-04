"""Launch-session use cases (M3T4, API_CONTRACT.md §7, PLT-09 launch 部分).

``create_launch`` protects one remote-connection launch end to end and
persists the one-time ticket row; ``consume_launch`` implements the
single-use GET semantics. Launch is NOT a task: no operation_tasks row, no
dispatch fence, no idempotency key (API_CONTRACT.md §6.1: 连接类能力不进入副
作用任务队列). What DOES apply (API_CONTRACT.md §7, §11):

- permission: ``operation.execute.<risk>`` per the profile (console.kvm.open
  = medium -> operator/admin), audited on denial;
- capability: the plan gates unknown/unsupported/not_configured capabilities
  (422 unsupported_operation / not_configured) and only ``channel=launch``
  profiles are creatable;
- device availability: enabled + readiness=ready, and a live adapter call —
  the adapter must PROVE the console still exists (a gone console is an
  honest not_configured, never a fabricated URL);
- rate limiting (per-user per-minute, route) and the §11 concurrency caps —
  每用户最多 3、每设备最多 1 活动票据 — enforced on ACTIVE (issued, not yet
  expired) rows under transaction-level PostgreSQL advisory locks so two
  concurrent creates cannot race past a cap;
- expiry: the row lives 60 seconds (profile timeout_seconds); the single-use
  GET only matches ``issued`` rows whose ``expires_at`` has not passed;
- audit: launch.create on issue and launch.consume on the first read, both
  in the SAME transaction as the row write/claim (DATA_MODEL.md §11). The
  vendor descriptor URL never enters audit rows.

Descriptor URLs never carry credentials or platform tokens (SECURITY.md §6,
ADR-006); the adapter is the only producer and the row only stores what the
adapter returned. The concurrency guards serialize per user then per device
(advisory locks acquired in that fixed order — no deadlock cycles), then
re-count inside the same transaction the INSERT commits in.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from app.adapters import UnknownAdapterError, get_adapter
from app.application.collection import build_device_session
from app.application.operations import AuditContext, build_snapshot
from app.domain import auth_errors
from app.domain.adapter import AdapterError, DeviceAdapter, LaunchDescriptor
from app.domain.errors import AppError
from app.domain.operation_plan import OperationRequest, execute_permission_for, plan_operation
from app.domain.roles import require_permission as matrix_require
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialKeyring
from app.infrastructure.time import utcnow
from app.models.auth import Session as AuthSession
from app.models.auth import User
from app.models.devices import Device
from app.models.launch import LaunchSession
from app.models.terminal import TerminalSession

PLT_09 = "PLT-09"

# Capability key -> row protocol (contracts/operations.json channel=launch
# profiles). Terminal keys (console.ssh.open / console.telnet.open) issue
# one-time browser-terminal tickets (M5T4, ADR-007); web keys
# (console.dsm.open, console.web.open) issue one-time URL descriptors that
# GET /launches/{id} consumes (M4T3 / M5T5, ADR-006); unknown launch-channel
# keys are refused rather than guessed (AGENTS.md: 不得自行猜测).
LAUNCH_PROTOCOL_BY_KEY: dict[str, str] = {
    "console.kvm.open": "kvm",
    "console.dsm.open": "web",  # NAS-ACT-02 (M4T3)
    "console.ssh.open": "ssh",  # CORE-ACT-03 / ACCESS-ACT-04 (M5T4)
    "console.telnet.open": "telnet",  # CORE-ACT-03 (M5T4)
    "console.web.open": "web",  # CORE-ACT-03 / ACCESS-ACT-04 (M5T5, ADR-006)
}

#: Terminal-ticket protocols: these launches return a WebSocket URL and are
#: consumed by ``WS /terminal/sessions/{ticket}`` — never by GET
#: ``/launches/{id}`` (a terminal ticket read through the descriptor GET is
#: a uniform 404 and does NOT consume the row).
TERMINAL_LAUNCH_PROTOCOLS = frozenset({"ssh", "telnet"})

MESSAGE_UNSUPPORTED_LAUNCH = "该能力不属于远程连接能力，不支持创建启动描述符"
MESSAGE_NOT_A_TASK_CHANNEL = "该能力属于持久化任务通道，不能作为远程连接启动"
MESSAGE_DESCRIPTOR_MISSING_URL = "设备未返回可打开的启动地址"
MESSAGE_DESCRIPTOR_BAD_SCHEME = "设备返回的启动地址不是有效的 http/https 地址"
MESSAGE_DESCRIPTOR_BAD_KIND = "设备返回了不支持的启动描述符类型"
MESSAGE_USER_SESSION_CAP = "当前用户同时打开的远程会话已达上限（3），请先关闭其他会话"
MESSAGE_DEVICE_SESSION_CAP = "该设备已有一个活动的远程会话，请先使用或等待其过期"
MESSAGE_DEVICE_DISABLED = "设备已停用，无法创建远程连接"
MESSAGE_DEVICE_NOT_READY = "设备未就绪，无法创建远程连接"
MESSAGE_TELNET_GLOBAL_DISABLED = (
    "Telnet 未在该部署启用（全局默认关闭，SECURITY.md §6/ADR-007）："
    "需部署管理员显式开启且只用于交互终端"
)

# API_CONTRACT.md §11: 每用户最多 3、每设备最多 1 个活动交互会话。
MAX_ACTIVE_LAUNCHES_PER_USER = 3
MAX_ACTIVE_LAUNCHES_PER_DEVICE = 1


def _cap_error(
    rows: list[LaunchSession],
    now: datetime.datetime,
    *,
    device: bool,
    terminal_blocking: bool = False,
) -> AppError:
    scope = "launch_session_device" if device else "launch_session_user"
    message = MESSAGE_DEVICE_SESSION_CAP if device else MESSAGE_USER_SESSION_CAP
    retry = 60 if terminal_blocking else _retry_after_any(rows, now)
    return AppError(
        "rate_limited",
        message,
        details={"retry_after_seconds": retry, "scope": scope},
    )


def _active_rows(
    db: Session,
    *,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
) -> list[LaunchSession]:
    """Active (issued + inside the ticket window) rows for a user or device."""
    conditions = [LaunchSession.status == "issued", LaunchSession.expires_at > utcnow()]
    if user_id is not None:
        conditions.append(LaunchSession.user_id == user_id)
    if device_id is not None:
        conditions.append(LaunchSession.device_id == device_id)
    return list(
        db.scalars(
            select(LaunchSession).where(*conditions).order_by(LaunchSession.expires_at)
        ).all()
    )


def _open_terminal_rows(
    db: Session,
    *,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
) -> list[TerminalSession]:
    """OPEN browser-terminal session rows for a user or device (M5T4).

    API_CONTRACT.md §11 concurrency: the terminal-session caps and the
    launch-ticket caps are ONE pool (documented in the M5T4 report) — an
    open session blocks a new launch for the same device and counts against
    the user's 3, so tickets cannot pile up around open sessions.
    """
    conditions = [TerminalSession.status == "open"]
    if user_id is not None:
        conditions.append(TerminalSession.user_id == user_id)
    if device_id is not None:
        conditions.append(TerminalSession.device_id == device_id)
    return list(db.scalars(select(TerminalSession).where(*conditions)).all())


def _retry_after_any(rows: list[LaunchSession], now: datetime.datetime) -> int:
    """Seconds until the last blocking ticket expires (>= 1)."""
    if not rows:
        return 1
    oldest_expiry = min(row.expires_at for row in rows)
    return max(1, int((oldest_expiry - now).total_seconds()) + 1)


def _serialize_user(db: Session, user_id: uuid.UUID) -> None:
    """Per-user transaction advisory lock: serializes launch creation for one
    user so the 3-active cap cannot be raced by concurrent requests. Released
    automatically at commit/rollback (transaction-scoped, no cleanup path)."""
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"launch-user:{user_id}"},
    )


def _serialize_device(db: Session, device_id: uuid.UUID) -> None:
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"launch-device:{device_id}"},
    )


def _audit_denial(
    logger: AuditLogger | None,
    audit: AuditContext,
    *,
    permission: str,
    path: str,
    device_id: uuid.UUID | None = None,
) -> None:
    """Audit one launch permission denial (M2T4 pattern, real resource path)."""
    if logger is None:
        return
    logger.record(
        action="access.denied",
        actor_user_id=audit.actor_user_id,
        session_id=audit.session_id,
        resource_type="device",
        resource_id=str(device_id) if device_id is not None else path[:64],
        device_id=device_id,
        requirement_id=PLT_09,
        request_id=audit.request_id,
        result="permission_denied",
        source_ip=audit.source_ip,
        user_agent_summary=audit.user_agent_summary,
        detail={"permission": permission, "method": "POST", "path": path},
    )


def _enforce_launch_permission(
    user: User,
    risk_level: str,
    *,
    logger: AuditLogger | None,
    audit: AuditContext,
    path: str,
    device_id: uuid.UUID | None = None,
) -> None:
    """SECURITY.md §3.1: operation.execute.<risk> per the launch profile."""
    permission = execute_permission_for(risk_level)
    if matrix_require(user.role, permission):
        return
    _audit_denial(logger, audit, permission=permission, path=path, device_id=device_id)
    raise auth_errors.permission_denied(permission)


def _adapter_error_to_app(exc: AdapterError, capability_key: str) -> AppError:
    """Map one launch-time adapter failure to the stable API envelope.

    not_configured carries capability_key + the adapter's reason
    (error-codes.json safe fields); other codes keep their message (the
    boundary filters details to contract-safe fields).
    """
    if exc.code == "not_configured":
        reason = exc.message or "required configuration"
        return AppError(
            "not_configured",
            exc.message,
            details={"capability_key": capability_key, "missing": reason[:200]},
        )
    return AppError(exc.code, exc.message)


def _descriptor_error(descriptor: LaunchDescriptor, capability_key: str) -> AppError | None:
    """Guard against fabricated descriptors (AGENTS.md: 不得把不存在的伪装成成功).

    Protocol semantics (M5T4): terminal protocols (ssh/telnet) MUST return a
    ``kind=terminal`` descriptor WITHOUT a URL (the ticket is consumed by the
    WebSocket endpoint, never by a page navigation); url protocols (kvm/web)
    MUST return a validated http(s) URL — the platform never opens
    javascript:/data: or empty targets in a browser tab.
    """
    protocol = LAUNCH_PROTOCOL_BY_KEY.get(capability_key)
    is_terminal = protocol in TERMINAL_LAUNCH_PROTOCOLS
    if is_terminal:
        if descriptor.kind != "terminal" or descriptor.url is not None:
            return AppError(
                "not_configured",
                MESSAGE_DESCRIPTOR_BAD_KIND,
                details={"capability_key": capability_key, "missing": "terminal_descriptor_required"},
            )
        return None
    if descriptor.kind != "url":
        return AppError(
            "not_configured",
            MESSAGE_DESCRIPTOR_BAD_KIND,
            details={"capability_key": capability_key, "missing": "unsupported_descriptor_kind"},
        )
    if not descriptor.url:
        return AppError(
            "not_configured",
            MESSAGE_DESCRIPTOR_MISSING_URL,
            details={"capability_key": capability_key, "missing": "no_descriptor_url"},
        )
    if not descriptor.url.startswith(("http://", "https://")):
        return AppError(
            "not_configured",
            MESSAGE_DESCRIPTOR_BAD_SCHEME,
            details={"capability_key": capability_key, "missing": "unsafe_descriptor_scheme"},
        )
    return None


def create_launch(
    db: Session,
    *,
    device: Device,
    capability_key: str,
    user: User,
    session: AuthSession,
    keyring: CredentialKeyring,
    logger: AuditLogger | None,
    audit: AuditContext,
    telnet_allowed: bool = False,
    now: datetime.datetime | None = None,
) -> LaunchSession:
    """Protection-chain steps for one launch; the caller (route) commits.

    Raises AppError codes: unsupported_operation / not_configured /
    validation_failed / permission_denied / rate_limited (concurrency caps).
    Never creates an operation task; on any failure NO launch row is
    persisted (a failed launch is not a fake success).
    """
    current = now if now is not None else utcnow()
    if not device.enabled:
        raise auth_errors.validation_failed("device", MESSAGE_DEVICE_DISABLED)
    if device.readiness != "ready":
        raise auth_errors.validation_failed("device", MESSAGE_DEVICE_NOT_READY)
    launch_path = f"/devices/{device.id}/launches"
    probe_plan = plan_operation(
        build_snapshot(db, device),
        OperationRequest(capability_key=capability_key, parameters={}),
    )
    _enforce_launch_permission(
        user,
        probe_plan.risk_level,
        logger=logger,
        audit=audit,
        path=launch_path,
        device_id=device.id,
    )
    if probe_plan.channel != "launch":
        raise AppError(
            "unsupported_operation",
            MESSAGE_NOT_A_TASK_CHANNEL,
            details={
                "requirement_id": probe_plan.requirement_id,
                "capability_key": probe_plan.capability_key,
            },
        )
    protocol = LAUNCH_PROTOCOL_BY_KEY.get(probe_plan.capability_key)
    if protocol is None:
        raise AppError(
            "unsupported_operation",
            MESSAGE_UNSUPPORTED_LAUNCH,
            details={
                "requirement_id": probe_plan.requirement_id,
                "capability_key": probe_plan.capability_key,
            },
        )
    # SECURITY.md §6 / ADR-007 / operations.json preconditions: Telnet is
    # globally disabled unless the deployment explicitly enables it; the
    # per-device opt-in is enforced by the adapter (live config check).
    # This gate must NOT contact the device while Telnet is off.
    if protocol == "telnet" and not telnet_allowed:
        raise AppError(
            "not_configured",
            MESSAGE_TELNET_GLOBAL_DISABLED,
            details={
                "capability_key": probe_plan.capability_key,
                "missing": "telnet_enabled",
            },
        )
    # Serialize the concurrency guards (fixed order: user then device) and
    # re-check inside the SAME transaction the INSERT commits in. The caps
    # count issued tickets AND open terminal sessions as one pool (§11).
    _serialize_user(db, user.id)
    _serialize_device(db, device.id)
    user_active = _active_rows(db, user_id=user.id)
    user_open_terminal = _open_terminal_rows(db, user_id=user.id)
    if len(user_active) + len(user_open_terminal) >= MAX_ACTIVE_LAUNCHES_PER_USER:
        raise _cap_error(
            user_active, current, device=False, terminal_blocking=bool(user_open_terminal)
        )
    device_active = _active_rows(db, device_id=device.id)
    device_open_terminal = _open_terminal_rows(db, device_id=device.id)
    if len(device_active) + len(device_open_terminal) >= MAX_ACTIVE_LAUNCHES_PER_DEVICE:
        raise _cap_error(
            device_active, current, device=True, terminal_blocking=bool(device_open_terminal)
        )

    try:
        adapter: DeviceAdapter = get_adapter(device.adapter_key)
    except UnknownAdapterError:
        raise AppError("not_configured", "设备适配器未注册") from None
    try:
        descriptor = adapter.create_launch(
            build_device_session(db, device=device, keyring=keyring),
            probe_plan.capability_key,
        )
    except AdapterError as exc:
        raise _adapter_error_to_app(exc, probe_plan.capability_key) from None
    descriptor_error = _descriptor_error(descriptor, probe_plan.capability_key)
    if descriptor_error is not None:
        raise descriptor_error

    expires_at = current + datetime.timedelta(seconds=probe_plan.timeout_seconds)
    row = LaunchSession(
        device_id=device.id,
        capability_key=probe_plan.capability_key,
        requirement_id=probe_plan.requirement_id,
        user_id=user.id,
        session_id=session.id,
        protocol=protocol,
        descriptor_url=descriptor.url,
        descriptor_data={
            "kind": descriptor.kind,
            "display_hint": descriptor.display_hint or "",
            "vendor_session_ref": descriptor.vendor_session_ref,
        },
        status="issued",
        # API_CONTRACT.md §7: 票据绑定…设备版本 (migration 0014) — the
        # terminal connect refuses a ticket whose device was re-configured.
        device_version=device.version,
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()
    if logger is not None:
        logger.record_in(
            db,
            action="launch.create",
            actor_user_id=user.id,
            session_id=session.id,
            resource_type="launch_session",
            resource_id=str(row.id),
            device_id=device.id,
            requirement_id=probe_plan.requirement_id,
            request_id=audit.request_id,
            result="success",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={
                "capability_key": probe_plan.capability_key,
                "protocol": protocol,
                "risk_level": probe_plan.risk_level,
                "expires_at": expires_at.isoformat(),
            },
        )
    return row


def consume_launch(
    db: Session,
    *,
    launch_id: str,
    user_id: uuid.UUID,
    logger: AuditLogger | None,
    audit: AuditContext,
    now: datetime.datetime | None = None,
) -> LaunchSession | None:
    """Single-use consume of one URL launch ticket (GET /launches/{id}).

    The conditional UPDATE claims ONLY an ``issued`` row whose user matches,
    whose 60-second window has not passed AND whose protocol is url-kind
    (kvm/web — API_CONTRACT.md §7 descriptors). Terminal tickets
    (ssh/telnet) are consumed exclusively by ``WS /terminal/sessions/
    {ticket}``: reading one through this GET is a uniform 404 that never
    consumes the row. A second read, a foreign user, an expired or revoked
    row and an unknown id all match zero rows and surface as a uniform 404
    by the caller (non-enumerable — a reader cannot distinguish "used",
    "expired" or "someone else's"). The claim + audit commit in ONE
    transaction (DATA_MODEL.md §11). The caller renders the response and
    commits. Returns None when nothing was claimable.
    """
    try:
        key = uuid.UUID(launch_id)
    except ValueError:
        return None
    current = now if now is not None else utcnow()
    row = db.execute(
        update(LaunchSession)
        .where(
            LaunchSession.id == key,
            LaunchSession.user_id == user_id,
            LaunchSession.status == "issued",
            LaunchSession.expires_at > current,
            LaunchSession.protocol.in_(("kvm", "web")),
        )
        .values(
            status="consumed",
            consumed_at=current,
            version=LaunchSession.version + 1,
        )
        .returning(LaunchSession)
    ).scalar_one_or_none()
    if row is None:
        return None
    if logger is not None:
        logger.record_in(
            db,
            action="launch.consume",
            actor_user_id=user_id,
            session_id=audit.session_id,
            resource_type="launch_session",
            resource_id=str(row.id),
            device_id=row.device_id,
            requirement_id=row.requirement_id,
            request_id=audit.request_id,
            result="success",
            source_ip=audit.source_ip,
            user_agent_summary=audit.user_agent_summary,
            detail={
                "capability_key": row.capability_key,
                "protocol": row.protocol,
            },
        )
    return row
