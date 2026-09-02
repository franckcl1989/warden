"""Device API (docs/API_CONTRACT.md §4, contracts/http-api.json PLT-02/PLT-03).

operationIds EXACTLY per contracts/http-api.json: device_probes_create,
devices_create, devices_list, devices_get, devices_update, devices_probe,
device_capabilities_list (PLT-02) and — added by M2T3 — device_components_list
and device_events_list (PLT-03, monitor.read for all roles). There is NO
``DELETE /devices`` (API_CONTRACT.md §4).

Permissions (SECURITY.md §3.1): reads need ``device.read`` (all roles);
create/update/probe need ``device.manage`` (admin only — PRODUCT_DESIGN.md
§4.2: 仅管理员可添加设备). Probe failures are returned as 200 with the
failed stages and a failure token (save-as-not_ready path); hard errors
(unknown adapter, SSRF policy violation, schema mismatch) are 422 envelope
errors. Device-probes is rate limited 10/min per user (API_CONTRACT.md §11).
Credentials are never echoed: responses carry only discovery, stages and the
token; the audit digest is written server-side.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.adapters import UnknownAdapterError, get_adapter
from app.api.deps import (
    AuthContext,
    get_audit_logger,
    get_credential_keyring,
    get_db,
    get_rate_limiter,
    require_permission,
)
from app.application.devices import (
    CapabilityInfo,
    build_connection_profile,
    get_device,
    list_capabilities,
    list_devices,
    probe_device,
    probe_existing_device,
    save_device_from_probe,
    update_device,
)
from app.application.monitoring import list_components, list_device_events
from app.config import WardenSettings
from app.domain import auth_errors
from app.domain.adapter import (
    ConnectionProfile,
    DeviceAdapter,
    DiscoveryResult,
    ProbeOutcome,
    ProbeStage,
    credentials_digest,
    validate_json_schema,
)
from app.domain.roles import DEVICE_MANAGE, DEVICE_READ, MONITOR_READ
from app.infrastructure.audit import AuditLogger
from app.infrastructure.crypto import CredentialKeyring
from app.infrastructure.rate_limit import RateLimiter
from app.infrastructure.sessions import client_summary
from app.models.devices import Device

router = APIRouter(tags=["devices"])

PLT_02 = "PLT-02"

DEVICE_TYPE_PATTERN = r"^(server|synology_nas|core_switch|access_switch)$"
REACHABILITY_PATTERN = r"^(unknown|online|offline)$"
HEALTH_PATTERN = r"^(unknown|healthy|warning|critical)$"


class _ProbeFields(BaseModel):
    device_type: str = Field(pattern=DEVICE_TYPE_PATTERN)
    adapter_key: str = Field(min_length=1, max_length=64)
    management_endpoint: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    connection_config: dict[str, object] = Field(default_factory=dict)
    credentials: dict[str, object]

    @field_validator("management_endpoint")
    @classmethod
    def _endpoint_shape(cls, value: str) -> str:
        stripped = value.strip()
        if stripped != value or any(char.isspace() for char in stripped):
            raise ValueError("管理地址不能包含空白字符")
        if "://" in stripped or "/" in stripped:
            raise ValueError("管理地址只能是主机名或 IP，不能包含协议或路径")
        if "@" in stripped:
            raise ValueError("管理地址不能包含用户信息")
        return stripped


class DeviceProbeRequest(_ProbeFields):
    pass


class DeviceCreateRequest(_ProbeFields):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    probe_token: str = Field(min_length=1, max_length=512)


class DeviceUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    management_endpoint: str | None = Field(default=None, min_length=1, max_length=255)
    adapter_key: str | None = Field(default=None, min_length=1, max_length=64)
    connection_config: dict[str, object] | None = None
    credentials: dict[str, object] | None = None
    probe_token: str | None = Field(default=None, max_length=512)

    @field_validator("management_endpoint")
    @classmethod
    def _endpoint_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if stripped != value or any(char.isspace() for char in stripped):
            raise ValueError("管理地址不能包含空白字符")
        if "://" in stripped or "/" in stripped:
            raise ValueError("管理地址只能是主机名或 IP，不能包含协议或路径")
        if "@" in stripped:
            raise ValueError("管理地址不能包含用户信息")
        return stripped


class ProbeStageView(BaseModel):
    stage: str
    ok: bool
    error_code: str | None
    detail: str | None


class CapabilitySupportView(BaseModel):
    capability_key: str
    support_state: str
    requirement_id: str
    discovery_method: str
    reason_code: str | None
    detail: str | None


class ComponentObservedView(BaseModel):
    kind: str
    native_id: str
    name: str
    status: str
    properties: dict[str, object]


class DiscoveryView(BaseModel):
    vendor: str
    model: str
    serial_number: str | None
    firmware_version: str | None
    capabilities: list[CapabilitySupportView]
    components: list[ComponentObservedView]


class DeviceProbeResponse(BaseModel):
    ok: bool
    stages: list[ProbeStageView]
    discovery: DiscoveryView | None
    probe_token: str
    expires_at: datetime.datetime


class DeviceView(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    device_type: str
    vendor: str | None
    model: str | None
    management_endpoint: str
    adapter_key: str
    connection_config: dict[str, object]
    enabled: bool
    readiness: str
    reachability: str
    health: str
    last_known_health: str | None
    serial_number: str | None
    firmware_version: str | None
    last_seen_at: datetime.datetime | None
    last_collected_at: datetime.datetime | None
    next_poll_at: datetime.datetime | None
    consecutive_failures: int
    consecutive_successes: int
    version: int
    created_at: datetime.datetime
    updated_at: datetime.datetime


class DeviceListResponse(BaseModel):
    items: list[DeviceView]
    page: int
    page_size: int
    total: int


class CapabilityView(BaseModel):
    capability_key: str
    requirement_id: str
    requirement_title: str | None
    support_state: str
    discovery_method: str
    reason_code: str | None
    detail: str | None
    last_checked_at: datetime.datetime
    adapter_version: str


class CapabilitiesResponse(BaseModel):
    items: list[CapabilityView]


class DeviceProbeExistingResponse(BaseModel):
    device: DeviceView
    ok: bool
    stages: list[ProbeStageView]
    discovery: DiscoveryView | None
    probe_token: str
    expires_at: datetime.datetime


def _resolve_adapter(adapter_key: str, device_type: str) -> DeviceAdapter:
    try:
        adapter = get_adapter(adapter_key)
    except UnknownAdapterError:
        raise auth_errors.validation_failed("adapter_key", "未知的适配器键") from None
    if device_type not in adapter.supported_device_types:
        raise auth_errors.validation_failed("adapter_key", "该适配器不支持此设备类别")
    return adapter


def _validate_connection_config(adapter: DeviceAdapter, connection_config: dict[str, object]) -> None:
    errors = validate_json_schema(connection_config, adapter.connection_schema)
    if errors:
        raise auth_errors.validation_failed("connection_config", errors[0])


def _validate_credentials(adapter: DeviceAdapter, credentials: dict[str, object]) -> None:
    errors = validate_json_schema(credentials, adapter.secret_schema)
    if errors:
        raise auth_errors.validation_failed("credentials", errors[0])


def _profile_for_request(
    adapter: DeviceAdapter,
    *,
    device_id: uuid.UUID | None,
    management_endpoint: str,
    port: int | None,
    connection_config: dict[str, object],
    credentials: dict[str, object],
) -> ConnectionProfile:
    return build_connection_profile(
        adapter,
        device_id=device_id,
        management_endpoint=management_endpoint,
        port=port,
        connection_config=connection_config,
        credentials=credentials,
    )


def _stage_view(stage: ProbeStage) -> ProbeStageView:
    return ProbeStageView(
        stage=stage.stage,
        ok=stage.ok,
        error_code=stage.error_code,
        detail=stage.detail_safe,
    )


def _discovery_view(discovery: DiscoveryResult) -> DiscoveryView:
    return DiscoveryView(
        vendor=discovery.vendor,
        model=discovery.model,
        serial_number=discovery.serial_number,
        firmware_version=discovery.firmware_version,
        capabilities=[
            CapabilitySupportView(
                capability_key=capability.capability_key,
                support_state=capability.support_state,
                requirement_id=capability.requirement_id,
                discovery_method=capability.discovery_method,
                reason_code=capability.reason_code,
                detail=capability.detail,
            )
            for capability in discovery.capabilities
        ],
        components=[
            ComponentObservedView(
                kind=component.kind,
                native_id=component.native_id,
                name=component.name,
                status=component.status,
                properties=component.properties,
            )
            for component in discovery.components
        ],
    )


def _outcome_response(
    outcome: ProbeOutcome,
) -> tuple[bool, list[ProbeStageView], DiscoveryView | None, str, datetime.datetime]:
    return (
        outcome.ok,
        [_stage_view(stage) for stage in outcome.stages],
        _discovery_view(outcome.discovery) if outcome.discovery is not None else None,
        outcome.probe_token,
        outcome.expires_at,
    )


def _check_probe_rate_limit(limiter: RateLimiter, context: AuthContext) -> None:
    result = limiter.check_probe(str(context.user.id))
    if not result.allowed:
        raise auth_errors.rate_limited(result.retry_after_seconds, "probe")


def _audit(
    request: Request,
    logger: AuditLogger,
    context: AuthContext,
    *,
    action: str,
    device: Device,
    detail: dict[str, object],
) -> None:
    source_ip = request.client.host if request.client else None
    logger.record(
        action=action,
        actor_user_id=context.user.id,
        session_id=context.session.id,
        resource_type="device",
        resource_id=str(device.id),
        device_id=device.id,
        requirement_id=PLT_02,
        request_id=str(request.scope.get("request_id") or ""),
        result="success",
        source_ip=source_ip,
        user_agent_summary=client_summary(source_ip, request.headers.get("user-agent")),
        detail=detail,
    )


@router.post(
    "/device-probes",
    operation_id="device_probes_create",
    response_model=DeviceProbeResponse,
    responses={
        "403": {"description": "permission_denied"},
        "422": {"description": "validation_failed / network_unreachable"},
        "429": {"description": "rate_limited"},
    },
)
def device_probes_create(
    body: DeviceProbeRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(DEVICE_MANAGE))],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> DeviceProbeResponse:
    _check_probe_rate_limit(limiter, context)
    adapter = _resolve_adapter(body.adapter_key, body.device_type)
    _validate_connection_config(adapter, body.connection_config)
    _validate_credentials(adapter, body.credentials)
    profile = _profile_for_request(
        adapter,
        device_id=None,
        management_endpoint=body.management_endpoint,
        port=body.port,
        connection_config=body.connection_config,
        credentials=body.credentials,
    )
    settings: WardenSettings = request.app.state.settings
    outcome = probe_device(profile, allow_save=True, settings=settings, adapter=adapter)
    ok, stages, discovery, token, expires_at = _outcome_response(outcome)
    return DeviceProbeResponse(
        ok=ok, stages=stages, discovery=discovery, probe_token=token, expires_at=expires_at
    )


@router.post(
    "/devices",
    operation_id="devices_create",
    response_model=DeviceView,
    status_code=201,
    responses={
        "403": {"description": "permission_denied"},
        "422": {"description": "validation_failed"},
        "429": {"description": "rate_limited"},
    },
)
def devices_create(
    body: DeviceCreateRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(DEVICE_MANAGE))],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    keyring: Annotated[CredentialKeyring, Depends(get_credential_keyring)],
) -> DeviceView:
    adapter = _resolve_adapter(body.adapter_key, body.device_type)
    _validate_connection_config(adapter, body.connection_config)
    _validate_credentials(adapter, body.credentials)
    profile = _profile_for_request(
        adapter,
        device_id=None,
        management_endpoint=body.management_endpoint,
        port=body.port,
        connection_config=body.connection_config,
        credentials=body.credentials,
    )
    settings: WardenSettings = request.app.state.settings
    device = save_device_from_probe(
        db,
        profile=profile,
        name=body.name,
        device_type=body.device_type,
        enabled=body.enabled,
        probe_token=body.probe_token,
        settings=settings,
        keyring=keyring,
        adapter=adapter,
    )
    _audit(
        request,
        logger,
        context,
        action="device.create",
        device=device,
        detail={
            "name": device.name,
            "device_type": device.device_type,
            "adapter_key": device.adapter_key,
            "management_endpoint": device.management_endpoint,
            "readiness": device.readiness,
            "enabled": device.enabled,
            "credentials_digest": credentials_digest(body.credentials),
        },
    )
    return DeviceView.model_validate(device, from_attributes=True)


@router.get(
    "/devices",
    operation_id="devices_list",
    response_model=DeviceListResponse,
    responses={"403": {"description": "permission_denied"}},
)
def devices_list(
    context: Annotated[AuthContext, Depends(require_permission(DEVICE_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort: str = Query(default="name", pattern=r"^-?(name|device_type|vendor|model|created_at)$"),
    name: str | None = Query(default=None, max_length=128),
    device_type: str | None = Query(default=None, pattern=DEVICE_TYPE_PATTERN),
    vendor: str | None = Query(default=None, max_length=128),
    model: str | None = Query(default=None, max_length=128),
    reachability: str | None = Query(default=None, pattern=REACHABILITY_PATTERN),
    health: str | None = Query(default=None, pattern=HEALTH_PATTERN),
    enabled: bool | None = Query(default=None),
) -> DeviceListResponse:
    del context
    rows, total = list_devices(
        db,
        page=page,
        page_size=page_size,
        sort=sort,
        name=name,
        device_type=device_type,
        vendor=vendor,
        model=model,
        reachability=reachability,
        health=health,
        enabled=enabled,
    )
    return DeviceListResponse(
        items=[DeviceView.model_validate(row, from_attributes=True) for row in rows],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/devices/{id}",
    operation_id="devices_get",
    response_model=DeviceView,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def devices_get(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(DEVICE_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> DeviceView:
    del context
    return DeviceView.model_validate(get_device(db, id), from_attributes=True)


def _parse_if_match(request: Request, current_version: int) -> int:
    raw = request.headers.get("if-match")
    if not raw:
        raise auth_errors.version_conflict(current_version)
    value = raw.strip().strip('"')
    try:
        return int(value)
    except ValueError:
        raise auth_errors.version_conflict(current_version) from None


@router.patch(
    "/devices/{id}",
    operation_id="devices_update",
    response_model=DeviceView,
    responses={
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "412": {"description": "version_conflict"},
        "422": {
            "description": "validation_failed / authentication_failed / tls_validation_failed / network_unreachable"
        },
    },
)
def devices_update(
    id: str,
    body: DeviceUpdateRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(DEVICE_MANAGE))],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    keyring: Annotated[CredentialKeyring, Depends(get_credential_keyring)],
) -> DeviceView:
    device = get_device(db, id)
    adapter = _resolve_adapter(
        body.adapter_key if body.adapter_key is not None else device.adapter_key,
        device.device_type,
    )
    if body.connection_config is not None:
        _validate_connection_config(adapter, body.connection_config)
    if body.credentials is not None:
        _validate_credentials(adapter, body.credentials)
    settings: WardenSettings = request.app.state.settings
    if_match_version = _parse_if_match(request, device.version)
    result = update_device(
        db,
        device,
        if_match_version=if_match_version,
        name=body.name,
        enabled=body.enabled,
        management_endpoint=body.management_endpoint,
        adapter_key=body.adapter_key,
        connection_config=body.connection_config,
        credentials=body.credentials,
        probe_token=body.probe_token,
        settings=settings,
        keyring=keyring,
        adapter=adapter,
    )
    detail: dict[str, object] = {"fields": list(result.changed_fields)}
    if result.credentials_digest_value is not None:
        detail["credentials_digest"] = result.credentials_digest_value
        detail["credentials_replaced"] = True
    _audit(request, logger, context, action="device.update", device=device, detail=detail)
    if result.security_config_changes:
        # SECURITY.md §6: 所有协议弱化配置写安全审计 (SNMPv2c/Telnet/verify_tls/
        # TLS 指纹/HTTP scheme), detected against the PREVIOUS stored config.
        _audit(
            request,
            logger,
            context,
            action="security.config_changed",
            device=device,
            detail={
                "changed_keys": list(result.security_config_changes),
                "device_name": result.device.name,
            },
        )
    return DeviceView.model_validate(result.device, from_attributes=True)


@router.post(
    "/devices/{id}/probe",
    operation_id="devices_probe",
    response_model=DeviceProbeExistingResponse,
    responses={
        "403": {"description": "permission_denied"},
        "404": {"description": "resource_not_found"},
        "422": {"description": "validation_failed"},
        "429": {"description": "rate_limited"},
    },
)
def devices_probe(
    id: str,
    request: Request,
    context: Annotated[AuthContext, Depends(require_permission(DEVICE_MANAGE))],
    db: Annotated[Session, Depends(get_db)],
    logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    keyring: Annotated[CredentialKeyring, Depends(get_credential_keyring)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> DeviceProbeExistingResponse:
    _check_probe_rate_limit(limiter, context)
    device = get_device(db, id)
    adapter = _resolve_adapter(device.adapter_key, device.device_type)
    settings: WardenSettings = request.app.state.settings
    outcome = probe_existing_device(
        db, device, settings=settings, keyring=keyring, adapter=adapter
    )
    ok, stages, discovery, token, expires_at = _outcome_response(outcome)
    _audit(
        request,
        logger,
        context,
        action="device.probe",
        device=device,
        detail={"ok": ok, "credentials_digest": outcome.credentials_digest},
    )
    return DeviceProbeExistingResponse(
        device=DeviceView.model_validate(device, from_attributes=True),
        ok=ok,
        stages=stages,
        discovery=discovery,
        probe_token=token,
        expires_at=expires_at,
    )


@router.get(
    "/devices/{id}/capabilities",
    operation_id="device_capabilities_list",
    response_model=CapabilitiesResponse,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def device_capabilities_list(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(DEVICE_READ))],
    db: Annotated[Session, Depends(get_db)],
) -> CapabilitiesResponse:
    del context
    device = get_device(db, id)
    items: list[CapabilityInfo] = list_capabilities(db, device)
    return CapabilitiesResponse(
        items=[
            CapabilityView(
                capability_key=item.capability_key,
                requirement_id=item.requirement_id,
                requirement_title=item.requirement_title,
                support_state=item.support_state,
                discovery_method=item.discovery_method,
                reason_code=item.reason_code,
                detail=item.detail,
                last_checked_at=item.last_checked_at,
                adapter_version=item.adapter_version,
            )
            for item in items
        ]
    )


class ComponentView(BaseModel):
    """Current component (API_CONTRACT.md §4: 当前组件，按 kind/status 过滤)."""

    id: uuid.UUID
    kind: str
    native_id: str
    name: str
    status: str
    properties: dict[str, object]
    first_seen_at: datetime.datetime
    last_seen_at: datetime.datetime


class DeviceComponentsListResponse(BaseModel):
    device_id: uuid.UUID
    items: list[ComponentView]
    page: int
    page_size: int
    total: int


class DeviceEventView(BaseModel):
    """One device event (API_CONTRACT.md §4: SEL、DSM、Trap、Syslog 等).

    The JSONB detail blob stays on the write path; the read view carries the
    message and its provenance (DATA_MODEL.md §5.5).
    """

    id: uuid.UUID
    component_id: uuid.UUID | None
    event_type: str
    severity: str
    message: str
    occurred_at: datetime.datetime
    received_at: datetime.datetime
    source: str
    native_event_id: str | None


class DeviceEventsListResponse(BaseModel):
    device_id: uuid.UUID
    items: list[DeviceEventView]
    page: int
    page_size: int
    total: int


COMPONENT_STATUS_PATTERN = r"^(unknown|ok|warning|critical|absent)$"
EVENT_SEVERITY_PATTERN = r"^(unknown|info|warning|critical)$"
EVENT_SOURCE_PATTERN = r"^(redfish_sel|dsm_log|snmp_trap|syslog|poll|oem_log)$"


@router.get(
    "/devices/{id}/components",
    operation_id="device_components_list",
    response_model=DeviceComponentsListResponse,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def device_components_list(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    kind: str | None = Query(default=None, max_length=32),
    status: str | None = Query(default=None, pattern=COMPONENT_STATUS_PATTERN),
) -> DeviceComponentsListResponse:
    del context
    device = get_device(db, id)
    rows, total = list_components(
        db,
        device=device,
        page=page,
        page_size=page_size,
        kind=kind,
        status=status,
    )
    return DeviceComponentsListResponse(
        device_id=device.id,
        items=[
            ComponentView(
                id=row.id,
                kind=row.kind,
                native_id=row.native_id,
                name=row.name,
                status=row.status,
                properties=dict(row.properties),
                first_seen_at=row.first_seen_at,
                last_seen_at=row.last_seen_at,
            )
            for row in rows
        ],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/devices/{id}/events",
    operation_id="device_events_list",
    response_model=DeviceEventsListResponse,
    responses={"403": {"description": "permission_denied"}, "404": {"description": "resource_not_found"}},
)
def device_events_list(
    id: str,
    context: Annotated[AuthContext, Depends(require_permission(MONITOR_READ))],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: str | None = Query(default=None, pattern=EVENT_SEVERITY_PATTERN),
    event_type: str | None = Query(default=None, max_length=64),
    source: str | None = Query(default=None, pattern=EVENT_SOURCE_PATTERN),
    from_: Annotated[datetime.datetime | None, Query(alias="from")] = None,
    to_: Annotated[datetime.datetime | None, Query(alias="to")] = None,
) -> DeviceEventsListResponse:
    del context
    device = get_device(db, id)
    rows, total = list_device_events(
        db,
        device=device,
        page=page,
        page_size=page_size,
        severity=severity,
        event_type=event_type,
        source=source,
        from_=from_,
        to_=to_,
    )
    return DeviceEventsListResponse(
        device_id=device.id,
        items=[
            DeviceEventView(
                id=row.id,
                component_id=row.component_id,
                event_type=row.event_type,
                severity=row.severity,
                message=row.message,
                occurred_at=row.occurred_at,
                received_at=row.received_at,
                source=row.source,
                native_event_id=row.native_event_id,
            )
            for row in rows
        ],
        page=page,
        page_size=page_size,
        total=total,
    )
