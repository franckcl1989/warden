"""Device onboarding use cases (PLT-02 / PLT-03 base capability discovery).

docs/API_CONTRACT.md §4, DATA_MODEL.md §4/§11, DEVICE_ADAPTERS.md §2.

Flow semantics (M1T3):

- ``probe_device`` resolves the endpoint through the SSRF policy
  (resolve-then-validate, SECURITY.md §7), runs the adapter's staged probe,
  discovers capabilities/components only when every stage passed, and signs a
  10-minute probe token bound to the exact normalized profile (credentials
  digest + endpoint + adapter key).
- ``save_device_from_probe`` validates the token (signature, expiry,
  fingerprint, device binding), re-runs the probe with the token-bound
  profile (a stateless token cannot carry discovery; the save never trusts a
  stale result — the fresh probe decides readiness), and writes device +
  encrypted credentials + capabilities + components in ONE transaction
  (DATA_MODEL.md §11). Failed probes save as ``not_ready`` + ``enabled=False``
  (PRODUCT_DESIGN.md §4.2); the token gates access, so the connection test
  can never be bypassed.
- ``update_device`` applies optimistic locking (If-Match version, 412 on
  mismatch). Name/enabled-only changes need no probe; management_endpoint /
  adapter / protocol-security / credentials changes require a probe token
  bound to the NEW profile and a fresh probe — the unverified configuration
  is never applied.
- ``probe_existing_device`` re-probes a saved device with its decrypted
  credentials; success refreshes identity/capabilities/components and marks
  ``ready``, failure marks ``misconfigured``.
- ``list_capabilities`` joins the persisted capability rows with the
  generated requirement registry (requirement id + title).

Credentials are plaintext only inside the probe boundary and inside the
adapter call; everything stored is encrypted via the keystore with AAD
device_id + adapter_key + secret_schema_version (SECURITY.md §5). Audit
carries only the credentials digest.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import cast

from sqlalchemy import ColumnElement, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.application.security_events import security_sensitive_config_change
from app.config import WardenSettings
from app.domain.adapter import (
    DEFAULT_MANAGEMENT_PORT,
    OPERATION_APPLIED_COMPONENT_KINDS,
    ConnectionProfile,
    DeviceAdapter,
    DiscoveryResult,
    ProbeOutcome,
    credentials_digest,
    profile_fingerprint,
)
from app.domain.auth_errors import resource_not_found, validation_failed, version_conflict
from app.domain.device_errors import probe_policy_violation, probe_stage_error
from app.infrastructure.crypto import CredentialKeyring, EncryptedSecret, credential_aad
from app.infrastructure.network_policy import (
    DEFAULT_ALLOWED_PORTS,
    DeviceEndpointPolicy,
    NetworkPolicyViolation,
)
from app.infrastructure.probe_tokens import TOKEN_TTL_SECONDS, ProbeTokenError, ProbeTokenSigner
from app.infrastructure.time import utcnow
from app.models.devices import Component, Device, DeviceCapability, DeviceCredential

DEVICE_NOT_FOUND = "设备不存在"


@dataclass(frozen=True)
class DeviceUpdateResult:
    """update_device outcome: the device plus what changed (for audit)."""

    device: Device
    changed_fields: tuple[str, ...]
    credentials_digest_value: str | None
    security_config_changes: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityInfo:
    """One persisted capability row joined with the generated registry."""

    capability_key: str
    requirement_id: str
    requirement_title: str | None
    support_state: str
    discovery_method: str
    reason_code: str | None
    detail: str | None
    last_checked_at: datetime
    adapter_version: str


def _policy(settings: WardenSettings) -> DeviceEndpointPolicy:
    return DeviceEndpointPolicy(settings.allowed_device_networks)


def _protocol_for(profile: ConnectionProfile) -> str:
    protocol = profile.connection_config.get("protocol")
    return protocol if isinstance(protocol, str) else "https"


def _signer(settings: WardenSettings) -> ProbeTokenSigner:
    return ProbeTokenSigner(settings.session_secret)


def build_connection_profile(
    adapter: DeviceAdapter,
    *,
    device_id: uuid.UUID | None,
    management_endpoint: str,
    port: int | None,
    connection_config: dict[str, object],
    credentials: dict[str, object],
) -> ConnectionProfile:
    """Build the profile an adapter probes with.

    The effective port is the request port, else ``connection_config.port``,
    else the https default; the effective port is merged back into the stored
    connection_config so a saved device is self-contained for future probes.
    ``verify_tls`` and ``tls_fingerprint_sha256`` are lifted out of the
    (non-sensitive) protocol config for the adapter's use (SECURITY.md §6).
    """
    config = dict(connection_config)
    raw_port = config.get("port")
    effective_port = port
    if effective_port is None and isinstance(raw_port, int):
        effective_port = raw_port
    if effective_port is None:
        effective_port = DEFAULT_MANAGEMENT_PORT
    config["port"] = effective_port
    verify_tls = config.get("verify_tls", True)
    fingerprint = config.get("tls_fingerprint_sha256")
    return ConnectionProfile(
        adapter_key=adapter.adapter_key,
        management_endpoint=management_endpoint,
        port=effective_port,
        connection_config=config,
        credentials=credentials,
        verify_tls=verify_tls if isinstance(verify_tls, bool) else True,
        tls_fingerprint_sha256=fingerprint if isinstance(fingerprint, str) else None,
        device_id=device_id,
    )


def _require_valid_token(
    settings: WardenSettings,
    probe_token: str | None,
    profile: ConnectionProfile,
    *,
    device_id: uuid.UUID | None,
) -> None:
    if not probe_token:
        raise validation_failed("probe_token", "需要探测令牌")
    try:
        claims = _signer(settings).verify(
            probe_token, fingerprint=profile_fingerprint(profile), now=utcnow()
        )
    except ProbeTokenError as exc:
        raise validation_failed("probe_token", str(exc)) from None
    if claims.device_id is not None and claims.device_id != device_id:
        raise validation_failed("probe_token", "探测令牌不属于该设备")


def probe_device(
    profile: ConnectionProfile,
    *,
    allow_save: bool,
    settings: WardenSettings,
    adapter: DeviceAdapter,
) -> ProbeOutcome:
    """Resolve (SSRF) then probe then discover; returns the signed outcome.

    Device-level failures (network/tls/auth/...) are returned as failed
    stages — the caller decides whether that is an error (update) or a
    save-as-not_ready (create). Policy violations raise before any device
    call: the endpoint is not in the allowed management CIDRs.
    """
    allowed_ports = DEFAULT_ALLOWED_PORTS[_protocol_for(profile)]
    try:
        resolved_ip, port = _policy(settings).resolve_endpoint(
            profile.management_endpoint, profile.port, allowed_ports
        )
    except NetworkPolicyViolation as exc:
        raise probe_policy_violation(exc.endpoint, exc.reason) from exc
    profile = replace(profile, resolved_ip=resolved_ip, port=port)
    result = adapter.probe(profile)
    discovery = adapter.discover(profile) if result.ok else None
    expires_at = utcnow() + timedelta(seconds=TOKEN_TTL_SECONDS)
    token = _signer(settings).create(
        fingerprint=profile_fingerprint(profile),
        device_id=None if allow_save else profile.device_id,
        expires_at=expires_at,
    )
    return ProbeOutcome(
        stages=result.stages,
        discovery=discovery,
        probe_token=token,
        expires_at=expires_at,
        credentials_digest=credentials_digest(profile.credentials),
    )


def _encrypt_credentials(
    keyring: CredentialKeyring,
    *,
    device_id: uuid.UUID,
    adapter_key: str,
    credentials: dict[str, object],
    secret_schema_version: int,
    key_version: int | None = None,
) -> EncryptedSecret:
    """Encrypt ``credentials`` under the AAD bound to ``adapter_key``.

    ``key_version`` defaults to the keyring's current version (fresh writes);
    pass the stored row's version to re-bind an existing ciphertext to a new
    AAD (e.g. an adapter_key change) without switching the master key.
    """
    plaintext = json.dumps(credentials, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    version = keyring.current_version if key_version is None else key_version
    return keyring.cipher_for(version).encrypt_secret(
        plaintext,
        key_version=version,
        aad=credential_aad(str(device_id), adapter_key, secret_schema_version),
    )


def _decrypt_credentials(
    keyring: CredentialKeyring,
    credential: DeviceCredential,
    *,
    device_id: uuid.UUID,
    adapter_key: str,
) -> dict[str, object]:
    encrypted = EncryptedSecret(
        ciphertext=credential.ciphertext,
        nonce=credential.nonce,
        key_version=credential.key_version,
    )
    plaintext = keyring.decrypt(
        encrypted,
        aad=credential_aad(str(device_id), adapter_key, credential.secret_schema_version),
    )
    value = json.loads(plaintext)
    if not isinstance(value, dict):
        raise validation_failed("credentials", "设备凭据内容无效")
    return value


def _write_capabilities(
    db: Session, device_id: uuid.UUID, discovery: DiscoveryResult, adapter: DeviceAdapter
) -> None:
    now = utcnow()
    db.execute(delete(DeviceCapability).where(DeviceCapability.device_id == device_id))
    for capability in discovery.capabilities:
        db.add(
            DeviceCapability(
                device_id=device_id,
                capability_key=capability.capability_key,
                support_state=capability.support_state,
                requirement_id=capability.requirement_id,
                discovery_method=capability.discovery_method,
                reason_code=capability.reason_code,
                detail=capability.detail,
                last_checked_at=now,
                adapter_version=adapter.adapter_version,
            )
        )


def _write_components(db: Session, device_id: uuid.UUID, discovery: DiscoveryResult) -> None:
    now = utcnow()
    existing = {
        (row.kind, row.native_id): row
        for row in db.scalars(select(Component).where(Component.device_id == device_id)).all()
    }
    seen: set[tuple[str, str]] = set()
    for component in discovery.components:
        key = (component.kind, component.native_id)
        seen.add(key)
        row = existing.get(key)
        if row is None:
            db.add(
                Component(
                    device_id=device_id,
                    kind=component.kind,
                    native_id=component.native_id,
                    name=component.name,
                    status=component.status,
                    properties=dict(component.properties),
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
        else:
            row.name = component.name
            row.status = component.status
            row.properties = dict(component.properties)
            row.last_seen_at = now
    for key, row in existing.items():
        # M3T3: operation-applied kinds (fru/firmware) are outside the
        # discovery inventory; never retire them as "missing" here.
        if key[0] in OPERATION_APPLIED_COMPONENT_KINDS:
            continue
        if key not in seen and row.retired_at is None:
            row.retired_at = now


def _apply_discovery(
    db: Session, device: Device, discovery: DiscoveryResult, adapter: DeviceAdapter
) -> None:
    device.vendor = discovery.vendor
    device.model = discovery.model
    device.serial_number = discovery.serial_number
    device.firmware_version = discovery.firmware_version
    device.last_seen_at = utcnow()
    _write_capabilities(db, device.id, discovery, adapter)
    _write_components(db, device.id, discovery)


def _map_insert_conflict(exc: IntegrityError) -> IntegrityError:
    constraint = ""
    diag = getattr(exc.orig, "diag", None)
    if diag is not None:
        constraint = str(getattr(diag, "constraint_name", "") or "")
    if constraint == "uq_devices_name":
        raise validation_failed("name", "设备名称已存在") from None
    if constraint == "uq_devices_type_endpoint_adapter":
        raise validation_failed("management_endpoint", "该管理地址已被同类型设备使用") from None
    raise exc


def save_device_from_probe(
    db: Session,
    *,
    profile: ConnectionProfile,
    name: str,
    device_type: str,
    enabled: bool,
    probe_token: str | None,
    settings: WardenSettings,
    keyring: CredentialKeyring,
    adapter: DeviceAdapter,
) -> Device:
    """Validate the probe token, re-probe, and save everything in one transaction.

    The fresh probe governs readiness: on success the device is saved
    ``ready`` with the requested ``enabled``; on failure it is saved
    ``not_ready`` + ``enabled=False`` (PRODUCT_DESIGN.md §4.2). Capabilities
    and components are written only when discovery succeeded.
    """
    _require_valid_token(settings, probe_token, profile, device_id=None)
    outcome = probe_device(profile, allow_save=True, settings=settings, adapter=adapter)
    ready = outcome.ok
    now = utcnow()
    device = Device(
        name=name,
        device_type=device_type,
        management_endpoint=profile.management_endpoint,
        adapter_key=profile.adapter_key,
        connection_config=profile.connection_config,
        enabled=enabled and ready,
        readiness="ready" if ready else "not_ready",
        vendor=None,
        model=None,
        serial_number=None,
        firmware_version=None,
        last_seen_at=now if ready else None,
    )
    db.add(device)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        _map_insert_conflict(exc)
    encrypted = _encrypt_credentials(
        keyring,
        device_id=device.id,
        adapter_key=profile.adapter_key,
        credentials=profile.credentials,
        secret_schema_version=adapter.secret_schema_version,
    )
    db.add(
        DeviceCredential(
            device_id=device.id,
            ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            key_version=encrypted.key_version,
            secret_schema_version=adapter.secret_schema_version,
        )
    )
    if ready and outcome.discovery is not None:
        _apply_discovery(db, device, outcome.discovery, adapter)
    db.commit()
    db.refresh(device)
    return device


def update_device(
    db: Session,
    device: Device,
    *,
    if_match_version: int,
    name: str | None,
    enabled: bool | None,
    management_endpoint: str | None,
    adapter_key: str | None,
    connection_config: dict[str, object] | None,
    credentials: dict[str, object] | None,
    probe_token: str | None,
    settings: WardenSettings,
    keyring: CredentialKeyring,
    adapter: DeviceAdapter,
) -> DeviceUpdateResult:
    """Optimistic-locked device update (ARCHITECTURE.md §6).

    Name/enabled-only changes apply without a probe. Security-relevant
    changes (management_endpoint / adapter_key / connection_config /
    credentials) require a probe token bound to the NEW profile and a fresh
    probe; when the fresh probe fails the change is rejected with the stage
    error — unverified configuration is never applied. A kept-credentials
    adapter_key change re-encrypts the stored ciphertext under the new AAD
    (device_id + new adapter_key + same secret_schema_version) with the same
    key_version, so later decrypts keep working. The enabled check runs
    after security changes so a PATCH that both fixes the config (re-probe ->
    ready) and enables the device works in one round trip.
    """
    if device.version != if_match_version:
        raise version_conflict(device.version)
    changed: list[str] = []
    sensitive_changes: list[str] = []
    new_credentials_digest: str | None = None
    security_relevant = any(
        value is not None for value in (management_endpoint, adapter_key, connection_config, credentials)
    )
    if security_relevant:
        if probe_token is None:
            raise validation_failed("probe_token", "修改连接配置或凭据需要先重新探测")
        previous_adapter_key = device.adapter_key
        effective_credentials = credentials
        if effective_credentials is None:
            credential_row = db.get(DeviceCredential, device.id)
            if credential_row is None:
                raise validation_failed("credentials", "设备凭据不存在")
            effective_credentials = _decrypt_credentials(
                keyring,
                credential_row,
                device_id=device.id,
                adapter_key=previous_adapter_key,
            )
        effective_endpoint = (
            management_endpoint if management_endpoint is not None else device.management_endpoint
        )
        effective_config = (
            dict(connection_config) if connection_config is not None else dict(device.connection_config)
        )
        effective_port = effective_config.get("port")
        profile = build_connection_profile(
            adapter,
            device_id=device.id,
            management_endpoint=effective_endpoint,
            port=effective_port if isinstance(effective_port, int) else None,
            connection_config=effective_config,
            credentials=effective_credentials,
        )
        _require_valid_token(settings, probe_token, profile, device_id=device.id)
        outcome = probe_device(profile, allow_save=False, settings=settings, adapter=adapter)
        if not outcome.ok:
            failed = next((stage for stage in outcome.stages if not stage.ok), None)
            if failed is None:
                raise validation_failed("probe", "设备探测失败")
            raise probe_stage_error(failed)
        if connection_config is not None:
            # Only after the fresh probe succeeded: the unverified change is
            # never applied, so it must not be audited as applied (M1T4).
            sensitive_changes = security_sensitive_config_change(
                dict(device.connection_config), dict(profile.connection_config)
            )
        device.management_endpoint = profile.management_endpoint
        device.adapter_key = profile.adapter_key
        device.connection_config = profile.connection_config
        if management_endpoint is not None:
            changed.append("management_endpoint")
        if adapter_key is not None:
            changed.append("adapter_key")
        if connection_config is not None:
            changed.append("connection_config")
        if credentials is not None:
            credential_row = db.get(DeviceCredential, device.id)
            encrypted = _encrypt_credentials(
                keyring,
                device_id=device.id,
                adapter_key=profile.adapter_key,
                credentials=effective_credentials,
                secret_schema_version=adapter.secret_schema_version,
            )
            if credential_row is None:
                db.add(
                    DeviceCredential(
                        device_id=device.id,
                        ciphertext=encrypted.ciphertext,
                        nonce=encrypted.nonce,
                        key_version=encrypted.key_version,
                        secret_schema_version=adapter.secret_schema_version,
                    )
                )
            else:
                credential_row.ciphertext = encrypted.ciphertext
                credential_row.nonce = encrypted.nonce
                credential_row.key_version = encrypted.key_version
                credential_row.secret_schema_version = adapter.secret_schema_version
            changed.append("credentials")
            new_credentials_digest = credentials_digest(effective_credentials)
        elif profile.adapter_key != previous_adapter_key:
            credential_row = db.get(DeviceCredential, device.id)
            if credential_row is None:
                raise validation_failed("credentials", "设备凭据不存在")
            encrypted = _encrypt_credentials(
                keyring,
                device_id=device.id,
                adapter_key=profile.adapter_key,
                credentials=effective_credentials,
                secret_schema_version=credential_row.secret_schema_version,
                key_version=credential_row.key_version,
            )
            credential_row.ciphertext = encrypted.ciphertext
            credential_row.nonce = encrypted.nonce
        device.readiness = "ready"
        device.last_seen_at = utcnow()
        if outcome.discovery is not None:
            _apply_discovery(db, device, outcome.discovery, adapter)
    if name is not None and name != device.name:
        device.name = name
        changed.append("name")
    if enabled is not None and enabled != device.enabled:
        if enabled and device.readiness != "ready":
            raise validation_failed("enabled", "设备未就绪，不能启用")
        device.enabled = enabled
        changed.append("enabled")
    device.version += 1
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _map_insert_conflict(exc)
    db.refresh(device)
    return DeviceUpdateResult(
        device=device,
        changed_fields=tuple(changed),
        credentials_digest_value=new_credentials_digest,
        security_config_changes=tuple(sensitive_changes),
    )


def probe_existing_device(
    db: Session,
    device: Device,
    *,
    settings: WardenSettings,
    keyring: CredentialKeyring,
    adapter: DeviceAdapter,
) -> ProbeOutcome:
    """Re-probe a saved device with its decrypted credentials.

    Success refreshes identity + capabilities + components and marks the
    device ``ready``; failure marks it ``misconfigured`` (the current
    configuration no longer verifies). The transition commits in one
    transaction.
    """
    credential_row = db.get(DeviceCredential, device.id)
    if credential_row is None:
        raise validation_failed("credentials", "设备凭据不存在")
    credentials = _decrypt_credentials(
        keyring,
        credential_row,
        device_id=device.id,
        adapter_key=device.adapter_key,
    )
    raw_port = device.connection_config.get("port")
    profile = build_connection_profile(
        adapter,
        device_id=device.id,
        management_endpoint=device.management_endpoint,
        port=raw_port if isinstance(raw_port, int) else None,
        connection_config=device.connection_config,
        credentials=credentials,
    )
    outcome = probe_device(profile, allow_save=False, settings=settings, adapter=adapter)
    if outcome.ok and outcome.discovery is not None:
        _apply_discovery(db, device, outcome.discovery, adapter)
        device.readiness = "ready"
    else:
        device.readiness = "misconfigured"
    db.commit()
    db.refresh(device)
    return outcome


def get_device(db: Session, device_id: str) -> Device:
    try:
        key = uuid.UUID(device_id)
    except ValueError:
        raise resource_not_found("device") from None
    device = db.get(Device, key)
    if device is None:
        raise resource_not_found("device")
    return device


def list_devices(
    db: Session,
    *,
    page: int,
    page_size: int,
    sort: str,
    name: str | None,
    device_type: str | None,
    vendor: str | None,
    model: str | None,
    reachability: str | None,
    health: str | None,
    enabled: bool | None,
) -> tuple[list[Device], int]:
    filters: list[ColumnElement[bool]] = []
    if name is not None:
        filters.append(Device.name == name)
    if device_type is not None:
        filters.append(Device.device_type == device_type)
    if vendor is not None:
        filters.append(Device.vendor == vendor)
    if model is not None:
        filters.append(Device.model == model)
    if reachability is not None:
        filters.append(Device.reachability == reachability)
    if health is not None:
        filters.append(Device.health == health)
    if enabled is not None:
        filters.append(Device.enabled == enabled)
    base = select(Device).where(*filters)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    columns: dict[str, ColumnElement[object]] = {
        "name": cast(ColumnElement[object], Device.name),
        "device_type": cast(ColumnElement[object], Device.device_type),
        "vendor": cast(ColumnElement[object], Device.vendor),
        "model": cast(ColumnElement[object], Device.model),
        "created_at": cast(ColumnElement[object], Device.created_at),
    }
    column = columns[sort.lstrip("-")]
    order = column.asc() if not sort.startswith("-") else column.desc()
    rows = db.scalars(
        base.order_by(order, Device.name.asc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return list(rows), int(total)


def list_capabilities(db: Session, device: Device) -> list[CapabilityInfo]:
    from app.generated.capabilities import REQUIREMENTS

    rows = db.scalars(
        select(DeviceCapability)
        .where(DeviceCapability.device_id == device.id)
        .order_by(DeviceCapability.capability_key.asc())
    ).all()
    items: list[CapabilityInfo] = []
    for row in rows:
        requirement = REQUIREMENTS.get(row.requirement_id)
        items.append(
            CapabilityInfo(
                capability_key=row.capability_key,
                requirement_id=row.requirement_id,
                requirement_title=requirement.title if requirement is not None else None,
                support_state=row.support_state,
                discovery_method=row.discovery_method,
                reason_code=row.reason_code,
                detail=row.detail,
                last_checked_at=row.last_checked_at,
                adapter_version=row.adapter_version,
            )
        )
    return items
