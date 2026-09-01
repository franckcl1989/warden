"""Fake adapter for tests and dev onboarding (M1T3).

``fake.simple`` is the CI-grade onboarding stand-in for device_type ``server``:
it reports stage-by-stage success, full identity and capability discovery
without touching the network. It MUST never be mistaken for hardware support:
its only purpose is exercising the onboarding pipeline, and the hardware
certification matrix (hardware-targets.json) stays ``not_started`` for it —
this module documents that and the registry test enforces it.

Failure injection is configured through the probe profile's
``connection_config`` (dev/test only): ``fail_tls: true`` makes the tls stage
fail with ``tls_validation_failed``, ``fail_credentials: true`` makes the auth
stage fail with ``authentication_failed``. Capabilities are derived from the
generated requirement registry (contracts/capabilities.json), so the fake
always mirrors the real server capability surface.
"""

from __future__ import annotations

from app.domain.adapter import (
    CapabilitySupport,
    ComponentObserved,
    ConnectionProfile,
    DiscoveryResult,
    ProbeResult,
    ProbeStage,
)
from app.generated.capabilities import REQUIREMENTS

FAIL_CREDENTIALS_KEY = "fail_credentials"
FAIL_TLS_KEY = "fail_tls"


class FakeSimpleAdapter:
    """Deterministic fake server adapter (adapter_key ``fake.simple``)."""

    adapter_key = "fake.simple"
    supported_device_types = frozenset({"server"})
    adapter_version = "0.1.0"
    secret_schema_version = 1
    secret_schema: dict[str, object] = {
        "type": "object",
        "required": ["username", "password"],
        "additionalProperties": False,
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "password": {"type": "string", "minLength": 1},
        },
    }
    connection_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "protocol": {"type": "string", "enum": ["https"]},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "verify_tls": {"type": "boolean"},
            "tls_fingerprint_sha256": {
                "type": ["string", "null"],
                "pattern": "^[0-9a-fA-F]{64}$",
            },
            # SECURITY.md §6 weak-protocol fields: dev/test only so M1T4 can
            # exercise the security.config_changed audit path without hardware.
            "snmp_version": {"type": "string", "enum": ["v3", "v2c"]},
            "telnet": {"type": "boolean"},
            FAIL_CREDENTIALS_KEY: {"type": "boolean"},
            FAIL_TLS_KEY: {"type": "boolean"},
        },
    }

    def probe(self, profile: ConnectionProfile) -> ProbeResult:
        config = profile.connection_config
        fail_tls = bool(config.get(FAIL_TLS_KEY, False))
        fail_credentials = bool(config.get(FAIL_CREDENTIALS_KEY, False))
        stages = [
            ProbeStage(stage="network", ok=True),
            ProbeStage(
                stage="tls",
                ok=not fail_tls,
                error_code="tls_validation_failed" if fail_tls else None,
                detail_safe="模拟 TLS 证书指纹不匹配（fail_tls 模式）" if fail_tls else None,
            ),
        ]
        if fail_tls:
            stages.append(ProbeStage(stage="auth", ok=False, detail_safe="前置阶段失败，未执行"))
            stages.append(ProbeStage(stage="identity", ok=False, detail_safe="前置阶段失败，未执行"))
            stages.append(ProbeStage(stage="capabilities", ok=False, detail_safe="前置阶段失败，未执行"))
        else:
            stages.append(
                ProbeStage(
                    stage="auth",
                    ok=not fail_credentials,
                    error_code="authentication_failed" if fail_credentials else None,
                    detail_safe="模拟凭据认证失败（fail_credentials 模式）" if fail_credentials else None,
                )
            )
            if fail_credentials:
                stages.append(ProbeStage(stage="identity", ok=False, detail_safe="前置阶段失败，未执行"))
                stages.append(
                    ProbeStage(stage="capabilities", ok=False, detail_safe="前置阶段失败，未执行")
                )
            else:
                stages.append(
                    ProbeStage(stage="identity", ok=True, detail_safe="已识别为 FakeServer-1")
                )
                stages.append(
                    ProbeStage(
                        stage="capabilities", ok=True, detail_safe="能力发现完成（来自生成的需求注册表）"
                    )
                )
        result = ProbeResult(stages=tuple(stages))
        if result.ok:
            return ProbeResult(
                stages=result.stages, identity_hint={"vendor": "Fake", "model": "FakeServer-1"}
            )
        return result

    def discover(self, profile: ConnectionProfile) -> DiscoveryResult:
        del profile
        # One row per capability key (device_capabilities UNIQUE
        # (device_id, capability_key)); when several requirements declare the
        # same key (e.g. indicator.led under SRV-MON-01 and SRV-MON-07), the
        # first requirement in the registry wins deterministically.
        capabilities: dict[str, CapabilitySupport] = {}
        for requirement in REQUIREMENTS.values():
            if requirement.device_type != "server":
                continue
            for key in (
                *requirement.metrics,
                *requirement.events,
                *(operation[0] for operation in requirement.operations),
            ):
                if key not in capabilities:
                    capabilities[key] = CapabilitySupport(
                        capability_key=key,
                        support_state="supported",
                        requirement_id=requirement.id,
                        discovery_method=self.adapter_key,
                    )
        components = (
            ComponentObserved(kind="processor", native_id="cpu-0", name="Fake CPU", status="ok"),
            ComponentObserved(kind="memory", native_id="dimm-0", name="Fake DIMM", status="ok"),
            ComponentObserved(kind="drive", native_id="drive-0", name="Fake Drive", status="ok"),
            ComponentObserved(kind="fan", native_id="fan-0", name="Fake Fan", status="ok"),
            ComponentObserved(kind="psu", native_id="psu-0", name="Fake PSU", status="ok"),
        )
        return DiscoveryResult(
            vendor="Fake",
            model="FakeServer-1",
            serial_number="FAKE-SN-0001",
            firmware_version="1.0.0",
            capabilities=tuple(capabilities.values()),
            components=components,
            secrets_schema=self.secret_schema,
            secrets_schema_version=self.secret_schema_version,
        )
