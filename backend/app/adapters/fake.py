"""Fake adapter for tests and dev onboarding (M1T3 probe/discover, M2T2 collect).

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

``collect`` (M2T2) returns deterministic ObservationBatches with real values
and units from contracts/metrics.json. Collection modes (dev/test only):

- ``failure_mode``: ``"network_unreachable"`` / ``"authentication_failed"`` /
  ``"protocol_error"`` (bool true -> network_unreachable) — the adapter raises
  ``AdapterError`` so the pipeline marks the run failed and feeds reachability;
- ``partial_mode``: a few metrics become ``ObservationError`` entries, the
  rest stay good (batch partial semantics);
- ``critical_mode``: health.overall=critical plus alert-worthy statuses
  (drive.status critical, drive.predictive_failure true) for alert tests;
- ``no_data_mode``: an empty supported batch with explicit error entries —
  never a fabricated empty success.
"""

from __future__ import annotations

import datetime

from app.domain.adapter import (
    AdapterError,
    CapabilitySupport,
    CollectionRequest,
    ComponentObserved,
    ConnectionProfile,
    DeviceSession,
    DiscoveryResult,
    EventObservation,
    Observation,
    ObservationBatch,
    ObservationError,
    ProbeResult,
    ProbeStage,
)
from app.generated.capabilities import REQUIREMENTS

FAIL_CREDENTIALS_KEY = "fail_credentials"
FAIL_TLS_KEY = "fail_tls"
FAILURE_MODE_KEY = "failure_mode"
PARTIAL_MODE_KEY = "partial_mode"
CRITICAL_MODE_KEY = "critical_mode"
NO_DATA_MODE_KEY = "no_data_mode"

FAILURE_CODES = ("network_unreachable", "authentication_failed", "protocol_error")


def batch_events(now: datetime.datetime) -> tuple[EventObservation, ...]:
    """Deterministic SEL events for the fake server (SRV-MON-08)."""
    return (
        EventObservation(
            event_type="event.sel",
            severity="info",
            message="模拟 SEL 事件：系统运行正常",
            occurred_at=now,
            source="redfish_sel",
            native_event_id="FAKE-SEL-0001",
        ),
    )


def _obs(
    metric_key: str,
    value: bool | int | float | str,
    now: datetime.datetime,
    kind: str | None = None,
    native: str | None = None,
) -> Observation:
    """One fake observation (source redfish, good quality)."""
    return Observation(metric_key, value, now, component_kind=kind, component_native_id=native, source="redfish")


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
            FAILURE_MODE_KEY: {
                "type": ["string", "boolean"],
                "enum": [True, False, "network_unreachable", "authentication_failed", "protocol_error"],
            },
            PARTIAL_MODE_KEY: {"type": "boolean"},
            CRITICAL_MODE_KEY: {"type": "boolean"},
            NO_DATA_MODE_KEY: {"type": "boolean"},
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

    def collect(self, session: DeviceSession, request: CollectionRequest) -> ObservationBatch:
        config = session.connection_config
        failure = config.get(FAILURE_MODE_KEY)
        if failure:
            code = failure if isinstance(failure, str) and failure in FAILURE_CODES else "network_unreachable"
            raise AdapterError(
                code,
                "模拟设备连接失败（failure_mode）" if code == "network_unreachable"
                else "模拟凭据认证失败（failure_mode）" if code == "authentication_failed"
                else "模拟协议错误（failure_mode）",
            )
        if config.get(NO_DATA_MODE_KEY):
            return ObservationBatch(
                errors=(
                    ObservationError(
                        key="health.overall", error_code="protocol_error",
                        stage="collect", detail="no_data_mode：设备未返回任何观测",
                    ),
                    ObservationError(
                        key="temperature.cpu", error_code="protocol_error",
                        stage="collect", detail="no_data_mode：设备未返回任何观测",
                    ),
                )
            )
        # Observations are stamped with the collection time (request.now) so
        # pipelines are deterministic: the same batch at different times is
        # distinguishable in metric_latest/metric_points.
        now = request.now
        if config.get(CRITICAL_MODE_KEY):
            return self._batch_critical(now)
        if config.get(PARTIAL_MODE_KEY):
            return self._batch_partial(now)
        return self._batch_normal(now)

    @staticmethod
    def _components(statuses: dict[str, str]) -> tuple[ComponentObserved, ...]:
        return (
            ComponentObserved(kind="processor", native_id="cpu-0", name="Fake CPU", status=statuses.get("cpu", "ok")),
            ComponentObserved(kind="memory", native_id="dimm-0", name="Fake DIMM", status=statuses.get("dimm", "ok")),
            ComponentObserved(kind="drive", native_id="drive-0", name="Fake Drive", status=statuses.get("drive", "ok")),
            ComponentObserved(kind="fan", native_id="fan-0", name="Fake Fan", status=statuses.get("fan", "ok")),
            ComponentObserved(kind="psu", native_id="psu-0", name="Fake PSU", status=statuses.get("psu", "ok")),
            ComponentObserved(kind="sensor", native_id="sensor-inlet", name="进风口传感器", status="ok"),
            ComponentObserved(kind="sensor", native_id="sensor-board", name="主板传感器", status="ok"),
        )

    def _batch_normal(self, now: datetime.datetime) -> ObservationBatch:
        observations = (
            _obs("health.overall", "healthy", now),
            _obs("indicator.led", "normal", now),
            _obs("chassis.intrusion", "normal", now),
            _obs("temperature.cpu", 42.5, now, kind="processor", native="cpu-0"),
            _obs("temperature.memory", 38.2, now, kind="memory", native="dimm-0"),
            _obs("memory.status", "ok", now, kind="memory", native="dimm-0"),
            _obs("memory.ecc_errors", 0, now, kind="memory", native="dimm-0"),
            _obs("drive.status", "ok", now, kind="drive", native="drive-0"),
            _obs("drive.smart", "passed", now, kind="drive", native="drive-0"),
            _obs("drive.predictive_failure", False, now, kind="drive", native="drive-0"),
            _obs("raid.status", "optimal", now, kind="drive", native="drive-0"),
            _obs("psu.present", "present", now, kind="psu", native="psu-0"),
            _obs("psu.status", "ok", now, kind="psu", native="psu-0"),
            _obs("psu.load_w", 312.5, now, kind="psu", native="psu-0"),
            _obs("psu.voltage_v", 12.1, now, kind="psu", native="psu-0"),
            _obs("fan.rpm", 8450.0, now, kind="fan", native="fan-0"),
            _obs("fan.status", "ok", now, kind="fan", native="fan-0"),
            _obs("temperature.inlet", 25.0, now, kind="sensor", native="sensor-inlet"),
            _obs("temperature.board", 33.1, now, kind="sensor", native="sensor-board"),
        )
        event = batch_events(now)[0]
        return ObservationBatch(
            observations=observations,
            events=(event,),
            components=self._components({}),
        )

    def _batch_partial(self, now: datetime.datetime) -> ObservationBatch:
        batch = self._batch_normal(now)
        observations: list[Observation] = []
        errors: list[ObservationError] = []
        for obs in batch.observations:
            if obs.metric_key in ("temperature.memory", "fan.status"):
                errors.append(
                    ObservationError(
                        key=obs.metric_key,
                        error_code="protocol_error",
                        stage="parse",
                        component_kind=obs.component_kind,
                        component_native_id=obs.component_native_id,
                        detail="partial_mode：该指标读取失败",
                    )
                )
            else:
                observations.append(obs)
        return ObservationBatch(
            observations=tuple(observations),
            events=batch.events,
            components=batch.components,
            errors=tuple(errors),
        )

    def _batch_critical(self, now: datetime.datetime) -> ObservationBatch:
        observations = (
            _obs("health.overall", "critical", now),
            _obs("indicator.led", "critical", now),
            _obs("chassis.intrusion", "normal", now),
            _obs("temperature.cpu", 42.5, now, kind="processor", native="cpu-0"),
            _obs("temperature.memory", 38.2, now, kind="memory", native="dimm-0"),
            _obs("memory.status", "ok", now, kind="memory", native="dimm-0"),
            _obs("memory.ecc_errors", 0, now, kind="memory", native="dimm-0"),
            _obs("drive.status", "critical", now, kind="drive", native="drive-0"),
            _obs("drive.smart", "failed", now, kind="drive", native="drive-0"),
            _obs("drive.predictive_failure", True, now, kind="drive", native="drive-0"),
            _obs("raid.status", "failed", now, kind="drive", native="drive-0"),
            _obs("psu.present", "present", now, kind="psu", native="psu-0"),
            _obs("psu.status", "ok", now, kind="psu", native="psu-0"),
            _obs("psu.load_w", 312.5, now, kind="psu", native="psu-0"),
            _obs("psu.voltage_v", 12.1, now, kind="psu", native="psu-0"),
            _obs("fan.rpm", 8450.0, now, kind="fan", native="fan-0"),
            _obs("fan.status", "ok", now, kind="fan", native="fan-0"),
            _obs("temperature.inlet", 25.0, now, kind="sensor", native="sensor-inlet"),
            _obs("temperature.board", 33.1, now, kind="sensor", native="sensor-board"),
        )
        return ObservationBatch(
            observations=observations,
            events=batch_events(now),
            components=self._components({"drive": "critical"}),
        )
