"""Fake adapter for tests and dev onboarding (M1T3 probe/discover, M2T2 collect, M2T4 operations).

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

Operation methods (M2T4, DEVICE_ADAPTERS.md §2.4/§4.2/§9): planning mirrors
the shared domain planner over the persisted snapshot; preflight/execute/
verify simulate the device-side flow. Modes (dev/test only, mirrors the
fail_credentials/fail_tls pattern):

- ``fail_preflight_mode`` / ``stale_preflight_mode``: preflight rejects the
  plan (validation_failed) or signals device-version drift;
- ``execute_fail_mode``: the device explicitly rejects the action
  (operation_failed);
- ``execute_ambiguous_mode``: the connection drops before the device can
  confirm whether the action executed (ok=False + ambiguous_result — §7:
  连接中断且无法确认是否执行 -> 禁止重放，进入待核验);
- ``execute_timeout_mode``: the device call times out after ~1 s
  (AdapterTimeoutError — worker wiring in M2T6 decides the outcome);
- ``ambiguous_mode``: the action is accepted but the connection drops before
  any verifiable result (disconnected, no job id) so verification turns
  ambiguous -> verification_required;
- ``device_job_mode``: returns ``device_job_id=fake-job-1`` so verify polls
  the persisted job instead of re-creating it;
- ``verify_fail_mode`` / ``verify_ambiguous_mode``: read-back explicitly fails
  or cannot prove either outcome.

M2T6 fault injection (dev/test only, same connection_config pattern):
``slow_mode`` reports stepwise progress inside execute (progress-event
throttling tests); ``job_poll_rounds`` (int) makes ``verify_operation`` report
the persisted device job as ``pending`` for that many polls before a terminal
verdict (waiting_device + lease-renewal tests); ``job_poll_fail_mode`` turns
that final verdict into an explicit failure; ``crash_before_fence_mode`` /
``crash_after_fence_mode`` raise ``SimulatedWorkerCrash`` once per device from
preflight / execute to simulate a worker process dying before / after the
dispatch fence commit — the executor must never re-execute a fenced task.
"""

from __future__ import annotations

import datetime
import time

from app.domain.adapter import (
    AdapterError,
    AdapterTimeoutError,
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
    OperationProgress,
    OperationResult,
    PreflightResult,
    ProbeResult,
    ProbeStage,
    VerificationResult,
)
from app.domain.operation_plan import DeviceSnapshot, OperationPlan, OperationRequest, plan_operation
from app.generated.capabilities import REQUIREMENTS

FAIL_CREDENTIALS_KEY = "fail_credentials"
FAIL_TLS_KEY = "fail_tls"
FAILURE_MODE_KEY = "failure_mode"
PARTIAL_MODE_KEY = "partial_mode"
CRITICAL_MODE_KEY = "critical_mode"
NO_DATA_MODE_KEY = "no_data_mode"

FAIL_PREFLIGHT_MODE_KEY = "fail_preflight_mode"
STALE_PREFLIGHT_MODE_KEY = "stale_preflight_mode"
EXECUTE_FAIL_MODE_KEY = "execute_fail_mode"
EXECUTE_AMBIGUOUS_MODE_KEY = "execute_ambiguous_mode"
EXECUTE_TIMEOUT_MODE_KEY = "execute_timeout_mode"
AMBIGUOUS_MODE_KEY = "ambiguous_mode"
DEVICE_JOB_MODE_KEY = "device_job_mode"
VERIFY_FAIL_MODE_KEY = "verify_fail_mode"
VERIFY_AMBIGUOUS_MODE_KEY = "verify_ambiguous_mode"
# M2T6 fault injection (dev/test only).
SLOW_MODE_KEY = "slow_mode"
JOB_POLL_ROUNDS_KEY = "job_poll_rounds"
JOB_POLL_FAIL_MODE_KEY = "job_poll_fail_mode"
CRASH_BEFORE_FENCE_MODE_KEY = "crash_before_fence_mode"
CRASH_AFTER_FENCE_MODE_KEY = "crash_after_fence_mode"

FAILURE_CODES = ("network_unreachable", "authentication_failed", "protocol_error")

FAKE_DEVICE_JOB_ID = "fake-job-1"


class SimulatedWorkerCrash(RuntimeError):
    """Dev/test-only worker-crash injection (M2T6).

    Raised by the fake adapter at a configured point (preflight =
    crash_before_fence_mode, execute = crash_after_fence_mode) to simulate the
    worker process dying. The executor lets it propagate (a real process
    crash has no exception handler), the pool releases the lease, and the
    maintenance recovery decides per the dispatch fence. Each mode fires ONCE
    per device so the test can then observe the recovery/verify path running
    to completion against the same device.
    """

    def __init__(self, stage: str) -> None:
        super().__init__(f"SimulatedWorkerCrash at {stage} (dev/test fault injection)")
        self.stage = stage


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

    def __init__(self) -> None:
        # Per-device fault-injection state (dev/test only). Keyed by device id
        # so the module-level singleton never leaks a fired crash/poll across
        # tests (every test recreates the database with fresh device ids).
        self._crashed_preflight: set[str] = set()
        self._crashed_execute: set[str] = set()
        self._job_poll_calls: dict[str, int] = {}

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
            # M2T4 operation-flow modes (dev/test only): preflight/execute/
            # verify behavior injection for the two-phase operation tests.
            FAIL_PREFLIGHT_MODE_KEY: {"type": "boolean"},
            STALE_PREFLIGHT_MODE_KEY: {"type": "boolean"},
            EXECUTE_FAIL_MODE_KEY: {"type": "boolean"},
            EXECUTE_AMBIGUOUS_MODE_KEY: {"type": "boolean"},
            EXECUTE_TIMEOUT_MODE_KEY: {"type": "boolean"},
            AMBIGUOUS_MODE_KEY: {"type": "boolean"},
            DEVICE_JOB_MODE_KEY: {"type": "boolean"},
            VERIFY_FAIL_MODE_KEY: {"type": "boolean"},
            VERIFY_AMBIGUOUS_MODE_KEY: {"type": "boolean"},
            # M2T6 fault-injection modes (dev/test only).
            SLOW_MODE_KEY: {"type": "boolean"},
            JOB_POLL_ROUNDS_KEY: {"type": "integer", "minimum": 0, "maximum": 50},
            JOB_POLL_FAIL_MODE_KEY: {"type": "boolean"},
            CRASH_BEFORE_FENCE_MODE_KEY: {"type": "boolean"},
            CRASH_AFTER_FENCE_MODE_KEY: {"type": "boolean"},
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

    def plan_operation(self, snapshot: DeviceSnapshot, request: OperationRequest) -> OperationPlan:
        """Mirror the shared domain planner (DEVICE_ADAPTERS.md §2.4).

        Planning semantics come from contracts/operations.json via the
        generated registry; the fake adds nothing of its own — real adapters
        override planning only when vendor specifics must feed the plan.
        """
        return plan_operation(snapshot, request)

    def preflight_operation(self, session: DeviceSession, plan: OperationPlan) -> PreflightResult:
        """Real-time read-only preflight (DEVICE_ADAPTERS.md §2.4).

        Success by default; ``fail_preflight_mode`` rejects with
        validation_failed, ``stale_preflight_mode`` signals device-version
        drift so the worker fails the task as preview_stale.
        ``crash_before_fence_mode`` fires ONCE per device from here: the
        simulated worker death happens before the dispatch fence is
        committed, so recovery may requeue the task (M2T6).
        """
        del plan
        config = session.connection_config
        device_key = str(session.device_id)
        if config.get(CRASH_BEFORE_FENCE_MODE_KEY) and device_key not in self._crashed_preflight:
            self._crashed_preflight.add(device_key)
            raise SimulatedWorkerCrash("preflight (crash_before_fence_mode)")
        if config.get(STALE_PREFLIGHT_MODE_KEY):
            return PreflightResult(
                ok=False,
                error_code="preview_stale",
                detail="stale_preflight_mode：设备版本与计划不一致",
                stale=True,
            )
        if config.get(FAIL_PREFLIGHT_MODE_KEY):
            return PreflightResult(
                ok=False,
                error_code="validation_failed",
                detail="fail_preflight_mode：实时前置检查未通过",
            )
        return PreflightResult(ok=True)

    def execute_operation(
        self,
        session: DeviceSession,
        plan: OperationPlan,
        progress: OperationProgress,
    ) -> OperationResult:
        """Simulated device-side execution (DEVICE_ADAPTERS.md §4.2/§9).

        Success by default with device-side evidence. Mode flags:
        execute_fail_mode -> explicit device failure (operation_failed);
        execute_ambiguous_mode -> the connection dropped before the device
        confirmed the action: ok=False + ambiguous_result (DEVICE_ADAPTERS.md
        §7 — 连接中断且无法确认是否执行：禁止重放，进入待核验);
        execute_timeout_mode -> AdapterTimeoutError after ~1 s;
        ambiguous_mode -> accepted but unverifiable (disconnected, no job);
        device_job_mode -> returns the persisted vendor job id (fake-job-1);
        slow_mode -> stepwise progress callbacks across ~1 s (throttling
        tests); crash_after_fence_mode fires ONCE per device from here — the
        simulated worker death happens AFTER the dispatch fence was
        committed, so recovery may only verify/read-back, never re-execute
        (M2T6).
        """
        del plan
        config = session.connection_config
        device_key = str(session.device_id)
        if config.get(CRASH_AFTER_FENCE_MODE_KEY) and device_key not in self._crashed_execute:
            self._crashed_execute.add(device_key)
            raise SimulatedWorkerCrash("execute (crash_after_fence_mode)")
        if config.get(EXECUTE_TIMEOUT_MODE_KEY):
            time.sleep(1.0)
            raise AdapterTimeoutError("execute_timeout_mode：模拟设备调用超时")
        if config.get(SLOW_MODE_KEY):
            for percent in (20, 40, 60, 80):
                progress(percent, f"模拟执行中（{percent}%）")
                time.sleep(0.25)
        if config.get(AMBIGUOUS_MODE_KEY):
            progress(50, "模拟命令已被设备接受，连接随后中断")
            return OperationResult(
                ok=True,
                evidence={"command": "fake-accepted", "mode": "ambiguous"},
                disconnected=True,
            )
        if config.get(DEVICE_JOB_MODE_KEY):
            progress(60, "设备已接受并创建异步作业")
            return OperationResult(
                ok=True,
                evidence={"command": "fake-ok", "job": FAKE_DEVICE_JOB_ID},
                device_job_id=FAKE_DEVICE_JOB_ID,
            )
        if config.get(EXECUTE_AMBIGUOUS_MODE_KEY):
            return OperationResult(
                ok=False,
                error_code="ambiguous_result",
                error_detail="execute_ambiguous_mode：连接中断且无法确认设备是否已执行",
                evidence={"command": "fake-unknown", "mode": "execute_ambiguous"},
            )
        if config.get(EXECUTE_FAIL_MODE_KEY):
            return OperationResult(
                ok=False,
                error_code="operation_failed",
                error_detail="execute_fail_mode：设备明确拒绝该操作",
                evidence={"command": "fake-fail"},
            )
        progress(100, "模拟执行完成")
        return OperationResult(ok=True, evidence={"command": "fake-ok"})

    def verify_operation(
        self,
        session: DeviceSession,
        plan: OperationPlan,
        result: OperationResult | None,
    ) -> VerificationResult:
        """Simulated read-back verification (DEVICE_ADAPTERS.md §4.2/§9).

        Reports success by default for every verification strategy (the fake
        device always confirms). Modes: verify_fail_mode -> explicit failed
        read-back; verify_ambiguous_mode -> neither outcome provable.

        Job polling (M2T6): when a device job id is present (persisted before
        polling) and ``job_poll_rounds`` > 0, the first N polls report
        ``pending`` (the job is still running — the worker stays in
        waiting_device and keeps renewing its lease); poll N+1 returns the
        terminal verdict (success by default, explicit failure under
        ``job_poll_fail_mode``). Poll counters are per device so the shared
        registry instance stays deterministic per test database.
        """
        config = session.connection_config
        job = result.device_job_id if result is not None else None
        if job is not None:
            rounds_value = config.get(JOB_POLL_ROUNDS_KEY) or 0
            rounds = rounds_value if isinstance(rounds_value, int) else 0
            if rounds > 0:
                device_key = str(session.device_id)
                poll_number = self._job_poll_calls.get(device_key, 0)
                self._job_poll_calls[device_key] = poll_number + 1
                if poll_number < rounds:
                    return VerificationResult(
                        succeeded=False,
                        pending=True,
                        evidence={
                            "job_status": "running",
                            "device_job_id": job,
                            "poll": poll_number + 1,
                            "rounds": rounds,
                        },
                    )
                if config.get(JOB_POLL_FAIL_MODE_KEY):
                    return VerificationResult(
                        succeeded=False,
                        evidence={
                            "job_status": "failed",
                            "mode": "job_poll_fail",
                            "device_job_id": job,
                        },
                        error_code="operation_failed",
                    )
        if config.get(VERIFY_AMBIGUOUS_MODE_KEY):
            return VerificationResult(
                succeeded=False,
                ambiguous=True,
                evidence={"mode": "verify_ambiguous", "strategy": plan.verification_strategy},
                error_code="ambiguous_result",
            )
        if config.get(VERIFY_FAIL_MODE_KEY):
            return VerificationResult(
                succeeded=False,
                evidence={"mode": "verify_fail", "strategy": plan.verification_strategy},
                error_code="operation_failed",
            )
        strategy = plan.verification_strategy
        return VerificationResult(
            succeeded=True,
            evidence={
                "mode": "verify_ok",
                "strategy": strategy,
                "device_job_id": job or (FAKE_DEVICE_JOB_ID if config.get(DEVICE_JOB_MODE_KEY) else None),
            },
        )

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
