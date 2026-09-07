"""Warden 0.1.0 bounded load-SMOKE benchmark (M6T4, pytest-free).

Synthetic smoke through the REAL platform stack — real PostgreSQL 18, a real
uvicorn API process and a real worker process — against five TEST-DEVICE
simulators bound to the machine's LAN IP (the platform's SSRF policy denies
loopback, so the simulators sit on the management network like real devices):

- 2 Redfish server simulators (Dell + Inspur healthy profiles, HTTP);
- 1 Synology DSM simulator (DS224+ healthy profile, HTTP);
- 2 Huawei switch SNMP agents (core S5732-H48XUM2CC 48GE+4XGE and access
  S5735-L48P4S-A1 48GE profiles, SNMPv3 over UDP).

Scenario (bounded window, default collection intervals 30/60/120 s):
onboarding through the real HTTP API, then ``--readers`` simulated concurrent
users read overview/devices/metrics-latest/metrics-series/alerts for the
whole window while the worker collects at the default cadence.

Measured: API read latency percentiles (the P95<500ms / P99<1s gates of
docs/TEST_STRATEGY.md §5 apply to the SITE acceptance run — this smoke is
synthetic and carries NO capacity promise, ADR-027), collection claim
latency P95, scheduler tick delay, queue depths and DB growth.

Output: a JSON report (``--report``), defaulting to
``deployment/release/load-smoke-<date>.json``.

Usage (repo venv, backend/ as CWD):
    python tests/performance/load_smoke.py [--window-seconds 600]
                                           [--readers 3]
                                           [--sim-host <lan-ip>]
                                           [--keep-db]

Requirements: the local Warden test PostgreSQL 18 on 127.0.0.1:55433 (role
``warden``, no password — the repo test DSN) and the venv deps (psycopg,
httpx, uvicorn, pysnmp, asyncssh are all lockfile dependencies).

Honesty notes (binding):
- simulators are tests/simulators TEST-DEVICE fixtures — this run is NOT a
  site acceptance run and never hardware evidence;
- every simulator is bound to the LAN management IP and passes the real
  SSRF policy + port whitelists (no monkeypatching anywhere);
- failures are recorded, never retried into success.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime
import gc
import ipaddress
import json
import os
import platform
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx
import psycopg
import uvicorn

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.infrastructure.time import utcnow  # noqa: E402
from tests.simulators.dsm.app import create_simulator as create_dsm_simulator  # noqa: E402
from tests.simulators.dsm.payloads import SimulatorConfig as DsmSimulatorConfig  # noqa: E402
from tests.simulators.redfish.app import SimulatorConfig as RedfishSimulatorConfig  # noqa: E402
from tests.simulators.redfish.app import create_simulator as create_redfish_simulator  # noqa: E402
from tests.simulators.switch.agent import AgentConfig as SwitchAgentConfig  # noqa: E402
from tests.simulators.switch.agent import AgentCredential, SwitchAgent  # noqa: E402
from tests.simulators.switch.profiles import profile_by_key  # noqa: E402

# ---- scenario constants ----------------------------------------------------

API_V1 = "/api/v1"
DEFAULT_PG_DSN = "postgresql://warden@127.0.0.1:55433/postgres"
SMOKE_DB = "warden_smoke"

# Simulator credentials are TEST-DEVICE fixtures (tests/ ignore S105/S106):
# never real-device credentials, never secrets of this platform.
SIM_USERNAME = "admin"
SIM_PASSWORD = "sim-pass-1"
V3_USERNAME = "monitor"
V3_AUTH_KEY = "sim-auth-key-1"
V3_PRIV_KEY = "sim-priv-key-1"

BOOTSTRAP_USERNAME = "smoke-admin"
BOOTSTRAP_PASSWORD = "Boot!strap-2026-Tmp1"
ADMIN_PASSWORD = "Adm!n-2026-StrongPass"
READER_PASSWORD = "Rd!r-2026-Strong-1"

# HTTP ports must sit inside the adapter protocol whitelists the SSRF policy
# enforces at probe time (http: {80,8080,8000}; switch probes resolve under
# the default https profile => {443,8443}): simulators bind real sockets on
# these management ports, exactly like a real device would.
SIM_PORTS = {"srv_dell": 8000, "srv_inspur": 8080, "dsm": 80, "sw_core": 8443, "sw_access": 443}

SIM_DEVICES = (
    {
        "key": "srv_dell",
        "name": "smoke-srv-dell",
        "device_type": "server",
        "adapter_key": "server.dell_idrac",
        "vendor_profile": "dell",
        "kind": "redfish",
    },
    {
        "key": "srv_inspur",
        "name": "smoke-srv-inspur",
        "device_type": "server",
        "adapter_key": "server.inspur_ibmc",
        "vendor_profile": "inspur",
        "kind": "redfish",
    },
    {
        "key": "dsm",
        "name": "smoke-nas-ds224",
        "device_type": "synology_nas",
        "adapter_key": "nas.synology_dsm",
        "vendor_profile": "ds224",
        "kind": "dsm",
    },
    {
        "key": "sw_core",
        "name": "smoke-sw-core-s5732",
        "device_type": "core_switch",
        "adapter_key": "switch.huawei_vrp_core",
        "vendor_profile": "core_s5732",
        "kind": "switch",
    },
    {
        "key": "sw_access",
        "name": "smoke-sw-access-s5735",
        "device_type": "access_switch",
        "adapter_key": "switch.huawei_vrp_access",
        "vendor_profile": "access_s5735",
        "kind": "switch",
    },
)

# Reader workload shape: per tick a reader issues the platform read surface a
# real user opens; pacing is per-tick seconds with a small jitter.
READ_TICK_SECONDS = 4.0
READ_JITTER_SECONDS = 1.5
SERIES_EVERY_N_TICKS = 2

# DB sampling cadence during the window (queue depth / size curve).
SAMPLE_INTERVAL_SECONDS = 15.0

SITE_GATE_NOTE = (
    "合成负载冒烟，不是现场验收运行：无任何容量承诺（ADR-027）；"
    "docs/TEST_STRATEGY.md §5 的 P95<500ms/P99<1s 读取门槛与调度 P95<10s 门槛"
    "只在现场按验收负载清单执行的验收运行上生效。"
)

_FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}={0,2}")


# ---- helpers ---------------------------------------------------------------


def detect_lan_ip() -> str:
    """Best-effort LAN IPv4 for the management NIC (UDP connect sends nothing)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))  # TEST-NET-1: never routed, no packets sent
        return str(probe.getsockname()[0])


def port_free(host: str, port: int, *, udp: bool = False) -> bool:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
            return True
        except OSError:
            return False


def json_now() -> str:
    return utcnow().isoformat()


# ---- simulator hosting (in-process threads; real sockets on the LAN IP) ----


class SimulatorHost:
    """One booted TEST-DEVICE simulator with a stable identity."""

    def __init__(
        self,
        key: str,
        kind: str,
        vendor_profile: str,
        host: str,
        port: int,
        *,
        agent: SwitchAgent | None = None,
    ) -> None:
        self.key = key
        self.kind = kind
        self.vendor_profile = vendor_profile
        self.host = host
        self.port = port
        self.agent = agent
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._failures: list[BaseException] = []
        self._server: uvicorn.Server | None = None

    @property
    def management_endpoint(self) -> str:
        return self.host

    def start(self) -> None:
        if self.kind == "switch":
            assert self.agent is not None
            self._start_agent(self.agent)
            return
        if self.kind == "redfish":
            app = create_redfish_simulator(RedfishSimulatorConfig(profile="healthy", vendor=self.vendor_profile))
        elif self.kind == "dsm":
            app = create_dsm_simulator(DsmSimulatorConfig(profile="healthy"))
        else:  # pragma: no cover - guarded by the caller
            raise ValueError(f"unknown simulator kind {self.kind!r}")
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=self.host,
                port=self.port,
                log_level="warning",
                access_log=False,
                timeout_keep_alive=1,
            )
        )
        self._thread = threading.Thread(target=self._server.run, name=f"sim-{self.key}", daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 20.0
        while not getattr(self._server, "started", False) and time.monotonic() < deadline:
            if not self._thread.is_alive():
                raise RuntimeError(f"simulator {self.key} thread exited before startup")
            time.sleep(0.02)
        if not getattr(self._server, "started", False):
            raise RuntimeError(f"simulator {self.key} did not start in time")

    def _start_agent(self, agent: SwitchAgent) -> None:
        ready = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stop_event = asyncio.Event()
            self._loop = loop
            self._stop_event = stop_event

            async def serve() -> None:
                await agent.start()
                ready.set()
                await stop_event.wait()
                await agent.stop()

            try:
                loop.run_until_complete(serve())
            except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
                self._failures.append(exc)
                ready.set()
            finally:
                with contextlib.suppress(BaseException):  # noqa: S110 - best-effort teardown
                    loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()

        self._thread = threading.Thread(target=run, name=f"sim-{self.key}", daemon=True)
        self._thread.start()
        if not ready.wait(20.0):
            raise RuntimeError(f"switch simulator {self.key} did not start: {self._failures[:1]}")
        if self._failures:
            raise RuntimeError(f"switch simulator {self.key} failed to start: {self._failures[0]!r}")
        bound = agent.port
        if bound is None or bound != self.port:
            raise RuntimeError(f"switch simulator {self.key} bound {bound}, wanted {self.port}")

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        elif self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=20.0)
            self._thread = None
        gc.collect()


def boot_simulators(host: str) -> list[SimulatorHost]:
    """Boot every scenario simulator on the management IP; caller stops them."""
    hosts: list[SimulatorHost] = []
    try:
        for spec in SIM_DEVICES:
            key = str(spec["key"])
            port = SIM_PORTS[key]
            kind = str(spec["kind"])
            if kind == "switch":
                profile = profile_by_key(str(spec["vendor_profile"]))
                agent = SwitchAgent(
                    SwitchAgentConfig(
                        profile=profile,
                        host=host,
                        port=port,
                        v3_user=AgentCredential(username=V3_USERNAME, auth_key=V3_AUTH_KEY, privacy_key=V3_PRIV_KEY),
                    )
                )
                sim = SimulatorHost(key, kind, str(spec["vendor_profile"]), host, port, agent=agent)
            else:
                sim = SimulatorHost(key, kind, str(spec["vendor_profile"]), host, port)
            sim.start()
            hosts.append(sim)
        return hosts
    except BaseException:
        for sim in hosts:
            sim.stop()
        raise


# ---- PostgreSQL plumbing ---------------------------------------------------


def pg_connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, connect_timeout=5)


def recreate_database(maintenance_dsn: str, db_name: str) -> None:
    with pg_connect(maintenance_dsn) as conn:
        conn.autocommit = True
        conn.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{db_name}"')


def drop_database(maintenance_dsn: str, db_name: str) -> None:
    with pg_connect(maintenance_dsn) as conn:
        conn.autocommit = True
        conn.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')


def run_alembic_upgrade(db_dsn: str) -> None:
    env = os.environ.copy()
    env["WARDEN_POSTGRES_DSN"] = db_dsn
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(BACKEND_DIR),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"alembic upgrade head failed\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )


def run_bootstrap_admin(db_dsn: str, username: str, password: str) -> None:
    env = os.environ.copy()
    env["WARDEN_POSTGRES_DSN"] = db_dsn
    env["WARDEN_BOOTSTRAP_ADMIN_PASSWORD"] = password
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "app.tools.bootstrap_admin", "--username", username],
        cwd=str(BACKEND_DIR),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"bootstrap_admin failed\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}")


def _env_for(db_dsn: str, secret_dir: Path, api_port: int, sim_host: str) -> dict[str, str]:
    env = os.environ.copy()
    env["WARDEN_POSTGRES_DSN"] = db_dsn
    env["WARDEN_APP_ENV"] = "development"
    env["WARDEN_PUBLIC_URL"] = f"http://127.0.0.1:{api_port}"
    env["WARDEN_ALLOWED_DEVICE_CIDRS"] = f"{sim_host}/32"
    env["WARDEN_CREDENTIAL_MASTER_KEY_FILE"] = str(secret_dir / "credential_master.key")
    env["WARDEN_FILE_MASTER_KEY_FILE"] = str(secret_dir / "file_master.key")
    env["WARDEN_SESSION_SECRET_FILE"] = str(secret_dir / "session_secret.txt")
    env["WARDEN_CSRF_SECRET_FILE"] = str(secret_dir / "csrf_secret.txt")
    return env


def write_secret_files(secret_dir: Path) -> None:
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "credential_master.key").write_text("K" * 64, encoding="utf-8")
    (secret_dir / "file_master.key").write_text("F" * 64, encoding="utf-8")
    (secret_dir / "session_secret.txt").write_text("S" * 64, encoding="utf-8")
    (secret_dir / "csrf_secret.txt").write_text("C" * 64, encoding="utf-8")


def spawn_platform_process(argv: Sequence[str], env: dict[str, str], log_path: Path, tag: str) -> subprocess.Popen[str]:
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(  # noqa: S603
            argv,
            cwd=str(BACKEND_DIR),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
    print(f"[smoke] {tag} pid={process.pid} log={log_path}")
    return process


def wait_for_api(api_base: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=api_base, timeout=3.0) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get("/health/ready")
            except httpx.HTTPError:
                time.sleep(0.5)
                continue
            if response.status_code == 200:
                return
            time.sleep(0.5)
    raise RuntimeError(f"API at {api_base} did not become ready within {timeout}s")


# ---- SQL snapshots ---------------------------------------------------------

TABLES_TO_TRACK = (
    "collection_runs",
    "components",
    "device_events",
    "metric_latest",
    "metric_points",
    "metric_rollups_5m",
    "audit_logs",
    "operation_tasks",
    "alerts",
    "ui_events",
    "sessions",
    "users",
    "files",
)


@dataclass
class DbSnapshot:
    taken_at: str
    database_bytes: int
    table_counts: dict[str, int]
    collection_states: dict[str, int]
    operation_states: dict[str, int]
    oldest_scheduled_age_seconds: float | None
    partitions: int

    def to_dict(self) -> dict[str, object]:
        return {
            "taken_at": self.taken_at,
            "database_bytes": self.database_bytes,
            "table_counts": self.table_counts,
            "collection_run_states": self.collection_states,
            "operation_task_states": self.operation_states,
            "oldest_scheduled_age_seconds": self.oldest_scheduled_age_seconds,
            "metric_points_partitions": self.partitions,
        }


def take_snapshot(db_dsn: str, db_name: str) -> DbSnapshot:
    with pg_connect(db_dsn) as conn:
        counts: dict[str, int] = {}
        for table in TABLES_TO_TRACK:
            # Table names come only from the module constant TABLES_TO_TRACK.
            with conn.cursor() as cursor:  # noqa: SIM117
                cursor.execute(f'SELECT count(*) FROM "{table}"')  # noqa: S608
                counts[table] = int(cursor.fetchone()[0])
        with conn.cursor() as cursor:  # noqa: SIM117
            cursor.execute("SELECT pg_database_size(%s)", (db_name,))
            database_bytes = int(cursor.fetchone()[0])
        collection_states = _state_counts(conn, "collection_runs")
        operation_states = _state_counts(conn, "operation_tasks")
        with conn.cursor() as cursor:  # noqa: SIM117
            cursor.execute(
                "SELECT extract(epoch FROM (now() - min(scheduled_at))) "
                "FROM collection_runs WHERE state IN ('scheduled', 'running')"
            )
            row = cursor.fetchone()
            oldest = float(row[0]) if row is not None and row[0] is not None else None
            cursor.execute(
                "SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relname LIKE 'metric_points%' "
                "AND c.relkind = 'r' AND c.relispartition"
            )
            partitions = int(cursor.fetchone()[0])
    return DbSnapshot(
        taken_at=json_now(),
        database_bytes=database_bytes,
        table_counts=counts,
        collection_states=collection_states,
        operation_states=operation_states,
        oldest_scheduled_age_seconds=oldest,
        partitions=partitions,
    )


def _state_counts(conn: psycopg.Connection, table: str) -> dict[str, int]:
    # Table names come only from module constants ("collection_runs"/"operation_tasks").
    with conn.cursor() as cursor:  # noqa: SIM117
        cursor.execute(f'SELECT state, count(*) FROM "{table}" GROUP BY state ORDER BY state')  # noqa: S608
        return {str(state): int(count) for state, count in cursor.fetchall()}


def fetch_claim_latencies(db_dsn: str, window_start: datetime.datetime) -> list[tuple[str, float]]:
    """(collection_type, seconds) for runs started inside the measurement window.

    Claim latency = started_at - scheduled_at: the full time a run waited for
    a worker to claim it after the scheduler made it due.
    """
    with pg_connect(db_dsn) as conn, conn.cursor() as cursor:
        cursor.execute(
            "SELECT collection_type, "
            "extract(epoch FROM (started_at - scheduled_at)) "
            "FROM collection_runs WHERE started_at >= %s AND state IN "
            "('succeeded', 'partial', 'failed', 'cancelled')",
            (window_start,),
        )
        return [(str(row[0]), float(row[1])) for row in cursor.fetchall()]


def fetch_schedule_gaps(
    db_dsn: str, interval_by_type: dict[str, float], window_start: datetime.datetime
) -> list[float]:
    """Seconds a run's creation lagged behind its interval grid.

    Per (device, type) the gap between two consecutive scheduled_at stamps
    minus the configured interval: positive values are scheduler-tick delay
    the next collection had to wait past its due instant.
    """
    with pg_connect(db_dsn) as conn, conn.cursor() as cursor:
        cursor.execute(
            "SELECT device_id, collection_type, scheduled_at FROM collection_runs "
            "WHERE scheduled_at >= %s ORDER BY device_id, collection_type, scheduled_at",
            (window_start,),
        )
        rows = cursor.fetchall()
    gaps: list[float] = []
    previous: dict[tuple[uuid.UUID, str], datetime.datetime] = {}
    for device_id, collection_type, scheduled_at in rows:
        key = (device_id, str(collection_type))
        interval = interval_by_type.get(str(collection_type))
        if interval is None:
            previous.pop(key, None)
            continue
        prior = previous.get(key)
        if prior is not None:
            gap = (scheduled_at - prior).total_seconds() - interval
            if gap > 0:
                gaps.append(gap)
        previous[key] = scheduled_at
    return gaps


def percentile(values: Sequence[float], ratio: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * ratio))
    return float(ordered[index])


def latency_stats(values: Sequence[float]) -> dict[str, float | None]:
    if not values:
        return {"count": 0, "p50": None, "p95": None, "p99": None, "max_ms": None}
    return {
        "count": len(values),
        "p50_ms": round(float(statistics.median(values)) * 1000.0, 1),
        "p95_ms": round((percentile(values, 0.95) or 0.0) * 1000.0, 1),
        "p99_ms": round((percentile(values, 0.99) or 0.0) * 1000.0, 1),
        "max_ms": round(max(values) * 1000.0, 1),
    }


# ---- HTTP client helpers ---------------------------------------------------


@dataclass
class Session:
    """One authenticated user session against the real API."""

    client: httpx.Client
    username: str
    csrf_token: str = ""

    def headers(self, *, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {} if extra is None else dict(extra)
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        return headers

    def post(self, path: str, json: dict[str, object]) -> httpx.Response:
        return self.client.post(path, json=json, headers=self.headers())

    def login(self, password: str) -> httpx.Response:
        response = self.post(f"{API_V1}/auth/login", {"username": self.username, "password": password})
        if response.status_code == 200:
            self.csrf_token = str(response.json().get("csrf_token", ""))
        return response


# ---- API flows -------------------------------------------------------------


def change_admin_password(admin: Session) -> None:
    response = admin.post(
        f"{API_V1}/auth/password",
        {"current_password": BOOTSTRAP_PASSWORD, "new_password": ADMIN_PASSWORD},
    )
    if response.status_code != 200:
        raise RuntimeError(f"admin password change failed: {response.status_code} {response.text[:300]}")


def change_password(session: Session, current_password: str, new_password: str) -> None:
    """First-login password change (users_create forces must_change_password)."""
    response = session.post(
        f"{API_V1}/auth/password",
        {"current_password": current_password, "new_password": new_password},
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"password change for {session.username} failed: {response.status_code} {response.text[:300]}"
        )


def create_user(admin: Session, username: str, password: str, role: str) -> None:
    response = admin.post(
        f"{API_V1}/users",
        {"username": username, "display_name": username, "role": role, "password": password},
    )
    if response.status_code != 201:
        raise RuntimeError(f"create user {username} failed: {response.status_code} {response.text[:300]}")


def probe_payload_for(spec: dict[str, object], sim: SimulatorHost) -> dict[str, object]:
    """The exact onboarding probe body per device kind (real SSRF policy path)."""
    kind = str(spec["kind"])
    base: dict[str, object] = {
        "device_type": str(spec["device_type"]),
        "adapter_key": str(spec["adapter_key"]),
        "management_endpoint": sim.management_endpoint,
    }
    if kind == "switch":
        base["connection_config"] = {"snmp_version": "v3", "port": sim.port}
        base["credentials"] = {"snmp": {"username": V3_USERNAME, "auth_key": V3_AUTH_KEY, "privacy_key": V3_PRIV_KEY}}
    else:
        base["port"] = sim.port
        base["connection_config"] = {"protocol": "http"}
        base["credentials"] = {"username": SIM_USERNAME, "password": SIM_PASSWORD}
    return base


def onboard_device(
    admin: Session,
    spec: dict[str, object],
    sim: SimulatorHost,
) -> dict[str, object]:
    """Probe (staged, real policy) then save the device; returns the view."""
    body = probe_payload_for(spec, sim)
    probe = admin.post(f"{API_V1}/device-probes", body)
    if probe.status_code != 200:
        raise RuntimeError(f"probe {spec['key']} http {probe.status_code}: {probe.text[:400]}")
    result = probe.json()
    if not result.get("ok"):
        stages = " | ".join(
            f"{stage.get('stage')}={stage.get('ok')}:{stage.get('error_code')}" for stage in result.get("stages", [])
        )
        raise RuntimeError(f"probe {spec['key']} not ok: {stages} {result.get('discovery')}")
    create_body: dict[str, object] = {
        "name": str(spec["name"]),
        "device_type": str(spec["device_type"]),
        "adapter_key": str(spec["adapter_key"]),
        "management_endpoint": sim.management_endpoint,
        "connection_config": body["connection_config"],
        "credentials": body["credentials"],
        "enabled": True,
        "probe_token": str(result["probe_token"]),
    }
    if str(spec["kind"]) != "switch":
        create_body["port"] = sim.port
    created = admin.post(f"{API_V1}/devices", create_body)
    if created.status_code != 201:
        raise RuntimeError(f"create {spec['key']} http {created.status_code}: {created.text[:400]}")
    return created.json()


def wait_all_collected(db_dsn: str, device_ids: Sequence[str], timeout: float = 300.0) -> None:
    """Wait until every device has at least two succeeded metrics collection runs."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with pg_connect(db_dsn) as conn, conn.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM collection_runs WHERE state = 'succeeded' AND collection_type = 'metrics'"
            )
            succeeded = int(cursor.fetchone()[0])
        if succeeded >= len(device_ids) * 2:
            return
        time.sleep(5.0)
    raise RuntimeError(
        f"devices did not complete 2 metrics collections within {timeout}s (succeeded metrics runs: {succeeded})"
    )


def fetch_series_targets(db_dsn: str, device_ids: Sequence[str]) -> list[tuple[str, str, str | None]]:
    """One (device_id, metric_key, component_id) series target per device.

    Picks a metric_latest row with a non-null value per device so the
    metrics/series reads always query a key the device really produces.
    """
    targets: list[tuple[str, str, str | None]] = []
    with pg_connect(db_dsn) as conn, conn.cursor() as cursor:
        for device_id in device_ids:
            cursor.execute(
                "SELECT metric_key, component_id FROM metric_latest "
                "WHERE device_id = %s AND value_double IS NOT NULL "
                "ORDER BY component_id NULLS LAST, metric_key LIMIT 1",
                (device_id,),
            )
            row = cursor.fetchone()
            if row is None:
                continue
            component_id = str(row[1]) if row[1] is not None else None
            targets.append((device_id, str(row[0]), component_id))
    return targets


# ---- reader workload -------------------------------------------------------


class ReaderLoad:
    """One simulated concurrent user reading the platform surface."""

    def __init__(
        self,
        session: Session,
        device_ids: list[str],
        series_targets: list[tuple[str, str, str | None]],
    ) -> None:
        self.session = session
        self.device_ids = device_ids
        self.series_targets = series_targets
        self.latencies: dict[str, list[float]] = {}
        self.http_status: Counter[str] = Counter()
        self.requests = 0

    def _get(self, label: str, path: str) -> httpx.Response:
        started = time.monotonic()
        try:
            response = self.session.client.get(path)
        except httpx.HTTPError as exc:
            self.latencies.setdefault(label, []).append(time.monotonic() - started)
            self.http_status[f"{label} http_error"] += 1
            self.requests += 1
            raise RuntimeError(f"read failed {path}: {exc!r}") from exc
        self._record(label, response, time.monotonic() - started)
        return response

    def _record(self, label: str, response: httpx.Response, seconds: float) -> None:
        self.latencies.setdefault(label, []).append(seconds)
        self.http_status[f"{label} {response.status_code}"] += 1
        self.requests += 1

    def _series_call(self, tick_number: int) -> None:
        """One metrics/series read for a metric that exists on the device."""
        target = self.series_targets[tick_number % len(self.series_targets)]
        device_id, metric_key, component_id = target
        window_start = utcnow() - datetime.timedelta(minutes=15)
        params: dict[str, str] = {
            "metric": metric_key,
            "from": window_start.isoformat(),
            "to": utcnow().isoformat(),
        }
        if component_id is not None:
            params["component_id"] = component_id
        self._get("metrics_series", f"{API_V1}/devices/{device_id}/metrics/series?{urlencode(params)}")

    def tick(self, tick_number: int) -> None:
        device_id = self.device_ids[tick_number % len(self.device_ids)]
        self._get("overview", f"{API_V1}/overview")
        self._get("devices_list", f"{API_V1}/devices?page=1&page_size=20&sort=name")
        self._get("device_get", f"{API_V1}/devices/{device_id}")
        self._get("metrics_latest", f"{API_V1}/devices/{device_id}/metrics/latest?page_size=100")
        self._get("alerts_list", f"{API_V1}/alerts?status=active&page=1&page_size=50")
        if tick_number % SERIES_EVERY_N_TICKS == 0:
            self._series_call(tick_number)


def run_reader_load(stop_event: threading.Event, session: Session, log: ReaderLoad) -> None:
    del session
    tick = 0
    while not stop_event.is_set():
        tick += 1
        try:
            log.tick(tick)
        except RuntimeError:
            print("[smoke] reader hit a hard failure; marking window aborted")
            log.http_status["aborted"] = 1
            stop_event.set()
            return
        stop_event.wait(READ_TICK_SECONDS + (tick % 3) * READ_JITTER_SECONDS / 3.0)


def summarize_reader(log: ReaderLoad) -> dict[str, object]:
    overall: list[float] = []
    by_endpoint: dict[str, dict[str, object]] = {}
    for path, values in log.latencies.items():
        overall.extend(values)
        by_endpoint[path] = latency_stats(values)
    return {
        "requests": log.requests,
        "http_status_counts": dict(sorted(log.http_status.items())),
        "latency_ms_overall": latency_stats(overall),
        "by_endpoint": by_endpoint,
    }


# ---- window + sampling -----------------------------------------------------


def queue_sample(db_dsn: str) -> dict[str, object]:
    with pg_connect(db_dsn) as conn:
        scheduled_running = _state_counts(conn, "collection_runs")
        operation = _state_counts(conn, "operation_tasks")
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT extract(epoch FROM (now() - min(scheduled_at))) "
                "FROM collection_runs WHERE state IN ('scheduled', 'running')"
            )
            row = cursor.fetchone()
            oldest = float(row[0]) if row is not None and row[0] is not None else None
    active = sum(count for state, count in scheduled_running.items() if state in ("scheduled", "running"))
    return {
        "collection_active": active,
        "collection_by_state": scheduled_running,
        "operation_by_state": operation,
        "oldest_scheduled_age_seconds": oldest,
    }


def run_window(
    db_dsn: str,
    db_name: str,
    api_base: str,
    readers: list[tuple[Session, ReaderLoad]],
    device_ids: list[str],
    window_seconds: float,
) -> dict[str, object]:
    """Run the bounded measurement window; returns the full results block."""
    interval_by_type = {"reachability": 30.0, "health": 30.0, "metrics": 60.0, "logs": 120.0}
    start_snapshot = take_snapshot(db_dsn, db_name)
    window_start = utcnow()
    print(f"[smoke] window start {window_start.isoformat()} ({window_seconds}s)")

    stop_event = threading.Event()
    threads = [
        threading.Thread(
            target=run_reader_load,
            args=(stop_event, session, load),
            name=f"reader-{session.username}",
            daemon=True,
        )
        for session, load in readers
    ]
    for thread in threads:
        thread.start()

    samples: list[dict[str, object]] = []
    reader_stop = stop_event  # shared: a reader hard-failure aborts the window
    deadline = time.monotonic() + window_seconds
    while time.monotonic() < deadline and not reader_stop.is_set():
        sample = queue_sample(db_dsn)
        sample["taken_at"] = json_now()
        samples.append(sample)
        reader_stop.wait(SAMPLE_INTERVAL_SECONDS)

    aborted = reader_stop.is_set()
    for thread in threads:
        thread.join(timeout=10.0)
    window_end = utcnow()
    end_snapshot = take_snapshot(db_dsn, db_name)
    print(f"[smoke] window end {window_end.isoformat()} aborted={aborted}")

    collection_reads = fetch_claim_latencies(db_dsn, window_start)
    by_type: dict[str, list[float]] = {}
    for collection_type, latency in collection_reads:
        by_type.setdefault(collection_type, []).append(latency)
    claim: dict[str, object] = {"overall": latency_stats([v for _, v in collection_reads])}
    for collection_type, values in by_type.items():
        claim[collection_type] = latency_stats(values)
    schedule_gaps = fetch_schedule_gaps(db_dsn, interval_by_type, window_start)

    db_growth: dict[str, object] = {
        "database_bytes_start": start_snapshot.database_bytes,
        "database_bytes_end": end_snapshot.database_bytes,
        "delta_bytes": end_snapshot.database_bytes - start_snapshot.database_bytes,
    }
    table_growth: dict[str, dict[str, int]] = {}
    for table in TABLES_TO_TRACK:
        delta = end_snapshot.table_counts[table] - start_snapshot.table_counts[table]
        table_growth[table] = {
            "start": start_snapshot.table_counts[table],
            "end": end_snapshot.table_counts[table],
            "delta": delta,
        }
    db_growth["tables"] = table_growth

    queue: dict[str, object] = {
        "end_of_window": {
            "collection_run_states": end_snapshot.collection_states,
            "operation_task_states": end_snapshot.operation_states,
            "oldest_scheduled_age_seconds": end_snapshot.oldest_scheduled_age_seconds,
        },
        "max_collection_active": max((int(sample["collection_active"]) for sample in samples), default=0),
        "max_oldest_scheduled_age_seconds": max(
            (float(sample["oldest_scheduled_age_seconds"] or 0.0) for sample in samples), default=0.0
        ),
        "samples": samples[-20:],
    }

    runs = end_snapshot.collection_states
    return {
        "window_started_at": window_start.isoformat(),
        "window_ended_at": window_end.isoformat(),
        "aborted": aborted,
        "duration_seconds": round(window_end.timestamp() - window_start.timestamp(), 1),
        "collection": {
            "runs_measured": len(collection_reads),
            "claim_latency_seconds": claim,
            "scheduler_gap_delay_seconds": latency_stats(schedule_gaps),
            "states_at_window_end": runs,
        },
        "api_reads": {f"user-{i + 1}": summarize_reader(load) for i, (_session, load) in enumerate(readers)},
        "queue": queue,
        "db_growth": db_growth,
        "active_alerts_at_window_end": end_snapshot.table_counts.get("alerts", 0),
    }


# ---- worker log summary ----------------------------------------------------


def summarize_worker_log(log_path: Path) -> dict[str, object]:
    """Count worker-side handler failures from the structured JSON log.

    A collection run that raises inside the pool is released for recovery and
    never re-executed (its lease-expired row is parked and requeued by the
    maintenance loop, or replaced by the next scheduled run). Every such event
    is a real reliability observation and must land in the report.
    """
    if not log_path.exists():
        return {"log_missing": True}
    failed = 0
    error_samples: list[str] = []
    last_exception = ""
    for raw in log_path.read_text(encoding="utf-8").splitlines():
        if not raw.startswith("{"):
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        event = entry.get("event")
        if event == "handler_failed":
            failed += 1
            exception = str(entry.get("exception") or "")
            if exception and len(error_samples) < 3:
                error_samples.append(exception.splitlines()[0])
            if exception:
                last_exception = exception
    return {
        "handler_failed_count": failed,
        "sample_error_first_lines": error_samples,
        "last_exception_first_line": last_exception.splitlines()[0] if last_exception else None,
    }


# ---- main ------------------------------------------------------------------


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Warden bounded load smoke (synthetic, ADR-027).")
    parser.add_argument("--window-seconds", type=float, default=600.0)
    parser.add_argument("--readers", type=int, default=3)
    parser.add_argument("--sim-host", default="", help="LAN management IP for the simulators")
    parser.add_argument("--api-port", type=int, default=8765)
    parser.add_argument("--pg-dsn", default=DEFAULT_PG_DSN)
    parser.add_argument("--db-name", default=SMOKE_DB)
    parser.add_argument("--keep-db", action="store_true", help="keep the smoke database on exit")
    parser.add_argument(
        "--report",
        default=str(REPO_ROOT / "deployment" / "release" / "load-smoke-report.json"),
        help="JSON report output path",
    )
    parser.add_argument(
        "--work-dir",
        default=str(REPO_ROOT / ".warden-data" / "load-smoke"),
        help="scratch dir for logs/secrets (repo-gitignored)",
    )
    return parser.parse_args(argv)


def run(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    sim_host = args.sim_host or detect_lan_ip()
    try:
        ipaddress.ip_address(sim_host)
    except ValueError as exc:
        raise ValueError(f"--sim-host must be an IP literal, got {sim_host!r}") from exc
    if ipaddress.ip_address(sim_host).is_loopback:
        raise ValueError("--sim-host must not be loopback (the platform SSRF policy denies it)")
    for port in SIM_PORTS.values():
        udp = port in (443, 8443)
        if not port_free(sim_host, port, udp=udp):
            raise RuntimeError(f"simulator port {sim_host}:{port} is not free")
    if not port_free("127.0.0.1", args.api_port):
        raise RuntimeError(f"api port 127.0.0.1:{args.api_port} is not free")

    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    secret_dir = work_dir / "secrets"
    write_secret_files(secret_dir)
    log_dir = work_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    db_name = args.db_name
    smoke_dsn = f"{args.pg_dsn.rsplit('/', 1)[0]}/{db_name}"
    api_base = f"http://127.0.0.1:{args.api_port}"
    report: dict[str, object] = {
        "kind": "warden-load-smoke",
        "label": "合成负载冒烟（5 个测试模拟器设备；不是现场验收负载，ADR-027）",
        "site_gate_note": SITE_GATE_NOTE,
        "run": {
            "started_at": json_now(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "sim_host": sim_host,
            "window_seconds": args.window_seconds,
            "readers": args.readers,
        },
        "status": "running",
    }

    process_handles: list[subprocess.Popen[str]] = []
    simulators: list[SimulatorHost] = []
    try:
        print(f"[smoke] postgres dsn {smoke_dsn} sim-host {sim_host}")
        recreate_database(args.pg_dsn, db_name)
        run_alembic_upgrade(smoke_dsn)
        run_bootstrap_admin(smoke_dsn, BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD)
        print("[smoke] database migrated; admin bootstrapped")

        api_process = spawn_platform_process(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(args.api_port),
                "--log-level",
                "warning",
            ],
            _env_for(smoke_dsn, secret_dir, args.api_port, sim_host),
            log_dir / "api.log",
            "api",
        )
        process_handles.append(api_process)
        wait_for_api(api_base)
        print("[smoke] api ready")

        simulators = boot_simulators(sim_host)
        print("[smoke] simulators booted: " + ", ".join(f"{s.key}=:{s.port}" for s in simulators))
        time.sleep(2.0)

        worker_process = spawn_platform_process(
            [sys.executable, "-m", "app.workers.run"],
            _env_for(smoke_dsn, secret_dir, args.api_port, sim_host),
            log_dir / "worker.log",
            "worker",
        )
        process_handles.append(worker_process)
        # The worker is verified through its pipeline output: scheduler ticks
        # only create runs once devices exist, so readiness is checked by
        # ``wait_all_collected`` after onboarding below.
        time.sleep(5.0)

        sim_by_key = {sim.key: sim for sim in simulators}
        with httpx.Client(base_url=api_base, timeout=30.0) as client:
            admin = Session(client, BOOTSTRAP_USERNAME)
            login = admin.login(BOOTSTRAP_PASSWORD)
            if login.status_code != 200:
                raise RuntimeError(f"admin login failed: {login.status_code} {login.text[:300]}")
            change_admin_password(admin)
            print("[smoke] admin login + first-login password change ok")

            reader_sessions: list[Session] = []
            for index in range(args.readers):
                username = f"smoke-reader-{index + 1}"
                initial_password = f"Init!-2026-Rd-{index + 1}"
                create_user(admin, username, initial_password, "viewer")
                session = Session(httpx.Client(base_url=api_base, timeout=30.0), username)
                response = session.login(initial_password)
                if response.status_code != 200:
                    raise RuntimeError(f"reader {username} login failed: {response.status_code}")
                # users_create forces must_change_password=True (same gate the
                # bootstrap admin passes through): the reader changes it once
                # over the real API before the read workload starts.
                change_password(session, initial_password, READER_PASSWORD)
                reader_sessions.append(session)
                check = session.client.get(f"{API_V1}/overview")
                if check.status_code != 200:
                    raise RuntimeError(f"reader {username} access check failed: {check.status_code} {check.text[:300]}")

            device_ids: list[str] = []
            onboarded: list[dict[str, object]] = []
            for spec in SIM_DEVICES:
                sim = sim_by_key[str(spec["key"])]
                view = onboard_device(admin, spec, sim)
                device_ids.append(str(view["id"]))
                onboarded.append(
                    {
                        "name": view["name"],
                        "device_type": view["device_type"],
                        "adapter_key": view["adapter_key"],
                        "model": view.get("model"),
                        "vendor": view.get("vendor"),
                        "id": str(view["id"]),
                    }
                )
                print(f"[smoke] onboarded {view['name']} id={view['id']}")
            report["scenario"] = {
                "devices": onboarded,
                "simulators": [
                    {
                        "key": sim.key,
                        "kind": sim.kind,
                        "profile": sim.vendor_profile,
                        "endpoint": f"{sim.host}:{sim.port}",
                    }
                    for sim in simulators
                ],
                "collection_intervals_seconds": {
                    "reachability": 30,
                    "health": 30,
                    "metrics": 60,
                    "logs": 120,
                    "discovery": 21600,
                },
                "read_tick_seconds": READ_TICK_SECONDS,
            }

            wait_all_collected(smoke_dsn, device_ids)
            print("[smoke] warm-up collections ok (2 succeeded metrics runs per device)")
            series_targets = fetch_series_targets(smoke_dsn, device_ids)
            if len(series_targets) < len(device_ids):
                raise RuntimeError(
                    f"series targets missing for devices "
                    f"({len(series_targets)}/{len(device_ids)}); metric_latest is empty"
                )
            report["scenario"]["series_targets"] = [
                {"device_id": device_id, "metric_key": metric_key, "component_id": component_id}
                for device_id, metric_key, component_id in series_targets
            ]
            time.sleep(5.0)

            readers = [(session, ReaderLoad(session, device_ids, series_targets)) for session in reader_sessions]
            results = run_window(
                smoke_dsn,
                db_name,
                api_base,
                readers,
                device_ids,
                float(args.window_seconds),
            )
            report["results"] = results

        report["status"] = "completed"
        report["run"]["finished_at"] = json_now()
    except BaseException as exc:  # noqa: BLE001 - the report must record failures honestly
        report["status"] = "failed"
        report["error"] = f"{type(exc).__name__}: {exc}"
        print(f"[smoke] FAILED: {type(exc).__name__}: {exc}")
        raise
    finally:
        for handle in process_handles:
            if handle.poll() is None:
                handle.terminate()
        for handle in process_handles:
            try:
                handle.wait(timeout=15.0)
            except subprocess.TimeoutExpired:
                handle.kill()
        for sim in simulators:
            sim.stop()
        if not args.keep_db:
            with contextlib.suppress(Exception):  # noqa: S110 - best-effort cleanup
                drop_database(args.pg_dsn, db_name)

        worker_errors = summarize_worker_log(log_dir / "worker.log")
        report["worker_log"] = worker_errors

        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"[smoke] report written: {report_path} (status={report['status']})")
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(run())
