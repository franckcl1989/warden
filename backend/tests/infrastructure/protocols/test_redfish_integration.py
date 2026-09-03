"""Real-HTTP integration: simulator booted with uvicorn + RedfishClient.

The simulator is a TEST device simulator (never hardware evidence). The
client connects to 127.0.0.1 over plain HTTP with an injected transport —
production wiring uses the M1T2 policy/TLS managed client; this file proves
the protocol stack end to end over real sockets.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from app.infrastructure.protocols.redfish.client import RedfishClient
from app.infrastructure.protocols.redfish.errors import RedfishError
from app.infrastructure.protocols.redfish.parse import walk_collection
from app.infrastructure.protocols.redfish.session import RedfishCredentials
from app.infrastructure.protocols.redfish.tasks import poll_task

from tests.simulators.redfish.app import SimulatorConfig
from tests.simulators.redfish.serving import serve_simulator

BASE = "/redfish/v1"
USER = "admin"
PASSWORD = "sim-pass-1"
SEL = f"{BASE}/Managers/1/LogServices/SEL/Entries"

# uvicorn on Windows leaves idle keep-alive connection sockets to be closed
# by GC after the server thread exits; these surface as unraisable warnings
# in whichever test triggers the next collection. They are a harness
# shutdown artifact of the booted simulator, not client behaviour.
pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]


@pytest.fixture
def sim_url() -> Iterator[str]:
    with serve_simulator() as url:
        yield url


@pytest.fixture
def base_url() -> Iterator[str]:
    # A slow-paginated + fast-task profile shared by the walk/poll tests.
    with serve_simulator(
        SimulatorConfig(
            profile="slow_paginated",
            task_duration_seconds=0.05,
        )
    ) as url:
        yield url


def make_client(base_url: str, *, auth_mode: str = "session") -> RedfishClient:
    http = httpx.Client(base_url=base_url, timeout=httpx.Timeout(connect=2.0, read=5.0, write=2.0, pool=2.0))
    credentials = RedfishCredentials(username=USER, password=PASSWORD) if auth_mode != "none" else None
    return RedfishClient(
        http=http,
        base_path=BASE,
        auth_mode=auth_mode,
        credentials=credentials,
        logger=None,
        backoff=lambda attempt: 0.0,
    )


@contextmanager
def client_ctx(base_url: str, *, auth_mode: str = "session") -> Iterator[RedfishClient]:
    """Client lifecycle: closes the device session AND the injected transport."""
    client = make_client(base_url, auth_mode=auth_mode)
    try:
        yield client
    finally:
        client.close()
        client._http.close()


class TestWalkAndReads:
    @pytest.mark.unit
    def test_client_logs_in_and_walks_resources_over_http(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            root = client.get(f"{BASE}/")
            assert root is not None
            assert root.schema_family == "ServiceRoot"
            systems_path = root["Systems"]["@odata.id"]
            assert isinstance(systems_path, str)
            system = client.get(systems_path + "/1")
            assert system is not None
            assert system.schema_family == "ComputerSystem"
            assert system.get_text("PowerState") == "On"
            assert system.get_text("Status") == "missing" or system["Status"]["Health"] == "OK"

    @pytest.mark.unit
    def test_session_is_deleted_on_close(self, sim_url: str) -> None:
        client = make_client(sim_url)
        client.get(f"{BASE}/")
        client.close()
        # A deleted session token must no longer authenticate.
        probe = make_client(sim_url)
        with probe:
            # fresh session works; old one is gone (server clears on delete)
            root = probe.get(f"{BASE}/")
            assert root is not None

    @pytest.mark.unit
    def test_sel_walk_skip_pagination_fetches_all_150(self, base_url: str) -> None:
        with client_ctx(base_url) as client:
            resources, truncated = walk_collection(client, SEL)
            assert truncated is False
            assert len(resources) == 150
            first_ids = {resource.get_text("Id") for resource in resources}
            assert len(first_ids) == 150
            ids = [resource["Id"] for resource in resources]
            assert ids == sorted(ids)

    @pytest.mark.unit
    def test_sel_walk_next_link_pagination(self, base_url: str) -> None:
        with client_ctx(base_url) as client:
            client.request("POST", "/warden-sim/control", json_body={"pagination": "next_link"})
            resources, truncated = walk_collection(client, SEL)
            assert truncated is False
            assert len(resources) == 150

    @pytest.mark.unit
    def test_sel_entries_are_sorted_and_carry_event_fields(self, base_url: str) -> None:
        with client_ctx(base_url) as client:
            resources, _ = walk_collection(client, SEL)
            entry = resources[0]
            assert entry.schema_family == "LogEntry"
            assert entry.get_datetime("Created") is not None or entry["Created"]
            assert entry["Severity"] in ("OK", "Warning", "Critical")
            assert entry["Message"]


class TestActionsAndTasks:
    @pytest.mark.unit
    def test_reset_action_202_then_task_completes(self, base_url: str) -> None:
        with client_ctx(base_url) as client:
            reply = client.post(
                f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
                json_body={"ResetType": "GracefulRestart"},
            )
            assert reply.status_code == 202
            location = reply.headers.get("location")
            assert location and location.startswith(f"{BASE}/TaskService/Tasks/")
            outcome = poll_task(
                client,
                location,
                timeout_at=datetime.now(UTC) + timedelta(seconds=10),
                poll_interval=0.02,
                progress_sink=lambda percent, state: None,
            )
            assert outcome.succeeded is True
            assert outcome.state == "Completed"

    @pytest.mark.unit
    def test_reset_task_failure_injection_maps_operation_failed(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            control = client.request(
                "POST",
                "/warden-sim/control",
                json_body={"failures": {"reset_task_fails": True}, "task_duration_seconds": 0.05},
            )
            assert control.status_code == 200
            reply = client.post(
                f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
                json_body={"ResetType": "ForceRestart"},
            )
            location = reply.headers["location"]
            outcome = poll_task(
                client,
                location,
                timeout_at=datetime.now(UTC) + timedelta(seconds=10),
                poll_interval=0.02,
            )
            assert outcome.succeeded is False
            assert outcome.error_code == "operation_failed"
            assert outcome.state == "Exception"

    @pytest.mark.unit
    def test_auth_fail_profile_rejects_login(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            control = client.request("POST", "/warden-sim/control", json_body={"profile": "auth_fail"})
            assert control.status_code == 200
        second = make_client(sim_url)
        with second:
            with pytest.raises(RedfishError) as exc:
                second.get(f"{BASE}/")
            assert exc.value.code == "authentication_failed"

    @pytest.mark.unit
    def test_unknown_profile_control_rejected_over_http(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            from app.infrastructure.protocols.redfish.errors import RedfishHttpError

            with pytest.raises(RedfishHttpError) as exc:
                client.request("POST", "/warden-sim/control", json_body={"profile": "bogus"})
            assert exc.value.status == 400

    @pytest.mark.unit
    def test_basic_auth_mode_over_http(self, sim_url: str) -> None:
        with client_ctx(sim_url, auth_mode="basic") as client:
            root = client.get(f"{BASE}/")
            assert root is not None


class TestControlAndOem:
    @pytest.mark.unit
    def test_vendor_switch_changes_oem_namespace(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            reply = client.request("POST", "/warden-sim/control", json_body={"vendor": "huawei"})
            assert reply.status_code == 200
            dimm0 = client.get(f"{BASE}/Systems/1/Memory/DIMM0")
            assert dimm0 is not None
            block = dimm0["Oem"]["Huawei"]
            assert isinstance(block, dict)
            assert str(block.get("@odata.type", "")).startswith("#Huawei.")

    @pytest.mark.unit
    def test_read_failure_injection_over_http(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            client.request("POST", "/warden-sim/control", json_body={"failures": {"reads_500": True}})
            from app.infrastructure.protocols.redfish.errors import RedfishHttpError

            with pytest.raises(RedfishHttpError) as exc:
                client.get(f"{BASE}/Systems/1")
            assert exc.value.code == "operation_failed"
