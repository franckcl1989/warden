"""Redfish TaskService poller tests.

Task states map: Completed -> success; Exception/Killed -> operation_failed;
Interrupted/Cancelled -> ambiguous_result; a vanished task (404) is
ambiguous; the poll is bounded by ``timeout_at``; progress percentages are
fed to the progress sink as they change; device message text never leaks.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from app.infrastructure.protocols.redfish.client import RedfishClient
from app.infrastructure.protocols.redfish.errors import RedfishError
from app.infrastructure.protocols.redfish.tasks import poll_task

BMC = "http://bmc.test"
BASE = "/redfish/v1"
TASK = f"{BASE}/TaskService/Tasks/1"
MONITOR = f"{TASK}/TaskMonitor"
USER = "sim-admin"
PASSWORD = "sim-password"
SECRET_TASK_TEXT = "simulated failure secret text"


class Recorder:
    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[str] = []
        self._responder = responder

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request.url.path)
        return self._responder(request)


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> RedfishClient:
    http = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=BMC,
        timeout=httpx.Timeout(connect=0.2, read=0.2, write=0.2, pool=0.2),
    )
    return RedfishClient(
        http=http,
        base_path=BASE,
        auth_mode="none",
        credentials=None,
        logger=None,
    )


def task_payload(state: str, percent: int | None = None, *, monitor: str | None = MONITOR) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "@odata.id": TASK,
        "@odata.type": "#Task.v1_7_1.Task",
        "Id": "1",
        "Name": "Simulated Reset",
        "TaskState": state,
        "TaskStatus": "OK" if state == "Completed" else ("Exception" if state == "Exception" else "Running"),
        "StartTime": "2026-09-03T08:00:00Z",
    }
    if percent is not None:
        payload["PercentComplete"] = percent
    if monitor is not None:
        payload["TaskMonitor"] = monitor
    return payload


def monitor_payload(state: str, percent: int) -> dict[str, Any]:
    return {
        "@odata.id": MONITOR,
        "@odata.type": "#TaskMonitor.v1_5_1.TaskMonitor",
        "TaskState": state,
        "PercentComplete": percent,
    }


def T0() -> datetime:
    return datetime(2026, 9, 3, 8, 0, 0, tzinfo=UTC)


def make_timeout_at(now: datetime) -> datetime:
    return now + timedelta(seconds=5)


class TestTerminalMapping:
    @pytest.mark.unit
    def test_completed_is_success_with_percent(self) -> None:
        recorder = Recorder(lambda r: httpx.Response(200, json=task_payload("Completed", 100)))
        client = make_client(recorder.handler)
        outcome = poll_task(client, TASK, timeout_at=make_timeout_at(T0()), now=lambda: T0())
        assert outcome.succeeded is True
        assert outcome.state == "Completed"
        assert outcome.timed_out is False
        assert outcome.percent == 100

    @pytest.mark.unit
    def test_exception_maps_operation_failed_without_device_text(self) -> None:
        def responder(request: httpx.Request) -> httpx.Response:
            body = task_payload("Exception", 40)
            body["Messages"] = [
                {
                    "@odata.type": "#Message.v1_1_2.Message",
                    "MessageId": "Base.1.13.GeneralError",
                    "Message": SECRET_TASK_TEXT,
                    "Severity": "Critical",
                }
            ]
            return httpx.Response(200, json=body)

        client = make_client(Recorder(responder).handler)
        outcome = poll_task(client, TASK, timeout_at=make_timeout_at(T0()), now=lambda: T0())
        assert outcome.succeeded is False
        assert outcome.error_code == "operation_failed"
        assert SECRET_TASK_TEXT not in repr(outcome)
        assert outcome.message_safe is None

    @pytest.mark.unit
    def test_killed_maps_operation_failed(self) -> None:
        recorder = Recorder(lambda r: httpx.Response(200, json=task_payload("Killed", 10)))
        client = make_client(recorder.handler)
        outcome = poll_task(client, TASK, timeout_at=make_timeout_at(T0()), now=lambda: T0())
        assert outcome.succeeded is False
        assert outcome.error_code == "operation_failed"

    @pytest.mark.unit
    def test_interrupted_maps_ambiguous_result(self) -> None:
        recorder = Recorder(lambda r: httpx.Response(200, json=task_payload("Interrupted", None)))
        client = make_client(recorder.handler)
        outcome = poll_task(client, TASK, timeout_at=make_timeout_at(T0()), now=lambda: T0())
        assert outcome.succeeded is None
        assert outcome.error_code == "ambiguous_result"

    @pytest.mark.unit
    def test_cancelled_maps_ambiguous_result(self) -> None:
        recorder = Recorder(lambda r: httpx.Response(200, json=task_payload("Cancelled", None)))
        client = make_client(recorder.handler)
        outcome = poll_task(client, TASK, timeout_at=make_timeout_at(T0()), now=lambda: T0())
        assert outcome.error_code == "ambiguous_result"

    @pytest.mark.unit
    def test_vanished_task_404_maps_ambiguous_result(self) -> None:
        recorder = Recorder(lambda r: httpx.Response(404, json={"error": {"code": "Base.1.13.GeneralError"}}))
        client = make_client(recorder.handler)
        outcome = poll_task(client, TASK, timeout_at=make_timeout_at(T0()), now=lambda: T0())
        assert outcome.succeeded is None
        assert outcome.error_code == "ambiguous_result"

    @pytest.mark.unit
    def test_unknown_state_is_protocol_error(self) -> None:
        recorder = Recorder(lambda r: httpx.Response(200, json=task_payload("Frobnicating")))
        client = make_client(recorder.handler)
        with pytest.raises(RedfishError) as exc:
            poll_task(client, TASK, timeout_at=make_timeout_at(T0()), now=lambda: T0())
        assert exc.value.code == "protocol_error"


class TestProgressAndPolling:
    @pytest.mark.unit
    def test_running_to_completed_feeds_progress_sink(self) -> None:
        sequence = [
            task_payload("Running", 50),
            task_payload("Running", 50),
            task_payload("Running", 75),
            task_payload("Completed", 100),
        ]
        state = {"n": 0}

        def responder(request: httpx.Request) -> httpx.Response:
            payload = sequence[min(state["n"], len(sequence) - 1)]
            state["n"] += 1
            return httpx.Response(200, json=payload)

        client = make_client(Recorder(responder).handler)
        sink: list[tuple[int | None, str | None]] = []
        outcome = poll_task(
            client,
            TASK,
            timeout_at=make_timeout_at(T0()),
            now=lambda: T0(),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
            progress_sink=lambda percent, task_state: sink.append((percent, task_state)),
        )
        assert outcome.succeeded is True
        assert sink == [(50, "Running"), (75, "Running"), (100, "Completed")]

    @pytest.mark.unit
    def test_no_duplicate_sink_calls_on_unchanged_state(self) -> None:
        def responder(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=task_payload("Running", 50))

        client = make_client(Recorder(responder).handler)
        sink: list[tuple[int | None, str | None]] = []
        outcome = poll_task(
            client,
            TASK,
            timeout_at=T0(),  # deadline already passed: single bounded poll
            now=lambda: T0(),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
            progress_sink=lambda percent, task_state: sink.append((percent, task_state)),
        )
        assert outcome.timed_out is True
        assert sink == [(50, "Running")]

    @pytest.mark.unit
    def test_polls_task_monitor_when_advertised(self) -> None:
        paths: list[str] = []
        monitor_count = {"n": 0}
        task_count = {"n": 0}

        def responder(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            paths.append(path)
            if path == TASK:
                task_count["n"] += 1
                return httpx.Response(200, json=task_payload("New", None))
            if path == MONITOR:
                monitor_count["n"] += 1
                states = [("Running", 50), ("Completed", 100)]
                payload = monitor_payload(*states[min(monitor_count["n"] - 1, 1)])
                return httpx.Response(200, json=payload)
            raise AssertionError(f"unexpected {path}")

        client = make_client(Recorder(responder).handler)
        sink: list[tuple[int | None, str | None]] = []
        outcome = poll_task(
            client,
            TASK,
            timeout_at=make_timeout_at(T0()),
            now=lambda: T0(),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
            progress_sink=lambda percent, task_state: sink.append((percent, task_state)),
        )
        assert outcome.succeeded is True
        assert outcome.percent == 100
        assert task_count["n"] == 1
        assert monitor_count["n"] >= 2
        assert sink == [(50, "Running"), (100, "Completed")]

    @pytest.mark.unit
    def test_timeout_bounds_polling(self) -> None:
        times = iter([T0(), T0() + timedelta(seconds=1), T0() + timedelta(seconds=6)])
        recorder = Recorder(lambda r: httpx.Response(200, json=task_payload("Running", 30)))
        client = make_client(recorder.handler)
        outcome = poll_task(
            client,
            TASK,
            timeout_at=T0() + timedelta(seconds=5),
            now=lambda: next(times),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
        )
        assert outcome.timed_out is True
        assert outcome.state == "Running"
        assert outcome.succeeded is None
        assert len(recorder.requests) >= 2

    @pytest.mark.unit
    def test_float_percent_is_reported_as_int(self) -> None:
        body = task_payload("Running", None)
        body["PercentComplete"] = 33.7
        recorder = Recorder(lambda r: httpx.Response(200, json=body))
        client = make_client(recorder.handler)
        sink: list[tuple[int | None, str | None]] = []
        outcome = poll_task(
            client,
            TASK,
            timeout_at=T0(),  # deadline already passed: single bounded poll
            now=lambda: T0(),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
            progress_sink=lambda percent, task_state: sink.append((percent, task_state)),
        )
        assert outcome.succeeded is None  # still running when the test clock stops
        assert outcome.percent == 33
        assert sink == [(33, "Running")]


class TestDeadlineClockHelpers:
    @pytest.mark.unit
    def test_clock_defaults_are_wall_clock(self) -> None:
        recorder = Recorder(lambda r: httpx.Response(200, json=task_payload("Completed", 100)))
        client = make_client(recorder.handler)
        outcome = poll_task(client, TASK, timeout_at=datetime.now(UTC) + timedelta(seconds=5))
        assert outcome.succeeded is True
