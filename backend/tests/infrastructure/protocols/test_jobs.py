"""Generic OEM vendor job polling shape tests.

Vendor job URIs and terminal predicates are filled by vendor overlays in
M3T5; this module only provides the bounded polling skeleton and progress
extraction hook.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from app.infrastructure.protocols.redfish.client import RedfishClient
from app.infrastructure.protocols.redfish.jobs import poll_vendor_job
from app.infrastructure.protocols.redfish.parse import RedfishResource

BMC = "http://bmc.test"
BASE = "/redfish/v1"
JOB = f"{BASE}/Oem/Vendor/Jobs/9"


def make_client(handler) -> RedfishClient:  # type: ignore[no-untyped-def]
    http = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=BMC,
        timeout=httpx.Timeout(connect=0.2, read=0.2, write=0.2, pool=0.2),
    )
    return RedfishClient(http=http, base_path=BASE, auth_mode="none", credentials=None, logger=None)


def job_payload(job_state: str, progress: int | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "@odata.id": JOB,
        "@odata.type": "#VendorJob.v1_0_0.VendorJob",
        "Id": "9",
        "JobState": job_state,
    }
    if progress is not None:
        payload["ProgressPercent"] = progress
    return payload


class TestVendorJobPolling:
    @pytest.mark.unit
    def test_polls_until_vendor_predicate_is_terminal(self) -> None:
        states = iter(["running", "running", "completed"])
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request.url.path)
            return httpx.Response(200, json=job_payload(next(states), 50))

        client = make_client(handler)

        def is_terminal(payload: RedfishResource, attempt: int) -> bool:
            return payload.get_text("JobState") == "completed" or attempt >= 5

        outcome = poll_vendor_job(
            client,
            JOB,
            is_terminal=is_terminal,
            timeout_at=datetime.now(UTC) + timedelta(seconds=30),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
        )
        assert outcome.terminal is True
        assert outcome.timed_out is False
        assert outcome.payload is not None
        assert outcome.payload.get_text("JobState") == "completed"
        assert requests == [JOB, JOB, JOB]

    @pytest.mark.unit
    def test_timeout_bounds_polling(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=job_payload("running"))

        client = make_client(handler)

        def is_terminal(payload: RedfishResource, attempt: int) -> bool:
            return False

        now = datetime(2026, 9, 3, 8, 0, 0, tzinfo=UTC)
        times = iter(
            [
                now,
                now + timedelta(seconds=1),
                now + timedelta(seconds=2),
                now + timedelta(seconds=12),
            ]
        )
        outcome = poll_vendor_job(
            client,
            JOB,
            is_terminal=is_terminal,
            timeout_at=now + timedelta(seconds=10),
            now=lambda: next(times),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
        )
        assert outcome.terminal is False
        assert outcome.timed_out is True
        assert outcome.attempts == 3

    @pytest.mark.unit
    def test_progress_hook_feeds_sink_on_change(self) -> None:
        values = [("running", 10), ("running", 55), ("running", 55), ("done", 100)]
        index = {"n": 0}
        sink: list[tuple[int | None, str | None]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            job_state, progress = values[index["n"]]
            index["n"] += 1
            return httpx.Response(200, json=job_payload(job_state, progress))

        client = make_client(handler)

        def is_terminal(payload: RedfishResource, attempt: int) -> bool:
            return payload.get_text("JobState") == "done"

        outcome = poll_vendor_job(
            client,
            JOB,
            is_terminal=is_terminal,
            timeout_at=datetime.now(UTC) + timedelta(seconds=30),
            poll_interval=0.0,
            sleep=lambda _seconds: None,
            percent_of=lambda payload: payload.get_number("ProgressPercent"),
            progress_sink=lambda percent, state: sink.append((percent, state)),
        )
        assert outcome.terminal is True
        assert sink == [(10, None), (55, None), (100, None)]
