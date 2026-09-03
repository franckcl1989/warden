"""DSM simulator behavior tests (ASGI in-process).

The simulator is a TEST device simulator (tests/simulators/dsm/README.md);
these tests pin its documented surface: profiles, knobs, honest error codes
and session semantics.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from tests.simulators.dsm.app import create_simulator
from tests.simulators.dsm.payloads import LOG_EPOCH, SimulatorConfig

READER = Path(__file__).resolve().parent / "README.md"


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_simulator()),
        base_url="http://dsm.test",
    ) as client:
        yield client


async def api_call(
    client: httpx.AsyncClient,
    api: str,
    method: str,
    *,
    version: int,
    sid: str | None = None,
    extra: dict[str, str] | None = None,
) -> httpx.Response:
    params: dict[str, str] = {"api": api, "method": method, "version": str(version)}
    if sid is not None:
        params["_sid"] = sid
    if extra:
        params.update(extra)
    return await client.get("/webapi/entry.cgi", params=params)


async def login(client: httpx.AsyncClient, *, username: str = "admin", password: str = "sim-pass-1") -> str:
    response = await client.get(
        "/webapi/auth.cgi",
        params={
            "api": "SYNO.API.Auth",
            "version": "6",
            "method": "login",
            "account": username,
            "passwd": password,
            "session": "DiskStation",
            "format": "sid",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    return body["data"]["sid"]


async def control(client: httpx.AsyncClient, body: object) -> dict[str, object]:
    response = await client.post("/warden-sim/control", json=body)
    assert response.status_code == 200
    return response.json()


class TestHonestFraming:
    def test_readme_declares_test_simulator(self) -> None:
        text = READER.read_text(encoding="utf-8")
        assert "TEST DEVICE SIMULATOR" in text
        assert "NOT evidence of hardware support" in text

    def test_module_docstring_declares_test_simulator(self) -> None:
        from tests.simulators.dsm.app import __doc__ as app_doc
        from tests.simulators.dsm.payloads import __doc__ as payload_doc

        assert app_doc is not None and "NOT evidence of hardware support" in app_doc
        assert payload_doc is not None and "TEST DEVICE SIMULATOR" in payload_doc
        assert payload_doc is not None and "NOT real-DSM evidence" in payload_doc


class TestDiscovery:
    async def test_anonymous_info_query_serves_api_map(self, http: httpx.AsyncClient) -> None:
        response = await http.get(
            "/webapi/query.cgi",
            params={"api": "SYNO.API.Info", "version": "1", "method": "query", "query": "all"},
        )
        body = response.json()
        assert body["success"] is True
        data = body["data"]
        for _api_name, entry in data.items():
            assert set(entry) == {"path", "minVersion", "maxVersion"}
            assert entry["path"] in ("query.cgi", "auth.cgi", "entry.cgi")
        assert data["SYNO.API.Auth"]["path"] == "auth.cgi"
        assert data["SYNO.API.Auth"]["maxVersion"] == 6
        assert data["SYNO.Storage.CGI.Storage"]["path"] == "entry.cgi"

    async def test_api_map_missing_profile_drops_storage_api(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_simulator(SimulatorConfig(profile="api_map_missing"))),
            base_url="http://dsm.test",
        ) as client:
            response = await client.get(
                "/webapi/query.cgi",
                params={"api": "SYNO.API.Info", "version": "1", "method": "query", "query": "all"},
            )
            data = response.json()["data"]
            assert "SYNO.Storage.CGI.Storage" not in data
            assert "SYNO.Core.UPS" in data

    async def test_missing_apis_control_drops_apis_live(self, http: httpx.AsyncClient) -> None:
        snapshot = await control(http, {"missing_apis": ["SYNO.Core.UPS"]})
        assert snapshot["missing_apis"] == ["SYNO.Core.UPS"]
        response = await http.get(
            "/webapi/query.cgi",
            params={"api": "SYNO.API.Info", "version": "1", "method": "query", "query": "all"},
        )
        assert "SYNO.Core.UPS" not in response.json()["data"]

    async def test_storage_max_version_inflation_via_control(self, http: httpx.AsyncClient) -> None:
        await control(http, {"storage_max_version": 9})
        response = await http.get(
            "/webapi/query.cgi",
            params={"api": "SYNO.API.Info", "version": "1", "method": "query", "query": "all"},
        )
        entry = response.json()["data"]["SYNO.Storage.CGI.Storage"]
        assert entry["maxVersion"] == 9

    async def test_version_out_of_range_is_104(self, http: httpx.AsyncClient) -> None:
        response = await http.get(
            "/webapi/query.cgi",
            params={"api": "SYNO.API.Info", "version": "99", "method": "query", "query": "all"},
        )
        body = response.json()
        assert body["success"] is False
        assert body["error"]["code"] == 104

    async def test_unknown_api_and_method_codes(self, http: httpx.AsyncClient) -> None:
        unknown_api = await http.get(
            "/webapi/entry.cgi", params={"api": "SYNO.Core.NoSuch", "method": "x", "version": "1"}
        )
        assert unknown_api.json()["error"]["code"] == 102
        sid = await login(http)
        unknown_method = await api_call(http, "SYNO.Core.UPS", "frobnicate", version=1, sid=sid)
        assert unknown_method.json()["error"]["code"] == 103


class TestSession:
    async def test_login_issues_sid_and_authenticated_calls_work(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        response = await api_call(http, "SYNO.Core.UPS", "get", version=1, sid=sid)
        assert response.json()["success"] is True
        assert response.json()["data"]["ups"]["status"] == "Normal"

    async def test_call_without_sid_is_session_timeout_106(self, http: httpx.AsyncClient) -> None:
        response = await api_call(http, "SYNO.Core.UPS", "get", version=1)
        body = response.json()
        assert body["success"] is False
        assert body["error"]["code"] == 106

    async def test_wrong_password_is_401(self, http: httpx.AsyncClient) -> None:
        response = await http.get(
            "/webapi/auth.cgi",
            params={
                "api": "SYNO.API.Auth",
                "version": "6",
                "method": "login",
                "account": "admin",
                "passwd": "wrong",
                "session": "DiskStation",
                "format": "sid",
            },
        )
        body = response.json()
        assert body["success"] is False
        assert body["error"]["code"] == 401

    async def test_login_otp_knob_answers_403(self, http: httpx.AsyncClient) -> None:
        await control(http, {"failures": {"login_otp": True}})
        response = await http.get(
            "/webapi/auth.cgi",
            params={
                "api": "SYNO.API.Auth",
                "version": "6",
                "method": "login",
                "account": "admin",
                "passwd": "sim-pass-1",
                "session": "DiskStation",
                "format": "sid",
            },
        )
        assert response.json()["error"]["code"] == 403

    async def test_logout_invalidates_sid(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        response = await http.get(
            "/webapi/auth.cgi",
            params={"api": "SYNO.API.Auth", "version": "6", "method": "logout", "_sid": sid},
        )
        assert response.json()["success"] is True
        call = await api_call(http, "SYNO.Core.UPS", "get", version=1, sid=sid)
        assert call.json()["error"]["code"] == 106

    async def test_expire_sessions_control_invalidates_all(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"expire_sessions": True})
        call = await api_call(http, "SYNO.Core.UPS", "get", version=1, sid=sid)
        assert call.json()["error"]["code"] == 106

    async def test_sessions_reject_106_knob(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"failures": {"sessions_reject_106": True}})
        call = await api_call(http, "SYNO.Core.UPS", "get", version=1, sid=sid)
        assert call.json()["error"]["code"] == 106


class TestProfiles:
    async def test_degraded_profile_state(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_simulator(SimulatorConfig(profile="degraded"))),
            base_url="http://dsm.test",
        ) as client:
            sid = await login(client)
            storage = await api_call(client, "SYNO.Storage.CGI.Storage", "load_info", version=1, sid=sid)
            data = storage.json()["data"]
            disk_by_id = {disk["id"]: disk for disk in data["disk"]}
            assert disk_by_id["sata1"]["status"] == "Healthy"
            assert disk_by_id["sata2"]["status"] == "Broken"
            assert disk_by_id["sata2"]["smart"] == "Fail"
            assert data["pool"][0]["status"] == "Degraded"
            assert data["volume"][0]["used_bytes"] > 0
            ups = await api_call(client, "SYNO.Core.UPS", "get", version=1, sid=sid)
            assert ups.json()["data"]["ups"]["status"] == "On Battery"
            system = await api_call(client, "SYNO.Core.System", "info", version=2, sid=sid)
            fan = system.json()["data"]["fan"][0]
            assert fan["rpm"] == 0
            assert fan["status"] == "Error"

    async def test_healthy_profile_state(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        storage = await api_call(http, "SYNO.Storage.CGI.Storage", "load_info", version=1, sid=sid)
        data = storage.json()["data"]
        assert {disk["status"] for disk in data["disk"]} == {"Healthy"}
        assert data["pool"][0]["status"] == "Normal"
        ups = await api_call(http, "SYNO.Core.UPS", "get", version=1, sid=sid)
        assert ups.json()["data"]["ups"]["status"] == "Normal"

    async def test_knobs_switch_live(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"ups_on_battery": True})
        ups = await api_call(http, "SYNO.Core.UPS", "get", version=1, sid=sid)
        assert ups.json()["data"]["ups"]["status"] == "On Battery"

    async def test_control_snapshot_reports_state(self, http: httpx.AsyncClient) -> None:
        snapshot = await control(http, {"profile": "slow_paginated"})
        assert snapshot["profile"] == "slow_paginated"
        assert snapshot["log_total"] == 150


class TestFamilyPayloads:
    async def test_slow_paginated_log_pages(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_simulator(SimulatorConfig(profile="slow_paginated"))),
            base_url="http://dsm.test",
        ) as client:
            sid = await login(client)
            page1 = await api_call(
                client, "SYNO.Core.System.Log", "list", version=1, sid=sid, extra={"offset": "0", "limit": "20"}
            )
            data = page1.json()["data"]
            assert data["total"] == 150
            assert len(data["log"]) == 20
            page2 = await api_call(
                client, "SYNO.Core.System.Log", "list", version=1, sid=sid, extra={"offset": "20", "limit": "20"}
            )
            entries2 = page2.json()["data"]["log"]
            assert entries2[0]["id"] == 21
            assert entries2[0]["time"] > data["log"][-1]["time"]
            assert data["log"][0]["time"] == int(LOG_EPOCH.timestamp()) + 1

    async def test_smart_test_task_lifecycle(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"task_duration_seconds": 0.05})
        start = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_test", version=1, sid=sid, extra={"disk": "sata1", "type": "quick"}
        )
        assert start.json()["success"] is True
        task_id = start.json()["data"]["taskid"]
        running = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_task_status", version=1, sid=sid, extra={"taskid": str(task_id)}
        )
        assert running.json()["data"]["status"] in ("running", "success")
        await asyncio.sleep(0.1)
        done = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_task_status", version=1, sid=sid, extra={"taskid": str(task_id)}
        )
        assert done.json()["data"]["status"] == "success"

    async def test_smart_test_failure_knob(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"failures": {"smart_test_fails": True}, "task_duration_seconds": 0.02})
        start = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_test", version=1, sid=sid, extra={"disk": "sata2", "type": "full"}
        )
        task_id = start.json()["data"]["taskid"]
        await asyncio.sleep(0.05)
        done = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_task_status", version=1, sid=sid, extra={"taskid": str(task_id)}
        )
        assert done.json()["data"]["status"] == "failure"

    async def test_update_job_lifecycle(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"task_duration_seconds": 0.05})
        start = await api_call(http, "SYNO.Core.Upgrade", "upgrade", version=1, sid=sid)
        assert start.json()["success"] is True
        task_id = start.json()["data"]["taskid"]
        await asyncio.sleep(0.1)
        done = await api_call(
            http, "SYNO.Core.Upgrade", "update_task_status", version=1, sid=sid, extra={"taskid": str(task_id)}
        )
        assert done.json()["data"]["status"] == "success"

    async def test_shutdown_side_effect_ends_sessions(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await api_call(http, "SYNO.Core.System", "shutdown", version=2, sid=sid)
        snapshot_response = await http.get("/warden-sim/control")
        assert snapshot_response.json()["sessions"] == 0
