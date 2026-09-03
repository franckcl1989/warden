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
        await control(http, {"smart_quick_duration_seconds": 0.05})
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
        await control(http, {"failures": {"smart_test_fails": True}, "smart_full_duration_seconds": 0.02})
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
        await control(http, {"upgrade_duration_seconds": 0.05, "upgrade_offline_seconds": 0.05})
        start = await api_call(http, "SYNO.Core.Upgrade", "upgrade", version=1, sid=sid)
        assert start.json()["success"] is True
        task_id = start.json()["data"]["taskid"]
        await asyncio.sleep(0.2)
        done = await api_call(
            http, "SYNO.Core.Upgrade", "update_task_status", version=1, sid=sid, extra={"taskid": str(task_id)}
        )
        assert done.json()["data"]["status"] == "success"
        snapshot_response = await http.get("/warden-sim/control")
        firmware = snapshot_response.json()["firmware"]
        assert firmware == "7.2.1-69057-update6 (simulated)"

    async def test_shutdown_side_effect_ends_sessions(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await api_call(http, "SYNO.Core.System", "shutdown", version=2, sid=sid)
        snapshot_response = await http.get("/warden-sim/control")
        assert snapshot_response.json()["sessions"] == 0


class TestM4T3OperationSurface:
    """M4T3 device-lifecycle DSL: power blips, SMART durations, the update
    fetch/reboot/bump flow, support exports, backup status and SNMP traps."""

    async def test_shutdown_powers_device_off_until_power_on(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await api_call(http, "SYNO.Core.System", "shutdown", version=2, sid=sid)
        snapshot = (await http.get("/warden-sim/control")).json()
        assert snapshot["power"] == "off"
        answer = await api_call(http, "SYNO.Core.System", "info", version=2, sid=sid)
        assert answer.status_code == 503
        root = await http.get("/")
        assert root.status_code == 503
        snapshot = await control(http, {"power_on": True})
        assert snapshot["power"] == "on"
        fresh = await login(http)
        info = await api_call(http, "SYNO.Core.System", "info", version=2, sid=fresh)
        assert info.status_code == 200
        assert info.json()["data"]["serial"] == "SIM-DS224P-0001"

    async def test_restart_blip_window_then_reconnect(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"restart_blip_seconds": 0.3})
        await api_call(http, "SYNO.Core.System", "restart", version=2, sid=sid)
        during = await api_call(http, "SYNO.Core.System", "info", version=2, sid=sid)
        assert during.status_code == 503
        await asyncio.sleep(0.4)
        fresh = await login(http)
        info = await api_call(http, "SYNO.Core.System", "info", version=2, sid=fresh)
        assert info.status_code == 200
        assert info.json()["data"]["serial"] == "SIM-DS224P-0001"

    async def test_restart_ignored_and_identity_change_knobs(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(http, {"failures": {"restart_ignored": True}})
        await api_call(http, "SYNO.Core.System", "restart", version=2, sid=sid)
        await asyncio.sleep(0.05)
        # The device never went down: the same session still works.
        info = await api_call(http, "SYNO.Core.System", "info", version=2, sid=sid)
        assert info.status_code == 200
        await control(
            http,
            {
                "failures": {"restart_ignored": False, "restart_identity_changes": True},
                "restart_blip_seconds": 0.2,
            },
        )
        await api_call(http, "SYNO.Core.System", "restart", version=2, sid=sid)
        await asyncio.sleep(0.3)
        fresh = await login(http)
        changed = await api_call(http, "SYNO.Core.System", "info", version=2, sid=fresh)
        assert changed.json()["data"]["serial"] == "SIM-DS224P-CHANGED (simulated)"

    async def test_smart_quick_full_durations_and_never_completes(
        self, http: httpx.AsyncClient
    ) -> None:
        sid = await login(http)
        await control(
            http,
            {
                "smart_quick_duration_seconds": 0.05,
                "smart_full_duration_seconds": 1.0,
            },
        )
        quick = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_test", version=1, sid=sid,
            extra={"disk": "sata1", "type": "quick"},
        )
        quick_id = quick.json()["data"]["taskid"]
        full = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_test", version=1, sid=sid,
            extra={"disk": "sata2", "type": "full"},
        )
        full_id = full.json()["data"]["taskid"]
        await control(http, {"failures": {"smart_test_never_completes": True}})
        never = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_test", version=1, sid=sid,
            extra={"disk": "sata1", "type": "quick"},
        )
        never_id = never.json()["data"]["taskid"]
        # The load_info surface reports the running jobs honestly.
        info = await api_call(http, "SYNO.Storage.CGI.Storage", "load_info", version=1, sid=sid)
        kinds = {job["kind"] for job in info.json()["data"]["active_jobs"]}
        assert kinds == {"smart"}
        await asyncio.sleep(0.2)
        quick_done = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_task_status", version=1, sid=sid,
            extra={"taskid": str(quick_id)},
        )
        assert quick_done.json()["data"]["status"] == "success"
        full_running = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_task_status", version=1, sid=sid,
            extra={"taskid": str(full_id)},
        )
        assert full_running.json()["data"]["status"] == "running"
        never_running = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_task_status", version=1, sid=sid,
            extra={"taskid": str(never_id)},
        )
        assert never_running.json()["data"]["status"] == "running"

    async def test_smart_test_rejects_unknown_disk(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        rejected = await api_call(
            http, "SYNO.Storage.CGI.Storage", "smart_test", version=1, sid=sid,
            extra={"disk": "sata9", "type": "quick"},
        )
        assert rejected.json()["success"] is False
        assert rejected.json()["error"]["code"] == 101

    async def test_update_reboot_window_then_firmware_bump(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(
            http,
            {"upgrade_duration_seconds": 0.05, "upgrade_offline_seconds": 0.4, "restart_blip_seconds": 0.05},
        )
        await api_call(http, "SYNO.Core.Upgrade", "upgrade", version=1, sid=sid)
        await asyncio.sleep(0.2)
        # The DSM is mid-reboot while the update installs: all WebAPI 503.
        during = await api_call(http, "SYNO.Core.Upgrade", "update_task_status", version=1, sid=sid)
        assert during.status_code == 503
        await asyncio.sleep(0.5)
        fresh = await login(http)
        info = await api_call(http, "SYNO.Core.System", "info", version=2, sid=fresh)
        assert info.json()["data"]["firmware"] == "7.2.1-69057-update6 (simulated)"
        snapshot = (await http.get("/warden-sim/control")).json()
        assert snapshot["firmware"] == "7.2.1-69057-update6 (simulated)"

    async def test_update_target_version_knob(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(
            http,
            {
                "upgrade_duration_seconds": 0.05,
                "upgrade_offline_seconds": 0.05,
                "upgrade_target_version": "7.2.1-69057-update9 (simulated)",
            },
        )
        await api_call(http, "SYNO.Core.Upgrade", "upgrade", version=1, sid=sid)
        await asyncio.sleep(0.3)
        fresh = await login(http)
        info = await api_call(http, "SYNO.Core.System", "info", version=2, sid=fresh)
        assert info.json()["data"]["firmware"] == "7.2.1-69057-update9 (simulated)"

    async def test_update_failure_and_never_completes(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        await control(
            http,
            {
                "upgrade_duration_seconds": 0.05,
                "upgrade_offline_seconds": 0.05,
                "failures": {"update_fails": True},
            },
        )
        start = await api_call(http, "SYNO.Core.Upgrade", "upgrade", version=1, sid=sid)
        failing_id = start.json()["data"]["taskid"]
        await asyncio.sleep(0.1)
        status = await api_call(
            http, "SYNO.Core.Upgrade", "update_task_status", version=1, sid=sid,
            extra={"taskid": str(failing_id)},
        )
        assert status.json()["data"]["status"] == "failure"
        snapshot = (await http.get("/warden-sim/control")).json()
        assert snapshot["firmware"] == "7.2.1-69057-update5 (simulated)"
        await control(
            http,
            {"failures": {"update_fails": False, "update_never_completes": True}, "upgrade_duration_seconds": 0.05},
        )
        start = await api_call(http, "SYNO.Core.Upgrade", "upgrade", version=1, sid=sid)
        stuck_id = start.json()["data"]["taskid"]
        await asyncio.sleep(0.2)
        stuck = await api_call(
            http, "SYNO.Core.Upgrade", "update_task_status", version=1, sid=sid,
            extra={"taskid": str(stuck_id)},
        )
        assert stuck.json()["data"]["status"] == "running"

    async def test_support_export_serves_downloadable_bundle(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        exported = await api_call(http, "SYNO.Core.Support", "export", version=1, sid=sid)
        assert exported.json()["success"] is True
        path = exported.json()["data"]["file"]
        assert path.startswith("/support/export/") and path.endswith(".zip")
        download = await http.get(path)
        assert download.status_code == 200
        assert download.headers["content-type"] == "application/zip"
        import io
        import json as jsonlib
        import zipfile

        with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
            names = set(archive.namelist())
            assert {"manifest.json", "log-entries.json", "system.json"} <= names
            manifest = jsonlib.loads(archive.read("manifest.json"))
        assert manifest["format"] == "warden-dsm-support-bundle/1"
        assert {source["name"] for source in manifest["sources"]} == {"system_log", "system_info"}
        assert all(len(source["sha256"]) == 64 for source in manifest["sources"])
        snapshot = (await http.get("/warden-sim/control")).json()
        assert snapshot["exported_bundles"] == 1

    async def test_backup_status_lists_packages_and_jobs(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        listed = await api_call(http, "SYNO.Core.Backup", "list", version=1, sid=sid)
        data = listed.json()["data"]
        assert data["total"] == 2
        assert {job["name"] for job in data["jobs"]} == {"Daily Backup", "Weekly Backup"}
        by_package = {package["package"]: package for package in data["packages"]}
        assert by_package["hyper_backup"]["available"] is True
        assert by_package["snapshot_replication"] == {
            "name": "Snapshot Replication",
            "package": "snapshot_replication",
            "available": False,
            "reason": "not_installed",
        }
        await control(http, {"backup_snapshot_available": True})
        listed = await api_call(http, "SYNO.Core.Backup", "list", version=1, sid=sid)
        data = listed.json()["data"]
        assert {job["type"] for job in data["jobs"]} == {"hyper_backup", "snapshot"}
        assert data["total"] == 3
        await control(http, {"backup_no_jobs": True})
        listed = await api_call(http, "SYNO.Core.Backup", "list", version=1, sid=sid)
        assert listed.json()["data"]["jobs"] == []
        assert listed.json()["data"]["total"] == 0

    async def test_snmp_set_get_and_test_trap_record(self, http: httpx.AsyncClient) -> None:
        sid = await login(http)
        current = await api_call(http, "SYNO.Core.Network.SNMP", "get", version=1, sid=sid)
        assert current.json()["data"] == {"enabled": False, "receiver_address": ""}
        rejected = await api_call(
            http, "SYNO.Core.Network.SNMP", "set", version=1, sid=sid,
            extra={"enabled": "true", "receiver_address": ""},
        )
        assert rejected.json()["error"]["code"] == 101
        accepted = await api_call(
            http, "SYNO.Core.Network.SNMP", "set", version=1, sid=sid,
            extra={"enabled": "true", "receiver_address": "192.0.2.10:1162"},
        )
        assert accepted.json()["data"] == {"enabled": True, "receiver_address": "192.0.2.10:1162"}
        readback = await api_call(http, "SYNO.Core.Network.SNMP", "get", version=1, sid=sid)
        assert readback.json()["data"] == {"enabled": True, "receiver_address": "192.0.2.10:1162"}
        snapshot = (await http.get("/warden-sim/control")).json()
        assert snapshot["traps"][0]["receiver_address"] == "192.0.2.10:1162"
        await api_call(
            http, "SYNO.Core.Network.SNMP", "set", version=1, sid=sid,
            extra={"enabled": "false", "receiver_address": ""},
        )
        readback = await api_call(http, "SYNO.Core.Network.SNMP", "get", version=1, sid=sid)
        assert readback.json()["data"] == {"enabled": False, "receiver_address": ""}

    async def test_web_origin_served_while_online(self, http: httpx.AsyncClient) -> None:
        root = await http.get("/")
        assert root.status_code == 200
        assert "text/html" in root.headers["content-type"]
        assert b"DSM (simulated)" in root.content
