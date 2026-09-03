"""Redfish simulator module tests (drive the ASGI app via httpx transport).

The simulator is a TEST device simulator — it is never evidence of hardware
support (module docstring + README; the certification matrix stays
``not_started`` until real-device runs exist).
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Iterator

import httpx
import pytest

from tests.simulators.redfish.app import (
    SimulatorConfig,
    create_simulator,
)

BASE = "/redfish/v1"
USER = "admin"
PASSWORD = "sim-pass-1"


def basic_auth() -> str:
    raw = f"{USER}:{PASSWORD}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


@pytest.fixture
async def http() -> Iterator[httpx.AsyncClient]:
    app = create_simulator(SimulatorConfig())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://sim", timeout=5.0) as client:
        yield client


async def login(client: httpx.AsyncClient) -> tuple[str, str]:
    response = await client.post(
        f"{BASE}/SessionService/Sessions",
        json={"UserName": USER, "Password": PASSWORD},
    )
    assert response.status_code == 201
    token = response.headers["x-auth-token"]
    location = response.headers["location"]
    return token, location


async def authed_get(client: httpx.AsyncClient, token: str, path: str) -> httpx.Response:
    return await client.get(path, headers={"X-Auth-Token": token})


class TestServiceRootAndAuth:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_root_requires_auth(self, http: httpx.AsyncClient) -> None:
        response = await http.get(f"{BASE}/")
        assert response.status_code == 401
        body = response.json()
        assert body["error"]["code"].startswith("Base.1.")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_login_exchange_and_session_delete(self, http: httpx.AsyncClient) -> None:
        token, location = await login(http)
        assert token
        assert location == f"{BASE}/SessionService/Sessions/1"
        response = await http.delete(location, headers={"X-Auth-Token": token})
        assert response.status_code == 204

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_login_with_wrong_password_is_401(self, http: httpx.AsyncClient) -> None:
        response = await http.post(
            f"{BASE}/SessionService/Sessions",
            json={"UserName": USER, "Password": "wrong-password"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"].startswith("Base.1.")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_service_root_lists_standard_links(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        response = await authed_get(http, token, f"{BASE}/")
        assert response.status_code == 200
        body = response.json()
        assert body["Id"] == "RootService"
        assert body["RedfishVersion"]
        assert body["Systems"]["@odata.id"] == f"{BASE}/Systems"
        assert body["Chassis"]["@odata.id"] == f"{BASE}/Chassis"
        assert body["Managers"]["@odata.id"] == f"{BASE}/Managers"
        assert body["SessionService"]["@odata.id"] == f"{BASE}/SessionService"
        assert body["UpdateService"]["@odata.id"] == f"{BASE}/UpdateService"
        assert body["TaskService"]["@odata.id"] == f"{BASE}/TaskService"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_basic_auth_works_without_session(self, http: httpx.AsyncClient) -> None:
        response = await http.get(f"{BASE}/Systems/1", headers={"Authorization": basic_auth()})
        assert response.status_code == 200
        assert response.json()["Id"] == "1"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_unknown_resource_is_404_with_base_error(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        response = await authed_get(http, token, f"{BASE}/Systems/99")
        assert response.status_code == 404
        assert response.json()["error"]["code"].startswith("Base.1.")


class TestProfiles:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_control_endpoint_switches_profile_and_reports_state(self, http: httpx.AsyncClient) -> None:
        control = await http.get("/warden-sim/control")
        assert control.status_code == 200
        snapshot = control.json()
        assert snapshot["profile"] == "healthy"
        result = await http.post("/warden-sim/control", json={"profile": "critical"})
        assert result.status_code == 200
        snapshot = (await http.get("/warden-sim/control")).json()
        assert snapshot["profile"] == "critical"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_unknown_profile_is_rejected(self, http: httpx.AsyncClient) -> None:
        response = await http.post("/warden-sim/control", json={"profile": "no-such-profile"})
        assert response.status_code == 400

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_healthy_system_state(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        body = (await authed_get(http, token, f"{BASE}/Systems/1")).json()
        assert body["PowerState"] == "On"
        assert body["Status"]["Health"] == "OK"
        assert body["Actions"]["#ComputerSystem.Reset"]["target"] == (f"{BASE}/Systems/1/Actions/ComputerSystem.Reset")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_critical_profile_system_health(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "critical"})
        token, _ = await login(http)
        body = (await authed_get(http, token, f"{BASE}/Systems/1")).json()
        assert body["Status"]["Health"] == "Critical"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_critical_chassis_indicator_intrusion_and_psu(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "critical"})
        token, _ = await login(http)
        chassis = (await authed_get(http, token, f"{BASE}/Chassis/1")).json()
        assert chassis["IndicatorLED"] == "Blinking"
        assert chassis["PhysicalSecurity"]["IntrusionSensor"] == "HardwareIntrusionDetected"
        power = (await authed_get(http, token, f"{BASE}/Chassis/1/Power")).json()
        psus = {psu["Id"]: psu for psu in power["PowerSupplies"]}
        assert psus["PSU1"]["Status"]["Health"] == "OK"
        assert psus["PSU2"]["Status"]["State"] == "Absent"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_critical_thermal_sensors(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "critical"})
        token, _ = await login(http)
        thermal = (await authed_get(http, token, f"{BASE}/Chassis/1/Thermal")).json()
        temps = {item["Name"]: item for item in thermal["Temperatures"]}
        cpu1 = temps["CPU1 Temp"]
        assert cpu1["ReadingCelsius"] > cpu1["UpperThresholdCritical"]
        fans = {item["Name"]: item for item in thermal["Fans"]}
        assert fans["FAN3"]["Status"]["Health"] == "Critical"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_healthy_thermal_is_within_thresholds(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        thermal = (await authed_get(http, token, f"{BASE}/Chassis/1/Thermal")).json()
        for item in thermal["Temperatures"]:
            assert item["ReadingCelsius"] < item["UpperThresholdCritical"]
        for fan in thermal["Fans"]:
            assert fan["Reading"] > fan["LowerThresholdCritical"]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_auth_fail_profile_rejects_login(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "auth_fail"})
        response = await http.post(
            f"{BASE}/SessionService/Sessions",
            json={"UserName": USER, "Password": PASSWORD},
        )
        assert response.status_code == 401


class TestComponents:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_memory_dimm_health_and_oem_ecc(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "critical"})
        token, _ = await login(http)
        for dimm_id in ("DIMM0", "DIMM1"):
            body = (await authed_get(http, token, f"{BASE}/Systems/1/Memory/{dimm_id}")).json()
            assert body["Id"] == dimm_id
            assert body["CapacityMiB"] > 0
        dimm1 = (await authed_get(http, token, f"{BASE}/Systems/1/Memory/DIMM1")).json()
        assert dimm1["Status"]["Health"] == "Critical"
        assert dimm1["Oem"]["Vendor"]["UncorrectableECCErrorCount"] == 7

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_drives_volumes_and_predictive_failure(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "critical"})
        token, _ = await login(http)
        drives = (await authed_get(http, token, f"{BASE}/Systems/1/Storage/SATA1/Drives")).json()
        ids = [entry["@odata.id"].rsplit("/", 1)[-1] for entry in drives["Members"]]
        assert "sda" in ids and "sdb" in ids
        sdb = (await authed_get(http, token, f"{BASE}/Systems/1/Storage/SATA1/Drives/sdb")).json()
        assert sdb["Status"]["Health"] == "Critical"
        assert sdb["Oem"]["Vendor"]["PredictiveFailure"] is True
        volume = (await authed_get(http, token, f"{BASE}/Systems/1/Storage/SATA1/Volumes/RAID6_1")).json()
        assert volume["VolumeType"] == "RAID6"
        assert volume["Oem"]["Vendor"]["RAIDStatus"] == "Degraded"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_healthy_drives_are_ok(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        sda = (await authed_get(http, token, f"{BASE}/Systems/1/Storage/SATA1/Drives/sda")).json()
        assert sda["Status"]["Health"] == "OK"
        assert sda["Oem"]["Vendor"]["PredictiveFailure"] is False
        volume = (await authed_get(http, token, f"{BASE}/Systems/1/Storage/SATA1/Volumes/RAID6_1")).json()
        assert volume["Oem"]["Vendor"]["RAIDStatus"] == "Optimal"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_managers_resource_and_log_service_links(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        manager = (await authed_get(http, token, f"{BASE}/Managers/1")).json()
        assert manager["ManagerType"] == "BMC"
        assert manager["FirmwareVersion"]
        assert manager["LogServices"]["@odata.id"] == f"{BASE}/Managers/1/LogServices"
        assert manager["VirtualMedia"]["@odata.id"] == f"{BASE}/Managers/1/VirtualMedia"
        sel = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL")).json()
        assert sel["Entries"]["@odata.id"] == f"{BASE}/Managers/1/LogServices/SEL/Entries"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_firmware_inventory_versions(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        bmc = (await authed_get(http, token, f"{BASE}/UpdateService/FirmwareInventory/BMC")).json()
        assert bmc["Version"] == "SIM-BMC-1.0.0"
        assert bmc["Status"]["Health"] == "OK"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_virtual_media_mount_cycle(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        media = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
        assert media["Inserted"] is False
        insert = await http.post(
            f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia",
            json={"Image": "https://files.warden.example/iso/win2019.iso?token=abc"},
            headers={"X-Auth-Token": token},
        )
        assert insert.status_code == 204
        media = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
        assert media["Inserted"] is True
        assert media["Image"] == "https://files.warden.example/iso/win2019.iso?token=abc"
        eject = await http.post(
            f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.EjectMedia",
            headers={"X-Auth-Token": token},
        )
        assert eject.status_code == 204
        media = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
        assert media["Inserted"] is False

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_media_host_allowlist_rejects_foreign_image_url(self, http: httpx.AsyncClient) -> None:
        # A fresh app with a host allowlist: only the platform file host may be used.
        app = create_simulator(SimulatorConfig(media_hosts_required=True, media_hosts=["files.warden.example"]))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://sim", timeout=5.0) as client:
            token, _ = await login(client)
            bad = await client.post(
                f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia",
                json={"Image": "https://evil.example/iso/x.iso"},
                headers={"X-Auth-Token": token},
            )
            assert bad.status_code == 400
            good = await client.post(
                f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia",
                json={"Image": "https://files.warden.example/iso/x.iso?token=t"},
                headers={"X-Auth-Token": token},
            )
            assert good.status_code == 204

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_eject_without_media_is_400(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.EjectMedia",
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 400


class TestTasksAndActions:
    async def _task_uri(self, http: httpx.AsyncClient, token: str) -> str:
        response = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
            json={"ResetType": "GracefulRestart"},
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 202
        assert response.headers["location"].startswith(f"{BASE}/TaskService/Tasks/")
        return response.headers["location"]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_reset_action_creates_completing_task(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"task_duration_seconds": 0.05})
        token, _ = await login(http)
        task_uri = await self._task_uri(http, token)
        body = (await authed_get(http, token, task_uri)).json()
        assert body["TaskState"] in ("Running", "Completed")
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            body = (await authed_get(http, token, task_uri)).json()
            if body["TaskState"] == "Completed":
                break
            await asyncio.sleep(0.02)
        assert body["TaskState"] == "Completed"
        assert body["TaskStatus"] == "OK"
        monitor = (await authed_get(http, token, f"{task_uri}/TaskMonitor")).json()
        assert monitor["PercentComplete"] == 100

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_task_failure_injection_ends_exception(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={"failures": {"reset_task_fails": True}, "task_duration_seconds": 0.05},
        )
        token, _ = await login(http)
        task_uri = await self._task_uri(http, token)
        deadline = time.monotonic() + 2.0
        body = {}
        while time.monotonic() < deadline:
            body = (await authed_get(http, token, task_uri)).json()
            if body["TaskState"] in ("Exception", "Killed", "Completed"):
                break
            await asyncio.sleep(0.02)
        assert body["TaskState"] == "Exception"
        assert body["Messages"] and body["Messages"][0]["Message"]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_reset_rejected_400_uses_extended_error(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"failures": {"reset_rejected_400": True}})
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
            json={"ResetType": "ForceRestart"},
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 400
        info = response.json()["error"]["@Message.ExtendedInfo"]
        ids = [member["MessageId"] for member in info]
        assert "Base.1.13.ActionNotSupported" in ids

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_reset_forbidden_403_uses_extended_error(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"failures": {"reset_forbidden_403": True}})
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
            json={"ResetType": "ForceRestart"},
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 403
        info = response.json()["error"]["@Message.ExtendedInfo"]
        assert any(member["MessageId"] == "Base.1.13.InsufficientPrivilege" for member in info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_reset_type_validation_400(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
            json={"ResetType": "Bogus"},
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 400

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_read_failure_injection_500(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"failures": {"reads_500": True}})
        token, _ = await login(http)
        response = await authed_get(http, token, f"{BASE}/Systems/1")
        assert response.status_code == 500
        assert response.json()["error"]["code"].startswith("Base.1.")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_read_failure_injection_403(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"failures": {"reads_403": True}})
        token, _ = await login(http)
        response = await authed_get(http, token, f"{BASE}/Systems/1")
        assert response.status_code == 403
        info = response.json()["error"]["@Message.ExtendedInfo"]
        assert any(member["MessageId"] == "Base.1.13.InsufficientPrivilege" for member in info)
        # The control endpoint itself stays reachable so tests can reset.
        control = await http.get("/warden-sim/control")
        assert control.status_code == 200

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_unknown_action_target_is_404(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.DoSomething",
            json={},
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 404

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_simple_update_creates_task(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"task_duration_seconds": 0.05})
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/UpdateService/Actions/UpdateService.SimpleUpdate",
            json={
                "Target": f"{BASE}/UpdateService/FirmwareInventory/BMC",
                "ImageURI": "http://127.0.0.1:1/noop.iso",
            },
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 202
        task_uri = response.headers["location"]
        deadline = time.monotonic() + 2.0
        body = {}
        while time.monotonic() < deadline:
            body = (await authed_get(http, token, task_uri)).json()
            if body["TaskState"] == "Completed":
                break
            await asyncio.sleep(0.02)
        assert body["TaskState"] == "Completed"


class TestSELPagination:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_slow_paginated_profile_serves_150_entries_in_pages_of_20(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "slow_paginated"})
        token, _ = await login(http)
        page1 = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries")).json()
        assert page1["Members@odata.count"] == 150
        assert len(page1["Members"]) == 20
        page2 = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip=20")).json()
        assert len(page2["Members"]) == 20
        assert page2["Members"][0]["Id"] != page1["Members"][0]["Id"]
        last = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip=140")).json()
        assert len(last["Members"]) == 10

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_next_link_pagination_style(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={"profile": "slow_paginated", "pagination": "next_link"},
        )
        token, _ = await login(http)
        page1 = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries")).json()
        assert "@odata.nextLink" in page1
        assert page1["@odata.nextLink"] == f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip=20"
        page2 = (await authed_get(http, token, page1["@odata.nextLink"])).json()
        assert len(page2["Members"]) == 20
        assert "@odata.nextLink" in page2
        last = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip=140")).json()
        assert "@odata.nextLink" not in last

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_sel_append_grows_tail_across_page_boundaries(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={"profile": "slow_paginated", "sel_append": 25},
        )
        token, _ = await login(http)
        page1 = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries")).json()
        assert page1["Members@odata.count"] == 175
        assert len(page1["Members"]) == 20
        # The appended entries live at the tail of the collection, spanning
        # the page boundary at $skip=150 (SEL000151..SEL000175).
        boundary = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip=150")).json()
        assert len(boundary["Members"]) == 20
        assert boundary["Members"][0]["Id"] == "SEL000151"
        assert boundary["Members"][-1]["Id"] == "SEL000170"
        last = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip=170")).json()
        assert [member["Id"] for member in last["Members"]] == [
            "SEL000171",
            "SEL000172",
            "SEL000173",
            "SEL000174",
            "SEL000175",
        ]
        # Appended entries are strictly newer than the base tail: the last
        # base entry (SEL000150, first member of the $skip=149 page) and the
        # first appended one are 13 min apart on the same clock as the base
        # entries.
        base_newest = (
            (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries?$skip=149")).json()
        )["Members"][0]
        assert base_newest["Id"] == "SEL000150"
        assert boundary["Members"][0]["Created"] > base_newest["Created"]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_sel_append_is_rejected_when_not_a_count(self, http: httpx.AsyncClient) -> None:
        response = await http.post("/warden-sim/control", json={"sel_append": "many"})
        assert response.status_code == 400
        response = await http.post("/warden-sim/control", json={"sel_append": True})
        assert response.status_code == 400
        response = await http.post("/warden-sim/control", json={"sel_append": -1})
        assert response.status_code == 400

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_sel_entries_carry_event_fields(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        entries = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries")).json()
        entry = entries["Members"][0]
        assert entry["Id"]
        assert entry["Created"]
        assert entry["Message"]
        assert entry["Severity"] in ("OK", "Warning", "Critical")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_critical_profile_sel_has_critical_entries(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"profile": "critical"})
        token, _ = await login(http)
        entries = (await authed_get(http, token, f"{BASE}/Managers/1/LogServices/SEL/Entries")).json()
        severities = {entry["Severity"] for entry in entries["Members"]}
        assert "Critical" in severities


class TestAbsoluteLinks:
    """absolute_links mode: path-only links rewritten to absolute same-origin URIs."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_absolute_links_emits_absolute_same_origin_uris(self) -> None:
        app = create_simulator(SimulatorConfig(profile="slow_paginated", pagination="next_link", absolute_links=True))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://sim", timeout=5.0) as client:
            token, location = await login(client)
            assert location.startswith("http://sim")
            root = (await authed_get(client, token, f"{BASE}/")).json()
            systems_href = root["Systems"]["@odata.id"]
            assert systems_href.startswith("http://sim")
            systems = (await authed_get(client, token, systems_href)).json()
            member_href = systems["Members"][0]["@odata.id"]
            assert member_href.startswith("http://sim")
            system = (await authed_get(client, token, member_href)).json()
            assert system["Actions"]["#ComputerSystem.Reset"]["target"].startswith("http://sim")
            entries = (await authed_get(client, token, f"{BASE}/Managers/1/LogServices/SEL/Entries")).json()
            assert entries["@odata.nextLink"].startswith("http://sim")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_absolute_links_flag_is_configurable_via_control(self) -> None:
        transport = httpx.ASGITransport(app=create_simulator(SimulatorConfig()))
        async with httpx.AsyncClient(transport=transport, base_url="http://sim", timeout=5.0) as client:
            snapshot = (await client.get("/warden-sim/control")).json()
            assert snapshot["absolute_links"] is False
            result = await client.post("/warden-sim/control", json={"absolute_links": True})
            assert result.status_code == 200
            snapshot = (await client.get("/warden-sim/control")).json()
            assert snapshot["absolute_links"] is True
            token, location = await login(client)
            assert location.startswith("http://sim")
            root = (await authed_get(client, token, f"{BASE}/")).json()
            assert root["Systems"]["@odata.id"].startswith("http://sim")


class TestOemVendorStubs:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_generic_vendor_oem_block_is_neutral(self, http: httpx.AsyncClient) -> None:
        token, _ = await login(http)
        root = (await authed_get(http, token, f"{BASE}/")).json()
        oem = root["Oem"]
        assert len(oem) == 1
        key, block = next(iter(oem.items()))
        assert key == "Vendor"
        assert block["@odata.type"].startswith("#WardenSim")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_vendor_switch_returns_vendor_oem_types(self, http: httpx.AsyncClient) -> None:
        for vendor in ("dell", "inspur", "xfusion", "lenovo", "huawei"):
            await http.post("/warden-sim/control", json={"vendor": vendor})
            token, _ = await login(http)
            root = (await authed_get(http, token, f"{BASE}/")).json()
            oem = root["Oem"]
            # Vendor keys are title-cased (dell -> Dell, xfusion -> XFusion).
            assert any(key.lower() == vendor for key in oem)
            block = oem[[key for key in oem if key.lower() == vendor][0]]
            assert block["@odata.type"].startswith("#")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_vendor_odata_type_on_memory_oem_extension(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"vendor": "dell"})
        token, _ = await login(http)
        dimm0 = (await authed_get(http, token, f"{BASE}/Systems/1/Memory/DIMM0")).json()
        block = dimm0["Oem"]["Dell"]
        assert block["@odata.type"].startswith("#Dell.")
        assert "CorrectableECCErrorCount" in block

class TestM3T3OperationSurface:
    """M3T3 operation semantics: power effects, manager restart, update, media."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_system_reset_graceful_shutdown_powers_off_then_on_restarts(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={"task_duration_seconds": 0.05, "power_blip_seconds": 0.3},
        )
        token, _ = await login(http)

        async def power_state() -> str:
            system = (await authed_get(http, token, f"{BASE}/Systems/1")).json()
            return system["PowerState"]

        assert await power_state() == "On"
        # GracefulShutdown: the reset task completion powers the system off.
        shutdown = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
            json={"ResetType": "GracefulShutdown"},
            headers={"X-Auth-Token": token},
        )
        assert shutdown.status_code == 202
        task_uri = shutdown.headers["location"]
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            body = (await authed_get(http, token, task_uri)).json()
            if body["TaskState"] == "Completed":
                break
            await asyncio.sleep(0.02)
        assert await power_state() == "Off"
        # ForceRestart from Off reboots back On through an Off blip window.
        restart = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
            json={"ResetType": "ForceRestart"},
            headers={"X-Auth-Token": token},
        )
        assert restart.status_code == 202
        restart_uri = restart.headers["location"]
        deadline = time.monotonic() + 2.0
        observed: list[str] = []
        while time.monotonic() < deadline:
            state = (await authed_get(http, token, restart_uri)).json()["TaskState"]
            observed.append(await power_state())
            if state == "Completed" and observed[-1] == "On":
                break
            await asyncio.sleep(0.02)
        assert "Off" in observed, "the reboot blip window must be observable"
        assert observed[-1] == "On"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_power_readback_stale_freezes_power_state(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={"task_duration_seconds": 0.05, "power_readback_stale": True},
        )
        token, _ = await login(http)
        shutdown = await http.post(
            f"{BASE}/Systems/1/Actions/ComputerSystem.Reset",
            json={"ResetType": "GracefulShutdown"},
            headers={"X-Auth-Token": token},
        )
        assert shutdown.status_code == 202
        task_uri = shutdown.headers["location"]
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            body = (await authed_get(http, token, task_uri)).json()
            if body["TaskState"] == "Completed":
                break
            await asyncio.sleep(0.02)
        system = (await authed_get(http, token, f"{BASE}/Systems/1")).json()
        assert system["PowerState"] == "On"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_manager_reset_invalidates_sessions_and_503_window(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"manager_blip_seconds": 0.6})
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/Managers/1/Actions/Manager.Reset",
            json={"ResetType": "GracefulRestart"},
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 202
        task_uri = response.headers["location"]
        # During the restart window every Redfish request answers 503.
        offline = await authed_get(http, token, f"{BASE}/Managers/1")
        assert offline.status_code == 503
        gone = await authed_get(http, token, task_uri)
        assert gone.status_code == 503
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            probe = await authed_get(http, token, f"{BASE}/Managers/1")
            if probe.status_code != 503:
                break
            await asyncio.sleep(0.05)
        # The manager is back: the old session token died with the reboot and
        # the reset task record vanished; a fresh session sees the same UUID.
        assert probe.status_code == 401
        assert (await authed_get(http, token, task_uri)).status_code == 401
        fresh_token, _ = await login(http)
        manager = (await authed_get(http, fresh_token, f"{BASE}/Managers/1")).json()
        assert manager["UUID"] == "66666666-7777-8888-9999-aaaaaaaaaaaa"
        assert (await authed_get(http, fresh_token, task_uri)).status_code == 404

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_simple_update_bumps_firmware_version_and_knobs(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={
                "task_duration_seconds": 0.05,
                "firmware_update_version": "SIM-BMC-1.1.0",
            },
        )
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/UpdateService/Actions/UpdateService.SimpleUpdate",
            json={
                "Targets": [f"{BASE}/UpdateService/FirmwareInventory/BMC"],
                "ImageURI": "http://127.0.0.1:1/fw.iso",
            },
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 202
        task_uri = response.headers["location"]
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            body = (await authed_get(http, token, task_uri)).json()
            if body["TaskState"] == "Completed":
                break
            await asyncio.sleep(0.02)
        inventory = (await authed_get(http, token, f"{BASE}/UpdateService/FirmwareInventory/BMC")).json()
        assert inventory["Version"] == "SIM-BMC-1.1.0"
        manager = (await authed_get(http, token, f"{BASE}/Managers/1")).json()
        assert manager["FirmwareVersion"] == "SIM-BMC-1.1.0"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_update_task_failure_and_never_completes(self, http: httpx.AsyncClient) -> None:
        await http.post("/warden-sim/control", json={"failures": {"update_task_fails": True}})
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/UpdateService/Actions/UpdateService.SimpleUpdate",
            json={"Targets": [], "ImageURI": "http://127.0.0.1:1/x.iso"},
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 400  # empty Targets -> ActionParameterValueNotInList
        response = await http.post(
            f"{BASE}/UpdateService/Actions/UpdateService.SimpleUpdate",
            json={
                "Targets": [f"{BASE}/UpdateService/FirmwareInventory/BMC"],
                "ImageURI": "http://127.0.0.1:1/x.iso",
            },
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 202
        task_uri = response.headers["location"]
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            body = (await authed_get(http, token, task_uri)).json()
            if body["TaskState"] in ("Exception", "Completed"):
                break
            await asyncio.sleep(0.02)
        assert body["TaskState"] == "Exception"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_update_fetch_required_reads_image_header(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={"task_duration_seconds": 0.05, "update_fetch_required": True},
        )
        token, _ = await login(http)
        response = await http.post(
            f"{BASE}/UpdateService/Actions/UpdateService.SimpleUpdate",
            json={
                "Targets": [f"{BASE}/UpdateService/FirmwareInventory/BMC"],
                "ImageURI": "http://not-reachable.invalid/x.iso",
            },
            headers={"X-Auth-Token": token},
        )
        assert response.status_code == 400

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_media_insert_allowlist_and_state(self, http: httpx.AsyncClient) -> None:
        await http.post(
            "/warden-sim/control",
            json={
                "media_insert_rejects_foreign_url": True,
                "media_hosts": ["127.0.0.1"],
            },
        )
        token, _ = await login(http)
        insert = await http.post(
            f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia",
            json={"Image": "http://evil.example.com/iso", "Inserted": True, "WriteProtected": True},
            headers={"X-Auth-Token": token},
        )
        assert insert.status_code == 400
        slot = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
        assert slot["Inserted"] is False
        ok = await http.post(
            f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia",
            json={"Image": "http://127.0.0.1:1/iso.iso", "Inserted": True, "WriteProtected": True},
            headers={"X-Auth-Token": token},
        )
        assert ok.status_code == 204
        slot = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
        assert slot["Inserted"] is True
        assert slot["Image"] == "http://127.0.0.1:1/iso.iso"
        eject = await http.post(
            f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.EjectMedia",
            headers={"X-Auth-Token": token},
        )
        assert eject.status_code == 204
        slot = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
        assert slot["Inserted"] is False

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_media_insert_delayed_applies_after_the_staging_delay(
        self, http: httpx.AsyncClient
    ) -> None:
        await http.post("/warden-sim/control", json={"media_insert_delayed": True})
        token, _ = await login(http)
        insert = await http.post(
            f"{BASE}/Managers/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia",
            json={"Image": "http://127.0.0.1:1/iso.iso", "Inserted": True, "WriteProtected": True},
            headers={"X-Auth-Token": token},
        )
        assert insert.status_code == 204
        # Acceptance is immediate but the slot state applies asynchronously.
        slot = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
        assert slot["Inserted"] is False
        assert slot["Image"] is None
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            slot = (await authed_get(http, token, f"{BASE}/Managers/1/VirtualMedia/1")).json()
            if slot["Inserted"] is True:
                break
            await asyncio.sleep(0.05)
        assert slot["Inserted"] is True
        assert slot["Image"] == "http://127.0.0.1:1/iso.iso"
