"""Fixture contract tests: canned simulator envelopes stay parseable.

The DSM fixtures (tests/fixtures/dsm/) are 模拟器来源 snapshots captured over
real HTTP from the DSM test simulator. These tests pin the client contract
onto the frozen snapshots (envelope parsing, discovery map shape, certified
parse tables) so silent simulator evolution cannot drift the fixtures, and
they assert the provenance index covers every file (never a 真机 claim).
"""

from __future__ import annotations

import json
from pathlib import Path

from app.infrastructure.protocols.dsm.discovery import parse_api_map
from app.infrastructure.protocols.dsm.errors import envelope_data
from app.infrastructure.protocols.dsm.parse import (
    disk_smart,
    disk_status,
    fan_status,
    log_severity,
    pool_status,
    usage_percent,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "dsm"
README = FIXTURES / "README.md"

FIXTURE_FILES = (
    "info-query-all-healthy.json",
    "info-query-api-map-missing.json",
    "login-otp-required.json",
    "system-info-healthy.json",
    "storage-degraded.json",
    "log-page1-healthy.json",
)


def load(name: str) -> dict[str, object]:
    payload: dict[str, object] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload


class TestProvenance:
    def test_index_covers_every_fixture(self) -> None:
        readme = README.read_text(encoding="utf-8")
        assert "模拟器来源" in readme
        assert "TEST SIMULATOR" in readme
        assert "never a 真机 claim" in readme or "real device" in readme
        for name in FIXTURE_FILES:
            assert (FIXTURES / name).exists()
            assert f"`{name}`" in readme, f"{name} missing from the README index"

    def test_no_secret_bearing_bodies_in_fixtures(self) -> None:
        rendered = "\n".join((FIXTURES / name).read_text(encoding="utf-8") for name in FIXTURE_FILES)
        assert "sid" not in rendered or '"sid"' not in rendered
        assert "sim-pass-1" not in rendered
        assert "passwd" not in rendered


class TestEnvelopes:
    def test_all_fixtures_are_valid_envelopes(self) -> None:
        for name in FIXTURE_FILES:
            body = load(name)
            ok, data, code = envelope_data(body)
            assert isinstance(body, dict)
            if name.startswith(("info-query", "system", "log-page")) or "storage" in name:
                assert ok is True
                assert data is not None
            else:
                assert ok is False
                assert code is not None


class TestDiscoveryFixtures:
    def test_healthy_map_shape(self) -> None:
        ok, data, _ = envelope_data(load("info-query-all-healthy.json"))
        assert ok
        assert data is not None
        api_map = parse_api_map(data)
        auth = api_map["SYNO.API.Auth"]
        assert auth.path == "auth.cgi"
        assert auth.max_version == 6
        storage = api_map["SYNO.Storage.CGI.Storage"]
        assert storage.path == "entry.cgi"
        assert storage.min_version == 1

    def test_api_map_missing_fixture_has_no_storage_api(self) -> None:
        ok, data, _ = envelope_data(load("info-query-api-map-missing.json"))
        assert ok
        api_map = parse_api_map(data)
        assert "SYNO.Storage.CGI.Storage" not in api_map
        assert "SYNO.Core.UPS" in api_map


class TestParseFixtures:
    def test_healthy_system_info_decodes(self) -> None:
        _, data, _ = envelope_data(load("system-info-healthy.json"))
        assert isinstance(data, dict)
        fans = data["fan"]
        assert all(fan_status(fan["status"]) == "ok" for fan in fans)
        assert fans[0]["rpm"] == 2100

    def test_storage_degraded_fixture_decodes_to_contracts(self) -> None:
        _, data, _ = envelope_data(load("storage-degraded.json"))
        assert isinstance(data, dict)
        disk_by_id = {disk["id"]: disk for disk in data["disk"]}
        assert disk_status(disk_by_id["sata1"]["status"]) == "ok"
        assert disk_status(disk_by_id["sata2"]["status"]) == "critical"
        assert disk_smart(disk_by_id["sata2"]["smart"]) == "failed"
        assert disk_by_id["sata2"]["bad_sectors"] == 512
        assert pool_status(data["pool"][0]["status"]) == "degraded"
        volume = data["volume"][0]
        percent = usage_percent(used=volume["used_bytes"], total=volume["total_bytes"])
        assert percent is not None
        assert 0.0 < percent < 100.0

    def test_log_page_fixture_carries_event_fields(self) -> None:
        _, data, _ = envelope_data(load("log-page1-healthy.json"))
        assert isinstance(data, dict)
        assert data["total"] == 24
        entries = data["log"]
        assert len(entries) == 5
        assert [entry["id"] for entry in entries] == [1, 2, 3, 4, 5]
        for entry in entries:
            assert log_severity(entry["level"]) in {"info", "warning", "critical"}
            assert entry["message"]

    def test_login_otp_fixture_is_the_two_factor_row(self) -> None:
        ok, _, code = envelope_data(load("login-otp-required.json"))
        assert ok is False
        assert code == 403
