"""M4T2 fixture drift check (tests/fixtures/dsm, provenance policy).

Each M4T2 fixture JSON is a FROZEN contract snapshot captured over real
HTTP from the DSM TEST SIMULATOR (模拟器来源 only — never 真机). This module
verifies every snapshot still equals what the simulator emits for its
documented profile/knobs: a drift means the snapshot must be re-taken AND
its provenance row updated in the README — never silently regenerated
(tests/fixtures/dsm/README.md rules + tests/simulators/dsm/README.md basis).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.simulators.dsm.payloads import (
    SimulatorConfig,
    api_info_payload,
    log_entries_payload,
    profile_config,
    share_payload,
    storage_payload,
    system_info_payload,
    ups_payload,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "dsm"


def _load(name: str) -> dict[str, object]:
    payload: dict[str, object] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload


@pytest.mark.unit
@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("info-query-ds224plus.json", api_info_payload(profile_config("ds224plus").effective_map())),
        ("system-info-ds224plus.json", system_info_payload(profile_config("ds224plus"))),
        ("system-info-ds225plus.json", system_info_payload(profile_config("ds225plus"))),
        ("storage-ds224plus-healthy.json", storage_payload(profile_config("ds224plus"))),
        ("storage-pool-rebuilding.json", storage_payload(SimulatorConfig(profile="ds224plus", pool_rebuilding=True))),
        ("share-list-ds224plus.json", share_payload(profile_config("ds224plus"))),
        (
            "share-list-no-quota.json",
            share_payload(SimulatorConfig(profile="ds224plus", share_no_quota=True)),
        ),
        ("ups-normal-ds224plus.json", ups_payload(profile_config("ds224plus"))),
        ("ups-on-battery.json", ups_payload(SimulatorConfig(profile="ds224plus", ups_on_battery=True))),
        ("log-page1-ds224plus.json", log_entries_payload(profile_config("ds224plus"), offset=0, limit=5)),
    ],
)
def test_m4t2_fixtures_match_simulator_payloads(filename: str, expected: dict[str, object]) -> None:
    assert _load(filename) == expected


@pytest.mark.unit
def test_ds224plus_info_fixture_advertises_share_api() -> None:
    body = _load("info-query-ds224plus.json")
    data = body["data"]
    assert isinstance(data, dict)
    assert "SYNO.Core.Share" in data


@pytest.mark.unit
def test_share_fixtures_carry_usage_denominators() -> None:
    body = _load("share-list-ds224plus.json")
    data = body["data"]
    assert isinstance(data, dict)
    shares = data["shares"]
    assert isinstance(shares, list)
    assert shares[0]["quota_bytes"] > 0
    no_quota = _load("share-list-no-quota.json")
    no_quota_data = no_quota["data"]
    assert isinstance(no_quota_data, dict)
    backup = next(share for share in no_quota_data["shares"] if isinstance(share, dict) and share["id"] == "backup")
    assert backup["quota_bytes"] == 0


@pytest.mark.unit
def test_rebuilding_fixture_carries_rebuild_progress() -> None:
    body = _load("storage-pool-rebuilding.json")
    data = body["data"]
    assert isinstance(data, dict)
    pool = data["pool"][0]
    assert isinstance(pool, dict)
    assert pool["status"] == "Rebuilding"
    assert pool["rebuild_progress"] == 45


@pytest.mark.unit
def test_identity_fixtures_keep_simulated_markers() -> None:
    for name in ("system-info-ds224plus.json", "system-info-ds225plus.json"):
        body = _load(name)
        data = body["data"]
        assert isinstance(data, dict)
        assert "(simulated)" in str(data["model"])
