"""DSM parse tests: certified mapping tables, tolerant readers, no fakes.

The tables decode the simulator DSL values documented in
``tests/simulators/dsm/README.md`` into the contracts enum sets; a DSM
literal NOT in a table decodes to the contract ``unknown`` sentinel, and
missing/wrong-typed fields decode to None (never 0/normal).
"""

from __future__ import annotations

from app.infrastructure.protocols.dsm import parse
from app.infrastructure.protocols.dsm.parse import (
    disk_smart,
    disk_status,
    fan_status,
    float_value,
    int_value,
    log_severity,
    pool_status,
    text_value,
    ups_status,
    usage_percent,
)


class TestEnumTables:
    def test_disk_status_rows(self) -> None:
        assert disk_status("Healthy") == "ok"
        assert disk_status("Cached") == "ok"
        assert disk_status("Degraded") == "warning"
        assert disk_status("Broken") == "critical"

    def test_unknown_dsm_literal_is_unknown_sentinel(self) -> None:
        assert disk_status("SpinningWithExtraMagic") == "unknown"

    def test_non_string_disk_status_is_unknown(self) -> None:
        assert disk_status(None) == "unknown"
        assert disk_status(7) == "unknown"

    def test_smart_rows(self) -> None:
        assert disk_smart("Normal") == "passed"
        assert disk_smart("Warning") == "warning"
        assert disk_smart("Fail") == "failed"
        assert disk_smart("Testing") == "running"

    def test_pool_rows(self) -> None:
        assert pool_status("Normal") == "optimal"
        assert pool_status("Degraded") == "degraded"
        assert pool_status("Rebuilding") == "rebuilding"
        assert pool_status("Failed") == "failed"

    def test_fan_rows(self) -> None:
        assert fan_status("Normal") == "ok"
        assert fan_status("Error") == "critical"
        assert fan_status("Absent") == "absent"

    def test_ups_rows(self) -> None:
        assert ups_status("Normal") == "normal"
        assert ups_status("On Battery") == "on_battery"
        assert ups_status("Low Battery") == "low_battery"
        assert ups_status("Comms Lost") == "communication_lost"
        assert ups_status("Fault") == "fault"

    def test_log_severity_normalization(self) -> None:
        assert log_severity("INFO") == "info"
        assert log_severity("WARNING") == "warning"
        assert log_severity("ERROR") == "critical"
        assert log_severity("CRITICAL") == "critical"
        assert log_severity("URGENT!!") == "unknown"

    def test_dsm_unknown_literal_maps_to_contract_unknown(self) -> None:
        assert disk_status("Unknown") == "unknown"
        assert ups_status("Unknown") == "unknown"


class TestScalarReaders:
    def test_int_value(self) -> None:
        assert int_value(5) == 5
        assert int_value("5") == 5
        assert int_value("-3") == -3
        assert int_value(" 7 ") == 7
        assert int_value(5.0) == 5
        assert int_value(5.5) is None
        assert int_value(True) is None
        assert int_value("n/a") is None
        assert int_value(None) is None

    def test_float_value(self) -> None:
        assert float_value(41) == 41.0
        assert float_value("41.5") == 41.5
        assert float_value("n/a") is None
        assert float_value(True) is None
        assert float_value("fast") is None

    def test_text_value(self) -> None:
        assert text_value("  ok  ") == "ok"
        assert text_value("-") is None
        assert text_value(5) is None

    def test_usage_percent_computed_from_bytes(self) -> None:
        assert usage_percent(used=1_500_000_000_000, total=4_000_000_000_000) == 37.5
        assert usage_percent(used="1500", total="4000") == 37.5

    def test_usage_percent_never_fabricates_without_denominator(self) -> None:
        assert usage_percent(used=1_500_000_000_000, total=None) is None
        assert usage_percent(used=1_500_000_000_000, total=0) is None
        assert usage_percent(used=None, total=4_000_000_000_000) is None

    def test_usage_overshoot_is_not_clamped_to_fake_100(self) -> None:
        assert usage_percent(used=5_000_000_000_000, total=4_000_000_000_000) is None


class TestTableIntegrity:
    def test_tables_only_map_into_contract_sets(self) -> None:
        component_status = {"unknown", "ok", "warning", "critical", "absent"}
        smart_status = {"unknown", "passed", "warning", "failed", "running"}
        raid_status = {"unknown", "optimal", "degraded", "rebuilding", "failed"}
        ups_state = {"unknown", "normal", "on_battery", "low_battery", "communication_lost", "fault"}
        event_severity = {"unknown", "info", "warning", "critical"}
        assert set(parse.DISK_STATUS_TABLE.values()) <= component_status
        assert set(parse.DISK_SMART_TABLE.values()) <= smart_status
        assert set(parse.POOL_STATUS_TABLE.values()) <= raid_status
        assert set(parse.FAN_STATUS_TABLE.values()) <= component_status
        assert set(parse.UPS_STATUS_TABLE.values()) <= ups_state
        assert set(parse.LOG_LEVEL_TABLE.values()) <= event_severity
