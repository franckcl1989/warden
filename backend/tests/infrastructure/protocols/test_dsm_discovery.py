"""DSM discovery tests: SYNO.API.Info.Query parsing, negotiation, gaps.

docs/DEVICE_ADAPTERS.md §5 + ADR-018: the discovered map is the versioned
basis; the negotiated version never exceeds the platform's certified row;
missing APIs surface as explicit gaps (never guessed URLs).
"""

from __future__ import annotations

import pytest
from app.infrastructure.protocols.dsm.discovery import (
    REASON_DEVICE_TOO_OLD,
    REASON_NOT_CERTIFIED,
    REASON_NOT_DISCOVERED,
    REASON_RANGE_MISMATCH,
    ApiInfo,
    DiscoveryEvidence,
    Negotiation,
    missing_apis,
    negotiate,
    parse_api_map,
)
from app.infrastructure.protocols.dsm.errors import DSMError


def _map() -> dict[str, object]:
    return {
        "SYNO.API.Info": {"path": "query.cgi", "minVersion": 1, "maxVersion": 1},
        "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 6},
        "SYNO.Storage.CGI.Storage": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 3},
        "SYNO.Core.UPS": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    }


class TestParseApiMap:
    def test_parses_discovery_data(self) -> None:
        parsed = parse_api_map(_map())
        assert set(parsed) == {
            "SYNO.API.Info",
            "SYNO.API.Auth",
            "SYNO.Storage.CGI.Storage",
            "SYNO.Core.UPS",
        }
        auth = parsed["SYNO.API.Auth"]
        assert auth.path == "auth.cgi"
        assert auth.min_version == 1
        assert auth.max_version == 6

    def test_entry_with_query_in_path_is_protocol_error(self) -> None:
        data = _map()
        data["SYNO.API.Auth"] = {"path": "auth.cgi?bogus=1", "minVersion": 1, "maxVersion": 6}
        with pytest.raises(DSMError) as exc:
            parse_api_map(data)
        assert exc.value.code == "protocol_error"

    def test_entry_with_inverted_range_is_protocol_error(self) -> None:
        data = _map()
        data["SYNO.API.Auth"] = {"path": "auth.cgi", "minVersion": 7, "maxVersion": 2}
        with pytest.raises(DSMError) as exc:
            parse_api_map(data)
        assert exc.value.code == "protocol_error"

    def test_non_object_data_is_protocol_error(self) -> None:
        with pytest.raises(DSMError) as exc:
            parse_api_map(["not", "a", "map"])
        assert exc.value.code == "protocol_error"

    def test_string_versions_are_rejected(self) -> None:
        data = _map()
        data["SYNO.API.Auth"] = {"path": "auth.cgi", "minVersion": "1", "maxVersion": "6"}
        with pytest.raises(DSMError):
            parse_api_map(data)


class TestNegotiation:
    def test_negotiates_down_to_certified_version(self) -> None:
        api = ApiInfo(name="SYNO.API.Auth", path="auth.cgi", min_version=1, max_version=9)
        result = negotiate(api, certified_version=6)
        assert result.callable
        assert result.spec is not None
        assert result.spec.version == 6  # never above the certified version

    def test_never_calls_above_certified_version(self) -> None:
        api = ApiInfo(name="SYNO.API.Auth", path="auth.cgi", min_version=1, max_version=99)
        result = negotiate(api, certified_version=6)
        assert result.spec is not None
        assert result.spec.version == 6

    def test_device_too_old_is_refused(self) -> None:
        api = ApiInfo(name="SYNO.API.Auth", path="auth.cgi", min_version=1, max_version=5)
        result = negotiate(api, certified_version=6)
        assert not result.callable
        assert result.reason == REASON_DEVICE_TOO_OLD

    def test_device_range_above_certified_is_refused(self) -> None:
        api = ApiInfo(name="SYNO.Storage.CGI.Storage", path="entry.cgi", min_version=8, max_version=12)
        result = negotiate(api, certified_version=6)
        assert not result.callable
        assert result.reason == REASON_RANGE_MISMATCH

    def test_uncertified_api_is_refused(self) -> None:
        api = ApiInfo(name="SYNO.Core.Bogus", path="entry.cgi", min_version=1, max_version=1)
        result = negotiate(api, certified_version=None)
        assert not result.callable
        assert result.reason == REASON_NOT_CERTIFIED

    def test_undiscovered_api_is_refused(self) -> None:
        result = negotiate(None, certified_version=6)
        assert not result.callable
        assert result.reason == REASON_NOT_DISCOVERED

    def test_certified_version_at_device_min_is_callable(self) -> None:
        api = ApiInfo(name="SYNO.Core.UPS", path="entry.cgi", min_version=6, max_version=6)
        result = negotiate(api, certified_version=6)
        assert result.callable
        assert result.spec is not None
        assert result.spec.version == 6


class TestGapsAndEvidence:
    def test_missing_apis_are_an_explicit_sorted_list(self) -> None:
        parsed = parse_api_map(_map())
        gaps = missing_apis(parsed, frozenset({"SYNO.Storage.CGI.Storage", "SYNO.Core.UPS", "SYNO.Core.Share"}))
        assert gaps == ("SYNO.Core.Share",)

    def test_evidence_freezes_sorted_rows(self) -> None:
        parsed = parse_api_map(_map())
        evidence = DiscoveryEvidence.from_map(parsed)
        names = [row[0] for row in evidence.api_map]
        assert names == sorted(names)
        assert ("SYNO.API.Auth", "auth.cgi", 1, 6) in evidence.api_map
        assert evidence.discovered_at

    def test_negotiation_never_fabricates_when_not_callable(self) -> None:
        result = Negotiation()
        assert result.callable is False
        assert result.spec is None
