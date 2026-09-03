"""Redfish tolerant DTO parsing tests (docs/DEVICE_ADAPTERS.md §4).

- ``@odata.type`` is parsed by SCHEMA FAMILY, never by specific minor version;
- missing/unknown fields yield typed sentinels, never 0/normal fakes;
- link following is bounded and same-origin only;
- collection walking handles Members + @odata.count with ``@odata.nextLink``
  and ``$skip`` fallback variants, with loop protection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest
from app.infrastructure.protocols.redfish.errors import RedfishError
from app.infrastructure.protocols.redfish.parse import (
    MAX_LINK_DEPTH,
    FieldSentinel,
    HttpReply,
    RedfishResource,
    bool_field,
    datetime_field,
    follow,
    is_sentinel,
    member_links,
    number_field,
    resolve_odata_id,
    schema_family,
    schema_version,
    text_field,
    walk_collection,
)

BMC = "http://bmc.test"


@dataclass
class FakeClient:
    """Minimal duck of the client: records requested paths, serves payloads."""

    routes: dict[str, tuple[int, Any]]
    requests: list[str] = field(default_factory=list)
    base_origin: str = BMC

    def request(self, method: str, url: str, json: Any = None) -> HttpReply:
        assert method == "GET"
        assert json is None
        path = url
        if url.startswith(BMC):
            path = url[len(BMC) :]
        self.requests.append(path)
        if path not in self.routes:
            raise AssertionError(f"no route for {path}")
        status, payload = self.routes[path]
        if status >= 400:
            from app.infrastructure.protocols.redfish.errors import map_http_error

            raise map_http_error(status, payload, context="read")
        return HttpReply(status_code=status, payload=payload, headers={})


class TestSchemaFamily:
    @pytest.mark.unit
    def test_family_and_version_parsed(self) -> None:
        assert schema_family("#Thermal.v1_5_0.Thermal") == "Thermal"
        assert schema_version("#Thermal.v1_5_0.Thermal") == (1, 5, 0)

    @pytest.mark.unit
    def test_family_ignores_minor_version(self) -> None:
        # DEVICE_ADAPTERS.md §4: never require old BMCs to implement the latest
        # schema — both versioned shapes belong to the SAME family.
        assert schema_family("#Thermal.v1_5_0.Thermal") == schema_family("#Thermal.v1_0_0.Thermal")
        assert schema_family("#ComputerSystem.v1_16_0.ComputerSystem") == "ComputerSystem"

    @pytest.mark.unit
    def test_family_without_version_is_tolerated(self) -> None:
        assert schema_family("#Thermal.Thermal") == "Thermal"

    @pytest.mark.unit
    def test_missing_or_garbage_returns_none(self) -> None:
        assert schema_family(None) is None
        assert schema_family("Thermal.v1_0_0") is None
        assert schema_family("") is None
        assert schema_family(42) is None


class TestSentinels:
    @pytest.mark.unit
    def test_sentinels_are_distinct_and_typed(self) -> None:
        assert FieldSentinel.MISSING != FieldSentinel.UNPARSEABLE
        assert is_sentinel(FieldSentinel.MISSING)
        assert not is_sentinel(None)
        assert not is_sentinel(0)
        assert not is_sentinel("")

    @pytest.mark.unit
    def test_text_missing_null_or_empty_are_missing(self) -> None:
        for data in ({}, {"Name": None}, {"Name": ""}):
            assert text_field(data, "Name") is FieldSentinel.MISSING

    @pytest.mark.unit
    def test_text_wrong_type_is_unparseable(self) -> None:
        assert text_field({"Name": 42}, "Name") is FieldSentinel.UNPARSEABLE

    @pytest.mark.unit
    def test_text_value_round_trips(self) -> None:
        assert text_field({"Name": "CPU 1"}, "Name") == "CPU 1"

    @pytest.mark.unit
    def test_number_accepts_numeric_strings(self) -> None:
        assert number_field({"ReadingCelsius": 25}, "ReadingCelsius") == 25
        assert number_field({"ReadingCelsius": 25.5}, "ReadingCelsius") == 25.5
        assert number_field({"ReadingCelsius": "25.5"}, "ReadingCelsius") == 25.5
        assert number_field({"ReadingCelsius": "25"}, "ReadingCelsius") == 25

    @pytest.mark.unit
    def test_number_unavailable_markers_are_missing_not_zero(self) -> None:
        # "never 0/normal fakes": an absent or N/A reading is MISSING, not 0.
        assert number_field({}, "ReadingCelsius") is FieldSentinel.MISSING
        assert number_field({"ReadingCelsius": None}, "ReadingCelsius") is FieldSentinel.MISSING
        assert number_field({"ReadingCelsius": "N/A"}, "ReadingCelsius") is FieldSentinel.MISSING
        assert number_field({"ReadingCelsius": "n/a"}, "ReadingCelsius") is FieldSentinel.MISSING
        assert number_field({"ReadingCelsius": ""}, "ReadingCelsius") is FieldSentinel.MISSING
        assert number_field({"ReadingCelsius": "-"}, "ReadingCelsius") is FieldSentinel.MISSING

    @pytest.mark.unit
    def test_number_garbage_is_unparseable(self) -> None:
        assert number_field({"ReadingCelsius": "high"}, "ReadingCelsius") is FieldSentinel.UNPARSEABLE
        assert number_field({"ReadingCelsius": True}, "ReadingCelsius") is FieldSentinel.UNPARSEABLE

    @pytest.mark.unit
    def test_bool_strict_but_sentinel_safe(self) -> None:

        assert bool_field({"PredictiveFailure": True}, "PredictiveFailure") is True
        assert bool_field({}, "PredictiveFailure") is FieldSentinel.MISSING
        assert bool_field({"PredictiveFailure": "true"}, "PredictiveFailure") is FieldSentinel.UNPARSEABLE

    @pytest.mark.unit
    def test_datetime_parses_and_normalizes_to_utc(self) -> None:
        assert datetime_field({"Created": "2026-09-03T10:11:12Z"}, "Created") == datetime(
            2026, 9, 3, 10, 11, 12, tzinfo=UTC
        )
        assert datetime_field({"Created": "2026-09-03T10:11:12.500+02:00"}, "Created") == datetime(
            2026, 9, 3, 8, 11, 12, 500000, tzinfo=UTC
        )

    @pytest.mark.unit
    def test_datetime_missing_or_naive_or_garbage(self) -> None:
        assert datetime_field({}, "Created") is FieldSentinel.MISSING
        assert datetime_field({"Created": None}, "Created") is FieldSentinel.MISSING
        assert datetime_field({"Created": "2026-09-03 10:11:12"}, "Created") is FieldSentinel.UNPARSEABLE
        assert datetime_field({"Created": "not a date"}, "Created") is FieldSentinel.UNPARSEABLE


class TestLinks:
    @pytest.mark.unit
    def test_resolve_odata_id_shapes(self) -> None:
        assert resolve_odata_id({"@odata.id": "/redfish/v1/Systems/1"}) == "/redfish/v1/Systems/1"
        assert resolve_odata_id("/redfish/v1/Systems/1") == "/redfish/v1/Systems/1"
        assert resolve_odata_id({"Id": "x"}) is None
        assert resolve_odata_id(None) is None

    @pytest.mark.unit
    def test_follow_fetches_resource(self) -> None:
        client = FakeClient(
            routes={"/redfish/v1/Systems/1": (200, {"@odata.type": "#ComputerSystem.v1_16_0.ComputerSystem"})}
        )
        resource = follow(client, "/redfish/v1/Systems/1")
        assert resource.schema_family == "ComputerSystem"
        assert client.requests == ["/redfish/v1/Systems/1"]

    @pytest.mark.unit
    def test_follow_rejects_cross_origin_absolute_url(self) -> None:
        client = FakeClient(routes={})
        with pytest.raises(RedfishError) as exc:
            follow(client, "http://evil.example/redfish/v1/Systems/1")
        assert exc.value.code == "protocol_error"

    @pytest.mark.unit
    def test_follow_chain_is_bounded(self) -> None:
        routes = {
            f"/redfish/v1/x/{i}": (200, {"@odata.id": f"/redfish/v1/x/{i + 1}"}) for i in range(MAX_LINK_DEPTH + 2)
        }
        client = FakeClient(routes=routes)
        with pytest.raises(RedfishError) as exc:
            follow(client, "/redfish/v1/x/0")
        assert exc.value.code == "protocol_error"
        assert len(client.requests) <= MAX_LINK_DEPTH + 1

    @pytest.mark.unit
    def test_follow_self_loop_raises(self) -> None:
        client = FakeClient(routes={"/redfish/v1/x/1": (200, {"@odata.id": "/redfish/v1/x/1"})})
        with pytest.raises(RedfishError) as exc:
            follow(client, "/redfish/v1/x/1")
        assert exc.value.code == "protocol_error"


class TestCollections:
    SEL = "/redfish/v1/Managers/1/LogServices/SEL/Entries"

    def page(self, entries: list[dict[str, Any]], count: int, next_link: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "@odata.type": "#LogEntryCollection.LogEntryCollection",
            "Members@odata.count": count,
            "Members": entries,
        }
        if next_link:
            body["@odata.nextLink"] = next_link
        return body

    @pytest.mark.unit
    def test_walk_follows_next_link(self) -> None:
        client = FakeClient(
            routes={
                f"{self.SEL}": (
                    200,
                    self.page(
                        [{"@odata.id": f"{self.SEL}/1", "Id": "1"}],
                        count=3,
                        next_link=f"{self.SEL}?$skip=1",
                    ),
                ),
                f"{self.SEL}?$skip=1": (
                    200,
                    self.page(
                        [{"@odata.id": f"{self.SEL}/2", "Id": "2"}, {"@odata.id": f"{self.SEL}/3", "Id": "3"}],
                        count=3,
                    ),
                ),
            }
        )
        resources, truncated = walk_collection(client, self.SEL)
        assert [r["Id"] for r in resources] == ["1", "2", "3"]
        assert truncated is False
        assert client.requests == [self.SEL, f"{self.SEL}?$skip=1"]

    @pytest.mark.unit
    def test_walk_falls_back_to_skip_pagination(self) -> None:
        # No @odata.nextLink: the walker continues with $skip while the server
        # advertised more members than it returned.
        client = FakeClient(
            routes={
                self.SEL: (200, self.page([{"Id": f"e{i}"} for i in range(2)], count=5)),
                f"{self.SEL}?$skip=2": (200, self.page([{"Id": f"e{i}"} for i in range(2, 5)], count=5)),
            }
        )
        resources, truncated = walk_collection(client, self.SEL)
        assert [r["Id"] for r in resources] == ["e0", "e1", "e2", "e3", "e4"]
        assert truncated is False
        assert client.requests == [self.SEL, f"{self.SEL}?$skip=2"]

    @pytest.mark.unit
    def test_walk_completes_when_count_unknown(self) -> None:
        client = FakeClient(
            routes={
                self.SEL: (
                    200,
                    {"Members": [{"Id": "e1"}], "Members@odata.count": 1},
                )
            }
        )
        resources, truncated = walk_collection(client, self.SEL)
        assert len(resources) == 1
        assert truncated is False

    @pytest.mark.unit
    def test_walk_empty_collection(self) -> None:
        client = FakeClient(routes={self.SEL: (200, {"Members": [], "Members@odata.count": 0})})
        resources, truncated = walk_collection(client, self.SEL)
        assert resources == []
        assert truncated is False

    @pytest.mark.unit
    def test_walk_missing_members_is_empty_not_error(self) -> None:
        client = FakeClient(routes={self.SEL: (200, {})})
        resources, truncated = walk_collection(client, self.SEL)
        assert resources == []
        assert truncated is False

    @pytest.mark.unit
    def test_walk_reports_truncation_when_skip_disallowed(self) -> None:
        client = FakeClient(routes={self.SEL: (200, self.page([{"Id": "e1"}], count=9))})
        resources, truncated = walk_collection(client, self.SEL, allow_skip_pagination=False)
        assert [r["Id"] for r in resources] == ["e1"]
        assert truncated is True

    @pytest.mark.unit
    def test_walk_loop_protection_on_repeating_next_link(self) -> None:
        loop_url = f"{self.SEL}?$skip=2"
        client = FakeClient(
            routes={
                self.SEL: (200, self.page([{"Id": "e1"}], count=9, next_link=loop_url)),
                loop_url: (200, self.page([{"Id": "e1"}], count=9, next_link=loop_url)),
            }
        )
        with pytest.raises(RedfishError) as exc:
            walk_collection(client, self.SEL)
        assert exc.value.code == "protocol_error"

    @pytest.mark.unit
    def test_walk_tolerates_string_members(self) -> None:
        client = FakeClient(
            routes={
                self.SEL: (
                    200,
                    {"Members@odata.count": 2, "Members": [f"{self.SEL}/1", f"{self.SEL}/2"]},
                )
            }
        )
        resources, _ = walk_collection(client, self.SEL)
        assert [r.odata_id for r in resources] == [f"{self.SEL}/1", f"{self.SEL}/2"]

    @pytest.mark.unit
    def test_member_links_helper(self) -> None:
        payload = {"Members": [{"@odata.id": "/redfish/v1/Systems/1"}], "Members@odata.count": 1}
        assert member_links(payload) == ["/redfish/v1/Systems/1"]
        assert member_links({"Members": "nope"}) == []


class TestResourceWrapper:
    @pytest.mark.unit
    def test_resource_exposes_metadata_and_helpers(self) -> None:
        payload = {
            "@odata.id": "/redfish/v1/Systems/1",
            "@odata.type": "#ComputerSystem.v1_16_0.ComputerSystem",
            "PowerState": "On",
        }
        resource = RedfishResource(payload)
        assert resource.odata_id == "/redfish/v1/Systems/1"
        assert resource.odata_type == "#ComputerSystem.v1_16_0.ComputerSystem"
        assert resource.schema_family == "ComputerSystem"
        assert resource["PowerState"] == "On"
        assert resource.get_text("PowerState") == "On"
        assert resource.get_text("Missing") is FieldSentinel.MISSING

    @pytest.mark.unit
    def test_resource_from_non_dict_payload_raises_protocol_error(self) -> None:
        with pytest.raises(RedfishError):
            RedfishResource(["not", "a", "dict"])
