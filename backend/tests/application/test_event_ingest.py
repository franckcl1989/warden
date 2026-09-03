"""Event-ingest platform layer tests: attribution + persistence (M5T1).

Real PostgreSQL integration (attribution reads devices, persistence writes
device_events with M2T2 dedupe + ui_events) and pure unit tests for the
attribution/IP rules.
"""

from __future__ import annotations

import datetime
import uuid

from app.application.event_ingest import (
    AttributionMap,
    DeviceExpectations,
    DeviceSnmpExpectation,
    IngestCounters,
    MatchKind,
    build_attribution_map,
    persist_ingest_event,
    route_syslog_message,
    route_trap,
)
from app.domain.adapter import EventObservation
from app.infrastructure.ingest.dispatcher import ClassifiedEvent, classify_syslog
from app.infrastructure.ingest.syslog_parse import ParsedSyslogMessage, parse_syslog_line
from app.infrastructure.ingest.trap_types import ParsedTrap, TrapVarBind
from app.infrastructure.observation_store import event_dedupe_hash
from app.models.devices import Device
from app.models.observation import DeviceEvent, UiEvent
from sqlalchemy import select
from sqlalchemy.orm import Session

UTC = datetime.UTC


def _device(
    db: Session,
    *,
    endpoint: str,
    name: str = "switch-1",
    device_type: str = "core_switch",
    adapter_key: str = "switch.huawei_vrp_core",
    connection_config: dict[str, object] | None = None,
    enabled: bool = True,
) -> Device:
    device = Device(
        name=name,
        device_type=device_type,
        management_endpoint=endpoint,
        adapter_key=adapter_key,
        connection_config=connection_config or {},
        readiness="ready",
        enabled=enabled,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def _syslog(text: str) -> ParsedSyslogMessage:
    parsed = parse_syslog_line(text)
    assert parsed is not None
    return parsed


def _flap_message(interface: str = "GigabitEthernet0/0/1") -> ParsedSyslogMessage:
    return _syslog(
        "<190>Aug  4 2026 14:22:01 s5732-1 tag: "
        f"{interface}: The protocol state of the link turned from UP to DOWN."
    )


def _classified_flap() -> ClassifiedEvent:
    event = classify_syslog(_flap_message())
    assert isinstance(event, ClassifiedEvent)
    return event


class TestAttributionMapUnit:
    def test_resolve_known_ip_matches(self) -> None:
        device_id = uuid.uuid4()
        mapping = AttributionMap(
            exact={"192.168.10.5": [(device_id, True)]}, networks=[]
        )
        match = mapping.resolve("192.168.10.5")
        assert match is not None
        assert match.kind is MatchKind.MATCHED
        assert match.device_id == device_id

    def test_no_match_is_unknown(self) -> None:
        mapping = AttributionMap(exact={}, networks=[])
        match = mapping.resolve("10.1.1.1")
        assert match is not None
        assert match.kind is MatchKind.UNKNOWN_IP
        assert match.device_id is None

    def test_disabled_only_device_is_disabled(self) -> None:
        device_id = uuid.uuid4()
        mapping = AttributionMap(
            exact={"192.168.10.6": [(device_id, False)]}, networks=[]
        )
        assert mapping.resolve("192.168.10.6").kind is MatchKind.DISABLED

    def test_overlapping_entries_are_ambiguous(self) -> None:
        first, second = uuid.uuid4(), uuid.uuid4()
        mapping = AttributionMap(
            exact={"10.0.0.5": [(first, True), (second, True)]},
            networks=[],
        )
        assert mapping.resolve("10.0.0.5").kind is MatchKind.AMBIGUOUS


class TestBuildAttributionMap:
    def test_endpoint_ip_literal_maps_to_device(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.7")
        mapping = build_attribution_map(db_session)
        match = mapping.resolve("192.168.10.7")
        assert match is not None
        assert match.kind is MatchKind.MATCHED
        assert match.device_id == device.id

    def test_hostname_endpoint_never_matches(self, db_session: Session) -> None:
        _device(db_session, endpoint="switch-1.internal")
        mapping = build_attribution_map(db_session)
        assert mapping.resolve("192.168.10.7").kind is MatchKind.UNKNOWN_IP

    def test_additional_event_source_ip_and_cidr_match(self, db_session: Session) -> None:
        device = _device(
            db_session,
            endpoint="192.168.10.7",
            connection_config={"event_source_ips": ["192.168.10.50", "10.20.0.0/16"]},
        )
        mapping = build_attribution_map(db_session)
        assert mapping.resolve("192.168.10.50").device_id == device.id
        assert mapping.resolve("10.20.5.5").device_id == device.id

    def test_disabled_device_is_marked_disabled(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.9", enabled=False)
        mapping = build_attribution_map(db_session)
        match = mapping.resolve("192.168.10.9")
        assert match is not None
        assert match.kind is MatchKind.DISABLED
        assert match.device_id == device.id

    def test_invalid_event_source_ip_is_ignored(self, db_session: Session) -> None:
        device = _device(
            db_session,
            endpoint="192.168.10.7",
            connection_config={"event_source_ips": ["not-an-ip"]},
        )
        mapping = build_attribution_map(db_session)
        assert mapping.resolve("192.168.10.7").device_id == device.id

    def test_shared_ip_between_devices_is_ambiguous(self, db_session: Session) -> None:
        _device(db_session, endpoint="192.168.10.11", name="switch-a")
        _device(
            db_session,
            endpoint="192.168.10.11",
            name="switch-b",
            device_type="access_switch",
            adapter_key="switch.huawei_vrp_access",
        )
        mapping = build_attribution_map(db_session)
        assert mapping.resolve("192.168.10.11").kind is MatchKind.AMBIGUOUS


class TestPersistIngestEvent:
    def test_event_stored_with_native_id_and_ui_event(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.12")
        event = _classified_flap()
        received = datetime.datetime(2026, 8, 4, 14, 22, 2, tzinfo=UTC)
        result = persist_ingest_event(db_session, device_id=device.id, event=event, received_at=received)
        assert result.stored is True
        row = db_session.scalar(select(DeviceEvent).where(DeviceEvent.device_id == device.id))
        assert row is not None
        assert row.event_type == "event.port_flap"
        assert row.severity == "warning"
        assert row.source == "syslog"
        assert row.message == "interface GigabitEthernet0/0/1 link down"
        assert row.occurred_at == datetime.datetime(2026, 8, 4, 14, 22, 1, tzinfo=UTC)
        assert row.native_event_id is not None
        assert row.native_event_id.startswith("syslog|")
        assert row.dedupe_hash is None
        assert row.component_id is None
        ui = db_session.scalar(select(UiEvent).where(UiEvent.entity_id == device.id))
        assert ui is not None
        assert ui.event_type == "device.updated"

    def test_repeated_identical_event_dedupes(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.13")
        event = _classified_flap()
        received = datetime.datetime(2026, 8, 4, 14, 22, 2, tzinfo=UTC)
        assert persist_ingest_event(db_session, device_id=device.id, event=event, received_at=received).stored
        assert persist_ingest_event(db_session, device_id=device.id, event=event, received_at=received).stored is False
        rows = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert len(rows) == 1

    def test_event_without_device_timestamp_uses_content_hash(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.14")
        parsed = parse_syslog_line("GigabitEthernet0/0/3 changed state to down")
        assert parsed is not None
        event = classify_syslog(parsed)
        assert isinstance(event, ClassifiedEvent)
        received = datetime.datetime(2026, 8, 4, 14, 22, 2, tzinfo=UTC)
        result = persist_ingest_event(db_session, device_id=device.id, event=event, received_at=received)
        assert result.stored is True
        row = db_session.scalar(select(DeviceEvent).where(DeviceEvent.device_id == device.id))
        assert row is not None
        assert row.native_event_id is None
        assert row.dedupe_hash is not None
        assert row.occurred_at == received
        duplicate = persist_ingest_event(
            db_session,
            device_id=device.id,
            event=event,
            received_at=datetime.datetime(2026, 8, 4, 14, 22, 9, tzinfo=UTC),
        )
        assert duplicate.stored is False

    def test_source_not_allowed_for_type_is_rejected(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.15")
        event = ClassifiedEvent(
            event_type="event.sel",
            severity="warning",
            message="x",
            source="syslog",
            occurred_at=None,
            component_native_id=None,
            native_event_id=None,
            basis="[test]",
        )
        result = persist_ingest_event(
            db_session,
            device_id=device.id,
            event=event,
            received_at=datetime.datetime(2026, 8, 4, 14, 22, 2, tzinfo=UTC),
        )
        assert result.stored is False
        assert result.reason == "source_not_allowed_for_type"
        rows = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert rows == []

    def test_unclassified_drop_is_never_stored(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.16")
        event = classify_syslog(_syslog("<190>Aug  4 2026 14:22:01 host tag: user executed display this"))
        assert not isinstance(event, ClassifiedEvent)
        rows = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert rows == []


class TestRouteSyslogMessage:
    def test_full_routing_pipeline(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.16")
        counters = IngestCounters()
        route_syslog_message(
            db_session, parsed=_flap_message("GigabitEthernet0/0/2"), peer="192.168.10.16", counters=counters
        )
        assert counters.syslog_messages == 1
        assert counters.stored_events == 1
        rows = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert len(rows) == 1

    def test_unattributed_message_dropped_with_counter(self, db_session: Session) -> None:
        _device(db_session, endpoint="192.168.10.16")
        counters = IngestCounters()
        route_syslog_message(
            db_session, parsed=_flap_message("GigabitEthernet0/0/2"), peer="10.99.99.99", counters=counters
        )
        assert counters.dropped_unattributed == 1
        rows = db_session.scalars(select(DeviceEvent)).all()
        assert rows == []

    def test_disabled_device_message_dropped_with_counter(self, db_session: Session) -> None:
        device = _device(db_session, endpoint="192.168.10.17", enabled=False)
        counters = IngestCounters()
        route_syslog_message(
            db_session, parsed=_flap_message("GigabitEthernet0/0/2"), peer="192.168.10.17", counters=counters
        )
        assert counters.dropped_device_disabled == 1
        rows = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert rows == []

    def test_unparseable_counts_but_is_not_stored(self, db_session: Session) -> None:
        _device(db_session, endpoint="192.168.10.17")
        counters = IngestCounters()
        route_syslog_message(db_session, parsed=None, peer="192.168.10.17", counters=counters)
        assert counters.dropped_unparseable == 1
        assert counters.syslog_messages == 1
        rows = db_session.scalars(select(DeviceEvent)).all()
        assert rows == []


class TestRouteTrap:
    def _cold_start_trap(self, community: str) -> ParsedTrap:
        return ParsedTrap(
            received_at=datetime.datetime(2026, 8, 4, 14, 30, 0, tzinfo=UTC),
            message_processing_model=1,
            security_model=2,
            security_name="v2c-device",
            security_level=1,
            community=community,
            varbinds=(
                TrapVarBind(name="1.3.6.1.2.1.1.3.0", value=10),
                TrapVarBind(name="1.3.6.1.6.3.1.1.4.1.0", value="1.3.6.1.6.3.1.1.5.1"),
            ),
        )

    def test_v2c_trap_with_matching_community_is_stored(self, db_session: Session) -> None:
        device = _device(
            db_session,
            endpoint="192.168.10.18",
            connection_config={"snmp_version": "v2c"},
        )
        counters = IngestCounters()
        expectations: DeviceExpectations = {
            device.id: DeviceSnmpExpectation(version="v2c", community="public")
        }
        route_trap(
            db_session,
            trap=self._cold_start_trap("public"),
            peer="192.168.10.18",
            counters=counters,
            expectations=expectations,
        )
        assert counters.stored_events == 1
        row = db_session.scalar(select(DeviceEvent).where(DeviceEvent.device_id == device.id))
        assert row is not None
        assert row.event_type == "event.device_restart"

    def test_v2c_trap_with_wrong_community_is_dropped_with_counter(
        self, db_session: Session
    ) -> None:
        device = _device(
            db_session,
            endpoint="192.168.10.18",
            connection_config={"snmp_version": "v2c"},
        )
        counters = IngestCounters()
        expectations: DeviceExpectations = {
            device.id: DeviceSnmpExpectation(version="v2c", community="public")
        }
        route_trap(
            db_session,
            trap=self._cold_start_trap("other-community"),
            peer="192.168.10.18",
            counters=counters,
            expectations=expectations,
        )
        assert counters.dropped_community_mismatch == 1
        rows = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert rows == []

    def test_v2c_trap_for_v3_device_is_unverifiable(self, db_session: Session) -> None:
        device = _device(
            db_session,
            endpoint="192.168.10.19",
            connection_config={"snmp_version": "v3"},
        )
        counters = IngestCounters()
        expectations: DeviceExpectations = {
            device.id: DeviceSnmpExpectation(version="v3", community=None)
        }
        route_trap(
            db_session,
            trap=self._cold_start_trap("public"),
            peer="192.168.10.19",
            counters=counters,
            expectations=expectations,
        )
        assert counters.dropped_community_unverifiable == 1
        rows = db_session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device.id)).all()
        assert rows == []

    def test_v3_trap_is_not_community_checked(self, db_session: Session) -> None:
        device = _device(
            db_session,
            endpoint="192.168.10.20",
            connection_config={"snmp_version": "v3"},
        )
        counters = IngestCounters()
        expectations: DeviceExpectations = {
            device.id: DeviceSnmpExpectation(version="v3", community=None)
        }
        trap = ParsedTrap(
            received_at=datetime.datetime(2026, 8, 4, 14, 30, 0, tzinfo=UTC),
            message_processing_model=3,
            security_model=3,
            security_name="monitor",
            security_level=3,
            community=None,
            varbinds=(
                TrapVarBind(name="1.3.6.1.2.1.1.3.0", value=10),
                TrapVarBind(name="1.3.6.1.6.3.1.1.4.1.0", value="1.3.6.1.6.3.1.1.5.1"),
            ),
        )
        route_trap(
            db_session,
            trap=trap,
            peer="192.168.10.20",
            counters=counters,
            expectations=expectations,
        )
        assert counters.stored_events == 1


class TestEventDedupeHashReuse:
    def test_hash_consistent_with_m2t2_store(self) -> None:
        parsed = parse_syslog_line("GigabitEthernet0/0/5 changed state to down")
        assert parsed is not None
        event = classify_syslog(parsed)
        assert isinstance(event, ClassifiedEvent)
        domain_event = EventObservation(
            event_type=event.event_type,
            severity=event.severity,
            message=event.message,
            occurred_at=datetime.datetime(2026, 8, 4, 14, 22, 1, tzinfo=UTC),
            source=event.source,
            component_native_id=event.component_native_id,
        )
        assert isinstance(event_dedupe_hash(domain_event), str)
