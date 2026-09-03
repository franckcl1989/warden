"""Event-ingest platform layer: attribution, classification routing, storage.

ARCHITECTURE.md §3.4 + RISK R-14: syslog/trap receivers hand every message to
this layer which (1) attributes the source IP against device management
endpoints and configured additional event-source IPs, (2) classifies to a
contracts/events.json type (infrastructure/ingest/dispatcher), and (3)
persists to ``device_events`` reusing the M2T2 store semantics (native-id
dedupe preferred, content-hash dedupe otherwise) plus a ``device.updated``
ui_event so SSE clients refresh the device.

Drop semantics (0.1.0 has no UI for unowned events — RISK R-14 decision,
documented in the M5T1 report): messages whose source IP matches no device
are DROPPED with a counter + structured log, never stored; the same applies
to unparseable/unclassifiable/missing-component messages and to messages
from disabled devices or ambiguous IPs. The counters feed the ingest
process health log; the /system/status surface is a later milestone (the
counter object is the single place they accumulate).
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import uuid
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.domain.adapter import EventObservation
from app.generated.events import EVENT_DEFINITIONS
from app.infrastructure.ingest.dispatcher import (
    ClassifiedEvent,
    DropReason,
    classify_syslog,
    classify_trap,
)
from app.infrastructure.ingest.syslog_parse import ParsedSyslogMessage
from app.infrastructure.ingest.trap_types import ParsedTrap
from app.infrastructure.observation_store import event_dedupe_hash
from app.models.devices import Device
from app.models.observation import DeviceEvent, UiEvent

_LOGGER = logging.getLogger("warden.event_ingest")

_EVENT_SEVERITIES = frozenset({"unknown", "info", "warning", "critical"})

EVENT_SOURCE_IPS_CONFIG_KEY = "event_source_ips"


class MatchKind(StrEnum):
    MATCHED = "matched"
    DISABLED = "disabled"
    UNKNOWN_IP = "unknown_ip"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class MatchResult:
    kind: MatchKind
    device_id: uuid.UUID | None = None


class AttributionMap:
    """Source-IP -> device attribution over a devices snapshot.

    Built from device management endpoints that are IP literals plus
    ``connection_config[event_source_ips]`` entries (IPs or CIDRs, R-14).
    Hostname endpoints never match: their devices must configure
    ``event_source_ips``. Resolution is exact: one device -> MATCHED, several
    -> AMBIGUOUS (dropped, never guessed), only disabled devices -> DISABLED.
    """

    def __init__(
        self,
        *,
        exact: dict[str, list[tuple[uuid.UUID, bool]]],
        networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, uuid.UUID, bool]],
    ) -> None:
        self._exact = exact
        self._networks = networks

    def resolve(self, source_ip: str) -> MatchResult:
        try:
            parsed = ipaddress.ip_address(source_ip)
        except ValueError:
            return MatchResult(kind=MatchKind.UNKNOWN_IP)
        canonical = str(parsed)
        found: list[tuple[uuid.UUID, bool]] = []
        seen: set[uuid.UUID] = set()
        for device_id, enabled in self._exact.get(canonical, ()):
            if device_id not in seen:
                seen.add(device_id)
                found.append((device_id, enabled))
        for network, device_id, enabled in self._networks:
            if parsed in network and device_id not in seen:
                seen.add(device_id)
                found.append((device_id, enabled))
        enabled_ids = [device_id for device_id, enabled in found if enabled]
        if not enabled_ids:
            disabled_ids = [device_id for device_id, enabled in found if not enabled]
            if len(disabled_ids) == 1:
                return MatchResult(kind=MatchKind.DISABLED, device_id=disabled_ids[0])
            if disabled_ids:
                return MatchResult(kind=MatchKind.AMBIGUOUS)
            return MatchResult(kind=MatchKind.UNKNOWN_IP)
        if len(enabled_ids) == 1:
            return MatchResult(kind=MatchKind.MATCHED, device_id=enabled_ids[0])
        return MatchResult(kind=MatchKind.AMBIGUOUS)


def build_attribution_map(db: Session) -> AttributionMap:
    """Attribution map over the current devices table (endpoints + source IPs).

    Malformed ``event_source_ips`` entries are skipped (they cannot be
    resolved); the devices-route schema validation plus this defensive parse
    keep the map honest. Hostname endpoints are skipped silently (they
    require ``event_source_ips`` to attribute — RISK R-14).
    """
    rows = db.execute(
        select(Device.id, Device.enabled, Device.management_endpoint, Device.connection_config)
    ).all()
    exact: dict[str, list[tuple[uuid.UUID, bool]]] = {}
    networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, uuid.UUID, bool]] = []
    for device_id, enabled, endpoint, connection_config in rows:
        targets = [endpoint]
        extra = connection_config.get(EVENT_SOURCE_IPS_CONFIG_KEY)
        if isinstance(extra, list):
            targets.extend(str(item) for item in extra)
        for raw in targets:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                # The management endpoint may legitimately be a hostname —
                # hostname endpoints never match and need event_source_ips;
                # only a malformed event_source_ips entry is worth a warning.
                try:
                    network = ipaddress.ip_network(raw, strict=False)
                except ValueError:
                    if raw != endpoint:
                        _LOGGER.warning(
                            "event_ingest.unresolvable_source_ip device_id=%s raw=%s",
                            device_id,
                            raw,
                        )
                    continue
                networks.append((network, device_id, enabled))
                continue
            exact.setdefault(str(address), []).append((device_id, enabled))
    return AttributionMap(exact=exact, networks=networks)


@dataclass
class IngestCounters:
    """Cumulative ingest counters (single consumer thread; no locking needed).

    The counts distinguish received vs stored vs each drop category so the
    ingest health log and the future /system/status surface (PLT-08) can show
    exactly where messages went.
    """

    syslog_messages: int = 0
    trap_messages: int = 0
    stored_events: int = 0
    deduped_events: int = 0
    dropped_unparseable: int = 0
    dropped_empty_message: int = 0
    dropped_unclassifiable: int = 0
    dropped_missing_component: int = 0
    dropped_unattributed: int = 0
    dropped_ambiguous: int = 0
    dropped_device_disabled: int = 0
    dropped_community_mismatch: int = 0
    dropped_community_unverifiable: int = 0
    errors: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "syslog_messages": self.syslog_messages,
            "trap_messages": self.trap_messages,
            "stored_events": self.stored_events,
            "deduped_events": self.deduped_events,
            "dropped_unparseable": self.dropped_unparseable,
            "dropped_empty_message": self.dropped_empty_message,
            "dropped_unclassifiable": self.dropped_unclassifiable,
            "dropped_missing_component": self.dropped_missing_component,
            "dropped_unattributed": self.dropped_unattributed,
            "dropped_ambiguous": self.dropped_ambiguous,
            "dropped_device_disabled": self.dropped_device_disabled,
            "dropped_community_mismatch": self.dropped_community_mismatch,
            "dropped_community_unverifiable": self.dropped_community_unverifiable,
            "errors": self.errors,
        }


@dataclass(frozen=True)
class DeviceSnmpExpectation:
    """Decrypted per-device SNMP auth expectation for trap verification."""

    version: str | None  # v3 | v2c | None (no snmp config)
    community: str | None  # v2c only


DeviceExpectations = dict[uuid.UUID, DeviceSnmpExpectation]


@dataclass(frozen=True)
class IngestPersistResult:
    """One classified event's persistence outcome."""

    stored: bool
    reason: str | None = None  # None = stored or deduped; else the rejection reason


def persist_ingest_event(
    db: Session,
    *,
    device_id: uuid.UUID,
    event: ClassifiedEvent,
    received_at: datetime.datetime,
) -> IngestPersistResult:
    """Persist one classified event with M2T2 dedupe semantics + ui_event.

    Validation mirrors the batch store's event rules (contracts/events.json
    required fields, normalized severity, source membership); a contract
    violation is a drop-with-reason, never a fabricated row.
    """
    definition = EVENT_DEFINITIONS.get(event.event_type)
    if definition is None:
        return IngestPersistResult(stored=False, reason="invalid_event_type")
    if event.source not in definition.sources:
        return IngestPersistResult(stored=False, reason="source_not_allowed_for_type")
    if event.severity not in _EVENT_SEVERITIES:
        return IngestPersistResult(stored=False, reason="invalid_severity")
    if "component_native_id" in definition.required_fields and event.component_native_id is None:
        return IngestPersistResult(stored=False, reason="missing_component")
    if not event.message:
        return IngestPersistResult(stored=False, reason="empty_message")

    detail = dict(event.detail)
    if event.component_native_id is not None:
        detail["component_native_id"] = event.component_native_id
    detail["basis"] = event.basis
    occurred_at = event.occurred_at if event.occurred_at is not None else received_at

    native = event.native_event_id
    params = {
        "device_id": device_id,
        "component_id": None,
        "event_type": event.event_type,
        "severity": event.severity,
        "message": event.message,
        "occurred_at": occurred_at,
        "received_at": received_at,
        "source": event.source,
        "native_event_id": native,
        "dedupe_hash": None if native is not None else event_dedupe_hash(_as_observation(event)),
        "detail": detail,
    }
    inserted = db.execute(
        pg_insert(DeviceEvent).values([params]).on_conflict_do_nothing().returning(DeviceEvent.id)
    ).all()
    if not inserted:
        return IngestPersistResult(stored=False, reason="deduped")
    _emit_device_updated(db, device_id=device_id)
    return IngestPersistResult(stored=True)


def _as_observation(event: ClassifiedEvent) -> EventObservation:
    occurred = event.occurred_at or datetime.datetime.now(datetime.UTC)
    return EventObservation(
        event_type=event.event_type,
        severity=event.severity,
        message=event.message,
        occurred_at=occurred,
        source=event.source,
        component_kind=None,
        component_native_id=event.component_native_id,
    )


def _emit_device_updated(db: Session, *, device_id: uuid.UUID) -> None:
    version = db.scalar(select(Device.version).where(Device.id == device_id))
    db.add(
        UiEvent(
            entity_type="device",
            entity_id=device_id,
            version=version if isinstance(version, int) else 1,
            event_type="device.updated",
            payload={},
        )
    )


def _drop_kind(result: DropReason) -> str:
    return {
        "empty_message": "dropped_empty_message",
        "unclassifiable": "dropped_unclassifiable",
        "missing_component": "dropped_missing_component",
    }.get(result.reason, "dropped_unclassifiable")


def _count_drop(counters: IngestCounters, kind: str) -> None:
    if not hasattr(counters, kind):
        counters.errors += 1
        return
    setattr(counters, kind, getattr(counters, kind) + 1)


def route_syslog_message(
    db: Session,
    *,
    parsed: ParsedSyslogMessage | None,
    peer: str,
    counters: IngestCounters,
    attribution: AttributionMap | None = None,
) -> None:
    """Full syslog routing: count -> attribute -> classify -> persist.

    ``attribution`` may be the service's cached map; when None the map is
    built from the current devices table (direct-call/test convenience).
    """
    counters.syslog_messages += 1
    if parsed is None:
        counters.dropped_unparseable += 1
        _LOGGER.info("event_ingest.drop reason=unparseable peer=%s", peer)
        return
    mapping = attribution if attribution is not None else build_attribution_map(db)
    match = mapping.resolve(peer)
    device_id = _matched_device(match, counters, source=parsed.raw)
    if device_id is None:
        return
    classified = classify_syslog(parsed)
    if isinstance(classified, DropReason):
        _count_drop(counters, _drop_kind(classified))
        return
    _store_or_dedupe(db, device_id=device_id, event=classified, counters=counters)


def route_trap(
    db: Session,
    *,
    trap: ParsedTrap,
    peer: str,
    counters: IngestCounters,
    expectations: DeviceExpectations | None = None,
    attribution: AttributionMap | None = None,
) -> None:
    """Full trap routing: count -> attribute -> v2c policy -> classify.

    For v2c traps the wire community is checked against the attributed
    device's decrypted expectation (v2c authenticates nothing; SECURITY.md
    §6 keeps v2c an explicit, audited choice): a v2c trap whose device is
    not configured v2c with the same community is dropped and counted, never
    stored. v3 traps are verified by the USM layer before they reach the
    receiver (wrong keys never decode).
    """
    counters.trap_messages += 1
    mapping = attribution if attribution is not None else build_attribution_map(db)
    match = mapping.resolve(peer)
    device_id = _matched_device(match, counters, source=f"trap:{trap.security_name}")
    if device_id is None:
        return
    if trap.security_model == 2:
        expectation = (expectations or {}).get(device_id)
        if expectation is not None and expectation.version == "v2c":
            if expectation.community is None or trap.community != expectation.community:
                counters.dropped_community_mismatch += 1
                _LOGGER.warning("event_ingest.drop reason=community_mismatch peer=%s", peer)
                return
        else:
            counters.dropped_community_unverifiable += 1
            _LOGGER.info(
                "event_ingest.drop reason=v2c_trap_for_unverifiable_device peer=%s",
                peer,
            )
            return
    classified = classify_trap(trap)
    if isinstance(classified, DropReason):
        _count_drop(counters, _drop_kind(classified))
        return
    _store_or_dedupe(db, device_id=device_id, event=classified, counters=counters)


def _matched_device(
    match: MatchResult,
    counters: IngestCounters,
    *,
    source: str,
) -> uuid.UUID | None:
    if match.kind is MatchKind.MATCHED:
        return match.device_id
    if match.kind is MatchKind.AMBIGUOUS:
        counters.dropped_ambiguous += 1
        _LOGGER.info("event_ingest.drop reason=ambiguous_source_ip source=%s", source)
        return None
    if match.kind is MatchKind.DISABLED:
        counters.dropped_device_disabled += 1
        _LOGGER.info("event_ingest.drop reason=device_disabled source=%s", source)
        return None
    counters.dropped_unattributed += 1
    _LOGGER.info("event_ingest.drop reason=unattributed_source_ip source=%s", source)
    return None


def _store_or_dedupe(
    db: Session,
    *,
    device_id: uuid.UUID,
    event: ClassifiedEvent,
    counters: IngestCounters,
) -> None:
    received_at = datetime.datetime.now(datetime.UTC)
    result = persist_ingest_event(db, device_id=device_id, event=event, received_at=received_at)
    if result.stored:
        counters.stored_events += 1
    elif result.reason == "deduped":
        counters.deduped_events += 1
    else:
        counters.errors += 1
        _LOGGER.warning(
            "event_ingest.persist_rejected device_id=%s reason=%s",
            device_id,
            result.reason,
        )


