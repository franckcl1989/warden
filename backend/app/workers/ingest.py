"""Event-ingest service: syslog/trap receivers -> platform events (M5T1).

ARCHITECTURE.md §3.4: the ingest process owns the UDP/TCP syslog listeners
and the SNMP trap listener (non-privileged ports, deployment maps 514/162).
It runs its own asyncio event loop:

- syslog + trap receivers decode datagrams on the loop and enqueue
  ``(parsed, peer)`` items on a BOUNDED queue;
- a dedicated consumer thread drains the queue and routes each item through
  the platform layer (app/application/event_ingest) with one PostgreSQL
  session per item — receivers never block on the database, and a PostgreSQL
  outage never masquerades as a received-and-stored message (drops are
  counted + logged; syslog/trap are device-push protocols, so a DB outage
  loses exactly the messages that arrived during it);
- a periodic refresh (default 60 s) reloads the device snapshot: the
  attribution map, the per-device SNMPv3 USM expectations (registered on the
  trap receiver engine, keyed by each device's authoritative engine id) and
  the accepted v2c communities. New/changed devices take effect within one
  refresh interval (0.1.0 documented behaviour).

Entry point: ``python -m app.workers.ingest``. Counters (IngestCounters)
accumulate in the consumer thread and are logged on every refresh; they are
the single source for the future /system/status receiver section (PLT-08).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import queue
import signal
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.application.event_ingest import (
    AttributionMap,
    DeviceExpectations,
    DeviceSnmpExpectation,
    IngestCounters,
    build_attribution_map,
    route_syslog_message,
    route_trap,
)
from app.application.system_state import record_ingest_heartbeat
from app.config import WardenSettings, get_settings
from app.infrastructure.crypto import (
    CredentialCipher,
    CredentialKeyring,
    DecryptionError,
    EncryptedSecret,
    credential_aad,
)
from app.infrastructure.db import create_db_engine, create_session_factory
from app.infrastructure.ingest.syslog_parse import ParsedSyslogMessage
from app.infrastructure.ingest.syslog_receiver import SyslogReceiver
from app.infrastructure.ingest.trap_receiver import TrapReceiver, TrapUser
from app.infrastructure.ingest.trap_types import ParsedTrap
from app.infrastructure.time import utcnow
from app.models.devices import Device, DeviceCredential

# Default USM engine id (hex for "warden-trap-recv"): the deterministic
# 0.1.0 single-site default; operators override via WARDEN_SNMP_TRAP_ENGINE_ID
# (config.py). Devices must be configured with the SAME engine id.
DEFAULT_TRAP_ENGINE_ID_HEX = "77617264656e2d747261702d72656376"

# How often the device snapshot (attribution + trap auth) refreshes.
DEFAULT_REFRESH_SECONDS = 60.0
QUEUE_MAXSIZE = 2048

# PLT-08 ingest heartbeat (M6T3b): received-message deltas flush to the
# single-row ingest_heartbeat at most every HEARTBEAT_FLUSH_SECONDS while the
# queue is busy (batched, throttled), immediately when the queue drains idle,
# and the row is ALWAYS stamped (updated_at = process-alive signal, events or
# not) at least every ``settings.ingest_heartbeat_interval_seconds``. The
# durable row is the /system/status ingest surface (ARCHITECTURE.md §9); the
# in-process IngestCounters stay the hot-path source (M5T1).
HEARTBEAT_FLUSH_SECONDS = 5.0

_LOGGER = logging.getLogger("warden.ingest")


@dataclass(frozen=True)
class _Snapshot:
    attribution: AttributionMap
    expectations: DeviceExpectations
    users: tuple[TrapUser, ...]
    communities: tuple[str, ...]
    device_count: int
    snmp_credential_load_failures: int


@dataclass
class PortOverrides:
    """Test hook: ephemeral (0) ports instead of the configured ones."""

    syslog_udp: int | None = None
    syslog_tcp: int | None = None
    snmp_trap: int | None = None


class IngestService:
    """Runs the ingest receivers + dispatch queue + device snapshot refresh."""

    def __init__(
        self,
        *,
        settings: WardenSettings,
        session_factory: sessionmaker[Session],
        keyring: CredentialKeyring,
        refresh_seconds: float = DEFAULT_REFRESH_SECONDS,
        port_overrides: PortOverrides | None = None,
        heartbeat_flush_seconds: float = HEARTBEAT_FLUSH_SECONDS,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._keyring = keyring
        self._refresh_seconds = refresh_seconds
        self._overrides = port_overrides or PortOverrides()
        self._heartbeat_flush_seconds = heartbeat_flush_seconds
        self._heartbeat_interval_seconds = float(settings.ingest_heartbeat_interval_seconds)
        self._log = structlog.get_logger("warden.ingest")
        self.counters = IngestCounters()
        self._queue_drops = 0
        self._queue: queue.Queue[tuple[str, object, str]] = queue.Queue(maxsize=QUEUE_MAXSIZE)
        # PLT-08 heartbeat state (single consumer thread, no locking): pending
        # received-message deltas not yet flushed + monotonic time of the last
        # successful heartbeat write.
        self._heartbeat_pending = 0
        self._heartbeat_last_write = 0.0
        self._snapshot = _Snapshot(
            attribution=AttributionMap(exact={}, networks=[]),
            expectations={},
            users=(),
            communities=(),
            device_count=0,
            snmp_credential_load_failures=0,
        )
        self._consumer_stop = threading.Event()
        self._consumer_thread: threading.Thread | None = None
        self._refresh_task: asyncio.Task[None] | None = None
        self.syslog: SyslogReceiver | None = None
        self.trap: TrapReceiver | None = None
        self._receivers_started = False

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        # Set FIRST so a cancelled/partial start still tears down through
        # stop() (idempotent: every teardown step None/_started-guarded).
        self._receivers_started = True
        engine_id = self._settings.snmp_trap_engine_id or DEFAULT_TRAP_ENGINE_ID_HEX
        handler_host = self._settings.ingest_bind_host
        self.syslog = SyslogReceiver(
            host=handler_host,
            udp_port=self._overrides.syslog_udp
            if self._overrides.syslog_udp is not None
            else self._settings.syslog_udp_port,
            tcp_port=self._overrides.syslog_tcp
            if self._overrides.syslog_tcp is not None
            else self._settings.syslog_tcp_port,
            handler=self._on_syslog_datagram,
            logger=self._log,
        )
        self.trap = TrapReceiver(
            host=handler_host,
            port=self._overrides.snmp_trap if self._overrides.snmp_trap is not None else self._settings.snmp_trap_port,
            handler=self._on_trap,
            engine_id_hex=engine_id,
            logger=self._log,
        )
        await self.syslog.start()
        await self.trap.start()
        await self.refresh_now()
        self._consumer_thread = threading.Thread(target=self._consume_forever, name="ingest-dispatch", daemon=True)
        self._consumer_thread.start()
        self._refresh_task = asyncio.create_task(self._refresh_forever())
        # PLT-08: stamp the durable heartbeat row at startup (process alive,
        # events or not) so /system/status can report the receiver honestly
        # before the first message arrives.
        self._flush_heartbeat()
        self._log.info(
            "ingest.started",
            syslog_udp_port=self.syslog.udp_port,
            syslog_tcp_port=self.syslog.tcp_port,
            trap_port=self.trap.port,
            engine_id=engine_id,
        )

    async def stop(self) -> None:
        if not self._receivers_started:
            return
        self._receivers_started = False
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._refresh_task
            self._refresh_task = None
        self._consumer_stop.set()
        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=15.0)
            self._consumer_thread = None
        # PLT-08: flush any uncommitted received-message delta on shutdown so
        # the durable counter never loses the tail of a crash-free run.
        if self._heartbeat_pending > 0:
            self._flush_heartbeat()
        if self.trap is not None:
            await self.trap.stop()
        if self.syslog is not None:
            await self.syslog.stop()
        # Let the proactor transports finish closing before the loop ends.
        await asyncio.sleep(0.05)
        self._log.info("ingest.stopped")

    # -- receivers (event loop side) ---------------------------------------

    def _on_syslog_datagram(self, parsed: ParsedSyslogMessage | None, peer: str, raw: str) -> None:
        del raw
        try:
            self._queue.put_nowait(("syslog", parsed, peer))
        except queue.Full:
            self._queue_drops += 1
            self._log.warning("ingest.queue.full", peer=peer)

    def _on_trap(self, trap: ParsedTrap, peer: str) -> None:
        try:
            self._queue.put_nowait(("trap", trap, peer))
        except queue.Full:
            self._queue_drops += 1
            self._log.warning("ingest.queue.full", peer=peer)

    # -- consumer thread (PostgreSQL side) ----------------------------------

    def _consume_forever(self) -> None:
        while not self._consumer_stop.is_set():
            try:
                kind, payload, peer = self._queue.get(timeout=0.5)
            except queue.Empty:
                self._maybe_flush_heartbeat(idle=True)
                continue
            # Received = the datagram reached the platform consumer (stored,
            # deduped or dropped all count as received); the durable counter
            # flushes with the batched heartbeat write.
            self._heartbeat_pending += 1
            try:
                self._route_one(kind, payload, peer)
            except Exception:
                self.counters.errors += 1
                _LOGGER.exception("ingest.dispatch.failed kind=%s", kind)
            self._maybe_flush_heartbeat(idle=False)

    def _route_one(self, kind: str, payload: object, peer: str) -> None:
        with self._session_factory() as session:
            if kind == "syslog":
                parsed = payload if isinstance(payload, ParsedSyslogMessage) else None
                route_syslog_message(
                    session,
                    parsed=parsed,
                    peer=peer,
                    counters=self.counters,
                    attribution=self._snapshot.attribution,
                )
            elif kind == "trap":
                if isinstance(payload, ParsedTrap):
                    route_trap(
                        session,
                        trap=payload,
                        peer=peer,
                        counters=self.counters,
                        expectations=self._snapshot.expectations,
                        attribution=self._snapshot.attribution,
                    )
            else:
                self.counters.errors += 1
            session.commit()

    # -- PLT-08 heartbeat flush ----------------------------------------------

    def _maybe_flush_heartbeat(self, *, idle: bool) -> None:
        """Flush the single-row heartbeat when a write is due.

        Two independent triggers (documented cadence): received-message
        deltas flush at most every ``heartbeat_flush_seconds`` while the
        queue is busy and immediately when the drain goes idle; the
        process-alive stamp (updated_at) is written at least every
        ``ingest_heartbeat_interval_seconds`` whether or not events arrived.
        """
        now = time.monotonic()
        if self._heartbeat_pending > 0 and (idle or now - self._heartbeat_last_write >= self._heartbeat_flush_seconds):
            self._flush_heartbeat()
            return
        if now - self._heartbeat_last_write >= self._heartbeat_interval_seconds:
            self._flush_heartbeat()

    def _flush_heartbeat(self) -> None:
        """One single-row upsert with the pending delta (own session).

        Callers gate the cadence (``_maybe_flush_heartbeat``); the startup
        stamp and the shutdown tail flush call unconditionally. A failed
        write keeps the pending delta AND advances the last-write clock: the
        next due flush retries the same delta (the previous commit never
        landed, so a DB outage never double-counts) at the regular cadence
        instead of turning into a per-tick connection hot loop.
        """
        pending = self._heartbeat_pending
        try:
            with self._session_factory() as session:
                record_ingest_heartbeat(
                    session,
                    events_received_delta=pending,
                    received_at=utcnow() if pending > 0 else None,
                    now=utcnow(),
                )
                session.commit()
        except Exception:
            _LOGGER.exception("ingest.heartbeat_flush_failed pending=%s", pending)
            self._heartbeat_last_write = time.monotonic()
            return
        self._heartbeat_pending = 0
        self._heartbeat_last_write = time.monotonic()

    # -- snapshot refresh ---------------------------------------------------

    async def refresh_now(self) -> None:
        """Reload the device snapshot (DB work in a thread; engine changes on loop)."""
        snapshot = await asyncio.to_thread(self._load_snapshot)
        self._snapshot = snapshot
        if self.trap is not None:
            self.trap.set_users(snapshot.users)
            self.trap.set_communities(snapshot.communities)
        self._log.info(
            "ingest.refreshed",
            devices=snapshot.device_count,
            users=len(snapshot.users),
            communities=len(snapshot.communities),
            snmp_credential_load_failures=snapshot.snmp_credential_load_failures,
            counters=self.counters.snapshot(),
        )

    async def _refresh_forever(self) -> None:
        while True:
            await asyncio.sleep(self._refresh_seconds)
            try:
                await self.refresh_now()
            except Exception:
                self.counters.errors += 1
                self._log.exception("ingest.refresh.failed")

    def _load_snapshot(self) -> _Snapshot:
        """One sync DB pass: attribution + decrypted SNMP trap expectations."""
        with self._session_factory() as session:
            attribution = build_attribution_map(session)
            rows = session.execute(
                select(Device, DeviceCredential).join(
                    DeviceCredential, DeviceCredential.device_id == Device.id, isouter=True
                )
            ).all()
            users: list[TrapUser] = []
            communities: list[str] = []
            expectations: DeviceExpectations = {}
            snmp_credential_load_failures = 0
            for device, credential in rows:
                try:
                    snmp = self._snmp_config(device, credential)
                except (DecryptionError, ValueError):
                    # A credential payload that cannot be decrypted/parsed is
                    # a real load failure (counted). A device that simply has
                    # no SNMP credentials is NOT a failure: non-SNMP adapters
                    # default to snmp_version v3 and legitimately carry no
                    # snmp section in their credentials.
                    snmp_credential_load_failures += 1
                    continue
                if snmp is None:
                    continue
                version, community, engine_id_hex, username, auth_key, privacy_key, auth_proto, priv_proto = snmp
                expectations[device.id] = DeviceSnmpExpectation(version=version, community=community)
                if version == "v2c":
                    if community and community not in communities:
                        communities.append(community)
                    continue
                if username is None or auth_key is None or privacy_key is None:
                    # v3-default device with no SNMP keys: no USM registration
                    # (its traps cannot decode), but nothing failed to load.
                    continue
                if engine_id_hex is None:
                    # v3 traps are stamped with the DEVICE engine id: without
                    # it the receiver cannot register USM keys that decode
                    # the device's traps (M5T1 report; the M5T2 adapter
                    # persists discovered engine ids into the device config).
                    _LOGGER.warning("ingest.v3_device_without_engine_id device_id=%s", device.id)
                    continue
                users.append(
                    TrapUser(
                        username=username,
                        engine_id_hex=engine_id_hex,
                        auth_protocol=auth_proto,
                        auth_key=auth_key,
                        privacy_protocol=priv_proto,
                        privacy_key=privacy_key,
                    )
                )
            return _Snapshot(
                attribution=attribution,
                expectations=expectations,
                users=tuple(users),
                communities=tuple(communities),
                device_count=len(rows),
                snmp_credential_load_failures=snmp_credential_load_failures,
            )

    def _snmp_config(
        self,
        device: Device,
        credential: DeviceCredential | None,
    ) -> tuple[str, str | None, str | None, str | None, str | None, str | None, str, str] | None:
        """Decrypted per-device SNMP expectation (None = no snmp config).

        Reads the documented convention (docs/API_CONTRACT.md §4.3): the
        snmp version lives in ``connection_config.snmp_version`` (v3 is the
        default), the v3 user/keys or the v2c community live in the
        credentials under ``snmp``. The device's authoritative USM engine id
        (hex) comes from ``connection_config.snmp_engine_id`` (the M5T2
        adapter persists the engine id it discovers there).
        """
        connection = dict(device.connection_config or {})
        version = connection.get("snmp_version", "v3")
        if version not in ("v2c", "v3"):
            return None
        engine_id = connection.get("snmp_engine_id")
        engine_id_hex = str(engine_id) if engine_id else None
        payload: object = None
        if credential is not None:
            try:
                aad = credential_aad(str(device.id), device.adapter_key, credential.secret_schema_version)
                secret = EncryptedSecret(
                    ciphertext=credential.ciphertext,
                    nonce=credential.nonce,
                    key_version=credential.key_version,
                )
                payload = json.loads(self._keyring.decrypt(secret, aad=aad))
            except (DecryptionError, ValueError) as exc:
                _LOGGER.warning(
                    "ingest.credential_load_failed device_id=%s error=%s",
                    device.id,
                    type(exc).__name__,
                )
                # Signal the failure so the caller counts it; a device whose
                # credentials cannot load gets NO expectation (traps for it
                # become unverifiable drops, never stored).
                raise
        snmp = payload if isinstance(payload, dict) else {}
        snmp_section = snmp.get("snmp")
        if not isinstance(snmp_section, dict):
            snmp_section = {}
        if version == "v2c":
            community = snmp_section.get("community")
            return version, str(community) if community else None, engine_id_hex, None, None, None, "sha", "aes128"
        username = snmp_section.get("username")
        auth_key = snmp_section.get("auth_key")
        privacy_key = snmp_section.get("privacy_key")
        auth_proto = str(snmp_section.get("auth_protocol", "sha"))
        priv_proto = str(snmp_section.get("privacy_protocol", "aes128"))
        return (
            version,
            None,
            engine_id_hex,
            str(username) if username else None,
            str(auth_key) if auth_key else None,
            str(privacy_key) if privacy_key else None,
            auth_proto,
            priv_proto,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="app.workers.ingest",
        description="Warden event-ingest service: syslog (UDP/TCP) + SNMP trap receivers.",
    )
    parser.parse_args(argv)
    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    keyring = CredentialKeyring.from_current(
        CredentialCipher(settings.credential_master_key.get_secret_value().encode("utf-8"))
    )
    service = IngestService(settings=settings, session_factory=session_factory, keyring=keyring)

    async def run() -> None:
        await service.start()
        stop_event = asyncio.Event()

        def _request_stop() -> None:
            stop_event.set()

        loop = asyncio.get_running_loop()
        for signal_name in ("SIGINT", "SIGTERM"):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(getattr(signal, signal_name), _request_stop)
        try:
            await stop_event.wait()
        finally:
            await service.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
