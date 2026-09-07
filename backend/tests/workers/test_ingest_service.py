"""Ingest service end-to-end: real UDP/TCP -> device_events rows (M5T1).

Starts the full IngestService against a real test database on ephemeral
ports, sends real syslog datagrams and v2c/v3 traps with the switch
simulator's emitters, and verifies attributed, deduplicated device_events
rows (the brief's integration evidence).

pysnmp's asyncio transports on the Windows proactor loop emit ResourceWarnings
from __del__ at garbage collection (fd already closed); they carry no
correctness signal for these tests. pytest turns them into
PytestUnraisableExceptionWarning failures, so this module ignores that
specific warning class.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import time

import pytest
from app.application.event_ingest import DeviceSnmpExpectation
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring, credential_aad
from app.infrastructure.db import create_db_engine, create_session_factory
from app.models.devices import Device, DeviceCredential
from app.models.observation import DeviceEvent
from app.workers.ingest import IngestService, PortOverrides
from pyasn1.type.univ import OctetString
from pysnmp.entity import config as snmp_config
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    NotificationType,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    sendNotification,
    usmAesCfb128Protocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto import rfc1902
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from tests.simulators.switch.emitters import (
    TRAP_COLD_START,
    TRAP_LINK_DOWN,
    vrp_auth_failure_line,
    vrp_link_state_line,
)

UTC = datetime.UTC

V3_ENGINE_ID = "73353733322d6869642d30303031"  # core_s5732 profile engine id
V3_USERNAME = "monitor"
V3_AUTH_KEY = "sim-auth-key-1"
V3_PRIV_KEY = "sim-priv-key-1"
V2C_COMMUNITY = "public"

MASTER_KEY_MATERIAL = b"test-master-key-material-32bytes!!"

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")


def _device(
    db: Session,
    *,
    name: str,
    endpoint: str,
    device_type: str,
    adapter_key: str,
    connection_config: dict[str, object],
    credentials: dict[str, object],
) -> Device:
    device = Device(
        name=name,
        device_type=device_type,
        management_endpoint=endpoint,
        adapter_key=adapter_key,
        connection_config=connection_config,
        readiness="ready",
    )
    db.add(device)
    db.flush()
    cipher = CredentialCipher(MASTER_KEY_MATERIAL)
    aad = credential_aad(str(device.id), adapter_key, 1)
    secret = cipher.encrypt_secret(json.dumps(credentials, sort_keys=True), key_version=1, aad=aad)
    db.add(
        DeviceCredential(
            device_id=device.id,
            ciphertext=secret.ciphertext,
            nonce=secret.nonce,
            key_version=secret.key_version,
            secret_schema_version=1,
        )
    )
    db.commit()
    db.refresh(device)
    return device


async def _wait_for(predicate: object, timeout: float = 8.0) -> None:  # noqa: ASYNC109 - polling helper
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        # asyncio.sleep (never time.sleep): the receivers live on this loop
        # and a blocking sleep would freeze trap delivery.
        await asyncio.sleep(0.1)
    raise AssertionError("condition not met within timeout")


async def _send_udp(port: int, payload: bytes) -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _NullProtocol(),
        local_addr=("127.0.0.1", 0),
        remote_addr=("127.0.0.1", port),
    )
    try:
        transport.sendto(payload)
        await asyncio.sleep(0.05)  # let the proactor write complete
    finally:
        transport.abort()  # immediate close (no pending-write wait)
        await asyncio.sleep(0.05)


async def _send_v3_trap(
    port: int,
    *,
    engine_id_hex: str,
    username: str,
    auth_key: str,
    privacy_key: str,
) -> None:
    sender = SnmpEngine(snmpEngineID=OctetString(hexValue=engine_id_hex))
    snmp_config.addV3User(
        sender,
        username,
        snmp_config.usmHMACSHAAuthProtocol,
        auth_key,
        snmp_config.usmAesCfb128Protocol,
        privacy_key,
    )
    try:
        result = await sendNotification(
            sender,
            UsmUserData(
                username, auth_key, privacy_key, usmHMACSHAAuthProtocol, usmAesCfb128Protocol
            ),
            UdpTransportTarget(("127.0.0.1", port), timeout=2, retries=0),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(TRAP_LINK_DOWN)).addVarBinds(
                ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.1"), rfc1902.Integer32(48))
            ),
        )
    finally:
        # Windows proactor (M6T2b): a trap send is fire-and-forget: the
        # sender may return while the UDP write is still in flight. Closing
        # the dispatcher then stalls the transport finalization forever and
        # its __del__ ResourceWarning fires at an arbitrary later cyclic GC.
        # Wait out the write, close, and drain the close callbacks while this
        # loop is still alive.
        await asyncio.sleep(0.05)
        sender.transportDispatcher.closeDispatcher()
        await asyncio.sleep(0)
    assert result[0] is None, result[0]


async def _send_v2c_trap(port: int, community: str, trap_oid: str) -> None:
    engine = SnmpEngine()
    try:
        result = await sendNotification(
            engine,
            CommunityData(community, mpModel=1),  # noqa: S508 - v2c ingest fixture
            UdpTransportTarget(("127.0.0.1", port), timeout=2, retries=0),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(trap_oid)),
        )
    finally:
        await asyncio.sleep(0.05)  # proactor write drain (M6T2b), see _send_v3_trap
        engine.transportDispatcher.closeDispatcher()
        await asyncio.sleep(0)
    assert result[0] is None, result[0]


async def _send_v1_trap(port: int, community: str, trap_oid: str) -> None:
    engine = SnmpEngine()
    try:
        result = await sendNotification(
            engine,
            CommunityData(community, mpModel=0),  # noqa: S508 - v1 ingest fixture
            UdpTransportTarget(("127.0.0.1", port), timeout=2, retries=0),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(trap_oid)),
        )
    finally:
        await asyncio.sleep(0.05)  # proactor write drain (M6T2b), see _send_v3_trap
        engine.transportDispatcher.closeDispatcher()
        await asyncio.sleep(0)
    assert result[0] is None, result[0]


class _NullProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int] | str) -> None:
        pass


@pytest.fixture()
def ingest_env(fresh_test_db_dsn: str, isolated_snmp_boots: None) -> dict[str, object]:
    del isolated_snmp_boots
    settings = WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        ingest_bind_host="127.0.0.1",
        _env_file=None,
    )
    engine = create_db_engine(fresh_test_db_dsn)
    session_factory = create_session_factory(engine)
    keyring = CredentialKeyring.from_current(CredentialCipher(MASTER_KEY_MATERIAL))
    try:
        yield {
            "settings": settings,
            "session_factory": session_factory,
            "keyring": keyring,
            "engine": engine,
        }
    finally:
        engine.dispose()


async def _start_service(env: dict[str, object], db_factory: object) -> IngestService:
    service = IngestService(
        settings=env["settings"],  # type: ignore[arg-type]
        session_factory=db_factory,  # type: ignore[arg-type]
        keyring=env["keyring"],  # type: ignore[arg-type]
        refresh_seconds=3600,
        port_overrides=PortOverrides(syslog_udp=0, syslog_tcp=0, snmp_trap=0),
    )
    await service.start()
    return service


class TestIngestServiceEndToEnd:
    async def test_v3_device_syslog_and_traps_become_device_events(
        self, ingest_env: dict[str, object]
    ) -> None:
        factory = ingest_env["session_factory"]
        assert factory is not None
        with factory() as db:
            v3_device = _device(
                db,
                name="core-s5732",
                endpoint="127.0.0.1",
                device_type="core_switch",
                adapter_key="switch.huawei_vrp_core",
                connection_config={
                    "snmp_version": "v3",
                    "snmp_engine_id": V3_ENGINE_ID,
                },
                credentials={
                    "snmp": {
                        "username": V3_USERNAME,
                        "auth_key": V3_AUTH_KEY,
                        "privacy_key": V3_PRIV_KEY,
                    }
                },
            )
        service = await _start_service(ingest_env, factory)
        try:
            assert service.syslog is not None and service.trap is not None
            udp_port = service.syslog.udp_port or 0
            trap_port = service.trap.port or 0

            await _send_udp(
                udp_port,
                vrp_link_state_line(
                    hostname="sim-s5732",
                    interface="GigabitEthernet0/0/1",
                    direction="down",
                    when=datetime.datetime(2026, 8, 4, 14, 22, 1, tzinfo=UTC),
                ).encode("utf-8"),
            )
            await _send_udp(
                udp_port,
                vrp_link_state_line(
                    hostname="sim-s5732",
                    interface="GigabitEthernet0/0/1",
                    direction="up",
                    when=datetime.datetime(2026, 8, 4, 14, 22, 5, tzinfo=UTC),
                ).encode("utf-8"),
            )
            await _send_udp(
                udp_port,
                vrp_auth_failure_line(
                    hostname="sim-s5732",
                    when=datetime.datetime(2026, 8, 4, 14, 23, 0, tzinfo=UTC),
                ).encode("utf-8"),
            )
            await _send_v3_trap(
                trap_port,
                engine_id_hex=V3_ENGINE_ID,
                username=V3_USERNAME,
                auth_key=V3_AUTH_KEY,
                privacy_key=V3_PRIV_KEY,
            )

            def _rows() -> int:
                with factory() as db:
                    return len(db.scalars(select(DeviceEvent)).all())

            await _wait_for(lambda: _rows() >= 4, timeout=15.0)
            with factory() as db:
                rows = db.scalars(select(DeviceEvent)).all()
                assert len(rows) == 4
                assert all(row.device_id == v3_device.id for row in rows)
                types = {row.event_type for row in rows}
                assert types == {"event.port_flap", "event.auth_failure"}
                sources = {row.source for row in rows}
                assert sources == {"syslog", "snmp_trap"}
                syslog_flaps = [
                    row
                    for row in rows
                    if row.source == "syslog" and row.event_type == "event.port_flap"
                ]
                assert {row.message for row in syslog_flaps} == {
                    "interface GigabitEthernet0/0/1 link down",
                    "interface GigabitEthernet0/0/1 link up",
                }
                trap_flaps = [row for row in rows if row.source == "snmp_trap"]
                assert len(trap_flaps) == 1
                assert trap_flaps[0].detail["trap_oid"] == "1.3.6.1.6.3.1.1.5.3"
                assert trap_flaps[0].detail["component_native_id"] == "48"
            assert service.counters.stored_events >= 4
        finally:
            await service.stop()

    async def test_v2c_device_trap_and_dedup_semantics(
        self, ingest_env: dict[str, object]
    ) -> None:
        factory = ingest_env["session_factory"]
        assert factory is not None
        with factory() as db:
            v2c_device = _device(
                db,
                name="access-s5735",
                endpoint="127.0.0.1",
                device_type="access_switch",
                adapter_key="switch.huawei_vrp_access",
                connection_config={"snmp_version": "v2c"},
                credentials={"snmp": {"community": V2C_COMMUNITY}},
            )
        service = await _start_service(ingest_env, factory)
        try:
            assert service.trap is not None
            trap_port = service.trap.port or 0
            await _send_v2c_trap(trap_port, V2C_COMMUNITY, TRAP_COLD_START)
            # An UNREGISTERED community never reaches the platform layer:
            # pysnmp's v2c proxy drops the trap at the engine (like USM for
            # v3) — documented transport-level semantics (platform-layer
            # community mismatch is covered by tests/application).
            await _send_v2c_trap(trap_port, "WRONG-COMMUNITY", TRAP_COLD_START)

            def _rows() -> int:
                with factory() as db:
                    return len(db.scalars(select(DeviceEvent)).all())

            await _wait_for(lambda: _rows() >= 1)
            assert service.counters.trap_messages == 1
            with factory() as db:
                rows = db.scalars(select(DeviceEvent)).all()
                assert len(rows) == 1
                row = rows[0]
                assert row.device_id == v2c_device.id
                assert row.event_type == "event.device_restart"
                assert row.source == "snmp_trap"
        finally:
            await service.stop()

    async def test_duplicate_syslog_dedupes_and_unattributed_drops(
        self, ingest_env: dict[str, object]
    ) -> None:
        factory = ingest_env["session_factory"]
        assert factory is not None
        service = await _start_service(ingest_env, factory)
        try:
            assert service.syslog is not None
            udp_port = service.syslog.udp_port or 0
            line = vrp_link_state_line(
                hostname="sim-x",
                interface="GigabitEthernet0/0/1",
                direction="down",
                when=datetime.datetime(2026, 8, 4, 14, 30, 0, tzinfo=UTC),
            ).encode("utf-8")
            await _send_udp(udp_port, line)
            await _send_udp(udp_port, line)
            await _wait_for(lambda: service.counters.dropped_unattributed >= 2)
            assert service.counters.stored_events == 0
            with factory() as db:
                rows = db.scalars(select(DeviceEvent)).all()
                assert rows == []
        finally:
            await service.stop()

    async def test_v1_traps_follow_the_community_policy(
        self, ingest_env: dict[str, object]
    ) -> None:
        factory = ingest_env["session_factory"]
        assert factory is not None
        with factory() as db:
            v2c_device = _device(
                db,
                name="access-s5735",
                endpoint="127.0.0.1",
                device_type="access_switch",
                adapter_key="switch.huawei_vrp_access",
                connection_config={"snmp_version": "v2c"},
                credentials={"snmp": {"community": V2C_COMMUNITY}},
            )
            # A second v2c device (different endpoint, never sends) makes the
            # receiver accept its community, so the platform policy layer —
            # not the engine — must reject a v1 trap that carries it from the
            # wrong device.
            _device(
                db,
                name="other-v2c",
                endpoint="127.0.0.9",
                device_type="access_switch",
                adapter_key="switch.huawei_vrp_access",
                connection_config={"snmp_version": "v2c"},
                credentials={"snmp": {"community": "lab-community"}},
            )
        service = await _start_service(ingest_env, factory)
        try:
            assert service.trap is not None
            trap_port = service.trap.port or 0

            # v1 coldStart with the attributed device's own community: stored.
            await _send_v1_trap(trap_port, V2C_COMMUNITY, TRAP_COLD_START)

            def _rows() -> int:
                with factory() as db:
                    return len(db.scalars(select(DeviceEvent)).all())

            await _wait_for(lambda: _rows() >= 1)

            # v1 coldStart with a registered-but-wrong community (source IP
            # 127.0.0.1 attributes to the V2C_COMMUNITY device): dropped by
            # the platform policy exactly like its v2c twin.
            await _send_v1_trap(trap_port, "lab-community", TRAP_COLD_START)
            await _wait_for(lambda: service.counters.dropped_community_mismatch >= 1)

            assert service.counters.trap_messages == 2
            assert service.counters.stored_events == 1
            with factory() as db:
                rows = db.scalars(select(DeviceEvent)).all()
                assert len(rows) == 1
                assert rows[0].device_id == v2c_device.id
                assert rows[0].event_type == "event.device_restart"
        finally:
            await service.stop()

    async def test_receiver_user_and_community_removal_paths(
        self, ingest_env: dict[str, object]
    ) -> None:
        """Delta removal: set_users/set_communities empty actually unregisters."""
        factory = ingest_env["session_factory"]
        assert factory is not None
        service = await _start_service(ingest_env, factory)
        try:
            assert service.trap is not None
            trap_port = service.trap.port or 0

            # v3 user registered at start (device below) decodes once...
            with factory() as db:
                _device(
                    db,
                    name="core-s5732",
                    endpoint="127.0.0.1",
                    device_type="core_switch",
                    adapter_key="switch.huawei_vrp_core",
                    connection_config={
                        "snmp_version": "v3",
                        "snmp_engine_id": V3_ENGINE_ID,
                    },
                    credentials={
                        "snmp": {
                            "username": V3_USERNAME,
                            "auth_key": V3_AUTH_KEY,
                            "privacy_key": V3_PRIV_KEY,
                        }
                    },
                )
            await service.refresh_now()
            await _send_v3_trap(
                trap_port,
                engine_id_hex=V3_ENGINE_ID,
                username=V3_USERNAME,
                auth_key=V3_AUTH_KEY,
                privacy_key=V3_PRIV_KEY,
            )
            await _wait_for(lambda: service.counters.trap_messages >= 1, timeout=15.0)

            # ...but a refresh that removes the device unregisters its USM
            # user: the same trap now never decodes (USM drop, engine-level).
            with factory() as db:
                device = db.scalar(select(Device).where(Device.name == "core-s5732"))
                assert device is not None
                db.execute(delete(DeviceCredential).where(DeviceCredential.device_id == device.id))
                db.delete(device)
                db.commit()
            await service.refresh_now()
            trap_messages_after_first = service.counters.trap_messages
            await _send_v3_trap(
                trap_port,
                engine_id_hex=V3_ENGINE_ID,
                username=V3_USERNAME,
                auth_key=V3_AUTH_KEY,
                privacy_key=V3_PRIV_KEY,
            )
            await asyncio.sleep(1.0)
            assert service.counters.trap_messages == trap_messages_after_first
        finally:
            await service.stop()


def test_snapshot_counts_only_real_credential_load_failures(
    ingest_env: dict[str, object],
) -> None:
    """Non-SNMP devices (v3 default, no keys) are not credential failures."""
    factory = ingest_env["session_factory"]
    keyring = ingest_env["keyring"]
    settings = ingest_env["settings"]
    assert factory is not None
    with factory() as db:
        v2c_device = _device(
            db,
            name="v2c-ok",
            endpoint="127.0.0.11",
            device_type="access_switch",
            adapter_key="switch.huawei_vrp_access",
            connection_config={"snmp_version": "v2c"},
            credentials={"snmp": {"community": "public"}},
        )
        nas_device = _device(
            db,
            name="nas-no-snmp",
            endpoint="127.0.0.12",
            device_type="synology_nas",
            adapter_key="nas.synology_dsm",
            connection_config={},
            credentials={"dsm": {"username": "admin", "password": "x"}},
        )
        broken = Device(
            name="broken-creds",
            device_type="core_switch",
            management_endpoint="127.0.0.13",
            adapter_key="switch.huawei_vrp_core",
            connection_config={"snmp_version": "v3"},
            readiness="ready",
        )
        db.add(broken)
        db.flush()
        foreign_cipher = CredentialCipher(b"other-master-material-32-bytes!!")
        aad = credential_aad(str(broken.id), broken.adapter_key, 1)
        secret = foreign_cipher.encrypt_secret(
            json.dumps({"snmp": {"username": "monitor"}}, sort_keys=True),
            key_version=1,
            aad=aad,
        )
        db.add(
            DeviceCredential(
                device_id=broken.id,
                ciphertext=secret.ciphertext,
                nonce=secret.nonce,
                key_version=secret.key_version,
                secret_schema_version=1,
            )
        )
        db.commit()
    service = IngestService(
        settings=settings,
        session_factory=factory,
        keyring=keyring,
        refresh_seconds=3600,
    )
    snapshot = service._load_snapshot()
    assert snapshot.snmp_credential_load_failures == 1  # only the broken row
    assert snapshot.communities == ("public",)
    assert snapshot.users == ()
    assert snapshot.expectations[v2c_device.id] == DeviceSnmpExpectation(
        version="v2c", community="public"
    )
    # The NAS device defaults to snmp_version v3 with no keys: an expected
    # configuration state (expectation present, no USM user), not a failure.
    assert snapshot.expectations[nas_device.id] == DeviceSnmpExpectation(
        version="v3", community=None
    )
    assert broken.id not in snapshot.expectations
