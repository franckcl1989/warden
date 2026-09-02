"""Factories for observation-pipeline tests (integration, real PostgreSQL).

Creates the FK chain device -> credentials/capabilities with contract-valid
rows for the fake.simple server adapter. The ``warden_test`` database is
recreated by the ``fresh_test_db_dsn``/``db_session`` fixtures before each
test.
"""

from __future__ import annotations

import datetime
import uuid

from app.adapters.fake import FakeSimpleAdapter
from app.domain.adapter import canonical_json
from app.generated.capabilities import REQUIREMENTS
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring
from app.models.devices import Device, DeviceCapability, DeviceCredential
from app.models.observation import CollectionRun
from sqlalchemy.orm import Session

FAKE = FakeSimpleAdapter()
DEV_MASTER_KEY = b"dev-master-key-00000000000000000"  # 32 bytes, dev/test only


def make_keyring() -> CredentialKeyring:
    return CredentialKeyring.from_current(CredentialCipher(DEV_MASTER_KEY))


def make_collection_device(
    db: Session,
    *,
    index: int = 0,
    connection_config: dict[str, object] | None = None,
    device_type: str = "server",
    enabled: bool = True,
    readiness: str = "ready",
    next_poll_at: datetime.datetime | None = None,
    keyring: CredentialKeyring | None = None,
) -> Device:
    if keyring is None:
        keyring = make_keyring()
    device = Device(
        name=f"obs-device-{index}",
        device_type=device_type,
        vendor="Fake",
        model="FakeServer-1",
        management_endpoint=f"192.168.20.{index % 250 + 1}",
        adapter_key=FAKE.adapter_key,
        connection_config=connection_config or {},
        enabled=enabled,
        readiness=readiness,
        reachability="unknown",
        health="unknown",
        next_poll_at=next_poll_at,
    )
    db.add(device)
    db.flush()
    if keyring is not None:
        db.add(
            DeviceCredential(
                device_id=device.id,
                ciphertext=b"x" * 16,
                nonce=b"n" * 12,
                key_version=1,
                secret_schema_version=FAKE.secret_schema_version,
            )
        )
        _encrypt_credentials(db, device, keyring)
    seed_capabilities(db, device)
    db.commit()
    db.refresh(device)
    return device


def _encrypt_credentials(db: Session, device: Device, keyring: CredentialKeyring) -> None:
    from app.infrastructure.crypto import credential_aad

    plaintext = canonical_json({"username": "admin", "password": "dev-only"})
    encrypted = keyring.current_cipher().encrypt_secret(
        plaintext,
        key_version=keyring.current_version,
        aad=credential_aad(str(device.id), device.adapter_key, FAKE.secret_schema_version),
    )
    row = db.get(DeviceCredential, device.id)
    assert row is not None
    row.ciphertext = encrypted.ciphertext
    row.nonce = encrypted.nonce
    row.key_version = encrypted.key_version


def seed_capabilities(db: Session, device: Device) -> None:
    """One supported capability row per server metric/event/operation key.

    Mirrors what ``fake.simple`` reports during discovery (first requirement
    wins deterministically).
    """
    now = datetime.datetime.now(datetime.UTC)
    seen: set[str] = set()
    for requirement in REQUIREMENTS.values():
        if requirement.device_type != device.device_type:
            continue
        for key in (
            *requirement.metrics,
            *requirement.events,
            *(operation[0] for operation in requirement.operations),
        ):
            if key in seen:
                continue
            seen.add(key)
            db.add(
                DeviceCapability(
                    device_id=device.id,
                    capability_key=key,
                    support_state="supported",
                    requirement_id=requirement.id,
                    discovery_method=FAKE.adapter_key,
                    last_checked_at=now,
                    adapter_version=FAKE.adapter_version,
                )
            )
    db.flush()


def make_collection_run(
    db: Session,
    *,
    device_id: uuid.UUID,
    collection_type: str = "metrics",
    state: str = "scheduled",
    scheduled_at: datetime.datetime | None = None,
    lease_owner: str | None = None,
    lease_expires_at: datetime.datetime | None = None,
) -> CollectionRun:
    run = CollectionRun(
        device_id=device_id,
        collection_type=collection_type,
        scheduled_at=scheduled_at or datetime.datetime.now(datetime.UTC),
        state=state,
        attempt_count=1 if state == "running" else 0,
        lease_owner=lease_owner,
        lease_expires_at=lease_expires_at,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run
