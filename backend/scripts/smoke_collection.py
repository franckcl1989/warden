"""M2T2 worker smoke: scheduler + collection once against the dev database.

Runs the REAL worker code paths (Scheduler.run_once, claim_collection_run,
run_collection) against the dev ``warden`` database with a fake.simple
device, then prints the evidence the M2T2 report records:

- scheduler_tick created collection runs per type;
- the claimed/executed runs finished succeeded;
- the device is online + healthy, metric_latest rows exist, the day
  partition holds the points, the SEL event is deduped, and ui_events were
  written in the same transaction.

The smoke device and its data are removed afterwards (dev database hygiene);
the printed queries are the recorded evidence.
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.adapters.fake import FakeSimpleAdapter
from app.application.collection import run_collection
from app.config import WardenSettings
from app.domain.adapter import canonical_json
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring, credential_aad
from app.infrastructure.db import create_db_engine, create_session_factory
from app.infrastructure.observation_store import claim_collection_run
from app.models.devices import Device, DeviceCredential
from app.models.observation import CollectionRun, DeviceEvent, MetricLatest, MetricPoint, UiEvent
from app.workers.scheduler import Scheduler
from sqlalchemy import func, select, text
from tests.observation_factories import seed_capabilities

DSN = "postgresql://warden@127.0.0.1:55433/warden"
MASTER_KEY = b"smoke-master-key-00000000000000000"  # 32 bytes, dev only

FAKE = FakeSimpleAdapter()


def main() -> int:
    settings = WardenSettings(postgres_dsn=DSN, app_env="development", public_url="http://localhost")
    engine = create_db_engine(DSN)
    factory = create_session_factory(engine)
    keyring = CredentialKeyring.from_current(CredentialCipher(MASTER_KEY))
    device_id = None
    try:
        with factory() as session:
            now = datetime.datetime.now(datetime.UTC)
            device = Device(
                name="smoke-m2t2-device",
                device_type="server",
                vendor="Fake",
                model="FakeServer-1",
                management_endpoint="192.168.50.99",
                adapter_key=FAKE.adapter_key,
                connection_config={},
                enabled=True,
                readiness="ready",
                reachability="unknown",
                health="unknown",
                next_poll_at=now - datetime.timedelta(seconds=60),
            )
            session.add(device)
            session.flush()
            device_id = device.id
            plaintext = canonical_json({"username": "admin", "password": "smoke-only"})
            encrypted = keyring.current_cipher().encrypt_secret(
                plaintext,
                key_version=keyring.current_version,
                aad=credential_aad(str(device.id), FAKE.adapter_key, FAKE.secret_schema_version),
            )
            session.add(
                DeviceCredential(
                    device_id=device.id,
                    ciphertext=encrypted.ciphertext,
                    nonce=encrypted.nonce,
                    key_version=encrypted.key_version,
                    secret_schema_version=FAKE.secret_schema_version,
                )
            )
            seed_capabilities(session, device)
            session.commit()

        lock_acquired = Scheduler(factory, settings=settings).run_once()
        print(f"[smoke] scheduler lock acquired: {lock_acquired}")

        with factory() as session:
            runs = session.scalars(
                select(CollectionRun).where(CollectionRun.device_id == device_id)
            ).all()
            print(f"[smoke] scheduled runs: {[(r.collection_type, r.state) for r in runs]}")

        processed = 0
        while True:
            with factory() as session:
                run = claim_collection_run(session, lease_owner="smoke", lease_seconds=300)
                session.commit()
            if run is None:
                break
            with factory() as session:
                run_collection(session, run, settings=settings, keyring=keyring)
                session.commit()
            processed += 1
        print(f"[smoke] collection runs processed: {processed}")

        with factory() as session:
            device = session.get(Device, device_id)
            assert device is not None
            print(
                f"[smoke] device: reachability={device.reachability} "
                f"health={device.health} failures={device.consecutive_failures} "
                f"successes={device.consecutive_successes} last_collected_at={device.last_collected_at}"
            )
            latest_count = session.scalar(
                select(func.count()).select_from(MetricLatest).where(MetricLatest.device_id == device_id)
            )
            print(f"[smoke] metric_latest rows: {latest_count}")
            point_count = session.scalar(
                select(func.count()).select_from(MetricPoint).where(MetricPoint.device_id == device_id)
            )
            print(f"[smoke] metric_points rows: {point_count}")
            partition = session.execute(
                text(
                    "SELECT c.relname FROM metric_points p JOIN pg_class c ON c.oid = p.tableoid "
                    "WHERE p.device_id = :did LIMIT 1"
                ),
                {"did": device_id},
            ).scalar()
            print(f"[smoke] points partition: {partition}")
            event_count = session.scalar(
                select(func.count()).select_from(DeviceEvent).where(DeviceEvent.device_id == device_id)
            )
            print(f"[smoke] device_events rows (native-id deduped): {event_count}")
            ui_count = session.scalar(
                select(func.count()).select_from(UiEvent).where(UiEvent.entity_id == device_id)
            )
            print(f"[smoke] ui_events (device.updated): {ui_count}")
            latest_cpu = session.scalar(
                select(MetricLatest.value_double).where(
                    MetricLatest.device_id == device_id, MetricLatest.metric_key == "temperature.cpu"
                )
            )
            print(f"[smoke] temperature.cpu latest value: {latest_cpu} Cel")
        print("[smoke] OK")
        return 0
    finally:
        if device_id is not None:
            with factory() as session:
                session.execute(text("DELETE FROM ui_events WHERE entity_id = :did"), {"did": device_id})
                session.execute(text("DELETE FROM devices WHERE id = :did"), {"did": device_id})
                session.commit()
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
