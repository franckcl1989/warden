"""Device API integration tests (real PostgreSQL, docs/API_CONTRACT §4).

Covers the two-step probe_token flow end to end: create with a valid token
(device + encrypted credentials + capabilities + components persisted in one
transaction, ciphertext != plaintext, response without credentials),
create with a failure token (not_ready + enabled=false), fingerprint
mismatch rejection, PATCH rules (If-Match 412, name-only without probe,
security changes require a new token, failed fresh probe rejected), re-probe
of a saved device, capabilities listing, filters, 404s, non-admin 403s and
audit rows.
"""

from __future__ import annotations

import json
import uuid

import pytest
from app.config import WardenSettings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring, EncryptedSecret, credential_aad
from app.models.auth import AuditLog
from app.models.devices import Component, Device, DeviceCapability, DeviceCredential
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_user,
    login_csrf,
)
from tests.api.test_probe_endpoint import base_probe

API = "/api/v1"
PROBE_PATH = f"{API}/device-probes"
DEVICES_PATH = f"{API}/devices"
PASSWORD = "device-pass-123"


def admin_csrf(device_client: TestClient) -> str:
    response, csrf = login_csrf(device_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    return csrf


def probe_and_get_token(
    device_client: TestClient,
    csrf: str,
    **probe_overrides: object,
) -> dict[str, object]:
    response = device_client.post(
        PROBE_PATH,
        json=base_probe(**probe_overrides),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    return response.json()


def create_device(
    device_client: TestClient,
    csrf: str,
    *,
    token: str,
    name: str = "fake-srv-01",
    enabled: bool = True,
    endpoint: str = "192.0.2.10",
    connection_config: dict[str, object] | None = None,
    credentials: dict[str, object] | None = None,
    **body_overrides: object,
) -> object:
    payload: dict[str, object] = {
        "name": name,
        "device_type": "server",
        "adapter_key": "fake.simple",
        "management_endpoint": endpoint,
        "connection_config": connection_config or {},
        "credentials": credentials or {"username": "admin", "password": PASSWORD},
        "enabled": enabled,
        "probe_token": token,
    }
    payload.update(body_overrides)
    return device_client.post(DEVICES_PATH, json=payload, headers={"X-CSRF-Token": csrf})


def device_row(db_session: Session, device_id: str) -> Device:
    row = db_session.get(Device, uuid.UUID(device_id))
    assert row is not None
    return row


def build_keyring(settings: WardenSettings) -> CredentialKeyring:
    key_file = settings.credential_master_key_file
    assert key_file is not None
    return CredentialKeyring.from_current(CredentialCipher(key_file.read_bytes()))


def decrypt_credentials(
    db_session: Session, device_id: str, keyring: CredentialKeyring
) -> dict[str, object]:
    row = db_session.scalar(
        select(DeviceCredential).where(DeviceCredential.device_id == uuid.UUID(device_id))
    )
    assert row is not None
    encrypted = EncryptedSecret(
        ciphertext=row.ciphertext, nonce=row.nonce, key_version=row.key_version
    )
    plaintext = keyring.decrypt(
        encrypted,
        aad=credential_aad(str(device_id), "fake.simple", row.secret_schema_version),
    )
    return json.loads(plaintext)


def count_audit(db_session: Session, action: str) -> int:
    return len(db_session.scalars(select(AuditLog).where(AuditLog.action == action)).all())


@pytest.mark.integration
def test_create_with_valid_token_succeeds(
    device_client: TestClient, db_session: Session, device_settings
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    assert probe["ok"] is True
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    body = created.json()
    assert body["name"] == "fake-srv-01"
    assert body["device_type"] == "server"
    assert body["readiness"] == "ready"
    assert body["enabled"] is True
    assert body["version"] == 1
    assert body["vendor"] == "Fake"
    assert body["serial_number"] == "FAKE-SN-0001"
    assert body["reachability"] == "unknown"
    assert body["health"] == "unknown"
    assert PASSWORD not in created.text
    assert "credentials" not in created.text

    device = device_row(db_session, body["id"])
    credential = db_session.scalar(
        select(DeviceCredential).where(DeviceCredential.device_id == device.id)
    )
    assert credential is not None
    assert credential.key_version == 1
    assert PASSWORD.encode("utf-8") not in credential.ciphertext
    decrypted = decrypt_credentials(db_session, body["id"], build_keyring(device_settings))
    assert decrypted == {"username": "admin", "password": PASSWORD}
    capabilities = db_session.scalars(
        select(DeviceCapability).where(DeviceCapability.device_id == device.id)
    ).all()
    assert len(capabilities) >= 20
    assert all(item.support_state == "supported" for item in capabilities)
    components = db_session.scalars(select(Component).where(Component.device_id == device.id)).all()
    assert len(components) == 5
    assert all(item.retired_at is None for item in components)
    assert count_audit(db_session, "device.create") == 1


@pytest.mark.integration
def test_create_with_failed_probe_token_saves_not_ready(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf, connection_config={"fail_credentials": True})
    assert probe["ok"] is False
    created = create_device(
        device_client,
        csrf,
        token=probe["probe_token"],
        enabled=True,
        connection_config={"fail_credentials": True},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["readiness"] == "not_ready"
    assert body["enabled"] is False
    assert body["vendor"] is None
    device = device_row(db_session, body["id"])
    assert db_session.scalar(
        select(DeviceCapability).where(DeviceCapability.device_id == device.id)
    ) is None


@pytest.mark.integration
def test_create_with_wrong_fingerprint_rejected(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    assert probe["ok"] is True
    wrong_endpoint = "192.0.2.20"
    created = create_device(device_client, csrf, token=probe["probe_token"], endpoint=wrong_endpoint)
    assert created.status_code == 422
    error = created.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "probe_token"
    assert count_audit(db_session, "device.create") == 0


@pytest.mark.integration
def test_create_with_tampered_token_rejected(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    tampered = probe["probe_token"][:-1] + ("0" if probe["probe_token"][-1] != "0" else "1")
    created = create_device(device_client, csrf, token=tampered)
    assert created.status_code == 422
    error = created.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "probe_token"


@pytest.mark.integration
def test_create_without_token_rejected(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    created = create_device(device_client, csrf, token="")
    assert created.status_code == 400
    assert created.json()["error"]["code"] == "invalid_request"


@pytest.mark.integration
def test_create_duplicate_name_rejected(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    first = create_device(device_client, csrf, token=probe["probe_token"])
    assert first.status_code == 201
    second_probe = probe_and_get_token(device_client, csrf, management_endpoint="192.0.2.30")
    duplicate = create_device(
        device_client, csrf, token=second_probe["probe_token"], endpoint="192.0.2.30"
    )
    assert duplicate.status_code == 422
    error = duplicate.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "name"


@pytest.mark.integration
def test_non_admin_cannot_manage_devices(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    create_user(db_session, username="operator.1", password="Oper!ator-2026-Pass", role="operator")
    create_user(db_session, username="viewer.1", password="View!er-2026-Pass", role="viewer")
    csrf_admin = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf_admin)
    created = create_device(device_client, csrf_admin, token=probe["probe_token"])
    assert created.status_code == 201
    for username, password in (("operator.1", "Oper!ator-2026-Pass"), ("viewer.1", "View!er-2026-Pass")):
        response, csrf = login_csrf(device_client, username, password)
        assert response.status_code == 200
        denied = device_client.post(
            DEVICES_PATH,
            json={
                "name": "blocked-device",
                "device_type": "server",
                "adapter_key": "fake.simple",
                "management_endpoint": "192.0.2.40",
                "connection_config": {},
                "credentials": {"username": "admin", "password": PASSWORD},
                "enabled": False,
                "probe_token": probe["probe_token"],
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert denied.status_code == 403
        patch_denied = device_client.patch(
            f"{DEVICES_PATH}/{created.json()['id']}",
            json={"name": "renamed"},
            headers={"X-CSRF-Token": csrf, "If-Match": "1"},
        )
        assert patch_denied.status_code == 403
        probe_denied = device_client.post(
            f"{DEVICES_PATH}/{created.json()['id']}/probe", headers={"X-CSRF-Token": csrf}
        )
        assert probe_denied.status_code == 403
    # All roles can read.
    response, viewer_csrf = login_csrf(device_client, "viewer.1", "View!er-2026-Pass")
    assert response.status_code == 200
    listing = device_client.get(DEVICES_PATH, headers={"X-CSRF-Token": viewer_csrf})
    assert listing.status_code == 200
    assert listing.json()["total"] == 1


@pytest.mark.integration
def test_list_filters_and_pagination(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe_a = probe_and_get_token(device_client, csrf)
    first = create_device(
        device_client, csrf, token=probe_a["probe_token"], name="srv-01", endpoint="192.0.2.10"
    )
    assert first.status_code == 201
    probe_b = probe_and_get_token(device_client, csrf, management_endpoint="192.0.2.11")
    second = create_device(
        device_client, csrf, token=probe_b["probe_token"], name="srv-02", endpoint="192.0.2.11"
    )
    assert second.status_code == 201
    headers = {"X-CSRF-Token": csrf}
    by_name = device_client.get(f"{DEVICES_PATH}?name=srv-01", headers=headers)
    assert by_name.status_code == 200
    assert by_name.json()["total"] == 1
    by_type = device_client.get(f"{DEVICES_PATH}?device_type=server", headers=headers)
    assert by_type.json()["total"] == 2
    by_vendor = device_client.get(f"{DEVICES_PATH}?vendor=Fake", headers=headers)
    assert by_vendor.json()["total"] == 2
    by_health = device_client.get(f"{DEVICES_PATH}?health=unknown", headers=headers)
    assert by_health.json()["total"] == 2
    by_enabled = device_client.get(f"{DEVICES_PATH}?enabled=true", headers=headers)
    assert by_enabled.json()["total"] == 2
    page = device_client.get(f"{DEVICES_PATH}?page=1&page_size=1", headers=headers)
    assert page.json()["total"] == 2
    assert len(page.json()["items"]) == 1


@pytest.mark.integration
def test_get_device_and_404(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    fetched = device_client.get(f"{DEVICES_PATH}/{device_id}", headers={"X-CSRF-Token": csrf})
    assert fetched.status_code == 200
    assert fetched.json()["version"] == 1
    assert PASSWORD not in fetched.text
    missing = device_client.get(
        f"{DEVICES_PATH}/00000000-0000-0000-0000-000000000000", headers={"X-CSRF-Token": csrf}
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "resource_not_found"
    garbage = device_client.get(f"{DEVICES_PATH}/not-a-uuid", headers={"X-CSRF-Token": csrf})
    assert garbage.status_code == 404
    from fastapi.testclient import TestClient

    anonymous = TestClient(device_client.app)
    assert anonymous.get(DEVICES_PATH).status_code == 401


@pytest.mark.integration
def test_patch_name_only_without_probe(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    patched = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"name": "renamed-srv"},
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert patched.status_code == 200
    body = patched.json()
    assert body["name"] == "renamed-srv"
    assert body["version"] == 2
    assert body["readiness"] == "ready"
    assert count_audit(db_session, "device.update") == 1


@pytest.mark.integration
def test_patch_if_match_mismatch_returns_412(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    stale = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"name": "first"},
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert stale.status_code == 200
    conflict = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"name": "second"},
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert conflict.status_code == 412
    error = conflict.json()["error"]
    assert error["code"] == "version_conflict"
    assert error["details"]["current_version"] == 2
    missing_header = device_client.patch(
        f"{DEVICES_PATH}/{device_id}", json={"name": "third"}, headers={"X-CSRF-Token": csrf}
    )
    assert missing_header.status_code == 412
    assert missing_header.json()["error"]["code"] == "version_conflict"


@pytest.mark.integration
def test_patch_endpoint_requires_new_probe_token(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    without_token = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"management_endpoint": "192.0.2.50"},
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert without_token.status_code == 422
    error = without_token.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "probe_token"


@pytest.mark.integration
def test_patch_security_changes_with_valid_token(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    new_probe = probe_and_get_token(
        device_client, csrf, management_endpoint="192.0.2.50", connection_config={"port": 8443}
    )
    patched = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={
            "management_endpoint": "192.0.2.50",
            "connection_config": {"port": 8443},
            "probe_token": new_probe["probe_token"],
        },
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert patched.status_code == 200
    body = patched.json()
    assert body["management_endpoint"] == "192.0.2.50"
    assert body["connection_config"]["port"] == 8443
    assert body["readiness"] == "ready"
    assert body["version"] == 2
    assert count_audit(db_session, "device.update") == 1


@pytest.mark.integration
def test_patch_credentials_replacement(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    new_password = "rotated-pass-456"
    new_probe = probe_and_get_token(
        device_client, csrf, credentials={"username": "admin", "password": new_password}
    )
    patched = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={
            "credentials": {"username": "admin", "password": new_password},
            "probe_token": new_probe["probe_token"],
        },
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert patched.status_code == 200
    assert patched.json()["version"] == 2
    assert new_password not in patched.text
    credential = db_session.scalar(
        select(DeviceCredential).where(DeviceCredential.device_id == uuid.UUID(device_id))
    )
    assert credential is not None
    assert new_password.encode("utf-8") not in credential.ciphertext
    audit = db_session.scalar(
        select(AuditLog).where(AuditLog.action == "device.update").order_by(AuditLog.occurred_at.desc())
    )
    assert audit is not None
    assert new_password not in str(audit.detail_jsonb)
    assert "credentials_digest" in audit.detail_jsonb


@pytest.mark.integration
def test_patch_with_failed_fresh_probe_rejected(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    new_probe = probe_and_get_token(
        device_client,
        csrf,
        connection_config={"fail_credentials": True},
        credentials={"username": "admin", "password": "bad-pass"},
    )
    patched = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={
            "credentials": {"username": "admin", "password": "bad-pass"},
            "connection_config": {"fail_credentials": True},
            "probe_token": new_probe["probe_token"],
        },
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert patched.status_code == 422
    error = patched.json()["error"]
    assert error["code"] == "authentication_failed"
    # The unverified configuration was NOT applied.
    fetched = device_client.get(f"{DEVICES_PATH}/{device_id}", headers={"X-CSRF-Token": csrf})
    assert fetched.json()["version"] == 1


@pytest.mark.integration
def test_patch_enable_not_ready_device_rejected(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf, connection_config={"fail_credentials": True})
    created = create_device(
        device_client,
        csrf,
        token=probe["probe_token"],
        connection_config={"fail_credentials": True},
    )
    assert created.status_code == 201
    assert created.json()["readiness"] == "not_ready"
    patched = device_client.patch(
        f"{DEVICES_PATH}/{created.json()['id']}",
        json={"enabled": True},
        headers={"X-CSRF-Token": csrf, "If-Match": "1"},
    )
    assert patched.status_code == 422
    error = patched.json()["error"]
    assert error["code"] == "validation_failed"
    assert error["details"]["field"] == "enabled"


@pytest.mark.integration
def test_probe_existing_device_refreshes_capabilities(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    first_check = db_session.scalar(
        select(DeviceCapability.last_checked_at).where(
            DeviceCapability.device_id == uuid.UUID(device_id)
        )
    )
    assert first_check is not None
    re_probe = device_client.post(
        f"{DEVICES_PATH}/{device_id}/probe", headers={"X-CSRF-Token": csrf}
    )
    assert re_probe.status_code == 200
    body = re_probe.json()
    assert body["ok"] is True
    assert body["discovery"]["vendor"] == "Fake"
    assert body["probe_token"]
    assert body["device"]["readiness"] == "ready"
    second_check = db_session.scalar(
        select(DeviceCapability.last_checked_at).where(
            DeviceCapability.device_id == uuid.UUID(device_id)
        )
    )
    assert second_check is not None
    assert second_check >= first_check
    assert count_audit(db_session, "device.probe") == 1
    # Components were upserted, not duplicated.
    components = db_session.scalars(select(Component).where(Component.device_id == uuid.UUID(device_id)))
    assert len(components.all()) == 5


@pytest.mark.integration
def test_probe_existing_failing_device_becomes_misconfigured(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(
        device_client, csrf, connection_config={"fail_credentials": True}
    )
    created = create_device(
        device_client,
        csrf,
        token=probe["probe_token"],
        connection_config={"fail_credentials": True},
    )
    assert created.status_code == 201
    assert created.json()["readiness"] == "not_ready"
    re_probe = device_client.post(
        f"{DEVICES_PATH}/{created.json()['id']}/probe", headers={"X-CSRF-Token": csrf}
    )
    assert re_probe.status_code == 200
    assert re_probe.json()["ok"] is False
    assert re_probe.json()["device"]["readiness"] == "misconfigured"


@pytest.mark.integration
def test_capabilities_listing(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    listing = device_client.get(
        f"{DEVICES_PATH}/{device_id}/capabilities", headers={"X-CSRF-Token": csrf}
    )
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert len(items) >= 20
    by_key = {item["capability_key"]: item for item in items}
    assert by_key["power.cycle"]["support_state"] == "supported"
    assert by_key["power.cycle"]["requirement_id"] == "SRV-ACT-02"
    assert by_key["power.cycle"]["requirement_title"]
    assert by_key["temperature.cpu"]["requirement_id"] == "SRV-MON-02"
    missing = device_client.get(
        f"{DEVICES_PATH}/00000000-0000-0000-0000-000000000000/capabilities",
        headers={"X-CSRF-Token": csrf},
    )
    assert missing.status_code == 404


@pytest.mark.integration
def test_audit_rows_never_contain_plaintext(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf)
    created = create_device(device_client, csrf, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    device_client.post(f"{DEVICES_PATH}/{device_id}/probe", headers={"X-CSRF-Token": csrf})
    audit_rows = db_session.scalars(select(AuditLog)).all()
    assert {row.action for row in audit_rows} >= {"device.create", "device.probe"}
    for row in audit_rows:
        if row.action.startswith("device."):
            assert PASSWORD not in str(row.detail_jsonb)
            assert "credentials_digest" in row.detail_jsonb or "fields" in row.detail_jsonb
