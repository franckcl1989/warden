"""M1 gate: adversarial security suite (PLT-01/02/07, M1T6 brief §1).

The milestone gate proves the security properties of the M1 implementation
against the REAL HTTP flow and the REAL freshly-migrated PostgreSQL — no test
doubles anywhere the real path exists:

- authz: anonymous 401s, viewer/operator 403s on device/user/audit
  administration, no endpoint to change another user's password, own-account
  reauth allowed, operator/viewer device.read;
- credential leakage: a full onboarding flow (probe → save → get → probe
  existing → keep-credentials update → audit list/get → probe failures →
  OpenAPI spec) plus DB evidence that stored credentials are ciphertext;
- SSRF: probe against loopback/metadata/RFC 1918/denied hostnames → 422
  network_unreachable stage=endpoint_policy;
- migrations: fresh-cluster upgrade head applies every revision and the
  append-only audit trigger rejects UPDATE/DELETE;
- fake-adapter end-to-end onboarding as a real logged-in user;
- session security: cookie attributes (HttpOnly/SameSite=Strict/Secure in
  production), independent sessions, logout revocation, absolute expiry;
- CSRF: missing/wrong token, Origin mismatch on login and on mutations.
"""

from __future__ import annotations

import base64
import datetime
import json
import uuid
from pathlib import Path

import psycopg
import psycopg.types.json
import pytest
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from app.config import WardenSettings
from app.generated.capabilities import REQUIREMENTS
from app.infrastructure.crypto import (
    CredentialCipher,
    CredentialKeyring,
    EncryptedSecret,
    credential_aad,
)
from app.infrastructure.csrf import hash_csrf_secret, issue_csrf_secret
from app.infrastructure.session_tokens import (
    SESSION_COOKIE_NAME,
    generate_session_token,
    hash_session_token,
)
from app.infrastructure.time import utcnow
from app.main import create_app
from app.models.auth import AuditLog
from app.models.auth import Session as DBSession
from app.models.devices import DeviceCredential
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.api.auth_helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_user,
    login,
    login_csrf,
)
from tests.api.test_devices import admin_csrf, create_device, probe_and_get_token
from tests.api.test_probe_endpoint import base_probe

API = "/api/v1"
PROBE_PATH = f"{API}/device-probes"
DEVICES_PATH = f"{API}/devices"
PASSWORD = "device-pass-123"
BACKEND_DIR = Path(__file__).resolve().parents[2]
MISSING_UUID = "00000000-0000-0000-0000-000000000000"
OPERATOR = ("operator.1", "Oper!ator-2026-Pass")
VIEWER = ("viewer.1", "View!er-2026-Pass")


def _login_csrf_ok(client: TestClient, username: str, password: str) -> str:
    response, csrf = login_csrf(client, username, password)
    assert response.status_code == 200, response.text
    return csrf


def _audit_counts(db: Session) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in db.scalars(select(AuditLog)).all():
        counts[row.action] = counts.get(row.action, 0) + 1
    return counts


# ---------------------------------------------------------------- authz (越权)

@pytest.mark.integration
def test_anonymous_calls_to_api_v1_require_auth(device_client: TestClient) -> None:
    anonymous = TestClient(device_client.app)
    user_body = {"username": "nobody", "display_name": "X", "role": "viewer", "password": "Valid!Pass-2026-x"}
    device_body = {
        "name": "x",
        "device_type": "server",
        "adapter_key": "fake.simple",
        "management_endpoint": "192.0.2.60",
        "connection_config": {},
        "credentials": {"username": "admin", "password": PASSWORD},
        "enabled": False,
        "probe_token": "x",
    }
    expectations: list[tuple[str, str, dict[str, object]]] = [
        ("get", f"{API}/auth/me", {}),
        ("post", f"{API}/auth/logout", {}),
        ("post", f"{API}/auth/reauth", {"json": {"password": "Whatever-2026!"}}),
        ("get", f"{API}/roles", {}),
        ("get", f"{API}/users", {}),
        ("post", f"{API}/users", {"json": user_body}),
        ("patch", f"{API}/users/{MISSING_UUID}", {"json": {"version": 1}}),
        ("get", f"{API}/devices", {}),
        ("get", f"{API}/devices/{MISSING_UUID}", {}),
        ("get", f"{API}/devices/{MISSING_UUID}/capabilities", {}),
        ("post", f"{API}/device-probes", {"json": base_probe()}),
        ("post", f"{API}/devices", {"json": device_body}),
        ("patch", f"{API}/devices/{MISSING_UUID}", {"json": {"name": "x"}, "headers": {"If-Match": "1"}}),
        ("post", f"{API}/devices/{MISSING_UUID}/probe", {}),
        ("get", f"{API}/audit-logs", {}),
        ("get", f"{API}/audit-logs/{MISSING_UUID}", {}),
    ]
    for method, path, kwargs in expectations:
        response = getattr(anonymous, method)(path, **kwargs)
        assert response.status_code == 401, (method, path, response.text)
        assert response.json()["error"]["code"] == "unauthenticated", (method, path)
    # /auth/login is the only public /api/v1 endpoint: bad credentials are a
    # validation error, never a 401 (the anonymous path must stay reachable).
    bad_login = anonymous.post(
        f"{API}/auth/login", json={"username": "nobody", "password": "Wrong-Pass-2026!"}
    )
    assert bad_login.status_code == 422
    assert bad_login.json()["error"]["code"] == "validation_failed"


@pytest.mark.integration
def test_viewer_and_operator_cannot_manage_devices_users_or_read_audit(
    device_client: TestClient, db_session: Session
) -> None:
    admin = create_admin(db_session)
    create_user(db_session, username=OPERATOR[0], password=OPERATOR[1], role="operator")
    create_user(db_session, username=VIEWER[0], password=VIEWER[1], role="viewer")
    csrf_admin = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf_admin)
    created = create_device(device_client, csrf_admin, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    for username, password in (OPERATOR, VIEWER):
        csrf = _login_csrf_ok(device_client, username, password)
        headers = {"X-CSRF-Token": csrf}
        # device administration: probe / create / update / re-probe all denied
        denied_probe = device_client.post(PROBE_PATH, json=base_probe(), headers=headers)
        assert denied_probe.status_code == 403, username
        assert denied_probe.json()["error"]["code"] == "permission_denied"
        denied_create = device_client.post(
            DEVICES_PATH,
            json={
                "name": "blocked-device",
                "device_type": "server",
                "adapter_key": "fake.simple",
                "management_endpoint": "192.0.2.70",
                "connection_config": {},
                "credentials": {"username": "admin", "password": PASSWORD},
                "enabled": False,
                "probe_token": probe["probe_token"],
            },
            headers=headers,
        )
        assert denied_create.status_code == 403, username
        denied_update = device_client.patch(
            f"{DEVICES_PATH}/{device_id}",
            json={"name": "renamed"},
            headers={**headers, "If-Match": "1"},
        )
        assert denied_update.status_code == 403, username
        denied_reprobe = device_client.post(
            f"{DEVICES_PATH}/{device_id}/probe", headers=headers
        )
        assert denied_reprobe.status_code == 403, username
        # user administration denied (list + create)
        assert device_client.get(f"{API}/users", headers=headers).status_code == 403, username
        denied_user_create = device_client.post(
            f"{API}/users",
            json={
                "username": "evil.user",
                "display_name": "E",
                "role": "viewer",
                "password": "Valid!Pass-2026-x",
            },
            headers=headers,
        )
        assert denied_user_create.status_code == 403, username
        # changing another user's password: the admin-only users_update path is
        # denied, and no dedicated per-user password endpoint exists (404/405)
        patch_other_password = device_client.patch(
            f"{API}/users/{admin.id}",
            json={"version": 1, "new_password": "Valid!Pass-2026-x"},
            headers=headers,
        )
        assert patch_other_password.status_code == 403, username
        no_password_endpoint = device_client.post(
            f"{API}/users/{admin.id}/password", headers=headers
        )
        assert no_password_endpoint.status_code == 404, username
        no_delete_endpoint = device_client.delete(f"{API}/users/{admin.id}", headers=headers)
        assert no_delete_endpoint.status_code == 405, username
        # audit read denied (admin-only)
        assert device_client.get(f"{API}/audit-logs", headers=headers).status_code == 403, username
        assert (
            device_client.get(f"{API}/audit-logs/{MISSING_UUID}", headers=headers).status_code
            == 403
        ), username
        # own-account reauth stays allowed for every role
        reauth = device_client.post(
            f"{API}/auth/reauth", json={"password": password}, headers=headers
        )
        assert reauth.status_code == 200, username


@pytest.mark.integration
def test_operator_and_viewer_can_read_devices_and_capabilities(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    create_user(db_session, username=OPERATOR[0], password=OPERATOR[1], role="operator")
    create_user(db_session, username=VIEWER[0], password=VIEWER[1], role="viewer")
    csrf_admin = admin_csrf(device_client)
    probe = probe_and_get_token(device_client, csrf_admin)
    created = create_device(device_client, csrf_admin, token=probe["probe_token"])
    assert created.status_code == 201
    device_id = created.json()["id"]
    for username, password in (OPERATOR, VIEWER):
        csrf = _login_csrf_ok(device_client, username, password)
        headers = {"X-CSRF-Token": csrf}
        listing = device_client.get(DEVICES_PATH, headers=headers)
        assert listing.status_code == 200, username
        assert listing.json()["total"] == 1, username
        fetched = device_client.get(f"{DEVICES_PATH}/{device_id}", headers=headers)
        assert fetched.status_code == 200, username
        capabilities = device_client.get(
            f"{DEVICES_PATH}/{device_id}/capabilities", headers=headers
        )
        assert capabilities.status_code == 200, username
        assert capabilities.json()["items"], username
        me = device_client.get(f"{API}/auth/me", headers=headers)
        permissions = me.json()["permissions"]
        assert "device.read" in permissions, username
        assert "device.manage" not in permissions, username
        assert "audit.read" not in permissions, username


# ------------------------------------------------------ credential leakage (凭据泄露)

@pytest.mark.integration
def test_credentials_never_leak_through_any_surface(
    device_client: TestClient, db_session: Session, device_settings: WardenSettings
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    headers = {"X-CSRF-Token": csrf}
    captured: list[object] = []

    def capture(response: object) -> object:
        captured.append(response)
        return response

    probe = capture(device_client.post(PROBE_PATH, json=base_probe(), headers=headers))
    assert probe.status_code == 200
    assert probe.json()["ok"] is True
    assert PASSWORD not in probe.text
    assert "password" not in probe.text

    created = capture(
        create_device(device_client, csrf, token=probe.json()["probe_token"])
    )
    assert created.status_code == 201
    device_id = created.json()["id"]
    assert PASSWORD not in created.text
    assert "password" not in created.text

    fetched = capture(device_client.get(f"{DEVICES_PATH}/{device_id}", headers=headers))
    assert fetched.status_code == 200
    listing = capture(device_client.get(DEVICES_PATH, headers=headers))
    assert listing.status_code == 200

    reprobe = capture(device_client.post(f"{DEVICES_PATH}/{device_id}/probe", headers=headers))
    assert reprobe.status_code == 200

    # keep-credentials update: connection_config change with a fresh probe
    # token and NO credentials in the payload (stored secrets are re-used)
    keep_probe = capture(
        device_client.post(
            PROBE_PATH, json=base_probe(connection_config={"port": 8443}), headers=headers
        )
    )
    assert keep_probe.status_code == 200
    updated = capture(
        device_client.patch(
            f"{DEVICES_PATH}/{device_id}",
            json={"connection_config": {"port": 8443}, "probe_token": keep_probe.json()["probe_token"]},
            headers={**headers, "If-Match": "1"},
        )
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    audit_list = capture(device_client.get(f"{API}/audit-logs", headers=headers))
    assert audit_list.status_code == 200
    assert "password" not in audit_list.text
    device_audit_ids = [
        item["id"] for item in audit_list.json()["items"] if item["action"].startswith("device.")
    ]
    assert device_audit_ids, "expected device.* audit rows"
    for audit_id in device_audit_ids:
        detail = capture(device_client.get(f"{API}/audit-logs/{audit_id}", headers=headers))
        assert detail.status_code == 200
        assert "password" not in detail.text, audit_id

    # probe failures: an auth-stage failure (200 with failed stages) and an
    # SSRF-policy rejection (422) must not echo anything either
    failed = capture(
        device_client.post(
            PROBE_PATH,
            json=base_probe(connection_config={"fail_credentials": True}),
            headers=headers,
        )
    )
    assert failed.status_code == 200
    assert failed.json()["ok"] is False
    assert PASSWORD not in failed.text
    assert "password" not in failed.text
    denied = capture(
        device_client.post(PROBE_PATH, json=base_probe(management_endpoint="127.0.0.1"), headers=headers)
    )
    assert denied.status_code == 422
    assert PASSWORD not in denied.text
    assert "password" not in denied.text

    # the OpenAPI spec is fetched anonymously like a real client would
    spec = capture(device_client.get("/openapi.json"))
    assert spec.status_code == 200
    spec_body = spec.json()
    spec_text = spec.text
    device_schema_props: set[str] = set()

    def _collect_props(node: object, props: set[str]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    props.update(value.keys())
                _collect_props(value, props)
        elif isinstance(node, list):
            for item in node:
                _collect_props(item, props)

    for path, operations in spec_body["paths"].items():
        if path.startswith(f"{API}/devices") or path == f"{API}/device-probes":
            for operation in operations.values():
                _collect_props(operation, device_schema_props)
    assert {"password", "username"} & device_schema_props == set(), (
        "the device secret schema must never be embedded in the OpenAPI spec"
    )

    # DB evidence: stored credentials are AES-GCM ciphertext, decryptable only
    # through the keystore with the device-bound AAD
    credential = db_session.scalar(
        select(DeviceCredential).where(DeviceCredential.device_id == uuid.UUID(device_id))
    )
    assert credential is not None
    assert PASSWORD.encode("utf-8") not in credential.ciphertext
    key_file = device_settings.credential_master_key_file
    assert key_file is not None
    keyring = CredentialKeyring.from_current(CredentialCipher(key_file.read_bytes()))
    plaintext = keyring.decrypt(
        EncryptedSecret(
            ciphertext=credential.ciphertext,
            nonce=credential.nonce,
            key_version=credential.key_version,
        ),
        aad=credential_aad(str(device_id), "fake.simple", credential.secret_schema_version),
    )
    assert json.loads(plaintext) == {"username": "admin", "password": PASSWORD}

    # the plaintext value, its base64 form and the stored ciphertext/nonce
    # (base64) must never have appeared in ANY captured response body
    forbidden = {
        PASSWORD,
        base64.b64encode(PASSWORD.encode("utf-8")).decode("ascii"),
        base64.b64encode(credential.ciphertext).decode("ascii"),
        base64.b64encode(credential.nonce).decode("ascii"),
    }
    for response in captured:
        text = response.text
        for material in forbidden:
            assert material not in text, (material, text)
    for material in forbidden:
        assert material not in spec_text, material


# ----------------------------------------------------------------- SSRF (跨站请求伪造防护)

@pytest.mark.integration
def test_probe_rejects_ssrf_targets(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    headers = {"X-CSRF-Token": csrf}
    for endpoint in ("127.0.0.1", "169.254.169.254", "::1", "10.0.0.1", "localhost"):
        response = device_client.post(
            PROBE_PATH, json=base_probe(management_endpoint=endpoint), headers=headers
        )
        assert response.status_code == 422, (endpoint, response.text)
        error = response.json()["error"]
        assert error["code"] == "network_unreachable", endpoint
        assert error["details"]["stage"] == "endpoint_policy", endpoint
        assert PASSWORD not in response.text, endpoint


# --------------------------------------------------------------- migrations (迁移)

def _head_revision() -> str:
    config = AlembicConfig(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None, "migration tree has no head revision"
    return head


@pytest.mark.integration
def test_full_upgrade_applies_all_revisions_and_audit_trigger_blocks_mutation(
    fresh_test_db_dsn: str,
) -> None:
    head = _head_revision()
    assert head == "0012_operation_attempts"
    with psycopg.connect(fresh_test_db_dsn) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        assert version is not None and version[0] == head, version
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            )
        }
        assert {
            "users",
            "sessions",
            "audit_logs",
            "devices",
            "device_credentials",
            "device_capabilities",
            "components",
            "operation_tasks",
            "operation_task_events",
            "collection_runs",
            "metric_points",
            "metric_latest",
            "device_events",
            "collection_observation_errors",
            "alerts",
            "ui_events",
            "metric_rollups_5m",
            "metric_rollups_1h",
            "preview_token_uses",
        } <= tables, tables
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_logs'::regclass"
            )
        }
        assert {"audit_logs_no_update", "audit_logs_no_delete"} <= triggers, triggers
        task_event_triggers = {
            row[0]
            for row in connection.execute(
                "SELECT tgname FROM pg_trigger "
                "WHERE tgrelid = 'operation_task_events'::regclass"
            )
        }
        assert {
            "operation_task_events_no_update",
            "operation_task_events_no_delete",
        } <= task_event_triggers, task_event_triggers
        connection.execute(
            "INSERT INTO audit_logs (id, action, result, detail_jsonb) "
            "VALUES (gen_random_uuid(), 'm1.gate', 'success', %s)",
            (psycopg.types.json.Jsonb({}),),
        )
        connection.commit()
        with pytest.raises(psycopg.Error):
            connection.execute(
                "UPDATE audit_logs SET result = 'tampered' WHERE action = 'm1.gate'"
            )
            connection.commit()
        with pytest.raises(psycopg.Error):
            connection.execute("DELETE FROM audit_logs WHERE action = 'm1.gate'")
            connection.commit()


# --------------------------------------------- fake-adapter E2E onboarding (假适配器端到端接入)

@pytest.mark.integration
def test_fake_adapter_full_onboarding_flow_end_to_end(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    csrf = admin_csrf(device_client)
    headers = {"X-CSRF-Token": csrf}

    probe = device_client.post(PROBE_PATH, json=base_probe(), headers=headers)
    assert probe.status_code == 200
    body = probe.json()
    assert body["ok"] is True

    created = create_device(
        device_client, csrf, token=body["probe_token"], name="e2e-srv-01", endpoint="192.0.2.10"
    )
    assert created.status_code == 201
    device_view = created.json()
    assert device_view["readiness"] == "ready"
    assert device_view["enabled"] is True
    device_id = device_view["id"]

    listing = device_client.get(DEVICES_PATH, headers=headers)
    assert listing.status_code == 200
    assert any(item["id"] == device_id for item in listing.json()["items"])

    capabilities = device_client.get(f"{DEVICES_PATH}/{device_id}/capabilities", headers=headers)
    assert capabilities.status_code == 200
    items = capabilities.json()["items"]
    expected_keys = {
        key
        for requirement in REQUIREMENTS.values()
        if requirement.device_type == "server"
        for key in (
            *requirement.metrics,
            *requirement.events,
            *(operation[0] for operation in requirement.operations),
        )
    }
    assert {item["capability_key"] for item in items} == expected_keys
    assert all(item["support_state"] == "supported" for item in items)

    reprobe = device_client.post(f"{DEVICES_PATH}/{device_id}/probe", headers=headers)
    assert reprobe.status_code == 200
    assert reprobe.json()["ok"] is True
    assert reprobe.json()["device"]["readiness"] == "ready"

    renamed = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"name": "e2e-srv-renamed"},
        headers={**headers, "If-Match": "1"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "e2e-srv-renamed"
    assert renamed.json()["version"] == 2

    new_endpoint = "192.0.2.51"
    moved_without_token = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"management_endpoint": new_endpoint},
        headers={**headers, "If-Match": "2"},
    )
    assert moved_without_token.status_code == 422
    assert moved_without_token.json()["error"]["details"]["field"] == "probe_token"

    new_probe = device_client.post(
        PROBE_PATH, json=base_probe(management_endpoint=new_endpoint), headers=headers
    )
    assert new_probe.status_code == 200
    moved = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"management_endpoint": new_endpoint, "probe_token": new_probe.json()["probe_token"]},
        headers={**headers, "If-Match": "2"},
    )
    assert moved.status_code == 200
    assert moved.json()["management_endpoint"] == new_endpoint
    assert moved.json()["version"] == 3

    disabled = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"enabled": False},
        headers={**headers, "If-Match": "3"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert disabled.json()["version"] == 4

    reenabled = device_client.patch(
        f"{DEVICES_PATH}/{device_id}",
        json={"enabled": True},
        headers={**headers, "If-Match": "4"},
    )
    assert reenabled.status_code == 200
    assert reenabled.json()["enabled"] is True
    assert reenabled.json()["version"] == 5

    counts = _audit_counts(db_session)
    assert counts["auth.login"] == 1, counts
    assert counts["device.create"] == 1, counts
    assert counts["device.probe"] == 1, counts
    assert counts["device.update"] == 4, counts
    ordered = db_session.scalars(
        select(AuditLog)
        .where(AuditLog.action.in_(("device.create", "device.probe", "device.update")))
        .order_by(AuditLog.occurred_at)
    ).all()
    assert [row.action for row in ordered] == [
        "device.create",
        "device.probe",
        "device.update",
        "device.update",
        "device.update",
        "device.update",
    ], [row.action for row in ordered]


# ------------------------------------------------------------- session security (会话安全)

@pytest.mark.integration
def test_session_cookie_attributes_and_independent_sessions(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    create_user(db_session, username=OPERATOR[0], password=OPERATOR[1], role="operator")
    admin_login = login(device_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert admin_login.status_code == 200
    admin_set_cookie = admin_login.headers.get("set-cookie", "")
    assert "HttpOnly" in admin_set_cookie
    assert "samesite=strict" in admin_set_cookie.lower()
    assert "path=/" in admin_set_cookie.lower()
    assert "secure" not in admin_set_cookie.lower(), "localhost dev must not force Secure"
    admin_cookie = device_client.cookies.get(SESSION_COOKIE_NAME)
    assert admin_cookie

    operator_login = login(device_client, OPERATOR[0], OPERATOR[1])
    assert operator_login.status_code == 200
    operator_cookie = device_client.cookies.get(SESSION_COOKIE_NAME)
    assert operator_cookie and operator_cookie != admin_cookie, "each login must issue a new token"

    rows = db_session.scalars(select(DBSession)).all()
    assert len(rows) == 2
    assert all(row.revoked_at is None for row in rows)
    assert all(row.session_id_hash != admin_cookie for row in rows), "DB stores only the hash"

    # Sessions are independent (SECURITY.md §2 does not require single-session):
    # the FIRST cookie still authenticates on a fresh client.
    other = TestClient(device_client.app)
    other.cookies.set(SESSION_COOKIE_NAME, admin_cookie)
    me = other.get(f"{API}/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == ADMIN_USERNAME


@pytest.mark.integration
def test_production_session_cookie_is_secure(
    device_settings: WardenSettings, db_session: Session
) -> None:
    create_admin(db_session)
    prod_settings = device_settings.model_copy(
        update={"app_env": "production", "public_url": "https://warden.example"}
    )
    app = create_app(prod_settings)
    try:
        with TestClient(app) as client:
            response = login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
            assert response.status_code == 200
            set_cookie = response.headers.get("set-cookie", "")
            assert "secure" in set_cookie.lower()
            assert "HttpOnly" in set_cookie
            assert "samesite=strict" in set_cookie.lower()
            assert "path=/" in set_cookie.lower()
    finally:
        engine = app.state.engine
        if engine is not None:
            engine.dispose()


@pytest.mark.integration
def test_absolute_expiry_enforced(device_client: TestClient, db_session: Session) -> None:
    user = create_admin(db_session)
    token = generate_session_token()
    db_session.add(
        DBSession(
            session_id_hash=hash_session_token(token),
            user_id=user.id,
            expires_at=utcnow() + datetime.timedelta(minutes=30),
            absolute_expires_at=utcnow() - datetime.timedelta(minutes=1),
            csrf_secret_hash=hash_csrf_secret(issue_csrf_secret()),
        )
    )
    db_session.commit()
    device_client.cookies.set(SESSION_COOKIE_NAME, token)
    me = device_client.get(f"{API}/auth/me")
    assert me.status_code == 401
    assert me.json()["error"]["code"] == "session_expired"


@pytest.mark.integration
def test_logout_revokes_session(device_client: TestClient, db_session: Session) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(device_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200
    cookie = device_client.cookies.get(SESSION_COOKIE_NAME)
    assert cookie
    logout = device_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 200
    assert "max-age=0" in logout.headers.get("set-cookie", "").lower()
    assert device_client.get(f"{API}/auth/me").status_code == 401
    row = db_session.scalar(
        select(DBSession).where(DBSession.session_id_hash == hash_session_token(cookie))
    )
    assert row is not None
    assert row.revoked_at is not None


# ----------------------------------------------------------------------- CSRF

@pytest.mark.integration
def test_csrf_required_on_mutating_requests_and_origin_checked(
    device_client: TestClient, db_session: Session
) -> None:
    create_admin(db_session)
    response, csrf = login_csrf(device_client, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert response.status_code == 200

    no_token = device_client.post(f"{API}/auth/logout")
    assert no_token.status_code == 403
    assert no_token.json()["error"]["code"] == "csrf_failed"

    wrong_token = device_client.post(
        f"{API}/auth/logout", headers={"X-CSRF-Token": "bm90LXRoZS1zZWNyZXQ"}
    )
    assert wrong_token.status_code == 403
    assert wrong_token.json()["error"]["code"] == "csrf_failed"

    no_token_patch = device_client.patch(
        f"{DEVICES_PATH}/{MISSING_UUID}",
        json={"name": "x"},
        headers={"If-Match": "1"},
    )
    assert no_token_patch.status_code == 403
    assert no_token_patch.json()["error"]["code"] == "csrf_failed"

    # a VALID token from the wrong origin is rejected on mutating requests
    cross_origin = device_client.post(
        f"{API}/auth/logout",
        headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"},
    )
    assert cross_origin.status_code == 403
    assert cross_origin.json()["error"]["code"] == "csrf_failed"

    # Origin mismatch on login is rejected too
    bad_origin_login = login(
        device_client, ADMIN_USERNAME, ADMIN_PASSWORD, origin="https://evil.example"
    )
    assert bad_origin_login.status_code == 403
    assert bad_origin_login.json()["error"]["code"] == "csrf_failed"

    # rejected CSRF attempts must not have damaged the session
    me = device_client.get(f"{API}/auth/me")
    assert me.status_code == 200

    ok = device_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 200
