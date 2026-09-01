"""Regression: PATCH adapter_key without replacing credentials must re-encrypt.

A PATCH that changes ``adapter_key`` while keeping the credentials decrypts
the existing ciphertext with the OLD AAD (device_id + old adapter_key +
secret_schema_version) and must store it again under the NEW AAD with the SAME
key_version (docs/SECURITY.md §5). Without the re-encryption the device row
carries the new adapter_key while the credential row stays bound to the old
AAD; every later decrypt (probe_existing_device, collection) fails AEAD and
wedges the device permanently.

The registry only has ``fake.simple`` (M3 brings real adapters), so this test
works at the service level with a test-only second adapter key
``fake.simple.v2`` that behaves identically and is never registered.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.adapters.fake import FakeSimpleAdapter
from app.application.devices import (
    build_connection_profile,
    probe_device,
    probe_existing_device,
    save_device_from_probe,
    update_device,
)
from app.config import WardenSettings
from app.infrastructure.crypto import (
    CredentialCipher,
    CredentialKeyring,
    DecryptionError,
    EncryptedSecret,
    credential_aad,
)
from app.models.devices import DeviceCredential
from sqlalchemy import select
from sqlalchemy.orm import Session

ENDPOINT = "192.0.2.10"
PASSWORD = "device-pass-123"


class FakeSimpleV2Adapter(FakeSimpleAdapter):
    """Test-only second adapter key with identical behavior (never registered)."""

    adapter_key = "fake.simple.v2"


@pytest.fixture
def reencrypt_settings(tmp_path: Path, fresh_test_db_dsn: str) -> WardenSettings:
    key_file = tmp_path / "credential_master.key"
    key_file.write_text("K" * 64, encoding="utf-8")
    session_file = tmp_path / "session_secret.txt"
    session_file.write_text("S" * 64, encoding="utf-8")
    return WardenSettings(
        postgres_dsn=fresh_test_db_dsn,
        app_env="development",
        public_url="http://localhost",
        _env_file=None,
        allowed_device_cidrs="192.0.2.0/24",
        credential_master_key_file=key_file,
        session_secret_file=session_file,
    )


@pytest.mark.integration
def test_adapter_key_change_reencrypts_credentials_under_new_aad(
    db_session: Session, reencrypt_settings: WardenSettings
) -> None:
    settings = reencrypt_settings
    keyring = CredentialKeyring.from_current(
        CredentialCipher(settings.credential_master_key_file.read_bytes())
    )
    old_adapter = FakeSimpleAdapter()
    new_adapter = FakeSimpleV2Adapter()
    credentials = {"username": "admin", "password": PASSWORD}

    initial_profile = build_connection_profile(
        old_adapter,
        device_id=None,
        management_endpoint=ENDPOINT,
        port=None,
        connection_config={},
        credentials=credentials,
    )
    initial_outcome = probe_device(
        initial_profile, allow_save=True, settings=settings, adapter=old_adapter
    )
    assert initial_outcome.ok
    device = save_device_from_probe(
        db_session,
        profile=initial_profile,
        name="fake-srv-01",
        device_type="server",
        enabled=True,
        probe_token=initial_outcome.probe_token,
        settings=settings,
        keyring=keyring,
        adapter=old_adapter,
    )
    credential = db_session.scalar(
        select(DeviceCredential).where(DeviceCredential.device_id == device.id)
    )
    assert credential is not None
    original_key_version = credential.key_version
    original_ciphertext = credential.ciphertext

    new_profile = build_connection_profile(
        new_adapter,
        device_id=device.id,
        management_endpoint=device.management_endpoint,
        port=None,
        connection_config=dict(device.connection_config),
        credentials=credentials,
    )
    new_outcome = probe_device(
        new_profile, allow_save=False, settings=settings, adapter=new_adapter
    )
    assert new_outcome.ok

    result = update_device(
        db_session,
        device,
        if_match_version=1,
        name=None,
        enabled=None,
        management_endpoint=None,
        adapter_key=new_adapter.adapter_key,
        connection_config=None,
        credentials=None,
        probe_token=new_outcome.probe_token,
        settings=settings,
        keyring=keyring,
        adapter=new_adapter,
    )
    assert result.device.adapter_key == "fake.simple.v2"
    assert "adapter_key" in result.changed_fields

    credential = db_session.scalar(
        select(DeviceCredential).where(DeviceCredential.device_id == device.id)
    )
    assert credential is not None
    assert credential.key_version == original_key_version
    assert credential.ciphertext != original_ciphertext

    encrypted = EncryptedSecret(
        ciphertext=credential.ciphertext,
        nonce=credential.nonce,
        key_version=credential.key_version,
    )
    new_aad = credential_aad(
        str(device.id), "fake.simple.v2", credential.secret_schema_version
    )
    decrypted = keyring.decrypt(encrypted, aad=new_aad)
    assert json.loads(decrypted) == credentials
    with pytest.raises(DecryptionError):
        keyring.decrypt(
            encrypted,
            aad=credential_aad(str(device.id), "fake.simple", credential.secret_schema_version),
        )

    reprobe = probe_existing_device(
        db_session, result.device, settings=settings, keyring=keyring, adapter=new_adapter
    )
    assert reprobe.ok
    assert result.device.readiness == "ready"
