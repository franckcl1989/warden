"""Credential keystore tests (docs/SECURITY.md §5).

AES-256-GCM application-layer encryption with per-credential random nonces,
key_version rotation and AAD binding to device/adapter/schema identity.
Plaintext must never appear in repr/str.
"""

from __future__ import annotations

import secrets

import pytest
from app.infrastructure.crypto import (
    CredentialCipher,
    CredentialKeyring,
    DecryptionError,
    EncryptedSecret,
    credential_aad,
)

MASTER_KEY_32 = b"k" * 32
MASTER_KEY_OTHER = b"x" * 32


def make_cipher() -> CredentialCipher:
    return CredentialCipher(MASTER_KEY_32)


@pytest.mark.unit
def test_round_trip_encrypt_decrypt() -> None:
    cipher = make_cipher()
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = cipher.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    assert cipher.decrypt_secret(encrypted, aad=aad) == "S3cret-Pass!"


@pytest.mark.unit
def test_wrong_key_fails() -> None:
    cipher_a = make_cipher()
    cipher_b = CredentialCipher(MASTER_KEY_OTHER)
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = cipher_a.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    with pytest.raises(DecryptionError):
        cipher_b.decrypt_secret(encrypted, aad=aad)


@pytest.mark.unit
def test_tampered_ciphertext_fails() -> None:
    cipher = make_cipher()
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = cipher.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    tampered = EncryptedSecret(
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 0xFF]),
        nonce=encrypted.nonce,
        key_version=encrypted.key_version,
    )
    with pytest.raises(DecryptionError):
        cipher.decrypt_secret(tampered, aad=aad)


@pytest.mark.unit
def test_aad_mismatch_fails() -> None:
    cipher = make_cipher()
    aad_a = credential_aad("device-1", "server.dell_idrac", 1)
    aad_b = credential_aad("device-2", "server.dell_idrac", 1)
    encrypted = cipher.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad_a)
    with pytest.raises(DecryptionError):
        cipher.decrypt_secret(encrypted, aad=aad_b)


@pytest.mark.unit
def test_per_encryption_nonce_is_unique_and_12_bytes() -> None:
    cipher = make_cipher()
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    first = cipher.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    second = cipher.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    assert len(first.nonce) == 12
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext
    assert first.key_version == second.key_version == 1


@pytest.mark.unit
def test_key_version_is_recorded() -> None:
    cipher = make_cipher()
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = cipher.encrypt_secret("S3cret-Pass!", key_version=7, aad=aad)
    assert encrypted.key_version == 7


@pytest.mark.unit
def test_short_master_key_material_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        CredentialCipher(b"too-short")


@pytest.mark.unit
def test_32_byte_material_used_as_is() -> None:
    raw = secrets.token_bytes(32)
    first = CredentialCipher(raw)
    second = CredentialCipher(raw)
    assert first.fingerprint() == second.fingerprint()


@pytest.mark.unit
def test_longer_material_derived_deterministically() -> None:
    hex_secret = "a" * 64
    base64_secret = "b" * 43
    hex_a = CredentialCipher(hex_secret.encode("ascii"))
    hex_b = CredentialCipher(hex_secret.encode("ascii"))
    assert hex_a.fingerprint() == hex_b.fingerprint()
    assert hex_a.fingerprint() != CredentialCipher(base64_secret.encode("ascii")).fingerprint()
    assert CredentialCipher(hex_secret.encode("ascii")).fingerprint() != CredentialCipher(
        b"a" * 32
    ).fingerprint()


@pytest.mark.unit
def test_reencrypt_changes_key_version_and_still_decrypts() -> None:
    old = make_cipher()
    new = CredentialCipher(b"n" * 32)
    ring = CredentialKeyring.from_current(old)
    ring.rotate(new)
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = old.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    reencrypted = ring.reencrypt(encrypted, aad=aad)
    assert reencrypted.key_version == 2
    assert ring.decrypt(reencrypted, aad=aad) == "S3cret-Pass!"
    assert new.decrypt_secret(reencrypted, aad=aad) == "S3cret-Pass!"


@pytest.mark.unit
def test_reencrypt_current_version_is_noop() -> None:
    ring = CredentialKeyring.from_current(make_cipher())
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = ring.current_cipher().encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    assert ring.reencrypt(encrypted, aad=aad) is encrypted


@pytest.mark.unit
def test_unknown_key_version_fails() -> None:
    ring = CredentialKeyring.from_current(make_cipher())
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = EncryptedSecret(ciphertext=b"garbage", nonce=b"n" * 12, key_version=99)
    with pytest.raises(DecryptionError, match="key_version"):
        ring.decrypt(encrypted, aad=aad)


@pytest.mark.unit
def test_rotate_returns_new_version_and_keeps_previous_valid() -> None:
    ring = CredentialKeyring.from_current(make_cipher())
    new_version = ring.rotate(CredentialCipher(b"r" * 32))
    assert new_version == 2
    assert ring.current_version == 2
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    old_encrypted = CredentialCipher(b"k" * 32).encrypt_secret(
        "S3cret-Pass!", key_version=1, aad=aad
    )
    assert ring.decrypt(old_encrypted, aad=aad) == "S3cret-Pass!"


@pytest.mark.unit
def test_rotate_to_same_key_rejected() -> None:
    ring = CredentialKeyring.from_current(make_cipher())
    with pytest.raises(ValueError, match="already"):
        ring.rotate(CredentialCipher(b"k" * 32))


@pytest.mark.unit
def test_rotate_drops_older_retired_keys() -> None:
    old = make_cipher()
    mid = CredentialCipher(b"m" * 32)
    new = CredentialCipher(b"n" * 32)
    ring = CredentialKeyring.from_current(old)
    ring.rotate(mid)
    ring.rotate(new)
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    old_encrypted = old.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    with pytest.raises(DecryptionError):
        ring.decrypt(old_encrypted, aad=aad)


@pytest.mark.unit
def test_repr_and_str_never_contain_plaintext_or_key() -> None:
    cipher = make_cipher()
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    encrypted = cipher.encrypt_secret("S3cret-Pass!", key_version=1, aad=aad)
    ring = CredentialKeyring.from_current(cipher)
    for rendered in (
        repr(cipher),
        str(cipher),
        repr(encrypted),
        str(encrypted),
        repr(ring),
        str(ring),
    ):
        assert "S3cret-Pass!" not in rendered
        assert "k" * 32 not in rendered
        assert b"k" * 32 not in rendered.encode("utf-8", errors="replace")


@pytest.mark.unit
def test_credential_aad_is_deterministic_and_sensitive_to_all_fields() -> None:
    base = credential_aad("device-1", "server.dell_idrac", 1)
    assert base == credential_aad("device-1", "server.dell_idrac", 1)
    assert base != credential_aad("device-2", "server.dell_idrac", 1)
    assert base != credential_aad("device-1", "nas.synology_dsm", 1)
    assert base != credential_aad("device-1", "server.dell_idrac", 2)
    assert base != credential_aad("device-1-2", "server.dell_idrac", 1)


@pytest.mark.unit
def test_previous_and_current_ring_classmethod() -> None:
    ring = CredentialKeyring.from_previous_and_current(make_cipher(), CredentialCipher(b"z" * 32))
    assert ring.current_version == 2
    aad = credential_aad("device-1", "server.dell_idrac", 1)
    old_encrypted = CredentialCipher(b"k" * 32).encrypt_secret(
        "S3cret-Pass!", key_version=1, aad=aad
    )
    new_encrypted = CredentialCipher(b"z" * 32).encrypt_secret(
        "S3cret-Pass!", key_version=2, aad=aad
    )
    assert ring.decrypt(old_encrypted, aad=aad) == "S3cret-Pass!"
    assert ring.decrypt(new_encrypted, aad=aad) == "S3cret-Pass!"
