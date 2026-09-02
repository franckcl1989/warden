"""Credential keystore: AES-256-GCM application-layer encryption (docs/SECURITY.md §5).

Design (M1T2, no credentials table yet — the table sweep lands with M1T3):

- ``CredentialCipher`` holds one master key derived from the read-only Secret
  file content. A file shorter than 32 bytes is rejected at startup; a 32-byte
  file is used as the AES-256 key directly; longer files (e.g. a 64-char hex
  or 43-char base64 secret) are deterministically derived to 32 bytes with
  HKDF-SHA256, info ``b"warden-credential-master-key-v1"``. The derivation is
  deterministic so the same file content always yields the same key.
- Each encryption uses a fresh random 12-byte nonce; authentication is AES-GCM.
- ``CredentialKeyring`` maps ``key_version`` to ciphers: the current key plus
  the retired-but-still-valid previous key for online rotation overlap. New
  writes use the current key; ``reencrypt`` moves a record to the current key
  version (a no-op when it is already current).
- AAD binds each ciphertext to device id + adapter key + secret schema version
  so a ciphertext cannot be substituted across devices/adapters/schemas.

The master key and plaintext never appear in repr/str/logs.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MIN_MASTER_KEY_BYTES = 32
NONCE_BYTES = 12
HKDF_INFO = b"warden-credential-master-key-v1"
AAD_PREFIX = b"warden-credential-aad-v1"

# M2T5 file master key (docs/SECURITY.md §9): config backups / support
# bundles / operation logs are encrypted with a per-file key that is wrapped
# by this master key. The HKDF context and the AAD prefix are DISTINCT from
# the credential keystore so a ciphertext can never be interpreted across the
# two contexts, and the wrap AAD binds the wrapped key to its storage name.
FILE_KEY_HKDF_INFO = b"warden-file-key-v1"
FILE_KEY_AAD_PREFIX = b"warden-file-key-aad-v1"

_KEY_REDACTED = "<redacted>"


class DecryptionError(Exception):
    """Raised when decryption fails (tamper, wrong key or unknown key_version)."""


@dataclass(frozen=True)
class EncryptedSecret:
    """Encrypted credential payload. ``repr`` shows only hex ciphertext."""

    ciphertext: bytes
    nonce: bytes
    key_version: int

    def __repr__(self) -> str:
        return (
            f"EncryptedSecret(ciphertext={self.ciphertext.hex()}, "
            f"nonce={self.nonce.hex()}, key_version={self.key_version})"
        )


def _derive_key(raw: bytes, info: bytes = HKDF_INFO) -> bytes:
    if len(raw) < MIN_MASTER_KEY_BYTES:
        msg = f"credential master key must be at least {MIN_MASTER_KEY_BYTES} bytes"
        raise ValueError(msg)
    if len(raw) == MIN_MASTER_KEY_BYTES:
        return raw
    return HKDF(
        algorithm=hashes.SHA256(),
        length=MIN_MASTER_KEY_BYTES,
        salt=None,
        info=info,
    ).derive(raw)


def credential_aad(device_id: str, adapter_key: str, secret_schema_version: int) -> bytes:
    """Length-prefixed AAD binding a ciphertext to device/adapter/schema identity."""
    parts = [
        len(device_id.encode("utf-8")).to_bytes(4, "big") + device_id.encode("utf-8"),
        len(adapter_key.encode("utf-8")).to_bytes(4, "big") + adapter_key.encode("utf-8"),
        len(str(secret_schema_version).encode("utf-8")).to_bytes(4, "big")
        + str(secret_schema_version).encode("utf-8"),
    ]
    return AAD_PREFIX + b"".join(parts)


class CredentialCipher:
    """One master key with AES-256-GCM encrypt/decrypt of credential secrets."""

    def __init__(self, master_key_material: bytes) -> None:
        self._key = _derive_key(master_key_material)
        self._aesgcm = AESGCM(self._key)
        self._key_sha256 = sha256(self._key).hexdigest()

    def fingerprint(self) -> str:
        """SHA-256 of the derived key (for key-version listing; not secret material)."""
        return self._key_sha256

    def encrypt_secret(self, plaintext: str, *, key_version: int, aad: bytes) -> EncryptedSecret:
        """Encrypt ``plaintext`` with a fresh random nonce under this key."""
        nonce = secrets.token_bytes(NONCE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return EncryptedSecret(ciphertext=ciphertext, nonce=nonce, key_version=key_version)

    def decrypt_secret(self, encrypted: EncryptedSecret, *, aad: bytes) -> str:
        """Decrypt and authenticate ``encrypted``; raises ``DecryptionError`` on failure."""
        try:
            plaintext = self._aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, aad)
        except Exception as exc:  # cryptography InvalidTag and ValueError surface here
            raise DecryptionError("credential decryption failed (tamper or wrong key)") from exc
        return plaintext.decode("utf-8")

    def __repr__(self) -> str:
        return f"CredentialCipher(key_sha256={self._key_sha256[:16]}...{_KEY_REDACTED})"

    __str__ = __repr__


class CredentialKeyring:
    """Current + retired-previous key versions; the unit M1T3's sweep re-encrypts against."""

    def __init__(self, keys: dict[int, CredentialCipher], *, current_version: int) -> None:
        if not keys:
            msg = "keyring requires at least one key"
            raise ValueError(msg)
        if any(version < 1 for version in keys):
            msg = "key versions must be positive integers"
            raise ValueError(msg)
        if current_version not in keys:
            msg = f"current_version {current_version} is not present in keys"
            raise ValueError(msg)
        self._keys = dict(keys)
        self._current_version = current_version

    @classmethod
    def from_current(cls, current: CredentialCipher) -> CredentialKeyring:
        return cls({1: current}, current_version=1)

    @classmethod
    def from_previous_and_current(
        cls, previous: CredentialCipher, current: CredentialCipher
    ) -> CredentialKeyring:
        return cls({1: previous, 2: current}, current_version=2)

    @property
    def current_version(self) -> int:
        return self._current_version

    def current_cipher(self) -> CredentialCipher:
        return self._keys[self._current_version]

    def versions(self) -> dict[int, CredentialCipher]:
        return dict(self._keys)

    def rotate(self, new_key: CredentialCipher) -> int:
        """Rotate to ``new_key``; keeps the previous key for overlap, drops older ones.

        Returns the new current key_version. Rotating to an already-present key
        (same fingerprint) is rejected: it cannot change protection.
        """
        if any(cipher.fingerprint() == new_key.fingerprint() for cipher in self._keys.values()):
            msg = "new key already present in the keyring"
            raise ValueError(msg)
        new_version = max(self._keys) + 1
        previous_version = self._current_version
        self._keys = {previous_version: self._keys[previous_version], new_version: new_key}
        self._current_version = new_version
        return new_version

    def cipher_for(self, key_version: int) -> CredentialCipher:
        try:
            return self._keys[key_version]
        except KeyError as exc:
            raise DecryptionError(f"unknown key_version {key_version}") from exc

    def decrypt(self, encrypted: EncryptedSecret, *, aad: bytes) -> str:
        return self.cipher_for(encrypted.key_version).decrypt_secret(encrypted, aad=aad)

    def reencrypt(self, encrypted: EncryptedSecret, *, aad: bytes) -> EncryptedSecret:
        """Return ``encrypted`` re-encrypted under the current key (no-op if already current)."""
        if encrypted.key_version == self._current_version:
            return encrypted
        plaintext = self.decrypt(encrypted, aad=aad)
        return self.current_cipher().encrypt_secret(
            plaintext, key_version=self._current_version, aad=aad
        )

    def __repr__(self) -> str:
        versions = ", ".join(
            f"{version}:{cipher.fingerprint()[:16]}..."
            for version, cipher in sorted(self._keys.items())
        )
        return f"CredentialKeyring(current_version={self._current_version}, keys={{{versions}}})"

    __str__ = __repr__


def file_key_aad(storage_name: str) -> bytes:
    """Length-prefixed AAD binding a wrapped file key to its storage name.

    SECURITY.md §9: per-file keys are wrapped under the file master key; the
    AAD prevents a wrapped key from being replayed under another storage name
    (an envelope swap across files).
    """
    parts = [
        len(storage_name.encode("utf-8")).to_bytes(4, "big") + storage_name.encode("utf-8"),
    ]
    return FILE_KEY_AAD_PREFIX + b"".join(parts)


class FileKeyCipher:
    """File master key: wraps per-file content keys (docs/SECURITY.md §9, M2T5).

    AES-256-GCM wrapping of random 32-byte per-file keys, master key derived
    from the read-only ``file_master_key_file`` Secret (config.py) with the
    DISTINCT HKDF context ``warden-file-key-v1`` — the credential keystore
    derivation context never applies here, so the two keystores cannot share
    material semantics. ``key_version`` is fixed at 1 for a single current
    master key in 0.1.0 (rotation would introduce a keyring like the
    credential one; not required by the M2 scope).
    """

    def __init__(self, master_key_material: bytes) -> None:
        # The 32-byte "use raw" shortcut of the credential derivation is NOT
        # reused here: the file-key master key must always be HKDF-derived
        # under its own info context so that identical secret-file material
        # can never yield the same key across the two keystores (SECURITY.md
        # §5/§9 context separation).
        if len(master_key_material) < MIN_MASTER_KEY_BYTES:
            msg = f"file master key must be at least {MIN_MASTER_KEY_BYTES} bytes"
            raise ValueError(msg)
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=MIN_MASTER_KEY_BYTES,
            salt=None,
            info=FILE_KEY_HKDF_INFO,
        ).derive(master_key_material)
        self._aesgcm = AESGCM(self._key)
        self._key_sha256 = sha256(self._key).hexdigest()

    def fingerprint(self) -> str:
        """SHA-256 of the derived key (key-identity, not secret material)."""
        return self._key_sha256

    def wrap(self, file_key: bytes, *, storage_name: str) -> EncryptedSecret:
        """Wrap one 32-byte file key under this master key (fresh nonce)."""
        nonce = secrets.token_bytes(NONCE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, file_key, file_key_aad(storage_name))
        return EncryptedSecret(ciphertext=ciphertext, nonce=nonce, key_version=1)

    def unwrap(self, wrapped: EncryptedSecret, *, storage_name: str) -> bytes:
        """Unwrap and authenticate ``wrapped``; raises ``DecryptionError``."""
        try:
            return self._aesgcm.decrypt(
                wrapped.nonce, wrapped.ciphertext, file_key_aad(storage_name)
            )
        except Exception as exc:  # cryptography InvalidTag and ValueError surface here
            raise DecryptionError("file key unwrap failed (tamper or wrong master key)") from exc

    def __repr__(self) -> str:
        return f"FileKeyCipher(key_sha256={self._key_sha256[:16]}...{_KEY_REDACTED})"

    __str__ = __repr__
