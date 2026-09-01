"""Credential master key rotation CLI (docs/SECURITY.md §5, rotation skeleton).

Lists and validates the key versions of the credential keystore from the
read-only Secret key files: the current key (``--current-key-file`` or
``WARDEN_CREDENTIAL_MASTER_KEY_FILE``) and the optional retired-but-still-valid
previous key (``--previous-key-file``) used for the rotation overlap.

The sweep that re-encrypts old credential records (``reencrypt_all`` over the
credentials table) lands with M1T3, when the table exists; this command today
validates the key files and prints the version layout the sweep would use.
Key material is never printed — only SHA-256 fingerprints of the derived keys
and version numbers.

Usage::

    python -m app.tools.key_rotation --current-key-file /run/secrets/credential.key
    python -m app.tools.key_rotation --current-key-file ... --previous-key-file ...
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.config import get_settings
from app.infrastructure.crypto import CredentialCipher, CredentialKeyring

MAX_FINGERPRINT_DISPLAY = 32


def _load_cipher(path: Path) -> CredentialCipher:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read key file {path}: {exc}"
        raise ValueError(msg) from exc
    material = raw.strip().encode("utf-8")
    if not material:
        msg = f"key file {path} is empty"
        raise ValueError(msg)
    return CredentialCipher(material)


def _print_ring(ring: CredentialKeyring) -> None:
    print(f"credential keyring: current key_version={ring.current_version}")
    for version in sorted(ring.versions()):
        cipher = ring.versions()[version]
        label = "current" if version == ring.current_version else "retired"
        print(
            f"  key_version {version} ({label}): "
            f"sha256 {cipher.fingerprint()[:MAX_FINGERPRINT_DISPLAY]}"
        )
    print(
        "note: the re-encrypt sweep over the credentials table lands with M1T3; "
        "until then old records keep their stored key_version."
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List and validate credential master key versions (M1 rotation skeleton)."
    )
    parser.add_argument(
        "--current-key-file",
        help="current credential master key file (WARDEN_CREDENTIAL_MASTER_KEY_FILE)",
    )
    parser.add_argument("--previous-key-file", help="retired previous key file (optional)")
    return parser.parse_args(argv)


def run(argv: list[str]) -> int:
    args = _parse_args(argv)
    current_path = args.current_key_file
    if not current_path:
        settings = get_settings()
        if settings.credential_master_key_file is not None:
            current_path = str(settings.credential_master_key_file)
    if not current_path:
        print(
            "error: no credential master key file "
            "(--current-key-file or WARDEN_CREDENTIAL_MASTER_KEY_FILE)",
            file=sys.stderr,
        )
        return 2
    previous_path = args.previous_key_file
    try:
        current = _load_cipher(Path(current_path))
        if previous_path:
            previous = _load_cipher(Path(previous_path))
            ring = CredentialKeyring.from_previous_and_current(previous, current)
        else:
            ring = CredentialKeyring.from_current(current)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_ring(ring)
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
