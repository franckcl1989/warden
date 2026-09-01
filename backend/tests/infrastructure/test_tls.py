"""TLS fingerprint pinning tests (docs/SECURITY.md §6).

Fingerprint format/compare helpers, the TlsVerification decision model and
the post-handshake pin check exercised against a real in-process TLS server
with an in-memory generated self-signed certificate.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from app.infrastructure.tls import (
    TlsDecisionState,
    TlsPinMismatch,
    TlsVerification,
    build_ssl_context,
    decide_verification,
    open_pinned_connection,
    tls_fingerprint,
    validate_fingerprint,
    verify_peer_connection,
    verify_peer_fingerprint,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class SelfSignedFixture:
    """In-memory self-signed leaf certificate and matching private key."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "warden-test")])
        now = datetime.now(UTC)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(123456)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        self.der = self.cert.public_bytes(serialization.Encoding.DER)
        self.pem = self.cert.public_bytes(serialization.Encoding.PEM)
        self.key_pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.fingerprint = tls_fingerprint(self.der)


@pytest.fixture(scope="module")
def self_signed() -> SelfSignedFixture:
    return SelfSignedFixture()


@pytest.mark.unit
def test_fingerprint_is_sha256_hex() -> None:
    der = b"some-der-bytes"
    fp = tls_fingerprint(der)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


@pytest.mark.unit
def test_fingerprint_format_validation() -> None:
    assert validate_fingerprint("a" * 64) is True
    assert validate_fingerprint("A" * 64) is True
    assert validate_fingerprint(("ab" * 32)[:63]) is False
    assert validate_fingerprint("a" * 65) is False
    assert validate_fingerprint(("a" * 63) + "g") is False
    assert validate_fingerprint("") is False


@pytest.mark.unit
def test_fingerprint_compare_mismatch(self_signed: SelfSignedFixture) -> None:
    assert verify_peer_fingerprint(self_signed.der, self_signed.fingerprint) is True
    assert verify_peer_fingerprint(self_signed.der, "0" * 64) is False
    with pytest.raises(ValueError):
        verify_peer_fingerprint(self_signed.der, "not-a-fingerprint")


@pytest.mark.unit
def test_decision_model_states(self_signed: SelfSignedFixture) -> None:
    assert decide_verification(False, None, self_signed.der) == TlsVerification(
        TlsDecisionState.NOT_CONFIGURED
    )
    assert decide_verification(True, None, self_signed.der) == TlsVerification(
        TlsDecisionState.NOT_CONFIGURED
    )
    assert decide_verification(True, self_signed.fingerprint, self_signed.der) == TlsVerification(
        TlsDecisionState.VERIFIED
    )
    mismatch = decide_verification(True, "0" * 64, self_signed.der)
    assert mismatch.state == TlsDecisionState.MISMATCH
    assert mismatch.expected_fingerprint == "0" * 64


@pytest.mark.unit
def test_decision_model_rejects_malformed_pin() -> None:
    with pytest.raises(ValueError):
        decide_verification(True, "short", b"der")


@pytest.mark.unit
def test_build_ssl_context_rejects_unverified_mode() -> None:
    with pytest.raises(ValueError, match="unverified"):
        build_ssl_context(verify_tls=False, pinned_fingerprint=None, ca_bundle_path=None)


@pytest.mark.unit
def test_build_ssl_context_ca_mode_validates_hostname_and_chain() -> None:
    ctx = build_ssl_context(verify_tls=True, pinned_fingerprint=None, ca_bundle_path=None)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


@pytest.mark.unit
def test_build_ssl_context_pin_mode_accepts_peer_for_post_handshake_check() -> None:
    ctx = build_ssl_context(verify_tls=True, pinned_fingerprint="a" * 64, ca_bundle_path=None)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


@pytest.mark.unit
def test_build_ssl_context_rejects_malformed_pin() -> None:
    with pytest.raises(ValueError):
        build_ssl_context(verify_tls=True, pinned_fingerprint="bad", ca_bundle_path=None)


@pytest.mark.unit
def test_verify_peer_connection_accepts_matching_pin(
    self_signed: SelfSignedFixture,
) -> None:
    with _tls_server(self_signed) as port:
        sock = _client_socket(port, self_signed.fingerprint)
        with sock:
            verify_peer_connection(sock, self_signed.fingerprint)


@pytest.mark.unit
def test_verify_peer_connection_rejects_wrong_pin(self_signed: SelfSignedFixture) -> None:
    with _tls_server(self_signed) as port:
        sock = _client_socket(port, self_signed.fingerprint)
        with sock, pytest.raises(TlsPinMismatch, match="fingerprint"):
            verify_peer_connection(sock, "0" * 64)


@pytest.mark.unit
def test_open_pinned_connection_round_trip_success(self_signed: SelfSignedFixture) -> None:
    with _tls_server(self_signed) as port, open_pinned_connection(
        "127.0.0.1", port, self_signed.fingerprint, timeout=3.0
    ) as tls:
        assert tls_fingerprint(tls.getpeercert(binary_form=True)) == self_signed.fingerprint


@pytest.mark.unit
def test_open_pinned_connection_wrong_pin_raises(self_signed: SelfSignedFixture) -> None:
    with _tls_server(self_signed) as port, pytest.raises(TlsPinMismatch):
        open_pinned_connection("127.0.0.1", port, "0" * 64, timeout=3.0)


class _TlsServer:
    """Threaded localhost TLS server serving the given self-signed cert."""

    def __init__(self, fixture: SelfSignedFixture) -> None:
        self._fixture = fixture
        self._ready = threading.Event()
        self._port: int | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._stop = threading.Event()

    def __enter__(self) -> int:
        self._thread.start()
        self._ready.wait()
        assert self._port is not None
        return self._port

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _run(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv = socket.socket()
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            srv.settimeout(0.2)
            self._port = srv.getsockname()[1]
            self._ready.set()
            cert_path = None
            try:
                cert_path = _write_temp(self._fixture)
                ctx.load_cert_chain(certfile=cert_path)
            finally:
                if cert_path is not None:
                    _remove_temp(cert_path)
            while not self._stop.is_set():
                try:
                    conn, _ = srv.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with conn:
                    try:
                        with ctx.wrap_socket(conn, server_side=True):
                            time.sleep(0.1)
                    except (ssl.SSLError, OSError):
                        pass
        finally:
            srv.close()


def _write_temp(fixture: SelfSignedFixture) -> str:
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".pem")
    with open(fd, "wb") as f:
        f.write(fixture.pem + fixture.key_pem)
    return path


def _remove_temp(path: str) -> None:
    import contextlib
    import os

    with contextlib.suppress(OSError):
        os.unlink(path)


def _tls_server(fixture: SelfSignedFixture):
    return _TlsServer(fixture)


def _client_socket(port: int, pin: str) -> ssl.SSLSocket:
    ctx = build_ssl_context(verify_tls=True, pinned_fingerprint=pin, ca_bundle_path=None)
    raw = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    return ctx.wrap_socket(raw, server_hostname=None)
