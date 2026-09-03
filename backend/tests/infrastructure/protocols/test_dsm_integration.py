"""Real-HTTP integration: DSM simulator booted with uvicorn + DSMClient.

The simulator is a TEST device simulator (never hardware evidence). The
client connects to 127.0.0.1 over plain HTTP with an injected transport —
production wiring uses the M1T2 policy/TLS managed client; this file proves
the DSM protocol stack end to end over real sockets: discovery, login,
sessioned calls, bounded re-login, logout and the honest failure knobs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import httpx
import pytest
from app.infrastructure.protocols.dsm.client import DSMClient
from app.infrastructure.protocols.dsm.discovery import AUTH_API_NAME
from app.infrastructure.protocols.dsm.errors import DSMError
from app.infrastructure.protocols.dsm.parse import disk_status, pool_status
from app.infrastructure.protocols.dsm.session import DSMCredentials

from tests.simulators.dsm.serving import serve_simulator

USER = "admin"
PASSWORD = "sim-pass-1"

# uvicorn on Windows leaves idle keep-alive connection sockets to be closed
# by GC after the server thread exits; these surface as unraisable warnings
# in whichever test triggers the next collection. They are a harness
# shutdown artifact of the booted simulator, not client behaviour.
pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]


@pytest.fixture
def sim_url() -> Iterator[str]:
    with serve_simulator() as url:
        yield url


def make_client(base_url: str, **kwargs: object) -> DSMClient:
    http = httpx.Client(base_url=base_url, timeout=httpx.Timeout(connect=2.0, read=5.0, write=2.0, pool=2.0))
    kwargs.setdefault("credentials", DSMCredentials(username=USER, password=PASSWORD))
    kwargs.setdefault("backoff", lambda attempt: 0.0)
    return DSMClient(http, **kwargs)  # type: ignore[arg-type]


@contextmanager
def client_ctx(base_url: str) -> Iterator[DSMClient]:
    """Client lifecycle: closes the device session AND the injected transport."""
    client = make_client(base_url)
    try:
        yield client
    finally:
        client.close()
        client._http.close()  # noqa: SLF001


class TestEndToEnd:
    @pytest.mark.unit
    def test_discover_login_call_logout_over_real_http(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            evidence = client.discover()
            names = [row[0] for row in evidence.api_map]
            assert "SYNO.API.Auth" in names
            assert "SYNO.Storage.CGI.Storage" in names
            system = client.call("SYNO.Core.System", "info", safe=True)
            assert isinstance(system, dict)
            assert "model" in system
            assert "fan" in system
            storage = client.call("SYNO.Storage.CGI.Storage", "load_info", safe=True)
            assert isinstance(storage, dict)
            assert storage["disk"][0]["status"] == "Healthy"
            assert disk_status(storage["disk"][0]["status"]) == "ok"
            assert pool_status(storage["pool"][0]["status"]) == "optimal"
            ups = client.call("SYNO.Core.UPS", "get", safe=True)
            assert isinstance(ups, dict)
            logs = client.call("SYNO.Core.System.Log", "list", safe=True, params={"offset": 0, "limit": 5})
            assert isinstance(logs, dict)
            assert logs["total"] == 24
            assert len(logs["log"]) == 5
            assert logs["log"][0]["message"]
        # Logout on close ended the device session.
        with httpx.Client() as http:
            response = http.get(f"{sim_url}/warden-sim/control")
            assert response.json()["sessions"] == 0

    @pytest.mark.unit
    def test_negotiation_never_above_certified_version_over_http(self, sim_url: str) -> None:
        with httpx.Client() as http:
            http.post(f"{sim_url}/warden-sim/control", json={"storage_max_version": 9})
        with client_ctx(sim_url) as client:
            client.call("SYNO.Storage.CGI.Storage", "load_info", safe=True)
            spec = client.call_spec("SYNO.Storage.CGI.Storage")
            assert spec is not None
            assert spec.version == 1  # certified row, not the advertised 9
            rows = client.call_ledger()
            storage_rows = [
                (row.api_name, row.method, row.path, row.version)
                for row in rows
                if row.api_name == "SYNO.Storage.CGI.Storage" and row.method == "load_info"
            ]
            assert storage_rows == [("SYNO.Storage.CGI.Storage", "load_info", "entry.cgi", 1)]
        # The device really advertised maxVersion 9 while the call ran.
        with httpx.Client() as http:
            snapshot = http.get(f"{sim_url}/warden-sim/control").json()
            assert snapshot["storage_max_version"] == 9

    @pytest.mark.unit
    def test_simulator_refuses_versions_outside_device_range(self, sim_url: str) -> None:
        with httpx.Client() as http:
            login = http.get(
                f"{sim_url}/webapi/auth.cgi",
                params={
                    "api": "SYNO.API.Auth",
                    "version": "6",
                    "method": "login",
                    "account": USER,
                    "passwd": PASSWORD,
                    "session": "DiskStation",
                    "format": "sid",
                },
            )
            sid = login.json()["data"]["sid"]
            raw = http.get(
                f"{sim_url}/webapi/entry.cgi",
                params={"api": "SYNO.Storage.CGI.Storage", "version": "9", "method": "load_info", "_sid": sid},
            )
            # Default map advertises maxVersion 1: version 9 is refused 104.
            assert raw.json()["error"]["code"] == 104

    @pytest.mark.unit
    def test_session_expiry_relogs_in_once_then_recovers(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            client.call("SYNO.Core.UPS", "get", safe=True)
            with httpx.Client() as http:
                http.post(f"{sim_url}/warden-sim/control", json={"expire_sessions": True})
            # The sid is now dead: the next call must re-login once and
            # succeed; bounded = exactly two logins on the device.
            result = client.call("SYNO.Core.UPS", "get", safe=True)
            assert isinstance(result, dict)
            assert result["ups"]["status"] == "Normal"
            with httpx.Client() as http:
                snapshot = http.get(f"{sim_url}/warden-sim/control").json()
                assert snapshot["logins"] == 2
                assert snapshot["sessions"] == 1

    @pytest.mark.unit
    def test_persistent_session_rejection_fails_bounded(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            client.call("SYNO.Core.UPS", "get", safe=True)
            with httpx.Client() as http:
                http.post(f"{sim_url}/warden-sim/control", json={"failures": {"sessions_reject_106": True}})
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "authentication_failed"
            assert exc.value.dsm_code == 106
            # Bounded: exactly one re-login happened (two logins total), no
            # login loop despite every answer being 106.
            with httpx.Client() as http:
                snapshot = http.get(f"{sim_url}/warden-sim/control").json()
                assert snapshot["logins"] == 2

    @pytest.mark.unit
    def test_unknown_dsm_code_is_preserved_not_guessed(self, sim_url: str) -> None:
        with client_ctx(sim_url) as client:
            client.call("SYNO.Core.UPS", "get", safe=True)
            with httpx.Client() as http:
                http.post(f"{sim_url}/warden-sim/control", json={"failures": {"error_unknown_2100": True}})
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "protocol_error"
            assert exc.value.dsm_code == 2100


class TestFailureModes:
    @pytest.mark.unit
    def test_wrong_password_over_http(self, sim_url: str) -> None:
        client = make_client(sim_url, credentials=DSMCredentials(username=USER, password="wrong-pass"))
        try:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "authentication_failed"
        finally:
            client.close()
            client._http.close()  # noqa: SLF001

    @pytest.mark.unit
    def test_two_factor_required_over_http(self, sim_url: str) -> None:
        with httpx.Client() as http:
            http.post(f"{sim_url}/warden-sim/control", json={"failures": {"login_otp": True}})
        client = make_client(sim_url)
        try:
            with pytest.raises(DSMError) as exc:
                client.call("SYNO.Core.UPS", "get", safe=True)
            assert exc.value.code == "not_configured"
            assert exc.value.missing == "otp"
        finally:
            client.close()
            client._http.close()  # noqa: SLF001

    @pytest.mark.unit
    def test_ledger_records_exact_api_version_basis(self, sim_url: str) -> None:
        client = make_client(sim_url)
        try:
            client.call("SYNO.Core.System", "info", safe=True)
            client.call("SYNO.Storage.CGI.Storage", "smart_test", safe=False, params={"disk": "sata1", "type": "quick"})
        finally:
            client.close()
        rows = client.call_ledger()
        bases = {(row.api_name, row.method, row.path, row.version, row.safe) for row in rows}
        assert ("SYNO.API.Auth", "login", "auth.cgi", 6, False) in bases
        assert ("SYNO.Core.System", "info", "entry.cgi", 2, True) in bases
        assert ("SYNO.Storage.CGI.Storage", "smart_test", "entry.cgi", 1, False) in bases
        assert (AUTH_API_NAME, "logout", "auth.cgi", 6, False) in bases
        client._http.close()  # noqa: SLF001
