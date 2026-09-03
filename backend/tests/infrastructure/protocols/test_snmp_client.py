"""SNMP client unit tests: error mapping, batch chunking, walk semantics.

The pysnmp wire glue is thin and is exercised against the real switch
simulator over UDP (tests/infrastructure/protocols/test_snmp_client_udp.py);
everything below tests the pure decision logic with hand-built pysnmp
response objects.
"""

from __future__ import annotations

import pytest
from app.infrastructure.protocols.snmp.client import (
    _AUTH_FAILURE_CODES,
    SnmpConnection,
    chunk_oids,
    map_varbinds,
    raise_for_error_indication,
    raise_for_error_status,
)
from app.infrastructure.protocols.snmp.errors import SnmpError
from app.infrastructure.protocols.snmp.values import NOT_PRESENT, SnmpKind, SnmpValue
from pysnmp.proto import errind, rfc1902
from pysnmp.smi import exval


class TestRaiseForErrorIndication:
    def test_none_passes(self) -> None:
        assert raise_for_error_indication(None, stage="request") is None

    def test_timeout_is_network_unreachable(self) -> None:
        with pytest.raises(SnmpError) as raised:
            raise_for_error_indication(errind.RequestTimedOut(), stage="request")
        assert raised.value.code == "network_unreachable"

    @pytest.mark.parametrize(
        "failure",
        [
            errind.WrongDigest(),
            errind.UnknownUserName(),
            errind.UnknownSecurityName(),
            errind.AuthenticationFailure(),
            errind.UnsupportedSecurityLevel(),
            errind.DecryptionError(),
        ],
    )
    def test_usm_failures_are_authentication_failed(self, failure: errind.ErrorIndication) -> None:
        with pytest.raises(SnmpError) as raised:
            raise_for_error_indication(failure, stage="request")
        assert raised.value.code == "authentication_failed"

    @pytest.mark.parametrize(
        "failure",
        [
            errind.ParseError(),
            errind.SerializationError(),
            errind.DeserializationError(),
            errind.OidNotIncreasing(),
            errind.LoopTerminated(),
            errind.ReportPduReceived(),
            errind.NoSuchContext(),
            # Not a USM code: the community security model carries no
            # authentication; a v2c wrong community surfaces as silence
            # (timeout -> network_unreachable), never authentication_failed.
            errind.UnknownCommunityName(),
        ],
    )
    def test_other_indications_are_protocol_error(self, failure: errind.ErrorIndication) -> None:
        with pytest.raises(SnmpError) as raised:
            raise_for_error_indication(failure, stage="request")
        assert raised.value.code == "protocol_error"


def test_auth_failure_codes_are_only_usm_semantics() -> None:
    assert frozenset(
        {
            "WrongDigest",
            "UnknownUserName",
            "UnknownSecurityName",
            "AuthenticationFailure",
            "UnsupportedSecurityLevel",
            "DecryptionError",
        }
    ) == _AUTH_FAILURE_CODES


class TestRaiseForErrorStatus:
    def test_no_error_passes(self) -> None:
        assert raise_for_error_status(0, stage="request") is None

    def test_too_big_is_protocol_error_with_hint(self) -> None:
        with pytest.raises(SnmpError) as raised:
            raise_for_error_status(1, stage="request")
        assert raised.value.code == "protocol_error"
        assert raised.value.hint == "reduce snmp batch size"

    def test_gen_err_is_protocol_error(self) -> None:
        with pytest.raises(SnmpError) as raised:
            raise_for_error_status(5, stage="request")
        assert raised.value.code == "protocol_error"


class TestMapVarbinds:
    def test_values_normalized_in_order(self) -> None:
        varbinds = [
            ("1.3.6.1.2.1.1.1.0", rfc1902.OctetString(b"sw")),
            ("1.3.6.1.2.1.1.3.0", rfc1902.TimeTicks(9)),
            ("1.3.6.1.2.1.2.2.1.10.1", rfc1902.Counter32(5)),
        ]
        values = map_varbinds(varbinds)
        assert [item.oid for item in values] == [
            "1.3.6.1.2.1.1.1.0",
            "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.2.1.2.2.1.10.1",
        ]
        assert [item.kind for item in values] == [SnmpKind.STRING, SnmpKind.TIMETICKS, SnmpKind.COUNTER]

    def test_missing_leaves_become_not_present(self) -> None:
        varbinds = [
            ("1.3.6.1.2.1.99.99.0", exval.noSuchObject),
            ("1.3.6.1.2.1.98.98.0", exval.noSuchInstance),
        ]
        values = map_varbinds(varbinds)
        assert values[0] is NOT_PRESENT
        assert values[1] is NOT_PRESENT

    def test_accepts_pysnmp_object_names(self) -> None:
        varbind = (rfc1902.ObjectName("1.3.6.1.2.1.1.1.0"), rfc1902.OctetString(b"sw"))
        value = map_varbinds([varbind])[0]
        assert isinstance(value, SnmpValue)
        assert value.oid == "1.3.6.1.2.1.1.1.0"


class TestChunkOids:
    def test_chunking_respects_batch_size(self) -> None:
        oids = [f"1.3.6.1.2.1.1.{index}.0" for index in range(7)]
        chunks = list(chunk_oids(oids, batch_size=3))
        assert [len(chunk) for chunk in chunks] == [3, 3, 1]
        assert chunks[0] == oids[:3]

    def test_chunking_requires_positive_batch(self) -> None:
        with pytest.raises(ValueError):
            list(chunk_oids(["1.3.6.1.2.1.1.1.0"], batch_size=0))


class TestSnmpConnection:
    def test_v3_defaults_are_auth_priv_sha_aes(self) -> None:
        connection = SnmpConnection(
            host="127.0.0.1",
            username="monitor",
            auth_key="auth-key-1",
            privacy_key="priv-key-1",
        )
        assert connection.version == "v3"
        assert connection.auth_protocol == "sha"
        assert connection.privacy_protocol == "aes128"

    def test_v3_requires_keys_for_the_default_auth_priv_level(self) -> None:
        with pytest.raises(ValueError):
            SnmpConnection(host="127.0.0.1", username="monitor", auth_key=None, privacy_key=None)

    def test_v3_no_auth_no_priv_is_explicit(self) -> None:
        connection = SnmpConnection(
            host="127.0.0.1",
            username="monitor",
            auth_protocol="none",
            privacy_protocol="none",
        )
        assert connection.auth_protocol == "none"

    def test_v2c_requires_community(self) -> None:
        connection = SnmpConnection(host="127.0.0.1", version="v2c", community="public")
        assert connection.community == "public"

    def test_repr_never_contains_keys_or_community(self) -> None:
        connection = SnmpConnection(
            host="127.0.0.1",
            version="v2c",
            community="top-secret-community",
            username="monitor",
            auth_key="auth-secret-key",
            privacy_key="priv-secret-key",
        )
        rendered = repr(connection)
        assert "top-secret-community" not in rendered
        assert "auth-secret-key" not in rendered
        assert "priv-secret-key" not in rendered

    def test_invalid_version_rejected(self) -> None:
        with pytest.raises(ValueError):
            SnmpConnection(host="127.0.0.1", version="v1")


def _typed_value(oid: str, raw: object) -> SnmpValue:
    value = map_varbinds([rfc1902.ObjectType(rfc1902.ObjectName(oid), raw)])[0]
    assert value is not NOT_PRESENT
    return value
