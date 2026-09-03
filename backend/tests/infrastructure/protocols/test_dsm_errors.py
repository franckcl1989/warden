"""DSM error mapping tests (DEVICE_ADAPTERS.md §5/§7, ADR-018).

Rows: the guide common block (100..108), the simulator-DSL login rows and
the unknown-code preservation rule — an unmapped DSM code is a
``protocol_error`` carrying the original code, never a guessed stable code.
"""

from __future__ import annotations

import httpx
import pytest
from app.infrastructure.protocols.dsm.errors import (
    DSMError,
    envelope_data,
    raise_envelope_error,
    raise_http_error,
)

AUTH = "SYNO.API.Auth"
STORAGE = "SYNO.Storage.CGI.Storage"
SYSTEM = "SYNO.Core.System"


class TestEnvelopeData:
    def test_success_with_data(self) -> None:
        ok, data, code = envelope_data({"success": True, "data": {"sid": "x"}})
        assert ok is True
        assert data == {"sid": "x"}
        assert code is None

    def test_success_without_data_is_empty_object(self) -> None:
        ok, data, code = envelope_data({"success": True})
        assert ok is True
        assert data == {}
        assert code is None

    def test_error_envelope_carries_code(self) -> None:
        ok, data, code = envelope_data({"success": False, "error": {"code": 106}})
        assert ok is False
        assert data is None
        assert code == 106

    def test_error_code_as_digit_string_is_tolerated(self) -> None:
        _, _, code = envelope_data({"success": False, "error": {"code": "401"}})
        assert code == 401

    def test_non_envelope_body_is_protocol_error(self) -> None:
        with pytest.raises(DSMError) as exc:
            envelope_data([1, 2, 3])
        assert exc.value.code == "protocol_error"
        assert exc.value.stage == "parse"

    def test_missing_success_field_is_protocol_error(self) -> None:
        with pytest.raises(DSMError) as exc:
            envelope_data({"data": {}})
        assert exc.value.code == "protocol_error"


class TestMappingRows:
    def test_401_login_is_authentication_failed(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=AUTH, method="login", code=401, context="login")
        assert exc.value.code == "authentication_failed"
        assert exc.value.dsm_code == 401

    def test_400_on_auth_is_authentication_failed_via_api_row(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=AUTH, method="login", code=400, context="login")
        assert exc.value.code == "authentication_failed"

    def test_400_on_other_api_is_validation_failed(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=STORAGE, method="load_info", code=400)
        assert exc.value.code == "validation_failed"

    def test_406_is_authentication_failed(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=AUTH, method="login", code=406, context="login")
        assert exc.value.code == "authentication_failed"

    def test_105_is_permission_denied_by_device(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=STORAGE, method="load_info", code=105)
        assert exc.value.code == "permission_denied_by_device"

    def test_106_is_authentication_failed_outside_relogin_path(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=STORAGE, method="load_info", code=106)
        assert exc.value.code == "authentication_failed"
        assert exc.value.dsm_code == 106

    def test_101_102_103_104_are_honest_rows(self) -> None:
        expected = {
            101: "validation_failed",
            102: "unsupported_capability",
            103: "unsupported_capability",
            104: "unsupported_capability",
        }
        for code, stable in expected.items():
            with pytest.raises(DSMError) as exc:
                raise_envelope_error(api_name=STORAGE, method="load_info", code=code)
            assert exc.value.code == stable, f"code {code} mapped to {exc.value.code}"

    def test_403_two_factor_on_login_is_not_configured_missing_otp(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=AUTH, method="login", code=403, context="login")
        assert exc.value.code == "not_configured"
        assert exc.value.missing == "otp"
        assert "two-factor" in exc.value.message

    def test_403_on_call_api_is_permission_denied(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=SYSTEM, method="info", code=403)
        assert exc.value.code == "permission_denied_by_device"

    def test_unknown_code_is_protocol_error_with_code_preserved(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=STORAGE, method="smart_task_status", code=2100)
        assert exc.value.code == "protocol_error"
        assert exc.value.dsm_code == 2100
        assert exc.value.detail_safe == "dsm_code:dsm_code_2100"
        assert "2100" not in exc.value.message  # message stays sanitized, code on attr

    def test_unknown_code_message_never_guesses_a_stable_code(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_envelope_error(api_name=STORAGE, method="load_info", code=4010)
        assert exc.value.code == "protocol_error"
        assert exc.value.dsm_code == 4010


class TestHttpMapping:
    def test_500_maps_operation_failed(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_http_error(500, context="read", api_name=STORAGE, method="load_info")
        assert exc.value.code == "operation_failed"

    def test_429_maps_rate_limited_with_retry_after_detail(self) -> None:
        with pytest.raises(DSMError) as exc:
            raise_http_error(429, context="read", api_name=STORAGE, method="load_info", retry_after_seconds=2.5)
        assert exc.value.code == "rate_limited"
        assert "retry_after" in (exc.value.detail_safe or "")

    def test_transport_errors_classify(self) -> None:
        from app.infrastructure.protocols.dsm.errors import classify_transport_error

        timeout = classify_transport_error(httpx.ConnectTimeout("boom"))
        assert timeout.code == "network_unreachable"
        conn = classify_transport_error(httpx.ConnectError("boom"))
        assert conn.code == "network_unreachable"
