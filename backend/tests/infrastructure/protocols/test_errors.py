"""Error mapping tests: Redfish errors -> stable contracts/error-codes.json codes.

docs/DEVICE_ADAPTERS.md §7: adapters may only return the subset below; message
text from the device must never leak into logs or API details (sanitized).
"""

from __future__ import annotations

import ssl

import httpx
import pytest
from app.infrastructure.protocols.redfish.errors import (
    ADAPTER_ERROR_CODES,
    RedfishError,
    RedfishHttpError,
    classify_transport_error,
    device_code_from_body,
    extended_message_ids,
    map_http_error,
)

SECRET_DEVICE_TEXT = "simulated BMC top secret device text"


def base_error_body(
    code: str = "Base.1.13.GeneralError",
    message: str = SECRET_DEVICE_TEXT,
    message_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    body: dict[str, object] = {"error": {"code": code, "message": message}}
    if message_ids:
        info: list[dict[str, str]] = [
            {
                "@odata.type": "#Message.v1_1_2.Message",
                "MessageId": message_id,
                "Message": SECRET_DEVICE_TEXT,
                "Severity": "Critical",
            }
            for message_id in message_ids
        ]
        body["error"]["@Message.ExtendedInfo"] = info  # type: ignore[typeddict-item]
    return body


class TestHttpMapping:
    @pytest.mark.unit
    def test_auth_context_401_maps_authentication_failed(self) -> None:
        err = map_http_error(401, base_error_body(), context="auth")
        assert isinstance(err, RedfishHttpError)
        assert err.code == "authentication_failed"
        assert err.status == 401

    @pytest.mark.unit
    def test_auth_context_403_maps_authentication_failed(self) -> None:
        err = map_http_error(403, base_error_body(), context="auth")
        assert err.code == "authentication_failed"

    @pytest.mark.unit
    def test_auth_context_session_endpoint_unsupported_is_not_ok(self) -> None:
        for status in (404, 405, 501):
            err = map_http_error(status, base_error_body(), context="auth")
            assert err.code == "authentication_failed"

    @pytest.mark.unit
    def test_auth_context_rate_limited_and_server_error(self) -> None:
        assert map_http_error(429, base_error_body(), context="auth").code == "rate_limited"
        assert map_http_error(503, base_error_body(), context="auth").code == "operation_failed"

    @pytest.mark.unit
    def test_read_context_not_found_maps_unsupported_capability(self) -> None:
        err = map_http_error(404, base_error_body(), context="read")
        assert err.code == "unsupported_capability"

    @pytest.mark.unit
    def test_read_context_permission_maps_permission_denied_by_device(self) -> None:
        assert map_http_error(403, base_error_body(), context="read").code == "permission_denied_by_device"

    @pytest.mark.unit
    def test_read_context_unauthorized_maps_authentication_failed(self) -> None:
        assert map_http_error(401, base_error_body(), context="read").code == "authentication_failed"

    @pytest.mark.unit
    def test_read_context_429_maps_rate_limited(self) -> None:
        assert map_http_error(429, base_error_body(), context="read").code == "rate_limited"

    @pytest.mark.unit
    def test_read_context_400_maps_protocol_error(self) -> None:
        assert map_http_error(400, base_error_body(), context="read").code == "protocol_error"

    @pytest.mark.unit
    def test_read_context_5xx_maps_operation_failed(self) -> None:
        for status in (500, 502, 503, 504):
            assert map_http_error(status, base_error_body(), context="read").code == "operation_failed"

    @pytest.mark.unit
    def test_action_not_supported_400_maps_unsupported_capability(self) -> None:
        body = base_error_body(message_ids=("Base.1.13.ActionNotSupported",))
        err = map_http_error(400, body, context="action")
        assert err.code == "unsupported_capability"
        assert err.message_ids == ("Base.1.13.ActionNotSupported",)

    @pytest.mark.unit
    def test_action_not_supported_400_matches_any_base_registry_version(self) -> None:
        # The mapping matches by MessageId NAME inside the Base registry
        # family: a device speaking any Base.1.x version (here Base.1.0 and
        # a Base.1.5 never enumerated) must still map — not degrade to
        # validation_failed.
        for message_id in (
            "Base.1.0.ActionNotSupported",
            "Base.1.13.ActionNotSupported",
            "Base.1.5.ActionNotSupported",
        ):
            err = map_http_error(400, base_error_body(message_ids=(message_id,)), context="action")
            assert err.code == "unsupported_capability"

    @pytest.mark.unit
    def test_action_unknown_and_property_unknown_match_any_base_version(self) -> None:
        for message_id in ("Base.1.11.ActionUnknown", "Base.1.9.PropertyUnknown"):
            err = map_http_error(400, base_error_body(message_ids=(message_id,)), context="action")
            assert err.code == "unsupported_capability"

    @pytest.mark.unit
    def test_non_base_registry_action_name_is_not_mis_mapped(self) -> None:
        # Base-registry matching is intentional: a vendor registry naming its
        # own ActionNotSupported is not the Base message and stays validation_failed.
        err = map_http_error(
            400,
            base_error_body(message_ids=("OemVendor.1.0.ActionNotSupported",)),
            context="action",
        )
        assert err.code == "validation_failed"

    @pytest.mark.unit
    def test_parameter_failure_in_other_base_version_stays_validation_failed(self) -> None:
        err = map_http_error(
            400,
            base_error_body(message_ids=("Base.1.0.ActionParameterMissing",)),
            context="action",
        )
        assert err.code == "validation_failed"

    @pytest.mark.unit
    def test_action_parameter_400_maps_validation_failed(self) -> None:
        body = base_error_body(message_ids=("Base.1.13.ActionParameterMissing",))
        assert map_http_error(400, body, context="action").code == "validation_failed"

    @pytest.mark.unit
    def test_action_conflict_maps_device_busy(self) -> None:
        assert map_http_error(409, base_error_body(), context="action").code == "device_busy"

    @pytest.mark.unit
    def test_action_404_maps_unsupported_capability(self) -> None:
        assert map_http_error(404, base_error_body(), context="action").code == "unsupported_capability"

    @pytest.mark.unit
    def test_action_5xx_maps_operation_failed(self) -> None:
        assert map_http_error(500, base_error_body(), context="action").code == "operation_failed"

    @pytest.mark.unit
    def test_task_404_maps_ambiguous_result(self) -> None:
        assert map_http_error(404, base_error_body(), context="task").code == "ambiguous_result"

    @pytest.mark.unit
    def test_task_5xx_maps_operation_failed(self) -> None:
        assert map_http_error(503, base_error_body(), context="task").code == "operation_failed"

    @pytest.mark.unit
    def test_unknown_status_400_read_maps_protocol_error(self) -> None:
        err = map_http_error(400, None, context="read")
        assert err.code == "protocol_error"

    @pytest.mark.unit
    def test_mapped_codes_stay_in_adapter_subset(self) -> None:
        samples = [
            (401, base_error_body(), "auth"),
            (403, base_error_body(), "read"),
            (404, base_error_body(), "read"),
            (429, base_error_body(), "action"),
            (400, base_error_body(message_ids=("Base.1.13.ActionNotSupported",)), "action"),
            (400, base_error_body(), "read"),
            (409, base_error_body(), "action"),
            (503, base_error_body(), "action"),
            (404, base_error_body(), "task"),
        ]
        for status, body, context in samples:
            err = map_http_error(status, body, context=context)
            assert err.code in ADAPTER_ERROR_CODES


class TestHttpErrorSanitization:
    @pytest.mark.unit
    def test_mapped_message_never_contains_device_text(self) -> None:
        err = map_http_error(500, base_error_body(), context="read")
        assert SECRET_DEVICE_TEXT not in str(err)
        assert SECRET_DEVICE_TEXT not in err.message
        assert err.detail_safe is None

    @pytest.mark.unit
    def test_body_is_captured_for_audit_but_not_in_str(self) -> None:
        body = base_error_body()
        err = map_http_error(404, body, context="read")
        assert err.body == body
        assert SECRET_DEVICE_TEXT not in repr(err)

    @pytest.mark.unit
    def test_repr_contains_only_safe_fields(self) -> None:
        err = map_http_error(400, base_error_body(), context="read")
        text = repr(err)
        assert "protocol_error" in text
        assert SECRET_DEVICE_TEXT not in text

    @pytest.mark.unit
    def test_extended_message_ids_extraction(self) -> None:
        body = base_error_body(message_ids=("Base.1.13.ActionNotSupported", "Base.1.13.ActionUnknown"))
        assert extended_message_ids(body) == ("Base.1.13.ActionNotSupported", "Base.1.13.ActionUnknown")

    @pytest.mark.unit
    def test_extended_message_ids_tolerates_missing_info(self) -> None:
        assert extended_message_ids({"error": {"code": "Base.1.13.GeneralError"}}) == ()
        assert extended_message_ids({}) == ()

    @pytest.mark.unit
    def test_device_code_extraction(self) -> None:
        body = base_error_body(code="Base.1.13.GeneralError")
        assert device_code_from_body(body) == "Base.1.13.GeneralError"
        assert device_code_from_body({}) is None


class TestTransportClassification:
    @pytest.mark.unit
    def test_connect_error_maps_network_unreachable(self) -> None:
        err = classify_transport_error(httpx.ConnectError("no route to host"))
        assert err.code == "network_unreachable"
        assert err.stage == "connect"

    @pytest.mark.unit
    def test_read_timeout_maps_network_unreachable(self) -> None:
        err = classify_transport_error(httpx.ReadTimeout("read timed out"))
        assert err.code == "network_unreachable"

    @pytest.mark.unit
    def test_certificate_verification_failure_maps_tls_validation_failed(self) -> None:
        cause = ssl.SSLCertVerificationError("certificate verify failed")
        wrapped = httpx.ConnectError(str(cause))
        wrapped.__cause__ = cause
        err = classify_transport_error(wrapped)
        assert err.code == "tls_validation_failed"
        assert err.stage == "tls"

    @pytest.mark.unit
    def test_unknown_transport_error_maps_protocol_error(self) -> None:
        err = classify_transport_error(RuntimeError("boom"))
        assert err.code == "protocol_error"
        assert isinstance(err, RedfishError)
