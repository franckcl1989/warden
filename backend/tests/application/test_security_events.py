"""Weak-protocol config change detector unit tests (SECURITY.md §6, M1T4).

The detector decides which denylisted ``connection_config`` keys changed;
these tests are DB-free. The denylist mirrors SECURITY.md §6: SNMPv2c,
Telnet, verify_tls=false, TLS fingerprint changes and the HTTP scheme.
"""

from __future__ import annotations

from app.application.security_events import SENSITIVE_CONFIG_KEYS, security_sensitive_config_change

FP_OLD = "a" * 64
FP_NEW = "b" * 64


def test_snmp_v2c_selection_detected() -> None:
    assert security_sensitive_config_change({}, {"snmp_version": "v2c"}) == ["snmp_version"]


def test_snmp_v2c_unchanged_not_audited() -> None:
    old = {"snmp_version": "v2c"}
    assert security_sensitive_config_change(old, dict(old)) == []


def test_snmp_upgrade_to_v3_not_audited() -> None:
    assert security_sensitive_config_change({"snmp_version": "v2c"}, {"snmp_version": "v3"}) == []


def test_telnet_enabled_detected() -> None:
    assert security_sensitive_config_change({}, {"telnet": True}) == ["telnet"]


def test_telnet_kept_enabled_not_audited() -> None:
    old = {"telnet": True}
    assert security_sensitive_config_change(old, dict(old)) == []


def test_verify_tls_disabled_detected() -> None:
    assert security_sensitive_config_change({"verify_tls": True}, {"verify_tls": False}) == [
        "verify_tls"
    ]


def test_verify_tls_absent_to_false_detected() -> None:
    assert security_sensitive_config_change({}, {"verify_tls": False}) == ["verify_tls"]


def test_tls_fingerprint_pinned_detected() -> None:
    assert security_sensitive_config_change({}, {"tls_fingerprint_sha256": FP_NEW}) == [
        "tls_fingerprint_sha256"
    ]


def test_tls_fingerprint_rotated_detected() -> None:
    old = {"tls_fingerprint_sha256": FP_OLD}
    assert security_sensitive_config_change(old, {"tls_fingerprint_sha256": FP_NEW}) == [
        "tls_fingerprint_sha256"
    ]


def test_tls_fingerprint_removed_detected() -> None:
    assert security_sensitive_config_change({"tls_fingerprint_sha256": FP_OLD}, {}) == [
        "tls_fingerprint_sha256"
    ]


def test_tls_fingerprint_unchanged_not_audited() -> None:
    old = {"tls_fingerprint_sha256": FP_OLD}
    assert security_sensitive_config_change(old, dict(old)) == []


def test_http_scheme_detected() -> None:
    assert security_sensitive_config_change({"protocol": "https"}, {"protocol": "http"}) == [
        "protocol"
    ]


def test_benign_keys_not_detected() -> None:
    assert security_sensitive_config_change({}, {"port": 8443, "ssh_port": 22, "name": "x"}) == []


def test_identical_config_not_detected() -> None:
    config = {"port": 443, "verify_tls": True, "snmp_version": "v3"}
    assert security_sensitive_config_change(config, dict(config)) == []


def test_multiple_weak_changes_detected_in_order() -> None:
    old = {"snmp_version": "v3", "verify_tls": True}
    new = {"snmp_version": "v2c", "verify_tls": False, "telnet": True}
    assert security_sensitive_config_change(old, new) == ["snmp_version", "telnet", "verify_tls"]


def test_none_configs_treated_as_empty() -> None:
    assert security_sensitive_config_change(None, None) == []
    assert security_sensitive_config_change(None, {"telnet": True}) == ["telnet"]


def test_sensitive_keys_denylist_contains_only_design_keys() -> None:
    assert {
        "snmp_version",
        "telnet",
        "verify_tls",
        "protocol",
        "tls_fingerprint_sha256",
    } == SENSITIVE_CONFIG_KEYS
