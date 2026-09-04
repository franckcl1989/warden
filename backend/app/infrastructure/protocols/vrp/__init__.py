"""VRP SSH protocol package (M5T3).

Template registry + prompt/error parser + CLI executor over asyncssh — the
only sanctioned command path for the Huawei VRP switch operations (no
free-text commands; typed params validated against per-template allowlists
before composition; SECURITY.md §8). All command texts are [sim] DSL until
hardware certification records per-model/VRP CLI evidence (ADR-018).
"""

from app.infrastructure.protocols.vrp.errors import VrpError, VrpTimeoutError
from app.infrastructure.protocols.vrp.executor import (
    PromptAction,
    VrpCliExecutor,
    template_evidence_for,
)
from app.infrastructure.protocols.vrp.parser import (
    clean_output,
    config_fingerprint,
    config_parse_ok,
    normalize_config_text,
    parse_compare_configuration,
    parse_dir_free_kb,
    parse_interface_state,
    parse_poe_state,
    parse_startup,
    parse_version,
    vrp_major_version,
)
from app.infrastructure.protocols.vrp.session import (
    VrpSshConfig,
    canonical_fingerprint,
    open_connection,
)
from app.infrastructure.protocols.vrp.templates import (
    VrpTemplate,
    template_for,
)

__all__ = [
    "PromptAction",
    "VrpCliExecutor",
    "VrpError",
    "VrpSshConfig",
    "VrpTemplate",
    "VrpTimeoutError",
    "canonical_fingerprint",
    "clean_output",
    "config_fingerprint",
    "config_parse_ok",
    "normalize_config_text",
    "open_connection",
    "parse_compare_configuration",
    "parse_dir_free_kb",
    "parse_interface_state",
    "parse_poe_state",
    "parse_startup",
    "parse_version",
    "template_evidence_for",
    "template_for",
    "vrp_major_version",
]
