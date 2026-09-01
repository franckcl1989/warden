"""Registry tests: generated modules are the only runtime source of truth.

The design baseline (docs/BLUEPRINT_AUDIT.md) forbids a second hand-written set
of metric/event/operation/alert enumerations: runtime code must import
``app.generated``. These tests pin that generated registries exist, are
importable, and exactly cover the committed contract files.
"""

from __future__ import annotations

import importlib
import json

import pytest
from app.contracts.loader import CONTRACTS_DIR
from app.tools.codegen import BACKEND_GENERATED

GENERATED_MODULES = (
    "metrics",
    "events",
    "operations",
    "alerts",
    "errors",
    "capabilities",
    "http_api",
    "hardware_targets",
)


@pytest.mark.unit
def test_generated_registry_modules_exist_and_import() -> None:
    for module_name in GENERATED_MODULES:
        module_path = BACKEND_GENERATED / f"{module_name}.py"
        assert module_path.is_file(), f"generated module missing: {module_name}.py"
        importlib.import_module(f"app.generated.{module_name}")


@pytest.mark.unit
def test_every_operations_profile_id_is_registered() -> None:
    from app.generated.operations import OPERATION_PROFILES

    operations = json.loads((CONTRACTS_DIR / "operations.json").read_text(encoding="utf-8"))
    profile_ids = {profile["id"] for profile in operations["profiles"]}
    assert profile_ids == set(OPERATION_PROFILES)


@pytest.mark.unit
def test_every_http_operation_id_is_unique_and_registered() -> None:
    from app.generated.http_api import HTTP_ENDPOINTS

    http_api = json.loads((CONTRACTS_DIR / "http-api.json").read_text(encoding="utf-8"))
    operation_ids = [endpoint["operation_id"] for endpoint in http_api["endpoints"]]
    assert len(operation_ids) == len(set(operation_ids)), "duplicate operation_id in http-api.json"
    assert set(operation_ids) == set(HTTP_ENDPOINTS)


@pytest.mark.unit
def test_no_hand_written_registry_next_to_generated() -> None:
    generated_files = {path.name for path in BACKEND_GENERATED.glob("*.py")}
    assert generated_files == {f"{name}.py" for name in GENERATED_MODULES}
