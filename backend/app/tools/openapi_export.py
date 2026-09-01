"""OpenAPI export: writes backend/openapi.gen.json from the FastAPI app.

The FastAPI app (app.main) lands in M0T3. Until then this target must fail
loudly instead of emitting a fake artifact; the generated file is gitignored.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = BACKEND_ROOT / "openapi.gen.json"


def run() -> None:
    try:
        app = importlib.import_module("app.main").app
    except ImportError:
        print("app.main not available yet (M0T3)", file=sys.stderr)
        sys.exit(1)
    schema = app.openapi()
    OPENAPI_PATH.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    print(f"OpenAPI exported to {OPENAPI_PATH}")


if __name__ == "__main__":
    run()
