"""Offline Python dependency license report (docs/SECURITY.md §10/§13).

Generates ``deployment/release/python-licenses.txt`` from the metadata of
the distributions installed in the interpreter that runs this script
(``importlib.metadata``; offline, no network, no extra tools).

Scope: every installed distribution of the interpreter (the documented
invocation uses ``backend/.venv`` so the report mirrors the locked dev
environment). Each row is tagged ``runtime`` (reachable from the
``warden-backend`` runtime dependencies in ``backend/uv.lock``) or
``dev-only``. License resolution order: ``License-Expression`` (PEP 639) →
single-line ``License`` → OSI ``Classifier`` → ``UNKNOWN``. Packages whose
``License`` header is a long text block are marked ``<text>`` with a
truncated first line; the full text stays in the package metadata.

Usage (repository root, Windows PowerShell):
    backend\\.venv\\Scripts\\python.exe scripts\\generate_python_licenses.py
"""

from __future__ import annotations

import importlib.metadata as metadata
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = REPO_ROOT / "backend" / "uv.lock"
OUT_FILE = REPO_ROOT / "deployment" / "release" / "python-licenses.txt"
TODAY = "2026-09-04"


def license_of(dist: metadata.Distribution) -> str:
    """Best-effort SPDX-ish license label from core metadata."""
    expression = (dist.metadata.get("License-Expression") or "").strip()
    if expression:
        return expression
    declared = (dist.metadata.get("License") or "").strip()
    if declared:
        one_line = " ".join(declared.split())
        if len(one_line) <= 60:
            return one_line
        first_line = one_line.split(". ")[0]
        return f"<text> {first_line[:40]}... (full text in package metadata)"
    classifiers = [
        c.split("License :: OSI Approved :: ")[1]
        for c in dist.metadata.get_all("Classifier") or []
        if c.startswith("License :: OSI Approved :: ")
    ]
    if classifiers:
        return classifiers[0]
    return "UNKNOWN"


def canonical(name: str) -> str:
    """PEP 503-style key: lowercased, ``-`` and ``_`` interchangeable."""
    return name.lower().replace("-", "_")


def runtime_closure(lock: dict[str, object]) -> set[str]:
    """Names reachable from the lockfile root's runtime dependencies.

    Marker conditions are ignored (edges are included regardless of
    platform); extras requested by a parent edge are traversed through the
    package's ``optional-dependencies``. The result is therefore a superset
    of any single platform's runtime install, which is the honest direction
    for a license gate. Returned names are canonicalized (PEP 503) so they
    match distribution metadata names.
    """
    packages = {
        canonical(p["name"]): p for p in lock["package"] if isinstance(p, dict)  # type: ignore[index]
    }
    root = next(p for p in packages.values() if p.get("source", {}).get("virtual") == ".")

    def edges_of(entry: dict[str, object], key: str) -> list[tuple[str, set[str]]]:
        """Unwrap ``dependencies``-style edges into (name, requested_extras)."""
        result: list[tuple[str, set[str]]] = []
        for edge in entry.get(key, []) if isinstance(entry.get(key), list) else []:
            if isinstance(edge, dict):
                extra = edge.get("extra") or []
                result.append((canonical(str(edge["name"])), set(extra) if isinstance(extra, list) else {str(extra)}))  # type: ignore[arg-type]
            else:
                result.append((canonical(str(edge)), set()))
        return result

    seen: set[str] = set()
    queue: list[tuple[str, set[str]]] = [
        (name, extras) for name, extras in edges_of(root, "dependencies")
    ]
    while queue:
        name, extras = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        package = packages.get(name, {})
        queue.extend(edges_of(package, "dependencies"))
        optional = package.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for extra in extras:
                queue.extend(edges_of(optional, extra))
    return seen


def main() -> int:
    dists = sorted(metadata.distributions(), key=lambda d: (d.metadata["Name"] or "").lower())
    with LOCKFILE.open("rb") as handle:
        lock = tomllib.load(handle)
    runtime = runtime_closure(lock)
    rows: list[tuple[str, str, str, str]] = []
    for dist in dists:
        name = dist.metadata["Name"] or "?"
        rows.append((name, dist.version, "runtime" if canonical(name) in runtime else "dev-only", license_of(dist)))
    unknown = [row for row in rows if row[3] == "UNKNOWN"]

    lines = [
        "# Warden 0.1.0 - Python dependency license report (offline)",
        "# Support: docs/SECURITY.md (section 10/13), docs/TEST_STRATEGY.md section 4 (release gate)",
        f"# Generated (UTC date): {TODAY}",
        "# Generator: scripts/generate_python_licenses.py (importlib.metadata of the running interpreter)",
        f"# Interpreter: {sys.executable}",
        "# Lockfile used for runtime/dev scoping: backend/uv.lock",
        f"# Scope: {len(rows)} installed distributions in the interpreter above (dev toolchain included;",
        "#   matches the full backend/uv.lock resolution). runtime = uv.lock runtime closure of",
        "#   warden-backend (all platform marker edges included; the Linux image installs a subset,",
        "#   see backend/Dockerfile `uv sync --no-dev --frozen`).",
        "# License value order: License-Expression -> single-line License -> OSI classifier -> UNKNOWN.",
        "#   Long License texts are shown truncated as <text>; full text lives in the package metadata.",
        "# UNKNOWN licenses must be reviewed manually before release; this report asserts nothing about",
        "#   license compatibility on its own.",
        "",
        f"{len(rows)} installed distributions; {len(unknown)} with UNKNOWN license",
        "name\tversion\tscope\tlicense",
    ]
    for name, version, scope, lic in rows:
        lines.append(f"{name}\t{version}\t{scope}\t{lic}")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT_FILE} ({len(rows)} rows, {len(unknown)} UNKNOWN licenses)")
    if unknown:
        print("UNKNOWN licenses:")
        for name, version, _scope, _lic in unknown:
            print(f"  {name} {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
