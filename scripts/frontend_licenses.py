"""Offline frontend dependency license report (docs/SECURITY.md §10/§13).

Usage (repository root, any Python >= 3.10; no third-party imports):
    backend\\.venv\\Scripts\\python.exe scripts\\frontend_licenses.py

What it does, all offline (no new packages, no network):
  1. runs ``npm ls --json --all`` in frontend/ to get the resolved install
     set (name@version) that npm itself reports for the checked-out tree;
  2. walks frontend/node_modules/**/package.json to read the declared license
     of every physically installed package (name/version/license);
  3. reconciles the two sets and writes deployment/release/frontend-licenses.txt
     with one row per (name, version, license, copies) plus honest notes for
     packages npm reports but no package.json was found for, and UNKNOWN
     licenses that need human review before release.

License value order: ``license`` string -> ``licenses`` array entries ->
UNKNOWN. Scope: the whole installed tree, dev tooling included (node_modules);
the shipped nginx image is built from ``npm ci --omit=dev`` output, so the
runtime-only license set is a subset the release pipeline must narrow (this
report intentionally over-covers rather than silently omitting dev packages).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TODAY = "2026-09-04"


def _npm_ls_json(frontend_dir: Path) -> dict[str, object]:
    """``npm ls --json --all`` for the installed tree (offline)."""
    if sys.platform == "win32":
        command = ["cmd", "/c", "npm", "ls", "--json", "--all"]
    else:
        command = ["npm", "ls", "--json", "--all"]
    result = subprocess.run(  # noqa: S603 - npm is a repository tool, argv is static
        command, cwd=frontend_dir, capture_output=True, text=True, shell=False, check=False
    )
    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(f"npm ls --json failed (exit {result.returncode}): {result.stderr[:500]}")
    try:
        parsed = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"npm ls output is not JSON: {result.stdout[:500]}") from exc
    assert isinstance(parsed, dict)
    return parsed


def _flatten_tree(node: dict[str, object]) -> set[tuple[str, str]]:
    """Collect (name, version) from an ``npm ls --json`` tree.

    npm only puts ``name`` on the root node; nested nodes are keyed by name
    inside ``dependencies``, so the recursion carries the key along.
    """
    found: set[tuple[str, str]] = set()

    def walk(name: str, current: object) -> None:
        if not isinstance(current, dict):
            return
        version = current.get("version")
        if name and isinstance(version, str) and version:
            found.add((name, version))
        for child_name, child in (current.get("dependencies") or {}).items():
            walk(child_name, child)

    walk(str(node.get("name") or ""), node)
    return found


def _license_of(package: dict[str, object]) -> str:
    raw = package.get("license")
    if isinstance(raw, str):
        return raw or "UNKNOWN"
    if isinstance(raw, dict):
        value = raw.get("type")
        return value if isinstance(value, str) and value else "UNKNOWN"
    licenses = package.get("licenses")
    if isinstance(licenses, list):
        kinds = []
        for item in licenses:
            if isinstance(item, dict) and isinstance(item.get("type"), str):
                kinds.append(item["type"])
        return "; ".join(kinds) if kinds else "UNKNOWN"
    return "UNKNOWN"


def _walk_node_modules(frontend_dir: Path) -> dict[tuple[str, str], tuple[str, int]]:
    """(name, version) -> (license, physical copies) for every package.json."""
    found: dict[tuple[str, str], tuple[str, int]] = {}
    root = frontend_dir / "node_modules"
    if not root.is_dir():
        raise RuntimeError(f"missing {root} - run `npm ci` first")
    for package_json in root.rglob("package.json"):
        if ".bin" in package_json.parts:
            continue
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        name = data.get("name")
        version = data.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            continue
        key = (name, version)
        license_name, copies = found.get(key, ("", 0))
        if not license_name:
            license_name = _license_of(data)
        found[key] = (license_name, copies + 1)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(REPO_ROOT / "deployment" / "release" / "frontend-licenses.txt"))
    args = parser.parse_args()

    frontend_dir = REPO_ROOT / "frontend"
    tree = _npm_ls_json(frontend_dir)
    expected = _flatten_tree(tree)
    root_name = tree.get("name")
    root_version = tree.get("version")
    if isinstance(root_name, str) and isinstance(root_version, str):
        expected.discard((root_name, root_version))
    physical = _walk_node_modules(frontend_dir)

    missing = sorted(expected - physical.keys())
    extraneous = sorted(set(physical) - expected)
    unknown = sorted((key for key, (lic, _copies) in physical.items() if lic == "UNKNOWN"))

    lines = [
        "# Warden 0.1.0 - frontend dependency license report (offline)",
        "# Support: docs/SECURITY.md (section 10/13), docs/TEST_STRATEGY.md section 4 (release gate)",
        f"# Generated (UTC date): {TODAY}",
        "# Generator: scripts/frontend_licenses.py (npm ls --json + node_modules package.json walk)",
        f"# Interpreter: {sys.executable}",
        "# Source of truth for the package set: frontend/package-lock.json (npm ci) and the installed",
        "#   node_modules tree; scope = full installed tree including dev tooling. The shipped nginx",
        "#   image runs `npm ci --omit=dev` (release pipeline), so the runtime-only set is a subset",
        "#   of this report - over-covering is intentional and honest.",
        "# License value order: package.json license (string) -> licenses[] -> UNKNOWN.",
        "# UNKNOWN licenses must be reviewed manually before release.",
        "",
        f"packages on disk: {len(physical)}; npm ls --json set: {len(expected)};",
        f"on disk but not in npm tree: {len(extraneous)}; in npm tree but no package.json found: {len(missing)};",
        f"UNKNOWN licenses: {len(unknown)}",
        "name\tversion\tlicense\tcopies",
    ]
    for (name, version), (license_name, copies) in sorted(physical.items(), key=lambda item: item[0][0].lower()):
        lines.append(f"{name}\t{version}\t{license_name}\t{copies}")
    if extraneous:
        lines.append("")
        lines.append("# NOTE - installed but not reported by npm ls --json (extraneous or pruned):")
        for name, version in extraneous:
            lines.append(f"#   {name}@{version}")
    if missing:
        lines.append("")
        lines.append("# NOTE - npm ls --json entries without a readable node_modules package.json:")
        for name, version in missing:
            lines.append(f"#   {name}@{version}")
    if unknown:
        lines.append("")
        lines.append("# NOTE - UNKNOWN licenses (review manually):")
        for name, version in unknown:
            lines.append(f"#   {name}@{version}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"wrote {out}: {len(physical)} packages on disk, "
        f"{len(missing)} missing, {len(extraneous)} extraneous, {len(unknown)} UNKNOWN licenses"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
