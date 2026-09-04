"""Offline Python vulnerability-scan placeholder (docs/SECURITY.md §10/§13).

This machine has NO pip-audit in the venv, no pip in the venv (uv-managed),
and no ``uv`` on PATH, and the task forbids installing new tools. The PyPI/
OSV advisory database is a networked resource anyway, so a truthful offline
"scan" does not exist. This generator therefore writes an honest artifact:

- the exact tooling state and the blocker statement (no scan was run, no
  "no vulnerabilities" claim is made);
- the inventory (name==version of every installed distribution, i.e. what a
  networked ``pip-audit`` would consume in this environment);
- the exact networked commands to run at release time.

Usage (repository root, Windows PowerShell):
    backend\\.venv\\Scripts\\python.exe scripts\\generate_python_vulnerabilities.py
"""

from __future__ import annotations

import importlib.metadata as metadata
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = REPO_ROOT / "backend" / "uv.lock"
OUT_FILE = REPO_ROOT / "deployment" / "release" / "python-vulnerabilities.txt"
TODAY = "2026-09-04"

TOOLING_STATUS = """\
Tooling state on the generation host (2026-09-04):
  - pip-audit:   NOT installed in backend/.venv (checked via importlib.metadata)
  - pip:         NOT installed in backend/.venv (uv-managed virtual environment)
  - uv:          NOT on PATH (project CI uses uv; this dev box does not have it)
  - network:     task forbids installing tools, and advisory DBs (PyPI JSON/OSV)
                 are a networked resource, so an offline "scan" cannot be truthful.
"""

BLOCKER_STATEMENT = """\
BLOCKER / honest status:
  NO vulnerability scan was executed and NO "no vulnerabilities" claim is made.
  The rows below are the inventory (names+versions of installed distributions)
  that the networked scan consumes. Vulnerability verdicts require the
  advisory database at release time and are therefore a release-time networked
  step (docs/TEST_STRATEGY.md section 4/8: release candidate gate). The result
  of that run belongs into the M6T4 release artifact set next to this file.
"""

NETWORKED_COMMANDS = """\
Exact commands for the release-time (networked) scan, run from backend/:

  1. Environment scan (project venv; fetches the advisory DB at run time):
        uv run --with pip-audit pip-audit
     pip-audit documentation (https://github.com/pypa/pip-audit) describes how
     to scope the scan (e.g. --local) for the installed pip-audit version.

  2. Lockfile scan (no project env needed; pip-audit reads uv.lock, supported
     since pip-audit 2.7.2; if the release host's pip-audit rejects the format,
     fall back to command 1):
        uvx pip-audit -r backend/uv.lock

  Air-gapped sites: mirror the advisory database in advance and point pip-audit
  at the mirror per its documentation; never ship this file as a verdict.
  Record the output (exit code, findings) in the M6T4 release statement.
"""


def main() -> int:
    dists = sorted(metadata.distributions(), key=lambda d: (d.metadata["Name"] or "").lower())
    with LOCKFILE.open("rb") as handle:
        lock = tomllib.load(handle)
    lock_count = len(lock["package"])

    inventory = "\n".join(
        f"{d.metadata['Name']}=={d.version}"
        for d in dists
        if d.metadata.get("Name")
    )

    content = "\n".join(
        [
            "# Warden 0.1.0 - Python dependency vulnerability record (offline placeholder)",
            "# Support: docs/SECURITY.md section 10/13, docs/TEST_STRATEGY.md section 4/8",
            f"# Generated (UTC date): {TODAY}",
            "# Generator: scripts/generate_python_vulnerabilities.py",
            f"# Interpreter: {sys.executable}",
            "",
            TOOLING_STATUS,
            BLOCKER_STATEMENT,
            NETWORKED_COMMANDS,
            "# --- installed-distribution inventory (what a networked environment",
            "#     scan would audit; backend/uv.lock pins these versions) ---",
            f"# lockfile package count: {lock_count}; installed distributions: {len(dists)}",
            "",
            inventory,
            "",
        ]
    )
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(content, encoding="utf-8")
    print(f"wrote {OUT_FILE} ({len(dists)} inventory rows, lockfile packages {lock_count})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
