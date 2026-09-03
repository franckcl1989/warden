"""M5T2 OID-ledger honesty suite.

Binding rules the adapter modules must never violate (M5T2 brief + ADR-018
spirit, docs/DEVICE_ADAPTERS.md §6):

- every OID row in the adapter ledger carries a [basis] tag;
- every dotted OID literal the Huawei adapter code reads/walks is a
  registered ledger row (adapter and simulator can never drift);
- no [huawei-doc-url] basis exists anywhere in the adapter or simulator
  (the environment could not reach a citable Huawei MIB reference on
  2026-09-04 — same outcome as M5T1 — so the Huawei subtree is [sim] DSL
  only, never a claim about a real Huawei MIB object);
- the simulator serves EXACTLY the leaves of the ledger (per profile where
  the layout differs): the honesty cross-test builds each agent tree and
  checks every registered scalar answers and every registered column has
  rows.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from app.adapters.huawei import oids
from app.infrastructure.protocols.snmp.oid import parse_oid
from tests.simulators.switch.agent import AgentConfig, SwitchAgent
from tests.simulators.switch.profiles import profile_by_key

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning",
    "ignore::ResourceWarning",
)

ADAPTER_DIR = Path(__file__).resolve().parents[3] / "app" / "adapters" / "huawei"
SIM_DIR = Path(__file__).resolve().parents[3] / "tests" / "simulators" / "switch"

_OID_LITERAL = re.compile(r"\b1\.3\.6\.1(?:\.\d+)+\b")


class TestBasisDiscipline:
    def test_every_row_has_a_basis_tag(self) -> None:
        for row in oids.ROWS:
            basis = str(row["basis"])
            assert basis.startswith("["), f"row {row['oid']} lacks a [basis] tag"
            assert basis.endswith("]"), f"row {row['oid']} basis must end with ]"
            assert row["oid"].startswith("1.3.6.1."), f"row {row['oid']} is not an OID"
            parse_oid(str(row["oid"]))  # must be well-formed

    def test_no_doc_url_claims_without_a_citable_page(self) -> None:
        """No [huawei-doc-url] basis exists anywhere: the Huawei subtree is
        [sim] DSL until hardware certification archives a real MIB
        reference (ADR-018)."""
        for row in oids.ROWS:
            assert "[huawei-doc-url]" not in str(row["basis"])
        for path in list(ADAPTER_DIR.glob("*.py")) + list(SIM_DIR.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            assert "huawei-doc-url" not in text, f"{path.name} claims a doc URL basis"

    def test_sim_rows_live_under_the_iana_cited_pen(self) -> None:
        for row in oids.HUAWEI_SIM_ROWS:
            oid = str(row["oid"])
            assert oid.startswith(oids.SIM_MONITOR_ROOT + "."), oid
            assert str(row["basis"]) == oids.SIM
        assert str(oids.HUAWEI_PEN) == "1.3.6.1.4.1.2011"
        for row in oids.RFC_ROWS:
            assert str(row["basis"]).startswith("[rfc-") or str(row["basis"]).startswith("[iana-")

    def test_ledger_has_no_duplicate_oids(self) -> None:
        seen: list[str] = []
        for row in oids.ROWS:
            assert str(row["oid"]) not in seen, f"duplicate OID {row['oid']}"
            seen.append(str(row["oid"]))


class TestAdapterOidLiteralsRegistered:
    def _allowed(self) -> frozenset[str]:
        """Registered ledger OIDs + the RFC seed OIDs + any parent prefix
        mentioned in docs (e.g. the sim subtree root)."""
        allowed = set(oids.oids()) | _rfc_seed_oids()
        parents: set[str] = set()
        for oid in allowed:
            parts = oid.split(".")
            for width in range(2, len(parts)):
                parents.add(".".join(parts[:width]))
        return frozenset(allowed | parents)

    @pytest.mark.parametrize("module", ["base.py", "core.py", "access.py", "oids.py"])
    def test_every_oid_literal_in_adapter_code_is_registered(self, module: str) -> None:
        """Every dotted OID the adapter code mentions must be a ledger row
        or a parent prefix of one (exact leaf or table-column prefix) — the
        honesty scan that keeps the adapter and the simulator ledger in
        lockstep."""
        source = (ADAPTER_DIR / module).read_text(encoding="utf-8")
        allowed = self._allowed()
        unknown: list[str] = []
        for match in _OID_LITERAL.finditer(source):
            literal = match.group(0)
            if literal not in allowed:
                unknown.append(literal)
        assert not unknown, f"{module} references unregistered OIDs: {sorted(set(unknown))}"

    def test_walk_prefixes_are_column_rows(self) -> None:
        """Column prefixes the readers walk must be registered as columns
        (so the honesty cross-test can pin the simulator tree to them)."""
        source = (ADAPTER_DIR / "base.py").read_text(encoding="utf-8")
        for match in _OID_LITERAL.finditer(source):
            literal = match.group(0)
            row = next((row for row in oids.ROWS if str(row["oid"]) == literal), None)
            if row is None or literal in _rfc_seed_oids():
                continue
            assert row["is_column"] or not literal.endswith("."), literal


def _rfc_seed_oids() -> frozenset[str]:
    from app.infrastructure.protocols.snmp import oid as snmp_oid_module

    values = {str(row["oid"]) for row in snmp_oid_module.SEED_SYSTEM}
    values.update(str(row["oid"]) for row in snmp_oid_module.SEED_IFTABLE_COLUMNS)
    return frozenset(values)


class TestSimulatorServesTheLedger:
    """The simulator tree per profile serves every ledger leaf it must
    (scalars answer, columns have rows) — adapter and simulator can never
    drift (agent trees are built offline; no UDP needed)."""

    def _tree_of(self, profile_key: str) -> SwitchAgent:
        agent = SwitchAgent(AgentConfig(profile=profile_by_key(profile_key), v3_user=None))
        agent._build_tree()  # noqa: SLF001 - offline tree build (no sockets)
        return agent

    def _assert_served(self, agent: SwitchAgent, row: dict[str, str | bool]) -> None:
        oid = str(row["oid"])
        tree = agent._tree
        if not bool(row["is_column"]):
            assert parse_oid(oid) in tree, f"{oid} ({row['label']}) not served on {agent.profile.profile_key}"
            return
        prefix = parse_oid(oid)
        rows = [key for key in tree if len(key) == len(prefix) + 1 and key[: len(prefix)] == prefix]
        assert rows, f"column {oid} ({row['label']}) has no rows on {agent.profile.profile_key}"

    @pytest.mark.parametrize(
        ("profile_key", "core_switch"),
        [("core_s5732", True), ("core_s5731s", True), ("access_s5735", False)],
    )
    def test_profile_tree_covers_the_ledger(self, profile_key: str, core_switch: bool) -> None:
        agent = self._tree_of(profile_key)
        layer2_oids = {oids.OID_LOOP_STATUS, oids.OID_STORM_STATUS, oids.COL_STP_STATE}
        poe_oids = {
            oids.OID_POE_TOTAL_MW,
            oids.OID_POE_BUDGET_MW,
            oids.OID_POE_ALARM,
            oids.COL_POE_STATE,
            oids.COL_POE_POWER_MW,
        }
        for row in oids.RFC_ROWS:
            self._assert_served(agent, row)
        for row in oids.HUAWEI_SIM_ROWS:
            oid = str(row["oid"])
            if oid in layer2_oids and not core_switch:
                continue
            if oid in poe_oids and core_switch:
                continue
            self._assert_served(agent, row)

    def test_poe_layout_only_on_the_access_profile(self) -> None:
        access = self._tree_of("access_s5735")
        core = self._tree_of("core_s5732")
        assert parse_oid(oids.OID_POE_BUDGET_MW) in access._tree  # noqa: SLF001
        assert parse_oid(oids.OID_POE_BUDGET_MW) not in core._tree  # noqa: SLF001
        assert parse_oid(oids.OID_LOOP_STATUS) not in access._tree  # noqa: SLF001
        assert parse_oid(oids.OID_LOOP_STATUS) in core._tree  # noqa: SLF001
