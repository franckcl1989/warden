"""Empty baseline revision (harness proof, no tables yet).

M0T4 ships only the migration harness: this revision gives later migrations a
stable parent (down_revision=None) and proves upgrade/downgrade run cleanly on
the real PostgreSQL 18 instance (docs/TEST_STRATEGY.md §2.2). The first
business tables arrive in M1/M2; per docs/DATA_MODEL.md §12, migrations are
forward-only in production and downgrades are exercised by tests only.
"""

from __future__ import annotations

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
