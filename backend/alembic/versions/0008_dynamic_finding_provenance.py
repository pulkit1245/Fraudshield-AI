"""Add sandbox provenance columns to dynamic_findings.

Revision ID: 0008
Revises:     0007
Create Date: 2026-08-16

Phase 1 of the sandbox hardening plan (docs/sandbox-hardening-plan.md §4).
Purely additive: two nullable columns that record *how* a dynamic finding was
produced, so a simulated run stops being indistinguishable from a live one at
the database layer.

  mode                 — which sandbox path produced this row, as reported by
                         SandboxManager.run(): "live", "simulate", or "mobsf".
  containment_verified — whether egress containment was actually *demonstrated*
                         for this run. Phase 3 populates it; nothing writes it
                         yet.

Both are NULLABLE BY DESIGN and are NOT back-filled. Existing rows have genuinely
unknown provenance, and back-filling them with "live" (or with False) would be
fabricating data — the exact defect class this plan exists to remove. NULL must
read as *unknown* everywhere downstream.

`containment_verified` is deliberately three-valued: NULL = not probed / unknown,
False = probed and containment did NOT hold, True = probed and demonstrated. A
run that merely *issued* `svc data disable` without checking the result is NULL,
not True (emulator_pool._harden_network:189-196 discards both returncodes).

No existing column, constraint, or index is touched, and no scoring input
changes: scoring_service._fetch_dynamic reads an explicit column list, so
adding columns here cannot perturb the risk score.

Down migration drops both columns. No data loss beyond the provenance metadata
itself, which is regenerated on the next analysis run.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    # Use IF NOT EXISTS so this migration is idempotent — the columns were
    # already added by the old revision-0007 run before the merge renumbering.
    conn.execute(sa.text(
        "ALTER TABLE dynamic_findings ADD COLUMN IF NOT EXISTS mode VARCHAR(16)"
    ))
    conn.execute(sa.text(
        "ALTER TABLE dynamic_findings ADD COLUMN IF NOT EXISTS containment_verified BOOLEAN"
    ))
    # Indexed because the operational question "which findings are not live?"
    # is a filter over the whole table, not a per-submission lookup.
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_dynamic_findings_mode ON dynamic_findings (mode)"
    ))


def downgrade() -> None:
    op.drop_index("ix_dynamic_findings_mode", table_name="dynamic_findings")
    op.drop_column("dynamic_findings", "containment_verified")
    op.drop_column("dynamic_findings", "mode")
