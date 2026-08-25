"""Add forensic behaviour columns to dynamic_findings.

Revision ID: 0009
Revises:     0008
Create Date: 2026-08-23

Purely additive, in service of the adversarial audit report
(tests/run_adversarial_test.py) and the target-app-centric exploration rework.
Two columns, both distinct from the deterministic `network_calls` ML feature:

  frida_events           — raw per-run Frida behaviour events captured during UI
                           exploration (file_access, network_payload, …). The
                           forensic record the audit report reads. NOT NULL,
                           defaults to '[]' so legacy rows read as "no events"
                           rather than NULL.
  observed_network_calls — real outbound connections seen by AdbNetworkObserver.
                           NULLABLE and fail-closed: NULL = observer unavailable
                           / not probed (unknown), [] = probed and nothing
                           connected. NOT back-filled — legacy rows are genuinely
                           unknown, and NULL must read as unknown downstream.

No scoring input changes (decision D3): ScoringService._fetch_dynamic reads an
explicit column list (sms_access, accessibility_abuse, overlay_detected,
network_calls), so adding columns here cannot perturb the risk score. This is
asserted by test_dynamic_provenance.py::test_scoring_input_is_unchanged_*.

No existing column, constraint, or index is touched. `network_calls` keeps its
exact semantics. Down migration drops both new columns; the data they hold is
forensic detail regenerated on the next analysis run.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    # IF NOT EXISTS keeps this idempotent, matching the 0008 convention.
    # frida_events is NOT NULL with a '[]' default so existing rows acquire an
    # empty forensic list rather than NULL (nothing is fabricated — an empty
    # list is the honest value for a row captured before the column existed).
    conn.execute(sa.text(
        "ALTER TABLE dynamic_findings "
        "ADD COLUMN IF NOT EXISTS frida_events JSONB NOT NULL DEFAULT '[]'::jsonb"
    ))
    # observed_network_calls is nullable BY DESIGN: NULL = unknown (observer
    # unavailable / not probed), which must stay distinct from [] (probed,
    # nothing connected). Never back-filled.
    conn.execute(sa.text(
        "ALTER TABLE dynamic_findings "
        "ADD COLUMN IF NOT EXISTS observed_network_calls JSONB"
    ))


def downgrade() -> None:
    op.drop_column("dynamic_findings", "observed_network_calls")
    op.drop_column("dynamic_findings", "frida_events")
