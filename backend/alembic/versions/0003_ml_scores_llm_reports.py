"""ml_scores + llm_reports tables (Member B's slice of §4)

Depends only on apk_submissions (from 0001), so on the isolated feat/m2 branch
it applies directly after 0001. At integration this sits alongside Member C's
0002; if `alembic heads` reports two heads, re-parent this down_revision to the
latest migration (a one-line merge Member D handles per §9 Git Workflow).

Revision ID: 0003
Revises: 0001
Create Date: 2026-07-03
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── ml_scores ───────────────────────────────────────────────────────
    op.create_table(
        "ml_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("apk_submissions.id"), nullable=False, unique=True),
        sa.Column("classifier_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("novelty_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("shap_values", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("model_version", sa.String(40), nullable=False),
    )

    # ── llm_reports ─────────────────────────────────────────────────────
    op.create_table(
        "llm_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("apk_submissions.id"), nullable=False, unique=True),
        sa.Column("summary_text", sa.Text(), nullable=True),
        sa.Column("ttp_mapping", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("sanitization_flags", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("model_used", sa.String(60), nullable=False),
        sa.Column("tokens_used", sa.Integer(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("llm_reports")
    op.drop_table("ml_scores")
