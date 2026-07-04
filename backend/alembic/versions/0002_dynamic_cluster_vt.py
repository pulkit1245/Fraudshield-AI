"""dynamic_findings, campaign_clusters, cluster_members, virustotal_lookups

Member C's slice of §4 + the pgvector extension. Parented to 0001 (Member A's
initial). At integration Member B's 0003 is also a child of 0001; run
`alembic merge heads` (Member D, per §9) to linearize the two feature branches.

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-03
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

VECTOR_DIM = 768


def _vector_type():
    """pgvector Vector(768) if available, else a JSONB fallback."""
    try:
        from pgvector.sqlalchemy import Vector

        return Vector(VECTOR_DIM)
    except Exception:  # noqa: BLE001
        return postgresql.JSONB()


def upgrade() -> None:
    # Required for family_signature similarity search.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # ── dynamic_findings ────────────────────────────────────────────────
    op.create_table(
        "dynamic_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("apk_submissions.id"), nullable=False, unique=True),
        sa.Column("sms_access", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("accessibility_abuse", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("overlay_detected", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("network_calls", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("sandbox_log_path", sa.Text(), nullable=True),
        sa.Column("run_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    # ── campaign_clusters ───────────────────────────────────────────────
    op.create_table(
        "campaign_clusters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("cluster_name", sa.String(120), nullable=False),
        sa.Column("family_signature", _vector_type(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    # ── cluster_members (composite PK) ──────────────────────────────────
    op.create_table(
        "cluster_members",
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("campaign_clusters.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("apk_submissions.id"), primary_key=True),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    # ── virustotal_lookups ──────────────────────────────────────────────
    op.create_table(
        "virustotal_lookups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("apk_submissions.id"), nullable=False, unique=True),
        sa.Column("vt_response", postgresql.JSONB(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("virustotal_lookups")
    op.drop_table("cluster_members")
    op.drop_table("campaign_clusters")
    op.drop_table("dynamic_findings")
