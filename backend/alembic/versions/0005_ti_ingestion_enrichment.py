"""Threat Intelligence ingestion enrichment schema.

Adds the columns required by the TI ingestion pipeline without touching
any existing column, index, or constraint introduced in migrations 0001-0004.

Changes
-------
ttps
  + mitre_technique_id  VARCHAR(20)  nullable  — ATT&CK technique ID (e.g. T1636.004)
  + mitre_tactic        VARCHAR(60)  nullable  — ATT&CK tactic name (e.g. Collection)
  + confidence_score    FLOAT        NOT NULL DEFAULT 0.85
                                               — approval-gate routing; scoring calibration
  + external_id         VARCHAR(200) nullable  — stable dedup key from source feed
                                               — partial unique index (WHERE NOT NULL)

detection_markers
  + false_positive_rate FLOAT        NOT NULL DEFAULT 0.0
                                               — analyst feedback calibration
  + external_id         VARCHAR(200) nullable  — marker-level dedup key
                                               — partial unique index (WHERE NOT NULL)

new table
  ti_ingestion_quarantine — holds records rejected by the validator so analysts
                            can inspect systematic feed gaps.

data migration
  ttps.source: "internal" → "manual"  (controlled-vocabulary normalisation)

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-24
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── ttps additions ───────────────────────────────────────────────────

    op.add_column(
        "ttps",
        sa.Column("mitre_technique_id", sa.String(20), nullable=True),
    )
    op.add_column(
        "ttps",
        sa.Column("mitre_tactic", sa.String(60), nullable=True),
    )
    op.add_column(
        "ttps",
        sa.Column(
            "confidence_score",
            sa.Float(),
            nullable=False,
            server_default="0.85",
        ),
    )
    # external_id: stable key from source feed used for deduplication.
    # nullable=True because hand-authored TTPs have no external feed ID.
    # The uniqueness constraint is enforced by a PARTIAL index below so that
    # multiple NULL values are allowed (PostgreSQL: NULL != NULL).
    op.add_column(
        "ttps",
        sa.Column("external_id", sa.String(200), nullable=True),
    )

    # Partial unique index: enforce uniqueness only on non-NULL external_id values.
    # This is the PostgreSQL-idiomatic approach for nullable unique columns.
    op.create_index(
        "ix_ttps_external_id_unique",
        "ttps",
        ["external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )
    op.create_index(
        "ix_ttps_mitre_technique_id",
        "ttps",
        ["mitre_technique_id"],
    )

    # ── detection_markers additions ──────────────────────────────────────

    op.add_column(
        "detection_markers",
        sa.Column(
            "false_positive_rate",
            sa.Float(),
            nullable=False,
            server_default="0.0",
        ),
    )
    op.add_column(
        "detection_markers",
        sa.Column("external_id", sa.String(200), nullable=True),
    )
    # Partial unique index for marker-level deduplication.
    op.create_index(
        "ix_detection_markers_external_id_unique",
        "detection_markers",
        ["external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )

    # ── ti_ingestion_quarantine ──────────────────────────────────────────
    # Holds records rejected by the ingestion validator so analysts can
    # discover systematic gaps in source feeds without silently dropping data.
    # No FK to ttps — quarantined records by definition have no TTP row yet.
    op.create_table(
        "ti_ingestion_quarantine",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("raw_payload", postgresql.JSONB(), nullable=False),
        sa.Column("failure_rule", sa.String(10), nullable=False),   # "V1".."V11"
        sa.Column("failure_msg", sa.Text(), nullable=False),
        sa.Column("ingestion_source", sa.String(60), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_ti_quarantine_source",
        "ti_ingestion_quarantine",
        ["ingestion_source"],
    )
    op.create_index(
        "ix_ti_quarantine_created_at",
        "ti_ingestion_quarantine",
        ["created_at"],
    )

    # ── data migration: normalise legacy source vocabulary ───────────────
    # Existing hand-authored rows used "internal" as the source value.
    # The reviewed plan extends the `source` column vocabulary, replacing
    # "internal" with "manual" to distinguish it from automated ingestion.
    op.execute(
        sa.text("UPDATE ttps SET source = 'manual' WHERE source = 'internal'")
    )


def downgrade() -> None:
    # Reverse data migration first.
    op.execute(
        sa.text("UPDATE ttps SET source = 'internal' WHERE source = 'manual'")
    )

    # Drop quarantine table.
    op.drop_index("ix_ti_quarantine_created_at", table_name="ti_ingestion_quarantine")
    op.drop_index("ix_ti_quarantine_source", table_name="ti_ingestion_quarantine")
    op.drop_table("ti_ingestion_quarantine")

    # Drop detection_markers additions.
    op.drop_index(
        "ix_detection_markers_external_id_unique",
        table_name="detection_markers",
    )
    op.drop_column("detection_markers", "external_id")
    op.drop_column("detection_markers", "false_positive_rate")

    # Drop ttps additions.
    op.drop_index("ix_ttps_mitre_technique_id", table_name="ttps")
    op.drop_index("ix_ttps_external_id_unique", table_name="ttps")
    op.drop_column("ttps", "external_id")
    op.drop_column("ttps", "confidence_score")
    op.drop_column("ttps", "mitre_tactic")
    op.drop_column("ttps", "mitre_technique_id")
