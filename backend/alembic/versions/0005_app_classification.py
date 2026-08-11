"""Add app_classifications table.

Revision ID: 0005
Revises:     0004
Create Date: 2026-08-07

Adds the `app_classifications` table keyed on `sha256_hash` so that each
unique APK binary is classified exactly once; duplicate submissions reuse the
cached result without a second LLM call.

Down migration drops the table entirely (no data loss risk — the row is
regenerated on next upload of the same APK).
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
    op.create_table(
        "app_classifications",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # Unique key — one classification per APK binary.
        sa.Column("sha256_hash", sa.CHAR(64), nullable=False, unique=True),
        sa.Column(
            "submission_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        # Classification output.
        sa.Column("primary_category", sa.String(80), nullable=False),
        sa.Column(
            "secondary_categories",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "confidence",
            sa.Float(),
            nullable=False,
            server_default=sa.text("0.0"),
        ),
        sa.Column("reasoning", sa.Text(), nullable=True),
        # Expected / unexpected baselines (from LLM or heuristic).
        sa.Column(
            "expected_permissions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "expected_behaviors",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "unexpected_permission_examples",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "unexpected_behavior_examples",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        # Provenance.
        sa.Column(
            "classified_by",
            sa.String(20),
            nullable=False,
            server_default="llm",
        ),
        sa.Column("raw_llm_json", postgresql.JSONB(), nullable=True),
        # Timestamps.
        sa.Column(
            "classified_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Indexes used by the service cache-lookup and dashboard queries.
    op.create_index(
        "ix_app_classifications_sha256_hash",
        "app_classifications",
        ["sha256_hash"],
        unique=True,
    )
    op.create_index(
        "ix_app_classifications_submission_id",
        "app_classifications",
        ["submission_id"],
    )
    op.create_index(
        "ix_app_classifications_primary_category",
        "app_classifications",
        ["primary_category"],
    )


def downgrade() -> None:
    op.drop_index("ix_app_classifications_primary_category", "app_classifications")
    op.drop_index("ix_app_classifications_submission_id", "app_classifications")
    op.drop_index("ix_app_classifications_sha256_hash", "app_classifications")
    op.drop_table("app_classifications")
