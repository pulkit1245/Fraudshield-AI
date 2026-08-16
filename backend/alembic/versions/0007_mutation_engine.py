"""Add mutation engine tables (malware_families, family_members, mutation_variants).

Revision ID: 0007
Revises:     0006
Create Date: 2026-08-15

Creates three tables for the Malware Mutation & Pattern-Generation Engine:

  * ``malware_families`` — one row per confirmed malware family; holds a 768-dim
    centroid signature (pgvector on Postgres, JSON on SQLite/dev) and a sample count.

  * ``family_members`` — normalised join table linking confirmed ``apk_submissions``
    to a ``malware_families`` row (mirrors ``cluster_members``).

  * ``mutation_variants`` — synthetically generated variant signatures produced by
    the seven mutation transforms; one row per (family × transform) pair generated
    at family-confirmation time.

Down migration drops all three tables in reverse dependency order.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: Union[str, None] = "fc3b3e1b0973"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── malware_families ────────────────────────────────────────────────
    op.create_table(
        "malware_families",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("family_name", sa.String(120), nullable=False),
        # 768-dim centroid embedding — pgvector on Postgres, JSON on SQLite/dev.
        # Stored as JSON here; the ORM's Vector768 TypeDecorator handles the
        # pgvector upgrade transparently on a live Postgres instance.
        sa.Column(
            "centroid_signature",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "sample_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
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
    op.create_index(
        "ix_malware_families_family_name",
        "malware_families",
        ["family_name"],
    )

    # ── family_members (join table) ──────────────────────────────────────
    op.create_table(
        "family_members",
        sa.Column(
            "family_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("malware_families.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "submission_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("apk_submissions.id"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_family_members_submission_id",
        "family_members",
        ["submission_id"],
    )

    # ── mutation_variants ────────────────────────────────────────────────
    # transform_type is one of: permission_swap, permission_addition,
    # class_rename, string_mangle, resource_repack, obfuscation_shift,
    # api_substitution.
    op.create_table(
        "mutation_variants",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "family_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("malware_families.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("transform_type", sa.String(30), nullable=False),
        # 768-dim vector of the mutated genome (same JSON/pgvector dual storage).
        sa.Column(
            "variant_signature",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        # Full mutated genome dict for forensic/audit purposes.
        sa.Column(
            "genome_snapshot",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_mutation_variants_family_id",
        "mutation_variants",
        ["family_id"],
    )
    op.create_index(
        "ix_mutation_variants_transform_type",
        "mutation_variants",
        ["transform_type"],
    )


def downgrade() -> None:
    # Drop in reverse dependency order.
    op.drop_index("ix_mutation_variants_transform_type", "mutation_variants")
    op.drop_index("ix_mutation_variants_family_id", "mutation_variants")
    op.drop_table("mutation_variants")

    op.drop_index("ix_family_members_submission_id", "family_members")
    op.drop_table("family_members")

    op.drop_index("ix_malware_families_family_name", "malware_families")
    op.drop_table("malware_families")
