"""initial schema — users, apk_submissions, static_findings, risk_verdicts, audit_logs

Member A's slice of the §4 Database Design. Member C's migration (0002) adds the
pgvector extension plus dynamic_findings, campaign_clusters, cluster_members and
virustotal_lookups on top of this.

Revision ID: 0001
Revises:
Create Date: 2026-07-03
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # gen_random_uuid() lives in pgcrypto on PG < 13; harmless if already present.
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto";')

    # ── users ───────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="analyst"),
        sa.Column("org_name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint("role IN ('analyst','lead','admin')", name="ck_users_role"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── apk_submissions ─────────────────────────────────────────────────
    op.create_table(
        "apk_submissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("sha256_hash", sa.CHAR(64), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued','static_running','dynamic_running',"
            "'scoring','completed','failed')",
            name="ck_submissions_status",
        ),
    )
    op.create_index("ix_submissions_sha256", "apk_submissions", ["sha256_hash"])
    op.create_index("ix_submissions_status", "apk_submissions", ["status"])
    op.create_index("ix_submissions_uploaded_by", "apk_submissions", ["uploaded_by"])

    # ── static_findings ─────────────────────────────────────────────────
    op.create_table(
        "static_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("apk_submissions.id"), nullable=False, unique=True),
        sa.Column("package_name", sa.String(255), nullable=True),
        sa.Column("permissions", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("certificate_info", postgresql.JSONB(), nullable=True),
        sa.Column("api_call_graph", postgresql.JSONB(), nullable=True),
        sa.Column("obfuscation_score", sa.Float(), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
    )

    # ── risk_verdicts ───────────────────────────────────────────────────
    op.create_table(
        "risk_verdicts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("apk_submissions.id"), nullable=False, unique=True),
        sa.Column("final_risk_score", sa.SmallInteger(), nullable=False),
        sa.Column("severity_band", sa.String(10), nullable=False),
        sa.Column("recommended_action", sa.String(30), nullable=False),
        sa.Column("analyst_override_score", sa.SmallInteger(), nullable=True),
        sa.Column("reviewed_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("final_risk_score BETWEEN 0 AND 100",
                           name="ck_verdict_score_range"),
        sa.CheckConstraint("severity_band IN ('low','medium','high','critical')",
                           name="ck_verdict_band"),
    )

    # ── audit_logs ──────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("target_type", sa.String(40), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("risk_verdicts")
    op.drop_table("static_findings")
    op.drop_index("ix_submissions_uploaded_by", table_name="apk_submissions")
    op.drop_index("ix_submissions_status", table_name="apk_submissions")
    op.drop_index("ix_submissions_sha256", table_name="apk_submissions")
    op.drop_table("apk_submissions")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
