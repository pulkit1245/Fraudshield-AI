"""`campaign_clusters` + `cluster_members` ORM models.

Maps to the §4 Database Design. `family_signature` is a 768-dim centroid embedding
stored in pgvector on Postgres. `Vector768` is a portable column type: it resolves
to pgvector's `vector(768)` on Postgres and to JSON everywhere else, so the
clustering test suite runs on SQLite with no pgvector/Postgres dependency.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, TypeDecorator

from app.core.database import Base
from app.core.types import UUID

EMBED_DIM = 768


class Vector768(TypeDecorator):
    """pgvector `vector(768)` on Postgres, JSON list elsewhere (tests/dev)."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            try:
                from pgvector.sqlalchemy import Vector

                return dialect.type_descriptor(Vector(EMBED_DIM))
            except Exception:  # noqa: BLE001 - pgvector missing → fall back to JSON
                pass
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return list(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return list(value)


class CampaignCluster(Base):
    __tablename__ = "campaign_clusters"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cluster_name: Mapped[str] = mapped_column(String(120), nullable=False)
    family_signature: Mapped[list] = mapped_column(Vector768, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    members: Mapped[list["ClusterMember"]] = relationship(
        "ClusterMember", back_populates="cluster",
        cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CampaignCluster {self.cluster_name} id={self.id}>"


class ClusterMember(Base):
    __tablename__ = "cluster_members"

    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaign_clusters.id", ondelete="CASCADE"),
        primary_key=True,
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("apk_submissions.id"),
        primary_key=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    cluster: Mapped["CampaignCluster"] = relationship(
        "CampaignCluster", back_populates="members"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ClusterMember cluster={self.cluster_id} sub={self.submission_id}>"
