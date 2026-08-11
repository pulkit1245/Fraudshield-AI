"""`app_classifications` ORM model — stores per-APK classification results.

One row per unique APK (keyed on sha256_hash) so repeated submissions of the
same file reuse the cached classification without hitting the LLM again.

Maps to the `app_classifications` table added in migration 0005.
Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import CHAR, DateTime, Float, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class AppClassification(Base):
    __tablename__ = "app_classifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Keyed on sha256 so the same APK never classifies twice.
    sha256_hash: Mapped[str] = mapped_column(
        CHAR(64), nullable=False, unique=True, index=True
    )
    # The submission that first triggered this classification.
    submission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    # Classification output
    primary_category: Mapped[str] = mapped_column(
        String(80), nullable=False, index=True
    )
    secondary_categories: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Policy baseline persisted for the report / downstream consumption
    expected_permissions: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    expected_behaviors: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    unexpected_permission_examples: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    unexpected_behavior_examples: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )

    # How was the classification produced?
    # "llm" | "heuristic" | "cached"
    classified_by: Mapped[str] = mapped_column(
        String(20), nullable=False, default="llm"
    )

    # Raw response for audit / replay
    raw_llm_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Timestamps
    classified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AppClassification sha256={self.sha256_hash[:12]}… "
            f"category={self.primary_category} confidence={self.confidence:.2f}>"
        )
