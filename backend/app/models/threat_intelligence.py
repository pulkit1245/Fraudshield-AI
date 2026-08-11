"""Versioned threat intelligence used by static analysis and RAG.

Extended by migration 0005 with ATT&CK attribution, confidence scoring,
external deduplication keys, and a quarantine model for rejected feed records.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class TTP(Base):
    __tablename__ = "ttps"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    indicators: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # source: controlled vocabulary — "manual" | "mitre_attack" | "misp" | "malwarebazaar"
    # (was "internal" before migration 0005 normalised it to "manual")
    source: Mapped[str] = mapped_column(String(120), nullable=False, default="manual")
    source_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # ── added by migration 0005 ──────────────────────────────────────────
    # ATT&CK attribution (nullable — hand-authored TTPs may not have these)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    # Quality signal: 1.0=analyst-reviewed, 0.85=mitre_attack, 0.5=misp, 0.4=malwarebazaar
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.85)
    # Stable dedup key from the source feed (STIX ID, MISP UUID, etc.).
    # Partial unique index enforced in DB (WHERE external_id IS NOT NULL).
    external_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    markers: Mapped[list["DetectionMarker"]] = relationship(
        "DetectionMarker", back_populates="ttp", cascade="all, delete-orphan", lazy="selectin"
    )


class DetectionMarker(Base):
    __tablename__ = "detection_markers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ttp_id: Mapped[str] = mapped_column(ForeignKey("ttps.id", ondelete="CASCADE"), nullable=False, index=True)
    signal_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    match_value: Mapped[str] = mapped_column(String(500), nullable=False)
    match_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="substring")
    bucket: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    severity: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    requires_context: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source: Mapped[str] = mapped_column(String(120), nullable=False, default="manual")
    source_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # ── added by migration 0005 ──────────────────────────────────────────
    # Analyst feedback: updated when a verdict is reviewed; used for calibration.
    false_positive_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Stable dedup key from source feed (partial unique index in DB).
    external_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    ttp: Mapped[TTP] = relationship("TTP", back_populates="markers")


class TIQuarantine(Base):
    """Records rejected by the TI ingestion validator.

    Stored so analysts can identify systematic gaps in source feeds without
    silently dropping data.  No FK to ttps — quarantined records by definition
    have no TTP row yet.
    """

    __tablename__ = "ti_ingestion_quarantine"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    failure_rule: Mapped[str] = mapped_column(String(10), nullable=False)   # "V1".."V11"
    failure_msg: Mapped[str] = mapped_column(Text, nullable=False)
    ingestion_source: Mapped[Optional[str]] = mapped_column(String(60), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
