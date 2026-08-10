"""Request and response schemas for the protected threat-intelligence API."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class TTPUpsert(BaseModel):
    """Used by the admin UI to create or update hand-authored TTPs.

    The `^TTP-[A-Z0-9-]+$` pattern constraint is intentional: manual TTPs
    follow the internal naming convention.  Automatically ingested TTPs
    (MITRE ATT&CK etc.) are written directly by the ingestion pipeline and
    do NOT go through this schema.
    """

    id: str = Field(pattern=r"^TTP-[A-Z0-9-]+$", max_length=80)
    name: str = Field(min_length=3, max_length=255)
    category: str = Field(min_length=2, max_length=80)
    description: str = Field(min_length=10)
    indicators: list[str] = Field(default_factory=list)
    # source vocabulary: "manual" | "mitre_attack" | "misp" | "malwarebazaar"
    source: str = Field(default="manual", max_length=120)
    source_reference: str | None = Field(default=None, max_length=255)
    active: bool = True


class TTPResponse(TTPUpsert):
    """Read model — includes all DB-generated and ingestion-enriched fields."""

    model_config = ConfigDict(from_attributes=True)

    version: int
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    # Added by migration 0005 — may be None for hand-authored entries.
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    confidence_score: float = 0.85
    external_id: Optional[str] = None


class TTPApprovalRequest(BaseModel):
    """Payload for PATCH /ttps/{ttp_id}/active.

    Deliberately minimal: the endpoint follows the same pattern as the
    existing PATCH /markers/{marker_id}/active which uses ActiveUpdate.
    This schema adds an optional analyst note for the audit log.
    """

    active: bool
    analyst_note: str | None = Field(default=None, max_length=500)


class MarkerCreate(BaseModel):
    ttp_id: str = Field(pattern=r"^TTP-[A-Z0-9-]+$", max_length=80)
    signal_type: Literal["api_signature", "permission", "manifest_component", "certificate"]
    match_value: str = Field(min_length=3, max_length=500)
    match_mode: Literal["exact", "substring", "regex"] = "substring"
    bucket: str = Field(min_length=2, max_length=80)
    severity: float = Field(default=0.25, ge=0.0, le=1.0)
    requires_context: bool = False
    source: str = Field(default="manual", max_length=120)
    source_reference: str | None = Field(default=None, max_length=255)


class MarkerResponse(MarkerCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    active: bool
    version: int
    created_at: datetime
    updated_at: datetime

    # Added by migration 0005
    false_positive_rate: float = 0.0
    external_id: Optional[str] = None


class ActiveUpdate(BaseModel):
    active: bool

