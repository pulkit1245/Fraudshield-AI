"""Request and response schemas for the protected threat-intelligence API."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TTPUpsert(BaseModel):
    id: str = Field(pattern=r"^TTP-[A-Z0-9-]+$", max_length=80)
    name: str = Field(min_length=3, max_length=255)
    category: str = Field(min_length=2, max_length=80)
    description: str = Field(min_length=10)
    indicators: list[str] = Field(default_factory=list)
    source: str = Field(default="internal", max_length=120)
    source_reference: str | None = Field(default=None, max_length=255)
    active: bool = True


class TTPResponse(TTPUpsert):
    model_config = ConfigDict(from_attributes=True)
    version: int
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class MarkerCreate(BaseModel):
    ttp_id: str = Field(pattern=r"^TTP-[A-Z0-9-]+$", max_length=80)
    signal_type: Literal["api_signature", "permission", "manifest_component", "certificate"]
    match_value: str = Field(min_length=3, max_length=500)
    match_mode: Literal["exact", "substring", "regex"] = "substring"
    bucket: str = Field(min_length=2, max_length=80)
    severity: float = Field(default=0.25, ge=0.0, le=1.0)
    requires_context: bool = False
    source: str = Field(default="internal", max_length=120)
    source_reference: str | None = Field(default=None, max_length=255)


class MarkerResponse(MarkerCreate):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    active: bool
    version: int
    created_at: datetime
    updated_at: datetime


class ActiveUpdate(BaseModel):
    active: bool
