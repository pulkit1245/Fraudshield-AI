"""Pydantic request/response models for the verdict & escalation endpoints.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class VerdictResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    submission_id: uuid.UUID
    final_risk_score: int = Field(ge=0, le=100)
    severity_band: str
    recommended_action: str
    analyst_override_score: Optional[int] = Field(default=None, ge=0, le=100)
    effective_score: int = Field(ge=0, le=100)
    reviewed_by: Optional[uuid.UUID] = None
    reviewed_at: Optional[datetime] = None


class VerdictOverrideRequest(BaseModel):
    override_score: int = Field(ge=0, le=100,
                                description="Human-judged 0–100 risk score.")
    reason: str = Field(min_length=3, max_length=1000)


class EscalateResponse(BaseModel):
    submission_id: uuid.UUID
    escalated: bool
    ioc_record: dict


class EscalateRequest(BaseModel):
    destination: str = Field(default="cert_in",
                             description="Escalation target, e.g. cert_in | npci.")
    note: Optional[str] = Field(default=None, max_length=1000)
