"""Pydantic request/response models for the submissions endpoints.

Mirrored in `shared/schemas/submission.json` (cross-team contract).
Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Responses ───────────────────────────────────────────────────────────
class SubmissionCreateResponse(BaseModel):
    id: uuid.UUID
    status: str = "queued"
    sha256_hash: str


class StageDetail(BaseModel):
    current_step: str
    step_description: str


class SubmissionStatusResponse(BaseModel):
    id: uuid.UUID
    status: str
    progress_pct: int
    stage_detail: Optional[StageDetail] = None
    analysis_stages: Optional[List[dict]] = None


class SubmissionSummary(BaseModel):
    """Row shape for the paginated queue table."""
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    original_filename: str
    sha256_hash: str
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    # Denormalized verdict fields (present once scoring completes).
    severity_band: Optional[str] = None
    final_risk_score: Optional[int] = None


class PaginatedSubmissions(BaseModel):
    items: List[SubmissionSummary]
    total: int
    page: int
    page_size: int


class StaticFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    package_name: Optional[str] = None
    permissions: dict[str, Any] = Field(default_factory=dict)
    certificate_info: Optional[dict[str, Any]] = None
    api_call_graph: Optional[dict[str, Any]] = None
    obfuscation_score: Optional[float] = None


class VerdictOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    final_risk_score: int
    severity_band: str
    recommended_action: str
    analyst_override_score: Optional[int] = None


class DynamicFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    sms_access: bool
    accessibility_abuse: bool
    overlay_detected: bool
    network_calls: list[Any]
    sandbox_log_path: Optional[str] = None
    run_at: datetime


class ClusterSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    cluster_name: str
    # member_count is not directly on the CampaignCluster model, we can't trivially map it via from_attributes 
    # unless we expose it as a property. Wait, CampaignCluster has `members: list[ClusterMember]`.
    # Let's just expose `id` and `cluster_name` to avoid complex properties if it's expensive.


class SubmissionDetail(BaseModel):
    """Full submission view (§5 GET /submissions/{id})."""
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    uploaded_by: uuid.UUID
    original_filename: str
    sha256_hash: str
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    static_finding: Optional[StaticFindingOut] = None
    verdict: Optional[VerdictOut] = None
    dynamic_finding: Optional[DynamicFindingOut] = None
    cluster: Optional[ClusterSummary] = None


# ── Query params ────────────────────────────────────────────────────────
class SubmissionFilter(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
