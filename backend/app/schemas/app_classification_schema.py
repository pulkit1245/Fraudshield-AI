"""Pydantic models for the App Classification and Permission Policy modules.

Defines:
  - AppClassificationResult: full LLM output + derived fields stored in DB
  - PermissionPolicyResult: output of the context-aware policy engine
  - AppClassificationOut: API-facing response model

Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── Category enum (open list — new strings are allowed) ─────────────────────
class AppCategory:
    """String constants for known application categories."""
    COMMUNICATION    = "Communication"
    FINANCE          = "Finance"
    BANKING          = "Banking"
    SHOPPING         = "Shopping"
    GAME             = "Game"
    EDUCATION        = "Education"
    HEALTH           = "Health"
    TRAVEL           = "Travel"
    MAPS             = "Maps"
    SOCIAL_MEDIA     = "Social Media"
    MEDIA            = "Media"
    VIDEO_STREAMING  = "Video Streaming"
    UTILITY          = "Utility"
    SYSTEM_TOOL      = "System Tool"
    PRODUCTIVITY     = "Productivity"
    PHOTO_EDITING    = "Photo Editing"
    MUSIC            = "Music"
    FILE_MANAGER     = "File Manager"
    VPN              = "VPN"
    BROWSER          = "Browser"
    LAUNCHER         = "Launcher"
    KEYBOARD         = "Keyboard"
    NEWS             = "News"
    FOOD_DELIVERY    = "Food Delivery"
    RIDE_SHARING     = "Ride Sharing"
    ECOMMERCE        = "E-commerce"
    CRYPTO           = "Crypto"
    GOVERNMENT       = "Government"
    OTHER            = "Other"


# ── Raw LLM classification output schema ─────────────────────────────────────
class LLMClassificationPayload(BaseModel):
    """Validated schema for the JSON returned by the classification LLM call."""

    primary_category: str = Field(..., min_length=2, max_length=80,
                                  description="Primary application category")
    secondary_categories: List[str] = Field(default_factory=list,
                                            description="Additional applicable categories")
    confidence: float = Field(..., ge=0.0, le=1.0,
                              description="Model confidence 0–1")
    reasoning: str = Field(..., min_length=5,
                           description="One-paragraph human reasoning")
    expected_permissions: List[str] = Field(default_factory=list,
                                            description="Permissions normal for this category")
    expected_behaviors: List[str] = Field(default_factory=list,
                                          description="Runtime behaviors expected for this category")
    unexpected_permission_examples: List[str] = Field(
        default_factory=list,
        description="Examples of permissions that would be suspicious for this category",
    )
    unexpected_behavior_examples: List[str] = Field(
        default_factory=list,
        description="Examples of runtime behaviors suspicious for this category",
    )

    @field_validator("primary_category", mode="before")
    @classmethod
    def normalise_category(cls, v: Any) -> str:
        return str(v).strip().title() if v else "Other"


# ── Full classification result (service return type) ─────────────────────────
class AppClassificationResult(BaseModel):
    """Complete classification result returned by AppClassificationService."""

    submission_id: uuid.UUID
    sha256_hash: str
    primary_category: str
    secondary_categories: List[str] = Field(default_factory=list)
    confidence: float
    reasoning: str
    expected_permissions: List[str] = Field(default_factory=list)
    expected_behaviors: List[str] = Field(default_factory=list)
    unexpected_permission_examples: List[str] = Field(default_factory=list)
    unexpected_behavior_examples: List[str] = Field(default_factory=list)
    classified_by: str = Field(default="llm",
                               description="'llm', 'heuristic', or 'cached'")
    raw_llm_json: Optional[dict[str, Any]] = None
    classified_at: Optional[datetime] = None


# ── Permission policy result ──────────────────────────────────────────────────
class PermissionPolicyResult(BaseModel):
    """Output of PermissionPolicyService.evaluate()."""

    category: str
    confidence: float

    # Coverage metrics (0–1)
    permission_coverage: float = Field(
        ..., description="Fraction of expected permissions present (0=none, 1=all)"
    )
    behavior_coverage: float = Field(
        ..., description="Fraction of expected behaviours covered by API/dynamic signals"
    )
    context_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Composite context-adjusted suspicion score (0=clean, 1=very suspicious)",
    )

    # Anomaly details
    unexpected_permissions: List[str] = Field(
        default_factory=list,
        description="Declared permissions not expected for this category",
    )
    missing_expected_permissions: List[str] = Field(
        default_factory=list,
        description="Expected permissions absent from the declaration",
    )
    unexpected_behaviors: List[str] = Field(
        default_factory=list,
        description="Observed behaviors not expected for this category",
    )

    # Evidence weight for the scoring ensemble
    anomaly_weight: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Normalised anomaly weight injected into the ML scoring ensemble",
    )


# ── API response ─────────────────────────────────────────────────────────────
class AppClassificationOut(BaseModel):
    """API response for GET /submissions/{id}/classification."""
    model_config = ConfigDict(from_attributes=True)

    submission_id: uuid.UUID
    primary_category: str
    secondary_categories: List[str]
    confidence: float
    reasoning: str
    classified_by: str
    classified_at: Optional[datetime] = None
    expected_permissions: List[str]
    expected_behaviors: List[str]
    # Policy engine results are included when present
    permission_policy: Optional[dict[str, Any]] = None
