"""Pydantic request/response models for the auth endpoints.

The JSON shapes here are mirrored verbatim in `shared/schemas/auth.json`, which
is the cross-team source of truth (Member D's frontend codes against it).

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ── Requests ────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128,
                          description="Minimum 8 characters.")
    org_name: str = Field(min_length=1, max_length=255,
                          description="Bank / NBFC name.")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


# ── Responses ───────────────────────────────────────────────────────────
class RegisterResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: EmailStr
    role: str


class TokenPairResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access-token lifetime in seconds.")


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: EmailStr
    role: str
    org_name: str
    created_at: datetime
