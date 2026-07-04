"""Auth endpoints: register, login, refresh, me.

    POST /api/v1/auth/register   → create analyst account
    POST /api/v1/auth/login      → access + refresh token pair
    POST /api/v1/auth/refresh    → rotate refresh → new access token
    GET  /api/v1/auth/me         → current analyst profile

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.auth_schema import (
    AccessTokenResponse,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenPairResponse,
    UserProfile,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_ACCESS_TTL_SECONDS = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


@router.post("/register", response_model=RegisterResponse,
             status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    repo = UserRepository(db)
    if repo.get_by_email(payload.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email already registered")
    user = repo.create(
        email=payload.email,
        password_hash=hash_password(payload.password),
        org_name=payload.org_name,
    )
    return RegisterResponse.model_validate(user)


@router.post("/login", response_model=TokenPairResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    repo = UserRepository(db)
    user = repo.get_by_email(payload.email)
    # Constant-ish response: same error whether email or password is wrong.
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials")
    return TokenPairResponse(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
        expires_in=_ACCESS_TTL_SECONDS,
    )


@router.post("/refresh", response_model=AccessTokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    try:
        user_id = uuid.UUID(str(claims.get("sub")))
    except (ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid token subject")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User no longer exists")
    return AccessTokenResponse(
        access_token=create_access_token(user),
        expires_in=_ACCESS_TTL_SECONDS,
    )


@router.get("/me", response_model=UserProfile)
def me(current_user: User = Depends(get_current_user)):
    return UserProfile.model_validate(current_user)
