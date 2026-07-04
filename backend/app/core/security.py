"""Security primitives: password hashing, JWT issue/verify, auth dependencies.

- bcrypt password hashing (passlib)
- HS256 JWTs: 15-minute access token + 7-day rotating refresh token
- `get_current_user` FastAPI dependency (validates JWT, loads the user)
- `require_role(...)` dependency factory for RBAC on protected routes

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User

# bcrypt with a sane default cost factor.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

# We validate the bearer token ourselves; auto_error=True → 403 on missing header.
bearer_scheme = HTTPBearer(auto_error=True)

ACCESS = "access"
REFRESH = "refresh"


# ── Password hashing ────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT ─────────────────────────────────────────────────────────────────
def _create_token(subject: str, token_type: str, expires_delta: timedelta,
                  extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_access_token(user: User) -> str:
    return _create_token(
        subject=str(user.id),
        token_type=ACCESS,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra={"role": user.role, "email": user.email},
    )


def create_refresh_token(user: User) -> str:
    return _create_token(
        subject=str(user.id),
        token_type=REFRESH,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_token(token: str, expected_type: str | None = None) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    if expected_type and payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Expected {expected_type} token",
        )
    return payload


# ── FastAPI dependencies ────────────────────────────────────────────────
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate the bearer access token and return the live User row."""
    payload = decode_token(credentials.credentials, expected_type=ACCESS)
    user_id = payload.get("sub")
    try:
        user_uuid = uuid.UUID(str(user_id))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed subject"
        )
    user = db.get(User, user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    return user


def require_role(*allowed_roles: str):
    """Dependency factory enforcing that the caller has one of `allowed_roles`.

    Usage:  Depends(require_role("lead", "admin"))
    """
    allowed: Iterable[str] = allowed_roles

    def _checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role in {tuple(allowed)}",
            )
        return current_user

    return _checker
