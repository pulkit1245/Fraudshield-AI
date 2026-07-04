"""Data-access layer for `users`.

Keeps SQLAlchemy queries out of the route handlers so auth logic stays testable.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        return self.db.get(User, user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email.lower())
        return self.db.execute(stmt).scalar_one_or_none()

    def create(self, *, email: str, password_hash: str, org_name: str,
               role: str = "analyst") -> User:
        user = User(
            email=email.lower(),
            password_hash=password_hash,
            org_name=org_name,
            role=role,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user
