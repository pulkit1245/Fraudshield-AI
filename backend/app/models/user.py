"""`users` ORM model — analyst / lead / admin accounts.

Maps to the §4 Database Design `users` table.
Owner: Member A.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import UUID

VALID_ROLES = ("analyst", "lead", "admin")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('analyst','lead','admin')", name="ck_users_role"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="analyst")
    org_name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # ── relationships ───────────────────────────────────────────────────
    submissions: Mapped[list["Submission"]] = relationship(  # noqa: F821
        "Submission", back_populates="uploader", lazy="selectin"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(  # noqa: F821
        "AuditLog", back_populates="user", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email} role={self.role}>"
