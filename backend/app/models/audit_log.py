"""`audit_logs` ORM model — immutable trail of sensitive actions.

Written on verdict override / escalate (Member A) and on sanitization flags
(Member B). Maps to the §4 Database Design `audit_logs` table.
Owner: Member A.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(60), nullable=False)  # e.g. 'verdict_override'
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)  # e.g. 'submission'
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    detail: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # reason, before/after
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped[Optional["User"]] = relationship(  # noqa: F821
        "User", back_populates="audit_logs", lazy="joined"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} target={self.target_type}:{self.target_id}>"
