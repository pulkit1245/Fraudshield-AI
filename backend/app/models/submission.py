"""`apk_submissions` ORM model — one uploaded APK and its pipeline status.

Maps to the §4 Database Design `apk_submissions` table.
Owner: Member A.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import CHAR, CheckConstraint, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import UUID

# Pipeline stages — the status column moves strictly forward through these.
SUBMISSION_STATUSES = (
    "queued",
    "static_running",
    "dynamic_running",
    "scoring",
    "completed",
    "failed",
)


class Submission(Base):
    __tablename__ = "apk_submissions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','static_running','dynamic_running',"
            "'scoring','completed','failed')",
            name="ck_submissions_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False, index=True)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued", index=True
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Soft-delete marker (DELETE endpoint sets this; retention job purges bytes).
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── relationships ───────────────────────────────────────────────────
    uploader: Mapped["User"] = relationship(  # noqa: F821
        "User", back_populates="submissions", lazy="joined"
    )
    static_finding: Mapped[Optional["StaticFinding"]] = relationship(  # noqa: F821
        "StaticFinding", back_populates="submission", uselist=False, lazy="selectin"
    )
    verdict: Mapped[Optional["RiskVerdict"]] = relationship(  # noqa: F821
        "RiskVerdict", back_populates="submission", uselist=False, lazy="selectin"
    )

    @property
    def progress_pct(self) -> int:
        """Rough progress percentage used by the lightweight /status endpoint."""
        order = {
            "queued": 5,
            "static_running": 30,
            "dynamic_running": 55,
            "scoring": 80,
            "completed": 100,
            "failed": 100,
        }
        return order.get(self.status, 0)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Submission {self.id} status={self.status}>"
