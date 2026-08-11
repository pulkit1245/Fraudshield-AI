"""`dynamic_findings` ORM model — output of the sandbox stage.

Maps to the §4 Database Design `dynamic_findings` table. Shares Member A's
declarative Base and portable column types.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class DynamicFinding(Base):
    __tablename__ = "dynamic_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("apk_submissions.id"),
        unique=True,
        nullable=False,
        index=True,
    )
    sms_access: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    accessibility_abuse: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    overlay_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Outbound connection attempts captured against the fake-DNS sink.
    network_calls: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Object-storage key for the full Frida log.
    sandbox_log_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    submission: Mapped["Submission"] = relationship(  # noqa: F821
        "Submission", lazy="joined", back_populates="dynamic_finding"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (f"<DynamicFinding sub={self.submission_id} sms={self.sms_access} "
                f"acc={self.accessibility_abuse} overlay={self.overlay_detected}>")
