"""`risk_verdicts` ORM model — final calibrated risk decision per submission.

Maps to the §4 Database Design `risk_verdicts` table.
Owner: Member A.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, SmallInteger, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import UUID

SEVERITY_BANDS = ("low", "medium", "high", "critical")
RECOMMENDED_ACTIONS = (
    "monitor",
    "block_hash",
    "alert_customers",
    "escalate_cert_in",
)


class RiskVerdict(Base):
    __tablename__ = "risk_verdicts"
    __table_args__ = (
        CheckConstraint(
            "final_risk_score BETWEEN 0 AND 100", name="ck_verdict_score_range"
        ),
        CheckConstraint(
            "severity_band IN ('low','medium','high','critical')",
            name="ck_verdict_band",
        ),
    )

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
    final_risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    severity_band: Mapped[str] = mapped_column(String(10), nullable=False)
    recommended_action: Mapped[str] = mapped_column(String(30), nullable=False)
    analyst_override_score: Mapped[Optional[int]] = mapped_column(
        SmallInteger, nullable=True
    )
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    submission: Mapped["Submission"] = relationship(  # noqa: F821
        "Submission", back_populates="verdict", lazy="joined"
    )
    reviewer: Mapped[Optional["User"]] = relationship(  # noqa: F821
        "User", lazy="joined", foreign_keys=[reviewed_by]
    )

    @property
    def effective_score(self) -> int:
        """Analyst override wins over the model score when present."""
        return (
            self.analyst_override_score
            if self.analyst_override_score is not None
            else self.final_risk_score
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RiskVerdict sub={self.submission_id} score={self.effective_score} band={self.severity_band}>"
