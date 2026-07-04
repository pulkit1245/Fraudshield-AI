"""`llm_reports` ORM model — the Claude-generated report per submission.

Maps to the §4 Database Design `llm_reports` table. `sanitization_flags` records
any prompt-injection attempts caught by the sanitization layer (the "AI Evasion
Defense" differentiator).

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class LLMReport(Base):
    __tablename__ = "llm_reports"

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
    # Plain-English behaviour summary an L1 analyst can act on.
    summary_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Mapped banking-fraud TTP taxonomy entries.
    ttp_mapping: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Logged prompt-injection attempts, if any.
    sanitization_flags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    model_used: Mapped[str] = mapped_column(String(60), nullable=False)
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    submission: Mapped["Submission"] = relationship(  # noqa: F821
        "Submission", lazy="joined", backref="llm_report"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<LLMReport sub={self.submission_id} model={self.model_used}>"
