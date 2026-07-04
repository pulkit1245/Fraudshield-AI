"""`virustotal_lookups` ORM model — cached VirusTotal hash-check responses.

Maps to the §4 Database Design `virustotal_lookups` table.
Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class VirustotalLookup(Base):
    __tablename__ = "virustotal_lookups"

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
    vt_response: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    submission: Mapped["Submission"] = relationship(  # noqa: F821
        "Submission", lazy="joined", backref="virustotal_lookup"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<VirustotalLookup sub={self.submission_id}>"
