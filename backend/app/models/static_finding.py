"""`static_findings` ORM model — output of the static-analysis stage.

Maps to the §4 Database Design `static_findings` table.
Owner: Member A.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class StaticFinding(Base):
    __tablename__ = "static_findings"

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
    package_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # declared + used permissions
    permissions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # signer, validity, self-signed flag
    certificate_info: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    # sensitive API-call summary from Androguard
    api_call_graph: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    # 0–1 heuristic from Apktool/JADX diffs
    obfuscation_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    submission: Mapped["Submission"] = relationship(  # noqa: F821
        "Submission", back_populates="static_finding", lazy="joined"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<StaticFinding sub={self.submission_id} pkg={self.package_name}>"
