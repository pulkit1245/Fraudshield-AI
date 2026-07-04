"""`ml_scores` ORM model — classifier + novelty + SHAP output per submission.

Maps to the §4 Database Design `ml_scores` table. Shares Member A's declarative
Base and portable column types.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid

from sqlalchemy import Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class MLScore(Base):
    __tablename__ = "ml_scores"

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
    # XGBoost / RandomForest probability in [0, 1].
    classifier_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Autoencoder reconstruction error, normalized to [0, 1].
    novelty_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Top-N SHAP feature contributions, shaped for the frontend heatmap.
    shap_values: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    model_version: Mapped[str] = mapped_column(String(40), nullable=False)

    submission: Mapped["Submission"] = relationship(  # noqa: F821
        "Submission", lazy="joined", backref="ml_score"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MLScore sub={self.submission_id} clf={self.classifier_score:.2f} nov={self.novelty_score:.2f}>"
