"""Analysis endpoints: LLM reports and ML scores.

    GET /api/v1/submissions/{id}/report    → the LLM-generated TTP report
    GET /api/v1/submissions/{id}/ml-score  → the ML scoring data (SHAP, etc)

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.core.security import get_current_user
from app.models.llm_report import LLMReport
from app.models.ml_score import MLScore
from app.models.user import User

router = APIRouter(prefix="/submissions", tags=["analysis"])
log = get_logger(__name__)


@router.get("/{submission_id}/report")
def get_report(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    report = db.execute(
        select(LLMReport).where(LLMReport.submission_id == submission_id)
    ).scalar_one_or_none()

    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Report not available yet")

    return {
        "summary_text": report.summary_text,
        "ttp_mapping": report.ttp_mapping,
        "sanitization_flags": report.sanitization_flags,
        "model_used": report.model_used,
    }


@router.get("/{submission_id}/ml-score")
def get_ml_score(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    score = db.execute(
        select(MLScore).where(MLScore.submission_id == submission_id)
    ).scalar_one_or_none()

    if score is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="ML Score not available yet")

    return {
        "classifier_score": score.classifier_score,
        "novelty_score": score.novelty_score,
        "shap_values": score.shap_values,
        "model_version": score.model_version,
    }
