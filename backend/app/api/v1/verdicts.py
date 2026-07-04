"""Verdict & escalation endpoints.

    GET   /api/v1/submissions/{id}/verdict           → calibrated risk verdict
    PATCH /api/v1/submissions/{id}/verdict/override   → lead/admin override (audited)
    POST  /api/v1/submissions/{id}/verdict/escalate   → CERT-In/NPCI IOC record

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.core.security import get_current_user, require_role
from app.models.user import User
from app.repositories.submission_repository import SubmissionRepository
from app.repositories.verdict_repository import VerdictRepository
from app.schemas.verdict_schema import (
    EscalateRequest,
    EscalateResponse,
    VerdictOverrideRequest,
    VerdictResponse,
)

router = APIRouter(prefix="/submissions", tags=["verdicts"])
log = get_logger(__name__)


def _to_response(verdict) -> VerdictResponse:
    return VerdictResponse(
        submission_id=verdict.submission_id,
        final_risk_score=verdict.final_risk_score,
        severity_band=verdict.severity_band,
        recommended_action=verdict.recommended_action,
        analyst_override_score=verdict.analyst_override_score,
        effective_score=verdict.effective_score,
        reviewed_by=verdict.reviewed_by,
        reviewed_at=verdict.reviewed_at,
    )


@router.get("/{submission_id}/verdict", response_model=VerdictResponse)
def get_verdict(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verdict = VerdictRepository(db).get_by_submission(submission_id)
    if verdict is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Verdict not available yet")
    return _to_response(verdict)


@router.patch("/{submission_id}/verdict/override", response_model=VerdictResponse)
def override_verdict(
    submission_id: uuid.UUID,
    payload: VerdictOverrideRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("lead", "admin")),
):
    verdict = VerdictRepository(db).apply_override(
        submission_id,
        override_score=payload.override_score,
        reviewer_id=current_user.id,
        reason=payload.reason,
    )
    if verdict is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Verdict not available yet")
    log.info("verdict.override", submission_id=str(submission_id),
             by=str(current_user.id), score=payload.override_score)
    return _to_response(verdict)


@router.post("/{submission_id}/verdict/escalate", response_model=EscalateResponse)
def escalate_verdict(
    submission_id: uuid.UUID,
    payload: EscalateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("lead", "admin")),
):
    sub_repo = SubmissionRepository(db)
    verdict_repo = VerdictRepository(db)

    submission = sub_repo.get(submission_id)
    if submission is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Submission not found")
    verdict = verdict_repo.get_by_submission(submission_id)
    if verdict is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Verdict not available yet")

    static = submission.static_finding
    ioc_record = {
        "sha256": submission.sha256_hash,
        "package_name": static.package_name if static else None,
        "severity_band": verdict.severity_band,
        "risk_score": verdict.effective_score,
        "recommended_action": verdict.recommended_action,
        "destination": payload.destination,
        "note": payload.note,
        "reported_by": str(current_user.id),
        "reported_at": datetime.now(timezone.utc).isoformat(),
    }

    verdict_repo.write_audit(
        user_id=current_user.id,
        action="verdict_escalate",
        target_type="submission",
        target_id=submission_id,
        detail={"destination": payload.destination, "note": payload.note},
    )
    log.info("verdict.escalate", submission_id=str(submission_id),
             destination=payload.destination, by=str(current_user.id))
    return EscalateResponse(
        submission_id=submission_id, escalated=True, ioc_record=ioc_record
    )
