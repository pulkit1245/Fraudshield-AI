"""Classification endpoints.

    GET  /api/v1/submissions/{id}/classification  → app category + policy context
    POST /api/v1/submissions/{id}/classification  → trigger re-classification

Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.core.security import get_current_user
from app.models.app_classification import AppClassification
from app.models.static_finding import StaticFinding
from app.models.submission import Submission
from app.models.user import User
from app.schemas.app_classification_schema import AppClassificationOut, PermissionPolicyResult
from app.services.permission_policy_service import PermissionPolicyService

router = APIRouter(prefix="/submissions", tags=["classification"])
log = get_logger(__name__)


@router.get(
    "/{submission_id}/classification",
    response_model=AppClassificationOut,
    summary="Get app classification and permission policy for a submission",
)
def get_classification(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AppClassificationOut:
    """Return the app category classification and context-aware permission policy.

    If the classification has not been run yet, returns 404 with a clear message.
    """
    # Verify submission exists and belongs to accessible scope.
    sub = db.get(Submission, submission_id)
    if sub is None or sub.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found"
        )

    cls_row = db.execute(
        select(AppClassification).where(
            AppClassification.submission_id == submission_id
        )
    ).scalar_one_or_none()

    if cls_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Classification not available yet. "
                "The pipeline may still be processing this submission."
            ),
        )

    # Build the policy context if static_findings are available.
    policy_context: PermissionPolicyResult | None = None
    static = db.execute(
        select(StaticFinding).where(StaticFinding.submission_id == submission_id)
    ).scalar_one_or_none()

    if static is not None:
        declared_perms = (static.permissions or {}).get("declared") or []
        try:
            policy_context = PermissionPolicyService().evaluate(
                category=cls_row.primary_category,
                confidence=cls_row.confidence,
                declared_permissions=declared_perms,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "classification.policy_eval_failed",
                submission_id=str(submission_id),
                error=str(exc),
            )

    return AppClassificationOut(
        submission_id=cls_row.submission_id,
        primary_category=cls_row.primary_category,
        secondary_categories=list(cls_row.secondary_categories or []),
        confidence=cls_row.confidence,
        reasoning=cls_row.reasoning or "",
        classified_by=cls_row.classified_by,
        classified_at=cls_row.classified_at,
        expected_permissions=list(cls_row.expected_permissions or []),
        expected_behaviors=list(cls_row.expected_behaviors or []),
        permission_policy=policy_context.model_dump() if policy_context else None,
    )


@router.post(
    "/{submission_id}/classification",
    response_model=AppClassificationOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger (re-)classification of an APK",
)
def trigger_classification(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AppClassificationOut:
    """Enqueue a (re-)classification task for a submission.

    Returns 202 Accepted and the current classification if available,
    or a stub response if not yet classified.
    """
    sub = db.get(Submission, submission_id)
    if sub is None or sub.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found"
        )

    # Enqueue the task (best-effort).
    try:
        from app.workers.tasks.classification_task import run_app_classification
        run_app_classification.delay(str(submission_id))
        log.info("classification.triggered", submission_id=str(submission_id),
                 by=str(current_user.id))
    except Exception as exc:  # noqa: BLE001
        log.warning("classification.enqueue_failed", submission_id=str(submission_id),
                    error=str(exc))

    # Return current classification if available.
    cls_row = db.execute(
        select(AppClassification).where(
            AppClassification.submission_id == submission_id
        )
    ).scalar_one_or_none()

    if cls_row:
        return AppClassificationOut(
            submission_id=cls_row.submission_id,
            primary_category=cls_row.primary_category,
            secondary_categories=list(cls_row.secondary_categories or []),
            confidence=cls_row.confidence,
            reasoning=cls_row.reasoning or "",
            classified_by=cls_row.classified_by,
            classified_at=cls_row.classified_at,
            expected_permissions=list(cls_row.expected_permissions or []),
            expected_behaviors=list(cls_row.expected_behaviors or []),
        )

    # Not classified yet — return stub.
    return AppClassificationOut(
        submission_id=submission_id,
        primary_category="pending",
        secondary_categories=[],
        confidence=0.0,
        reasoning="Classification task has been enqueued.",
        classified_by="pending",
        classified_at=None,
        expected_permissions=[],
        expected_behaviors=[],
    )
