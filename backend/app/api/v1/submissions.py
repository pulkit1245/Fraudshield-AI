"""Submission intake & queue endpoints.

    POST   /api/v1/submissions            → upload APK, hash, store, enqueue jobs
    GET    /api/v1/submissions            → paginated / filterable queue
    GET    /api/v1/submissions/{id}       → full detail
    GET    /api/v1/submissions/{id}/status→ lightweight polling
    DELETE /api/v1/submissions/{id}       → soft-delete (lead/admin)

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.core.security import get_current_user, require_role
from app.models.user import User
from app.repositories.submission_repository import SubmissionRepository
from app.schemas.submission_schema import (
    PaginatedSubmissions,
    SubmissionCreateResponse,
    SubmissionDetail,
    SubmissionStatusResponse,
    SubmissionSummary,
)
from app.utils.file_storage import storage
from app.utils.hashing import sha256_bytes
from app.utils.validators import ValidationError, validate_apk_upload

router = APIRouter(prefix="/submissions", tags=["submissions"])
log = get_logger(__name__)


def _enqueue_pipeline(submission_id: uuid.UUID) -> None:
    """Fan out static + dynamic analysis jobs.

    Lazy imports keep heavy analysis deps out of the API import path, and each
    enqueue is best-effort so a missing broker (local dev) never fails the upload.
    """
    sid = str(submission_id)
    try:
        from app.workers.tasks.static_task import run_static_analysis

        run_static_analysis.delay(sid)
    except Exception as exc:  # noqa: BLE001
        log.warning("enqueue.static_failed", submission_id=sid, error=str(exc))

    # Dynamic analysis is Member C's task; send by name so we don't hard-depend.
    try:
        from app.workers.tasks.static_task import get_celery_app

        get_celery_app().send_task(
            "app.workers.tasks.dynamic_task.run_dynamic_analysis",
            args=[sid],
            queue="dynamic_queue",
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("enqueue.dynamic_skipped", submission_id=sid, error=str(exc))


@router.post("", response_model=SubmissionCreateResponse,
             status_code=status.HTTP_201_CREATED)
async def create_submission(
    response: Response,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = await file.read()
    try:
        validate_apk_upload(data, filename=file.filename or "")
    except ValidationError as ve:
        raise HTTPException(status_code=ve.status_code, detail=ve.message)

    sha256 = sha256_bytes(data)
    repo = SubmissionRepository(db)

    # Duplicate-hash detection: identical bytes → return the existing submission
    # (idempotent) instead of re-queuing the whole pipeline.
    existing = repo.get_by_hash(sha256)
    if existing is not None:
        response.status_code = status.HTTP_200_OK
        log.info("submission.duplicate", submission_id=str(existing.id), sha256=sha256,
                 existing_status=existing.status)
        return SubmissionCreateResponse(
            id=existing.id, status=existing.status, sha256_hash=sha256
        )

    storage_key = storage.upload_apk(data, sha256, file.filename or "sample.apk")
    submission = repo.create(
        uploaded_by=current_user.id,
        original_filename=file.filename or "sample.apk",
        sha256_hash=sha256,
        storage_path=storage_key,
    )
    _enqueue_pipeline(submission.id)

    log.info("submission.created", submission_id=str(submission.id),
             sha256=sha256, by=str(current_user.id))
    return SubmissionCreateResponse(
        id=submission.id, status=submission.status, sha256_hash=sha256
    )


@router.get("", response_model=PaginatedSubmissions)
def list_submissions(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo = SubmissionRepository(db)
    rows, total = repo.list(
        status=status_filter, severity=severity, page=page, page_size=page_size
    )
    items = []
    for sub in rows:
        summary = SubmissionSummary.model_validate(sub)
        if sub.verdict is not None:
            summary.severity_band = sub.verdict.severity_band
            summary.final_risk_score = sub.verdict.effective_score
        items.append(summary)
    return PaginatedSubmissions(items=items, total=total, page=page, page_size=page_size)


@router.get("/{submission_id}", response_model=SubmissionDetail)
def get_submission(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo = SubmissionRepository(db)
    sub = repo.get(submission_id)
    if sub is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Submission not found")
    return SubmissionDetail.model_validate(sub)


@router.get("/{submission_id}/status", response_model=SubmissionStatusResponse)
def get_submission_status(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.utils.stage_tracker import get_stage_detail

    repo = SubmissionRepository(db)
    sub = repo.get(submission_id)
    if sub is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Submission not found")
    stage_detail = None
    if sub.status in ("static_running", "dynamic_running", "scoring"):
        stage_detail = get_stage_detail(str(submission_id))
    return SubmissionStatusResponse(
        id=sub.id,
        status=sub.status,
        progress_pct=sub.progress_pct,
        stage_detail=stage_detail,
        analysis_stages=sub.analysis_stages,
    )


@router.delete("/{submission_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_submission(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("lead", "admin")),
):
    repo = SubmissionRepository(db)
    if not repo.soft_delete(submission_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Submission not found")
    log.info("submission.deleted", submission_id=str(submission_id),
             by=str(current_user.id))
    return None
