"""Celery task: classify an APK into an application category.

    run_app_classification(submission_id)

Runs immediately after the APK metadata is available (androguard extraction
inside the static task). Persists an `app_classifications` row so that:

  - PermissionPolicyService can contextualise permission risk downstream.
  - ScoringService can adjust the ML ensemble weight with context_score.
  - LLMOrchestrationService can include category context in the threat report.

The task is designed to be non-blocking for the existing pipeline:
  - If the task fails (LLM unavailable, bad APK, etc.) the pipeline continues
    with the heuristic fallback result.
  - The task idempotently uses the SHA-256 cache — re-running is safe.

Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

from app.core.database import session_scope
from app.core.logging import get_logger

log = get_logger(__name__)


def _celery():
    from app.workers.tasks.static_task import get_celery_app
    return get_celery_app()


celery_app = _celery()


@celery_app.task(
    name="app.workers.tasks.classification_task.run_app_classification",
    bind=True,
    max_retries=2,
    default_retry_delay=8,
    acks_late=True,
    queue="static_queue",
)
def run_app_classification(self, submission_id: str) -> dict:
    """Classify the submitted APK's purpose/category.

    Fetches the already-extracted androguard data from `static_findings`
    (populated by the static task that runs concurrently or just before),
    then calls AppClassificationService which handles LLM + heuristic
    fallback + DB persistence.

    Returns a summary dict for Celery result tracking.
    """
    log.info("classification_task.start", submission_id=submission_id)
    try:
        result = _run(submission_id)
        log.info(
            "classification_task.done",
            submission_id=submission_id,
            category=result.get("primary_category"),
            method=result.get("classified_by"),
        )
        return result

    except Exception as exc:  # noqa: BLE001
        log.error("classification_task.failed", submission_id=submission_id,
                  error=str(exc))
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            # Non-fatal: the pipeline can continue without a classification.
            log.warning(
                "classification_task.max_retries_exceeded",
                submission_id=submission_id,
            )
            return {
                "submission_id": submission_id,
                "primary_category": "Other",
                "classified_by": "failed",
                "error": str(exc),
            }


def _run(submission_id: str) -> dict:
    """Inner implementation extracted for testability."""
    import uuid as _uuid

    from sqlalchemy import select

    from app.models.static_finding import StaticFinding
    from app.models.submission import Submission
    from app.services.app_classification_service import AppClassificationService

    sub_uuid = _uuid.UUID(submission_id)

    with session_scope() as db:
        # Fetch submission for sha256_hash.
        sub = db.get(Submission, sub_uuid)
        if sub is None:
            raise ValueError(f"Submission {submission_id} not found")

        # Fetch static_findings for the androguard-extracted metadata.
        static = db.execute(
            select(StaticFinding).where(StaticFinding.submission_id == sub_uuid)
        ).scalar_one_or_none()

        # Build the ag_extract dict from persisted static_findings columns.
        # This mirrors the shape returned by androguard_wrapper.extract().
        ag_extract: dict = {}
        if static is not None:
            perms = static.permissions or {}
            graph = static.api_call_graph or {}
            ag_extract = {
                "package_name": static.package_name,
                "app_name": graph.get("app_name"),
                "version_name": None,
                "main_activity": None,
                "permissions": perms,
                "certificate_info": static.certificate_info or {},
                "api_call_graph": graph,
                "obfuscation_score": static.obfuscation_score,
            }

        svc = AppClassificationService(db)
        result = svc.classify(
            submission_id=sub_uuid,
            sha256_hash=sub.sha256_hash,
            ag_extract=ag_extract,
        )

    return {
        "submission_id": submission_id,
        "primary_category": result.primary_category,
        "secondary_categories": result.secondary_categories,
        "confidence": result.confidence,
        "classified_by": result.classified_by,
    }
