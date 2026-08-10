"""Celery task: static analysis of a submitted APK.

    run_static_analysis(submission_id)

Flow:
  1. mark submission `static_running`
  2. run StaticAnalysisService → persist static_findings
  3. if dynamic analysis already finished, advance to `scoring` and kick the
     scoring/LLM chain (Member B's task, sent by name); otherwise leave the
     status for the dynamic task to advance.

The Celery app is resolved defensively: it uses Member C's
`app.workers.celery_app` when present, else builds an equivalent app from
settings so this task is runnable on the `feat/m1-*` branch in isolation.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

from app.core.config import settings
from app.core.database import session_scope
from app.core.logging import get_logger
from app.services.static_analysis_service import StaticAnalysisService

log = get_logger(__name__)

_celery = None


def get_celery_app():
    """Return the shared Celery app (Member C's if available, else a fallback)."""
    global _celery
    if _celery is not None:
        return _celery
    try:  # Member C owns the canonical app (queues, retries, Flower).
        from app.workers.celery_app import celery_app  # type: ignore
    except Exception:  # noqa: BLE001
        from celery import Celery

        celery_app = Celery(
            "fraudshield",
            broker=settings.RABBITMQ_URL,
            backend=settings.REDIS_URL,
        )
        celery_app.conf.task_default_queue = "static_queue"
    _celery = celery_app
    return _celery


celery_app = get_celery_app()


def _dynamic_finished(db, submission_id) -> bool:
    """Best-effort check for a dynamic_findings row without importing Member C's model."""
    from sqlalchemy import text

    try:
        row = db.execute(
            text("SELECT 1 FROM dynamic_findings WHERE submission_id = :sid LIMIT 1"),
            {"sid": str(submission_id)},
        ).first()
        return row is not None
    except Exception:  # table may not exist yet on an isolated branch
        return False


@celery_app.task(
    name="app.workers.tasks.static_task.run_static_analysis",
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
    queue="static_queue",
)
def run_static_analysis(self, submission_id: str):
    log.info("static_task.start", submission_id=submission_id)
    try:
        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository

            repo = SubmissionRepository(db)
            repo.update_status(submission_id, "static_running")
            repo.update_analysis_stage(submission_id, "Static Analysis", "running")

        from app.utils.stage_tracker import set_stage_detail
        set_stage_detail(submission_id, "extracting permissions", "Parsing APK manifest and permission declarations.")

        with session_scope() as db:
            service = StaticAnalysisService(db)
            service.analyze(submission_id)

        set_stage_detail(submission_id, "parsing manifest", "Static analysis findings persisted.")

        # Advance the pipeline if the dynamic path is already done.
        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository

            repo = SubmissionRepository(db)
            if _dynamic_finished(db, submission_id):
                repo.update_status(submission_id, "scoring")
                _enqueue_scoring(submission_id)
            repo.update_analysis_stage(submission_id, "Static Analysis", "completed")

        log.info("static_task.done", submission_id=submission_id)
        return {"submission_id": submission_id, "stage": "static_complete"}

    except Exception as exc:  # noqa: BLE001
        log.error("static_task.failed", submission_id=submission_id, error=str(exc))
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            with session_scope() as db:
                from app.repositories.submission_repository import SubmissionRepository

                SubmissionRepository(db).update_status(
                    submission_id, "failed", completed=True
                )
                SubmissionRepository(db).update_analysis_stage(
                    submission_id, "Static Analysis", "failed",
                    error_message=str(exc)
                )
            raise


def _enqueue_scoring(submission_id: str) -> None:
    """Kick Member B's scoring/LLM chain by name (best-effort)."""
    try:
        get_celery_app().send_task(
            "app.workers.tasks.scoring_task.run_scoring",
            args=[submission_id],
            queue="static_queue",
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("scoring.enqueue_skipped", submission_id=submission_id, error=str(exc))
