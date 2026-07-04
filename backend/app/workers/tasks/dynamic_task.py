"""Celery task: dynamic sandbox analysis of a submitted APK.

    run_dynamic_analysis(submission_id)   [dynamic_queue]

Runs on the dedicated dynamic_queue so a slow sandbox run never blocks the static
path. Persists dynamic_findings, best-effort kicks the VirusTotal + clustering
side-lookups, and advances the pipeline to scoring once static analysis is also
done (symmetric with Member A's static_task).

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

from app.core.database import session_scope
from app.core.logging import get_logger
from app.services.dynamic_analysis_service import DynamicAnalysisService

log = get_logger(__name__)


def _celery():
    from app.workers.celery_app import celery_app

    return celery_app


celery_app = _celery()


def _static_finished(db, submission_id) -> bool:
    from app.models.static_finding import StaticFinding
    from sqlalchemy import select

    row = db.execute(
        select(StaticFinding.id).where(StaticFinding.submission_id == submission_id)
    ).first()
    return row is not None


@celery_app.task(
    name="app.workers.tasks.dynamic_task.run_dynamic_analysis",
    bind=True, max_retries=3, default_retry_delay=15, acks_late=True,
    queue="dynamic_queue",
)
def run_dynamic_analysis(self, submission_id: str):
    log.info("dynamic_task.start", submission_id=submission_id)
    try:
        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository

            SubmissionRepository(db).update_status(submission_id, "dynamic_running")

        with session_scope() as db:
            DynamicAnalysisService(db).analyze(submission_id)

        _side_lookups(submission_id)

        # Advance to scoring if static is already done.
        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository

            if _static_finished(db, submission_id):
                SubmissionRepository(db).update_status(submission_id, "scoring")
                _enqueue_scoring(submission_id)

        log.info("dynamic_task.done", submission_id=submission_id)
        return {"submission_id": submission_id, "stage": "dynamic_complete"}

    except Exception as exc:  # noqa: BLE001
        log.error("dynamic_task.failed", submission_id=submission_id, error=str(exc))
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            with session_scope() as db:
                from app.repositories.submission_repository import SubmissionRepository

                SubmissionRepository(db).update_status(
                    submission_id, "failed", completed=True
                )
            raise


def _side_lookups(submission_id: str) -> None:
    """VirusTotal hash check + campaign clustering — independent, best-effort."""
    try:
        with session_scope() as db:
            from app.services.virustotal_service import VirustotalService

            VirustotalService(db).lookup(submission_id)
    except Exception as exc:  # noqa: BLE001
        log.debug("dynamic.vt_skipped", submission_id=submission_id, error=str(exc))
    try:
        with session_scope() as db:
            from app.services.clustering_service import ClusteringService

            ClusteringService(db).assign(submission_id)
    except Exception as exc:  # noqa: BLE001
        log.debug("dynamic.cluster_skipped", submission_id=submission_id, error=str(exc))


def _enqueue_scoring(submission_id: str) -> None:
    try:
        celery_app.send_task(
            "app.workers.tasks.scoring_task.run_scoring",
            args=[submission_id], queue="static_queue",
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("dynamic.scoring_enqueue_skipped", submission_id=submission_id, error=str(exc))
