"""Celery task: scoring ensemble for a submission.

    run_scoring(submission_id)

Runs after static + dynamic analysis (kicked by Member A's static_task). Computes
the ML scores + calibrated verdict, then chains the LLM report task. Shares the
one Celery app instance exposed by static_task so routing/registration is
consistent across the fleet.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

from app.core.database import session_scope
from app.core.logging import get_logger
from app.services.scoring_service import ScoringService

log = get_logger(__name__)


def _celery():
    from app.workers.tasks.static_task import get_celery_app

    return get_celery_app()


celery_app = _celery()


@celery_app.task(
    name="app.workers.tasks.scoring_task.run_scoring",
    bind=True, max_retries=3, default_retry_delay=10, acks_late=True,
    queue="static_queue",
)
def run_scoring(self, submission_id: str):
    log.info("scoring_task.start", submission_id=submission_id)
    try:
        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository

            repo = SubmissionRepository(db)
            repo.update_status(submission_id, "scoring")
            repo.update_analysis_stage(submission_id, "ML Risk Scoring", "running")

        from app.utils.stage_tracker import set_stage_detail
        set_stage_detail(submission_id, "computing risk score", "Running ML ensemble and calibrating final verdict.")

        with session_scope() as db:
            summary = ScoringService(db).score(submission_id)
            from app.repositories.submission_repository import SubmissionRepository
            SubmissionRepository(db).update_analysis_stage(submission_id, "ML Risk Scoring", "completed")

        _enqueue_llm(submission_id)
        log.info("scoring_task.done", submission_id=submission_id,
                 band=summary["severity_band"], score=summary["final_risk_score"])
        return summary
    except Exception as exc:  # noqa: BLE001
        log.error("scoring_task.failed", submission_id=submission_id, error=str(exc))
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            with session_scope() as db:
                from app.repositories.submission_repository import SubmissionRepository

                repo = SubmissionRepository(db)
                repo.update_status(
                    submission_id, "failed", completed=True
                )
                repo.update_analysis_stage(
                    submission_id, "ML Risk Scoring", "failed", error_message=str(exc)
                )
            raise


def _enqueue_llm(submission_id: str) -> None:
    try:
        celery_app.send_task(
            "app.workers.tasks.llm_task.generate_report",
            args=[submission_id],
            queue="static_queue",
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("llm.enqueue_skipped", submission_id=submission_id, error=str(exc))
