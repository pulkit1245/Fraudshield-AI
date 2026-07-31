"""Celery task: generate the sanitized LLM report for a submission.

    generate_report(submission_id)

Final stage of the pipeline: sanitize → RAG retrieve → Claude (agentic, tiered)
→ persist `llm_reports` → mark submission completed. Chained after run_scoring.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

from app.core.database import session_scope
from app.core.logging import get_logger
from app.services.llm_orchestration_service import LLMOrchestrationService

log = get_logger(__name__)


def _celery():
    from app.workers.tasks.static_task import get_celery_app

    return get_celery_app()


celery_app = _celery()


@celery_app.task(
    name="app.workers.tasks.llm_task.generate_report",
    bind=True, max_retries=2, default_retry_delay=15, acks_late=True,
    queue="static_queue",
)
def generate_report(self, submission_id: str):
    log.info("llm_task.start", submission_id=submission_id)
    try:
        with session_scope() as db:
            result = LLMOrchestrationService(db).generate_report(submission_id)
        log.info("llm_task.done", submission_id=submission_id, model=result["model_used"])
        return result
    except Exception as exc:  # noqa: BLE001
        log.error("llm_task.failed", submission_id=submission_id, error=str(exc))
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            # Scoring already succeeded and a verdict exists; only the report
            # generation failed. Mark the submission completed so it surfaces in
            # the dashboard rather than being stuck in "scoring" forever.
            try:
                with session_scope() as db:
                    from app.repositories.submission_repository import SubmissionRepository
                    SubmissionRepository(db).update_status(
                        submission_id, "completed", completed=True
                    )
            except Exception:  # noqa: BLE001
                pass
            raise
