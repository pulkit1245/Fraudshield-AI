"""Celery task: dynamic sandbox analysis of a submitted APK.

    run_dynamic_analysis(submission_id)   [dynamic_queue]

Runs on the dedicated dynamic_queue so a slow sandbox run never blocks the static
path. Persists dynamic_findings, best-effort kicks the VirusTotal + clustering
side-lookups, and advances the pipeline to scoring once static analysis is also
done (symmetric with Member A's static_task).

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import os

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


# Max retries raised to 6: up to 3 waiting for static analysis in simulate mode,
# plus the original 3 for actual analysis failures.
@celery_app.task(
    name="app.workers.tasks.dynamic_task.run_dynamic_analysis",
    bind=True, max_retries=6, default_retry_delay=15, acks_late=True,
    queue="dynamic_queue",
)
def run_dynamic_analysis(self, submission_id: str):
    log.info("dynamic_task.start", submission_id=submission_id)
    try:
        # In simulate mode the sandbox derives findings from static signals.
        # If static analysis hasn't written its row yet, retry after a short
        # delay (up to 3 times) so the simulation has real data to work with.
        sandbox_mode = os.getenv("SANDBOX_MODE", "live").lower()
        if sandbox_mode == "simulate":
            with session_scope() as db:
                if not _static_finished(db, submission_id):
                    wait_retries = self.request.retries  # retries so far
                    if wait_retries < 3:
                        log.info(
                            "dynamic_task.waiting_for_static",
                            submission_id=submission_id,
                            retry=wait_retries,
                        )
                        raise self.retry(countdown=5)
                    # After 3 waits, proceed anyway with whatever is available.
                    log.warning(
                        "dynamic_task.static_not_ready_proceeding",
                        submission_id=submission_id,
                    )

        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository

            repo = SubmissionRepository(db)
            repo.update_status(submission_id, "dynamic_running")
            repo.update_analysis_stage(submission_id, "Dynamic Analysis", "running")

        from app.utils.stage_tracker import set_stage_detail
        set_stage_detail(submission_id, "running sandbox", "Executing APK in the dynamic analysis sandbox.")

        with session_scope() as db:
            DynamicAnalysisService(db).analyze(submission_id)

        set_stage_detail(submission_id, "capturing syscalls", "Sandbox run complete, cross-checking with VirusTotal and clustering.")

        _side_lookups(submission_id)

        # Advance to scoring if static is already done.
        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository
            repo = SubmissionRepository(db)
            repo.update_analysis_stage(submission_id, "Dynamic Analysis", "completed")

            if _static_finished(db, submission_id):
                repo.update_status(submission_id, "scoring")
                _enqueue_scoring(submission_id)

        log.info("dynamic_task.done", submission_id=submission_id)
        return {"submission_id": submission_id, "stage": "dynamic_complete"}

    except Exception as exc:  # noqa: BLE001
        err_str = str(exc)
        log.error("dynamic_task.failed", submission_id=submission_id, error=err_str)

        # Fail fast on architecture mismatch, retrying will never succeed
        if "INSTALL_FAILED_NO_MATCHING_ABIS" in err_str:
            with session_scope() as db:
                from app.repositories.submission_repository import SubmissionRepository
                repo = SubmissionRepository(db)
                repo.update_status(submission_id, "failed", completed=True)
                repo.update_analysis_stage(
                    submission_id, "Dynamic Analysis", "failed",
                    error_message=f"Architecture mismatch (APK lacks 64-bit ARM / arm64-v8a support): {err_str}"
                )
            return {"submission_id": submission_id, "stage": "dynamic_failed_abi"}

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
                    submission_id, "Dynamic Analysis", "failed",
                    error_message=err_str
                )
            raise


def _side_lookups(submission_id: str) -> None:
    """VirusTotal hash check + campaign clustering — independent, best-effort."""
    try:
        with session_scope() as db:
            from app.services.virustotal_service import VirustotalService
            from app.repositories.submission_repository import SubmissionRepository
            
            repo = SubmissionRepository(db)
            repo.update_analysis_stage(submission_id, "Threat Intelligence", "running")
            VirustotalService(db).lookup(submission_id)
            repo.update_analysis_stage(submission_id, "Threat Intelligence", "completed")
    except Exception as exc:  # noqa: BLE001
        log.debug("dynamic.vt_skipped", submission_id=submission_id, error=str(exc))
        with session_scope() as db:
            from app.repositories.submission_repository import SubmissionRepository
            SubmissionRepository(db).update_analysis_stage(
                submission_id, "Threat Intelligence", "failed",
                error_message=str(exc)
            )
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
