"""Celery-beat maintenance tasks (§ Member C Task 4).

    purge_expired_apks()   → delete raw APK bytes from object storage after 90 days
                             while retaining findings/verdict metadata (data-
                             protection per §5.4). Each purge is audit-logged.
    recompute_clusters()   → periodic centroid recompute across all clusters.

Both are scheduled from `celery_app.beat_schedule`.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.database import session_scope
from app.core.logging import get_logger
from app.models.submission import Submission
from app.utils.audit import record_audit
from app.utils.file_storage import storage

log = get_logger(__name__)

RETENTION_DAYS = 90
PURGED_SENTINEL = "PURGED"


def _celery():
    from app.workers.celery_app import celery_app

    return celery_app


celery_app = _celery()


@celery_app.task(name="app.workers.tasks.retention_task.purge_expired_apks")
def purge_expired_apks() -> dict:
    """Purge raw APKs older than RETENTION_DAYS; keep metadata + findings."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    purged = 0
    with session_scope() as db:
        rows = db.execute(
            select(Submission).where(
                Submission.submitted_at < cutoff,
                Submission.storage_path.isnot(None),
                Submission.storage_path != PURGED_SENTINEL,
            )
        ).scalars().all()

        for sub in rows:
            try:
                storage.delete(sub.storage_path)
            except Exception as exc:  # noqa: BLE001
                log.warning("retention.delete_failed", submission_id=str(sub.id),
                            error=str(exc))
                continue
            record_audit(
                db, action="apk_purged", target_type="submission",
                target_id=sub.id,
                detail={"retention_days": RETENTION_DAYS, "was": sub.storage_path},
                commit=False,
            )
            sub.storage_path = PURGED_SENTINEL
            purged += 1
        db.commit()

    log.info("retention.purge_complete", purged=purged, cutoff=cutoff.isoformat())
    return {"purged": purged, "cutoff": cutoff.isoformat()}


@celery_app.task(name="app.workers.tasks.retention_task.recompute_clusters")
def recompute_clusters() -> dict:
    """Recompute all cluster centroids (drift correction as new samples arrive)."""
    with session_scope() as db:
        from app.services.clustering_service import ClusteringService

        n = ClusteringService(db).recompute_all()
    return {"clusters_recomputed": n}


@celery_app.task(name="app.workers.tasks.retention_task.recover_stuck_submissions")
def recover_stuck_submissions() -> dict:
    """Detect submissions stuck in intermediate states and advance their pipeline.

    If a submission has been in ``static_running`` or ``dynamic_running`` for
    more than ``STUCK_MINUTES`` and both analysis findings rows exist, advance
    it to ``scoring`` and kick the scoring chain.  This handles the case where
    a Celery worker was SIGKILL'd (hard time-limit) before it could run the
    pipeline-advancement logic.
    """
    from datetime import datetime, timedelta, timezone as tz

    from sqlalchemy import text

    STUCK_MINUTES = 12  # slightly longer than the hard time limit (600s = 10 min)
    cutoff = datetime.now(tz.utc) - timedelta(minutes=STUCK_MINUTES)
    recovered = 0

    with session_scope() as db:
        stuck = db.execute(
            text("""
                SELECT s.id
                  FROM apk_submissions s
                 WHERE s.status IN ('static_running', 'dynamic_running')
                   AND s.submitted_at < :cutoff
                   AND s.deleted_at IS NULL
                   AND EXISTS (SELECT 1 FROM static_findings  WHERE submission_id = s.id)
                   AND EXISTS (SELECT 1 FROM dynamic_findings WHERE submission_id = s.id)
            """),
            {"cutoff": cutoff},
        ).fetchall()

        for (sid,) in stuck:
            from app.repositories.submission_repository import SubmissionRepository

            repo = SubmissionRepository(db)
            repo.update_status(str(sid), "scoring")
            log.info("retention.recovered_stuck", submission_id=str(sid))
            try:
                celery_app.send_task(
                    "app.workers.tasks.scoring_task.run_scoring",
                    args=[str(sid)], queue="static_queue",
                )
            except Exception:  # noqa: BLE001
                pass
            recovered += 1

    log.info("retention.recover_stuck_complete", recovered=recovered)
    return {"recovered": recovered}
