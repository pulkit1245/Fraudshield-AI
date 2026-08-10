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

    # Purge old quarantine records.  These are diagnostic only; 90 days is
    # more than sufficient for analysts to act on them.
    with session_scope() as db:
        from sqlalchemy import text as _text
        result = db.execute(
            _text(
                "DELETE FROM ti_ingestion_quarantine "
                "WHERE created_at < now() - interval '90 days'"
            )
        )
        db.commit()
        quarantine_purged = result.rowcount if result.rowcount is not None else 0
    log.info("retention.quarantine_purge_complete", purged=quarantine_purged)

    return {"purged": purged, "cutoff": cutoff.isoformat(), "quarantine_purged": quarantine_purged}


@celery_app.task(name="app.workers.tasks.retention_task.recompute_clusters")
def recompute_clusters() -> dict:
    """Recompute all cluster centroids (drift correction as new samples arrive)."""
    with session_scope() as db:
        from app.services.clustering_service import ClusteringService

        n = ClusteringService(db).recompute_all()
    return {"clusters_recomputed": n}
