"""Dashboard aggregate endpoints.

    GET /api/v1/dashboard/stats  → severity counts, queue depth, avg triage time
                                    (cached in Redis, 60s TTL per §1)
    GET /api/v1/dashboard/queue  → most-recent active submissions (lightweight)

Redis caching degrades gracefully: if the cache is unreachable the stats are
computed live, so the endpoint never hard-fails on a missing broker.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.core.security import get_current_user
from app.models.submission import Submission
from app.models.verdict import RiskVerdict
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
log = get_logger(__name__)

_CACHE_KEY = "dashboard:stats"
_CACHE_TTL = 60
_ACTIVE_STATUSES = ("queued", "static_running", "dynamic_running", "scoring")

# Lazily-initialized Redis client (None if unavailable).
_redis = None
_redis_last_attempt: float = 0.0
_REDIS_RETRY_INTERVAL = 30.0  # seconds between reconnect attempts


def _get_redis():
    """Return Redis client, retrying connection every 30s if previously failed."""
    global _redis, _redis_last_attempt
    import time
    now = time.monotonic()
    if _redis is not None:
        return _redis
    if now - _redis_last_attempt < _REDIS_RETRY_INTERVAL:
        return None  # Back-off: don't hammer Redis on every request
    _redis_last_attempt = now
    try:  # pragma: no cover - depends on a running Redis
        import redis

        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.2)
        client.ping()
        _redis = client
    except Exception:  # noqa: BLE001
        _redis = None
    return _redis



def _compute_stats(db: Session) -> dict:
    # Counts by severity band (only submissions that reached a verdict).
    band_rows = db.execute(
        select(RiskVerdict.severity_band, func.count()).group_by(RiskVerdict.severity_band)
    ).all()
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for band, count in band_rows:
        if band in by_severity:
            by_severity[band] = int(count)

    queue_depth = db.execute(
        select(func.count())
        .select_from(Submission)
        .where(Submission.status.in_(_ACTIVE_STATUSES), Submission.deleted_at.is_(None))
    ).scalar_one()

    total = db.execute(
        select(func.count()).select_from(Submission).where(Submission.deleted_at.is_(None))
    ).scalar_one()

    completed = db.execute(
        select(func.count())
        .select_from(Submission)
        .where(Submission.status == "completed")
    ).scalar_one()

    # Average triage time — computed in Python so it's engine-portable
    # (avoids Postgres-only date arithmetic and works on SQLite in tests).
    pairs = db.execute(
        select(Submission.submitted_at, Submission.completed_at)
        .where(Submission.completed_at.isnot(None))
        .limit(1000)
    ).all()
    durations = [
        (row.completed_at - row.submitted_at).total_seconds()
        for row in pairs
        if row.submitted_at is not None and row.completed_at is not None
    ]
    avg_seconds = round(sum(durations) / len(durations), 1) if durations else None

    return {
        "by_severity": by_severity,
        "queue_depth": int(queue_depth),
        "total_submissions": int(total),
        "completed": int(completed),
        "avg_triage_seconds": avg_seconds,
    }


@router.get("/stats")
def dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    client = _get_redis()
    if client is not None:
        try:
            cached = client.get(_CACHE_KEY)
            if cached:
                return json.loads(cached)
        except Exception:  # noqa: BLE001
            pass

    stats = _compute_stats(db)

    if client is not None:
        try:
            client.setex(_CACHE_KEY, _CACHE_TTL, json.dumps(stats))
        except Exception:  # noqa: BLE001
            pass
    return stats


@router.get("/queue")
def dashboard_queue(
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (
        db.execute(
            select(Submission)
            .where(Submission.deleted_at.is_(None))
            .order_by(Submission.submitted_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(s.id),
                "original_filename": s.original_filename,
                "status": s.status,
                "progress_pct": s.progress_pct,
                "submitted_at": s.submitted_at.isoformat() if s.submitted_at else None,
            }
            for s in rows
        ],
        "count": len(rows),
    }
