"""Live per-stage processing detail, cached in Redis for the /status endpoint.

Celery tasks call set_stage_detail() at natural checkpoints as they run
(e.g. "extracting permissions" -> "parsing manifest"). The status endpoint
calls get_stage_detail() to surface this to the frontend while a submission
is static_running, dynamic_running, or scoring. Entries self-expire via TTL
so a crashed task never leaves stale detail behind.

Owner: Backend.
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

_CACHE_PREFIX = "stage_detail:"
_TTL_SECONDS = 300

_redis = None
_redis_tried = False


def _get_redis():
    global _redis, _redis_tried
    if _redis_tried:
        return _redis
    _redis_tried = True
    try:  # pragma: no cover - needs Redis
        import redis

        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.2)
        client.ping()
        _redis = client
    except Exception:  # noqa: BLE001
        _redis = None
    return _redis


def set_stage_detail(
    submission_id: uuid.UUID | str, current_step: str, step_description: str
) -> None:
    """Write live stage detail for a submission. Best-effort — never raises."""
    client = _get_redis()
    if client is None:
        return
    key = f"{_CACHE_PREFIX}{submission_id}"
    payload = json.dumps(
        {"current_step": current_step, "step_description": step_description}
    )
    try:
        client.setex(key, _TTL_SECONDS, payload)
    except Exception:  # noqa: BLE001
        log.warning("stage_tracker.set_failed", submission_id=str(submission_id))


def get_stage_detail(submission_id: uuid.UUID | str) -> Optional[dict]:
    """Read live stage detail for a submission, or None if missing/expired."""
    client = _get_redis()
    if client is None:
        return None
    key = f"{_CACHE_PREFIX}{submission_id}"
    try:
        raw = client.get(key)
    except Exception:  # noqa: BLE001
        return None
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None