"""TI Pipeline Fallback Reporter.

When the ingestion pipeline silently falls back to an alternative strategy
(e.g. TAXII instead of GitHub, skip instead of query), it calls
``emit_fallback()`` to record a structured event in Redis.

The dashboard API reads these events via ``GET /admin/threat-intelligence/pipeline/fallbacks``.

Event schema
------------
{
    "ts":        "2026-08-09T08:30:00Z",   # ISO-8601 UTC
    "source":    "mitre_attack",           # Which fetcher/normalizer
    "stage":     "fetcher",                # fetcher | normalizer | deduplicator
    "original":  "GitHub CDN",             # What was intended
    "fallback":  "TAXII 2.1",             # What was actually used
    "reason":    "ConnectionError: ...",   # Why the original failed
}
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Literal

import structlog

log = structlog.get_logger(__name__)

# Redis key storing the fallback event list (newest first via LPUSH).
_FALLBACK_KEY = "ti:fallback_events"
# Cap: keep the most recent N events only.
_MAX_EVENTS = 100


Stage = Literal["fetcher", "normalizer", "deduplicator"]


def emit_fallback(
    *,
    source: str,
    stage: Stage,
    original: str,
    fallback: str,
    reason: str,
) -> None:
    """Push one fallback event to Redis.

    Never raises — if Redis is unavailable the event is silently lost
    (the pipeline must not fail due to reporting).
    """
    try:
        import redis as _redis_lib
        from app.core.config import settings

        r = _redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "stage": stage,
            "original": original,
            "fallback": fallback,
            "reason": reason,
        }
        r.lpush(_FALLBACK_KEY, json.dumps(event))
        r.ltrim(_FALLBACK_KEY, 0, _MAX_EVENTS - 1)
        log.info(
            "ti.fallback_reporter.emitted",
            source=source,
            stage=stage,
            original=original,
            fallback=fallback,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("ti.fallback_reporter.redis_error", error=str(exc))


def get_recent_fallbacks(limit: int = 50) -> list[dict]:
    """Read the most recent fallback events from Redis.

    Returns an empty list if Redis is unavailable.
    """
    try:
        import redis as _redis_lib
        from app.core.config import settings

        r = _redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
        raw = r.lrange(_FALLBACK_KEY, 0, limit - 1)
        return [json.loads(item) for item in raw]
    except Exception as exc:  # noqa: BLE001
        log.warning("ti.fallback_reporter.read_error", error=str(exc))
        return []
