"""VirusTotal hash cross-check with Redis caching.

Looks up a submission's SHA-256 against VirusTotal v3, caches the response in
Redis for 24h (quota conservation), and persists it to `virustotal_lookups`.
Degrades cleanly: no API key → `not_configured`; unknown hash → `not_found`;
network/HTTP error → `error` — never raises into the pipeline.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.submission import Submission
from app.models.virustotal_lookup import VirustotalLookup

log = get_logger(__name__)

VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
CACHE_TTL = 24 * 3600
_CACHE_PREFIX = "vt:"

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


class VirustotalService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def lookup(self, submission_id: uuid.UUID | str) -> dict[str, Any]:
        submission_id = _as_uuid(submission_id)
        submission = self.db.get(Submission, submission_id)
        if submission is None:
            raise ValueError(f"Submission {submission_id} not found")
        sha256 = submission.sha256_hash

        cached = self._cache_get(sha256)
        if cached is not None:
            self._persist(submission_id, cached)
            return cached

        response = self._query_vt(sha256)
        self._cache_set(sha256, response)
        self._persist(submission_id, response)
        return response

    # ── VT call ─────────────────────────────────────────────────────────
    def _query_vt(self, sha256: str) -> dict[str, Any]:
        api_key = (settings.VIRUSTOTAL_API_KEY or "").strip()
        # Guard: strip any non-ASCII characters (e.g. inline comments with em-dashes
        # that end up in the value when the .env line has a trailing comment).
        api_key = api_key.encode("ascii", errors="ignore").decode("ascii").strip()
        if not api_key:
            return {"status": "not_configured", "sha256": sha256}
        try:
            import requests

            resp = requests.get(
                VT_URL.format(sha256=sha256),
                headers={"x-apikey": api_key},
                timeout=10,
            )
            if resp.status_code == 404:
                return {"status": "not_found", "sha256": sha256}
            resp.raise_for_status()
            return self._summarize(sha256, resp.json())
        except Exception as exc:  # noqa: BLE001
            log.warning("vt.query_failed", error=str(exc))
            return {"status": "error", "sha256": sha256, "detail": str(exc)}

    @staticmethod
    def _summarize(sha256: str, raw: dict) -> dict[str, Any]:
        attrs = (raw.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "status": "ok",
            "sha256": sha256,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": attrs.get("reputation"),
            "meaningful_name": attrs.get("meaningful_name"),
            "raw_stats": stats,
        }

    # ── cache + persist ─────────────────────────────────────────────────
    def _cache_get(self, sha256: str) -> Optional[dict]:
        client = _get_redis()
        if client is None:
            return None
        try:  # pragma: no cover
            raw = client.get(_CACHE_PREFIX + sha256)
            return json.loads(raw) if raw else None
        except Exception:  # noqa: BLE001
            return None

    def _cache_set(self, sha256: str, value: dict) -> None:
        client = _get_redis()
        if client is None:
            return
        try:  # pragma: no cover
            client.setex(_CACHE_PREFIX + sha256, CACHE_TTL, json.dumps(value))
        except Exception:  # noqa: BLE001
            pass

    def _persist(self, submission_id: uuid.UUID, response: dict) -> VirustotalLookup:
        existing = self.db.execute(
            select(VirustotalLookup).where(VirustotalLookup.submission_id == submission_id)
        ).scalar_one_or_none()
        if existing is None:
            row = VirustotalLookup(submission_id=submission_id)
            self.db.add(row)
        else:
            row = existing
        row.vt_response = response
        self.db.commit()
        self.db.refresh(row)
        return row


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
