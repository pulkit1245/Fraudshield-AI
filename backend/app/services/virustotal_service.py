"""VirusTotal hash cross-check with Redis caching.

Looks up a submission's SHA-256 against VirusTotal v3, caches the response in
Redis for 24h (quota conservation), and persists it to `virustotal_lookups`.
Degrades cleanly, never raising into the pipeline. Statuses:
  ok / not_found  — real verdicts, cached 24h
  not_configured  — no API key in the environment
  invalid_key     — VT returned 401/403
  quota_exceeded  — VT returned 429
  error           — network/HTTP failure
Only `ok` and `not_found` are cached; failures must stay retryable.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import json
import re
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

# Only real verdicts are worth caching for 24h. Caching a transient failure
# (bad key, quota exhausted, network blip) would pin VT "broken" for a full day
# even after the underlying problem is fixed.
_CACHEABLE = {"ok", "not_found"}

_VT_KEY_RE = re.compile(r"^[0-9a-f]{64}$")

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
        # Never cache failures — see _CACHEABLE.
        if response.get("status") in _CACHEABLE:
            self._cache_set(sha256, response)
        self._persist(submission_id, response)
        return response

    # ── VT call ─────────────────────────────────────────────────────────
    def _query_vt(self, sha256: str) -> dict[str, Any]:
        api_key = _clean_secret(settings.VIRUSTOTAL_API_KEY)
        if not api_key:
            # Loud, because this is silent-degradation territory: the pipeline
            # keeps running and the score just goes neutral, so a missing key
            # otherwise looks like "VT says nothing suspicious".
            log.warning(
                "vt.not_configured",
                hint="VIRUSTOTAL_API_KEY resolved empty in this process. Under "
                     "Docker check that infra/docker-compose.yml does not set it "
                     "to an empty value (that overrides env_file).",
            )
            return {"status": "not_configured", "sha256": sha256}
        if not _VT_KEY_RE.match(api_key):
            # Don't hard-fail (VT could change format) but make it findable.
            log.warning("vt.key_malformed", key_len=len(api_key),
                        hint="expected 64 lowercase hex chars")
        try:
            import requests

            resp = requests.get(
                VT_URL.format(sha256=sha256),
                headers={"x-apikey": api_key},
                timeout=10,
            )
            if resp.status_code == 404:
                return {"status": "not_found", "sha256": sha256}
            if resp.status_code in (401, 403):
                log.error("vt.auth_failed", status=resp.status_code, key_len=len(api_key))
                return {
                    "status": "invalid_key",
                    "sha256": sha256,
                    "detail": f"VirusTotal rejected the API key (HTTP {resp.status_code})",
                }
            if resp.status_code == 429:
                log.warning("vt.quota_exceeded")
                return {
                    "status": "quota_exceeded",
                    "sha256": sha256,
                    "detail": "VirusTotal quota exceeded (HTTP 429). Public keys "
                              "allow 4 req/min and 500 req/day.",
                }
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


def _clean_secret(raw: str | None) -> str:
    """Normalise a secret read from the environment.

    Defends against the classic `.env` footgun where a trailing comment ends up
    inside the value:

        VIRUSTOTAL_API_KEY=abc123...        # Member C — hash cross-check

    Compose V2 and python-dotenv both strip that comment themselves, but plenty
    of other paths don't (a raw `export`, a CI secret pasted with its comment, a
    k8s ConfigMap), and a key with a comment glued on fails as an opaque 401.
    Belt-and-braces. We only strip from a `#` preceded by whitespace, so secrets
    that legitimately contain `#` are left intact.
    """
    value = (raw or "").strip()
    if not value:
        return ""
    # A value that is *entirely* a comment means the key was never set, e.g.
    # `CLAUDE_API_KEY=            # Member B — LLM orchestration`. Treat as unset.
    if value.startswith("#"):
        return ""
    trimmed = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    if trimmed != value:
        log.warning(
            "vt.key_had_inline_comment",
            hint="Stripped a trailing '# ...' comment from VIRUSTOTAL_API_KEY. "
                 "Move the comment to its own line in .env.",
        )
    # Quotes are stripped by dotenv but not by Compose's env_file parser.
    if len(trimmed) >= 2 and trimmed[0] == trimmed[-1] and trimmed[0] in "\"'":
        trimmed = trimmed[1:-1].strip()
    return trimmed


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
