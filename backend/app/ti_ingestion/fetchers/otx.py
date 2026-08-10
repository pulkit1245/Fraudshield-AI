"""AlienVault OTX threat intelligence fetcher.

Searches AlienVault OTX pulses for recent mobile threats using the search query
"Android".

API Endpoint : https://otx.alienvault.com/api/v1/search/pulses
Headers      : X-OTX-API-KEY

Requires an API key to be set in the ``OTX_API_KEY`` environment variable.
If not set, the fetcher is skipped.

Incremental updates: compares the ``modified`` timestamp of each pulse against
the last-fetch timestamp stored in Redis.
"""
from __future__ import annotations

import os
from typing import Iterator

import requests

from app.core.logging import get_logger
from app.ti_ingestion.fallback_reporter import emit_fallback
from app.ti_ingestion.fetchers.base import BaseFetcher

log = get_logger(__name__)

_API_URL = "https://otx.alienvault.com/api/v1/search/pulses"
_REQUEST_TIMEOUT = 30   # seconds


def _failure_reason(exc: Exception) -> str:
    """Map a request failure to a fixed, actionable message.

    Returns one of a closed set of strings — never the raw exception. OTX
    authenticates via the ``X-OTX-API-KEY`` header, and requests' exception
    text can include the prepared request, so interpolating ``str(exc)`` here
    risks writing the API key into Redis and onto an admin dashboard.
    """
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status in (401, 403):
        return ("OTX rejected the API key (HTTP %d). Check OTX_API_KEY in .env "
                "is current and has not been revoked." % status)
    if status == 429:
        return ("OTX rate limit exceeded (HTTP 429). The next scheduled run "
                "will retry; no pulses were ingested.")
    if status is not None:
        return ("OTX returned HTTP %d. The API may be degraded; the next "
                "scheduled run will retry." % status)
    if isinstance(exc, requests.Timeout):
        return (f"OTX did not respond within {_REQUEST_TIMEOUT}s. "
                "No pulses were ingested this run.")
    if isinstance(exc, requests.ConnectionError):
        return ("Could not reach otx.alienvault.com — network or DNS failure "
                "from the worker container.")
    return (f"OTX fetch failed with {type(exc).__name__}. "
            "See worker logs (otx.fetcher.error) for details.")


class AlienVaultOtxFetcher(BaseFetcher):
    """Fetches Android threat pulses from AlienVault OTX."""

    source_name = "otx"
    last_fetch_key = "ti:last_fetch:otx"

    def __init__(self, last_fetch_ts: str | None = None) -> None:
        """
        Parameters
        ----------
        last_fetch_ts:
            ISO 8601 timestamp of the last successful fetch.
            Only pulses with ``modified > last_fetch_ts`` will be yielded.
        """
        self._last_fetch_ts = last_fetch_ts

    def fetch(self) -> Iterator[dict]:
        """Yield raw pulse objects from AlienVault OTX."""
        api_key = os.getenv("OTX_API_KEY", "").strip()
        if not api_key:
            self.failed = True
            emit_fallback(
                source="otx",
                stage="fetcher",
                original="AlienVault OTX API (otx.alienvault.com) — real-time Android pulses",
                fallback="Skipped — source disabled",
                reason="OTX_API_KEY is not set in environment. Add it to .env to enable this source.",
            )
            log.info("otx.fetcher.skip_missing_key")
            return

        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        }
        params = {
            "q": "Android",
            "limit": 20
        }

        try:
            resp = requests.get(
                _API_URL,
                headers=headers,
                params=params,
                timeout=_REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            result = resp.json()
        except Exception as exc:  # noqa: BLE001
            self.failed = True
            log.error("otx.fetcher.error", error=str(exc))
            # Without this the dashboard shows nothing when the key is present
            # but rejected/expired/rate-limited — indistinguishable from a
            # healthy run. `reason` is a fixed classification, never the raw
            # exception: the request URL carries the key in its headers and
            # str(exc) can echo it back.
            emit_fallback(
                source="otx",
                stage="fetcher",
                original="AlienVault OTX API (otx.alienvault.com) — real-time Android pulses",
                fallback="Skipped — no pulses ingested this run",
                reason=_failure_reason(exc),
            )
            return

        results = result.get("results") or []
        log.info("otx.fetcher.data_loaded", total_pulses=len(results))

        yielded = 0
        skipped_stale = 0
        skipped_non_android = 0

        for pulse in results:
            pulse_id = pulse.get("id")
            name = pulse.get("name") or ""
            description = pulse.get("description") or ""
            tags = [t.lower() for t in (pulse.get("tags") or []) if isinstance(t, str)]

            # Double check relevance to Android / Mobile to keep TTPs focused.
            is_relevant = (
                "android" in name.lower()
                or "android" in description.lower()
                or "apk" in name.lower()
                or "apk" in description.lower()
                or "mobile" in name.lower()
                or any("android" in t or "apk" in t or "mobile" in t for t in tags)
            )
            if not is_relevant:
                skipped_non_android += 1
                continue

            # Incremental check using OTX's modified timestamp (ISO 8601)
            modified = pulse.get("modified")
            if self._last_fetch_ts and modified:
                if modified <= self._last_fetch_ts:
                    skipped_stale += 1
                    continue

            yield pulse
            yielded += 1

        log.info(
            "otx.fetcher.done",
            yielded=yielded,
            skipped_non_android=skipped_non_android,
            skipped_stale=skipped_stale
        )
