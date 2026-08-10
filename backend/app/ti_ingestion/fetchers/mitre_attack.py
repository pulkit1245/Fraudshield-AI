"""MITRE ATT&CK for Mobile fetcher.

Downloads the mobile-attack STIX 2.1 bundle from the canonical
``mitre-attack/attack-stix-data`` GitHub repository (the ``mitre/cti``
repository was deprecated in 2023).

Primary URL  : GitHub raw (no auth, CDN-cached, fast)
Fallback URL : TAXII 2.1 endpoint (in case GitHub is unavailable)

Only ``attack-pattern`` STIX objects whose ``x_mitre_platforms`` list
includes ``"Android"`` are yielded.  This excludes iOS-only and desktop
techniques, keeping the knowledge base focused on the Android banking-fraud
threat model.

The fetcher performs **incremental** updates: the ISO 8601 ``modified``
timestamp of each STIX object is compared against the last-fetch high-water
mark stored in Redis.  On first run the full bundle is processed.

No API key is required.  Both endpoints are public.
"""
from __future__ import annotations

import json
from typing import Iterator

import requests

from app.core.logging import get_logger
from app.ti_ingestion.fallback_reporter import emit_fallback
from app.ti_ingestion.fetchers.base import BaseFetcher

log = get_logger(__name__)

# Current canonical URL (STIX 2.1, ATT&CK v16+).
# The `mitre/cti` repository was deprecated in 2023; this is its replacement.
_PRIMARY_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/mobile-attack/mobile-attack-16.1.json"
)

# TAXII 2.1 fallback — collection ID for Mobile ATT&CK.
_TAXII_ROOT = "https://attack-taxii.mitre.org/api/v21"
_TAXII_COLLECTION_ID = "x9ed6cfa-b6d4-4a9e-9423-a6a3b2ed02b5"

_REQUEST_TIMEOUT = 30   # seconds
_ANDROID_PLATFORM = "Android"


class MitreAttackFetcher(BaseFetcher):
    """Fetches Android-relevant ATT&CK for Mobile attack-patterns."""

    source_name = "mitre_attack"
    last_fetch_key = "ti:last_fetch:mitre_attack"

    def __init__(self, last_fetch_ts: str | None = None) -> None:
        """
        Parameters
        ----------
        last_fetch_ts:
            ISO 8601 timestamp of the last successful fetch.  Only objects
            with ``modified > last_fetch_ts`` will be yielded.  Pass ``None``
            on first run to process the full bundle.
        """
        self._last_fetch_ts = last_fetch_ts

    def fetch(self) -> Iterator[dict]:
        """Yield raw STIX attack-pattern objects for Android techniques."""
        bundle = self._download_bundle()
        if bundle is None:
            self.failed = True
            return

        objects = bundle.get("objects", [])
        log.info("mitre_attack.fetcher.bundle_loaded", total_objects=len(objects))

        yielded = 0
        skipped_type = 0
        skipped_platform = 0
        skipped_stale = 0
        skipped_deprecated = 0

        for obj in objects:
            # Only process technique objects.
            if obj.get("type") != "attack-pattern":
                skipped_type += 1
                continue

            # Skip deprecated / revoked techniques.
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                skipped_deprecated += 1
                continue

            # Filter to Android platform only.
            platforms = obj.get("x_mitre_platforms") or []
            if _ANDROID_PLATFORM not in platforms:
                skipped_platform += 1
                continue

            # Incremental update: skip objects not modified since last fetch.
            if self._last_fetch_ts:
                modified = obj.get("modified", "")
                if modified and modified <= self._last_fetch_ts:
                    skipped_stale += 1
                    continue

            yield obj
            yielded += 1

        log.info(
            "mitre_attack.fetcher.done",
            yielded=yielded,
            skipped_type=skipped_type,
            skipped_platform=skipped_platform,
            skipped_stale=skipped_stale,
            skipped_deprecated=skipped_deprecated,
        )

    # ── internal helpers ─────────────────────────────────────────────────

    def _download_bundle(self) -> dict | None:
        """Download the STIX bundle. Tries primary URL then TAXII fallback."""
        bundle = self._fetch_github()
        if bundle is not None:
            return bundle

        # ── FALLBACK: GitHub CDN unreachable → TAXII 2.1 ─────────────────
        self._github_error_reason = getattr(self, "_github_error_reason", "Connection failed")
        emit_fallback(
            source="mitre_attack",
            stage="fetcher",
            original="GitHub CDN (raw.githubusercontent.com/mitre-attack/attack-stix-data)",
            fallback="TAXII 2.1 (attack-taxii.mitre.org)",
            reason=self._github_error_reason,
        )
        log.warning("mitre_attack.fetcher.github_failed_trying_taxii")
        return self._fetch_taxii()

    def _fetch_github(self) -> dict | None:
        try:
            resp = requests.get(
                _PRIMARY_URL,
                timeout=_REQUEST_TIMEOUT,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            bundle = resp.json()
            log.info("mitre_attack.fetcher.github_ok", url=_PRIMARY_URL,
                     size_bytes=len(resp.content))
            return bundle
        except requests.RequestException as exc:
            self._github_error_reason = str(exc)
            log.warning("mitre_attack.fetcher.github_error", error=str(exc), url=_PRIMARY_URL)
            return None
        except (json.JSONDecodeError, ValueError) as exc:
            self._github_error_reason = f"JSON parse error: {exc}"
            log.error("mitre_attack.fetcher.github_parse_error", error=str(exc))
            return None

    def _fetch_taxii(self) -> dict | None:
        """Fetch all attack-pattern objects via TAXII 2.1 paged requests."""
        url = f"{_TAXII_ROOT}/collections/{_TAXII_COLLECTION_ID}/objects/"
        headers = {
            "Accept": "application/taxii+json;version=2.1",
        }
        params: dict = {"match[type]": "attack-pattern", "limit": 100}
        objects: list[dict] = []

        try:
            while url:
                resp = requests.get(url, headers=headers, params=params,
                                    timeout=_REQUEST_TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                objects.extend(data.get("objects") or [])

                # TAXII 2.1 pagination via Link header or next field.
                next_url = data.get("next")
                if next_url:
                    url = next_url
                    params = {}   # next URL already contains query params
                else:
                    url = ""      # exit loop

            log.info("mitre_attack.fetcher.taxii_ok", objects=len(objects))
            return {"objects": objects}
        except requests.RequestException as exc:
            log.error("mitre_attack.fetcher.taxii_error", error=str(exc))
            return None
        except (json.JSONDecodeError, ValueError) as exc:
            log.error("mitre_attack.fetcher.taxii_parse_error", error=str(exc))
            return None
