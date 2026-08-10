"""Celery task: ingest MITRE ATT&CK for Mobile into the ttps table.

This task is registered in the existing ``celery_app`` via ``include``
and scheduled via ``beat_schedule`` in ``celery_app.py``.  It does NOT
create a second Celery instance.

Pipeline per run
----------------
1. Acquire Redis distributed lock (prevents concurrent beat firings).
2. Read last-fetch high-water mark from Redis.
3. Fetch raw STIX objects from MITRE ATT&CK (GitHub CDN, TAXII fallback).
4. For each object:
   a. Normalise (MitreAttackNormalizer)
   b. Validate (11-rule gate)
   c. Deduplicate (two sequential queries — no OR clause)
   d. Upsert (INSERT / UPDATE / SKIP) OR quarantine on failure.
5. Persist last-fetch timestamp on full success.
6. Release lock.

On task failure (exception) the last-fetch timestamp is NOT updated so the
next run re-processes from the same high-water mark.

Owner: TI Engineer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.database import session_scope
from app.core.logging import get_logger
from app.ti_ingestion.deduplicator import DedupAction, deduplicate
from app.ti_ingestion.fetchers.malwarebazaar import MalwareBazaarFetcher
from app.ti_ingestion.fetchers.mitre_attack import MitreAttackFetcher
from app.ti_ingestion.fetchers.otx import AlienVaultOtxFetcher
from app.ti_ingestion.normalizer import (
    AlienVaultOtxNormalizer,
    MalwareBazaarNormalizer,
    MitreAttackNormalizer,
)
from app.ti_ingestion.upsert import quarantine, upsert
from app.ti_ingestion.validator import validate

log = get_logger(__name__)

# Lock TTL: 1 hour — enough for the STIX bundle or feeds to be processed.
_LOCK_TTL_SECONDS = 3600


def _celery():
    from app.workers.celery_app import celery_app
    return celery_app


celery_app = _celery()


def _redis():
    import redis as _redis_lib
    from app.core.config import settings
    return _redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def _execute_ingestion(self, fetcher_class, normalizer_class, lock_key: str, source_name: str) -> dict[str, Any]:
    """Generic runner for a threat intelligence ingestion feed."""
    r = _redis()

    lock = r.lock(lock_key, timeout=_LOCK_TTL_SECONDS, blocking_timeout=5)
    acquired = lock.acquire(blocking=False)
    if not acquired:
        log.info("ti.ingest.skipped_lock_held", source=source_name)
        return {"status": "skipped", "reason": "another run in progress"}

    inserted = updated = skipped = quarantined = normalise_error = 0

    try:
        last_fetch_ts: str | None = r.get(fetcher_class.last_fetch_key)
        log.info("ti.ingest.start", source=source_name, since=last_fetch_ts)

        fetcher = fetcher_class(last_fetch_ts=last_fetch_ts)
        normalizer = normalizer_class()
        run_start = datetime.now(timezone.utc).isoformat()

        # MalwareBazaar uses YYYY-MM-DD HH:MM:SS format for timestamps
        if source_name == "malwarebazaar":
            run_start = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        for raw_obj in fetcher.fetch():
            record = None
            try:
                record = normalizer.normalize(raw_obj)
            except Exception as exc:  # noqa: BLE001
                log.warning("ti.ingest.normalise_error", error=str(exc))
                normalise_error += 1
                continue

            if record is None:
                normalise_error += 1
                continue

            result = validate(record)
            if not result.ok:
                log.info(
                    "ti.ingest.validation_failed",
                    rule=result.rule,
                    msg=result.message,
                    db_id=record.db_id,
                )
                with session_scope() as db:
                    quarantine(
                        db,
                        raw_payload=record.raw_payload,
                        failure_rule=result.rule,
                        failure_msg=result.message,
                        ingestion_source=record.source,
                    )
                quarantined += 1
                continue

            with session_scope() as db:
                decision = deduplicate(db, record)

            with session_scope() as db:
                action = upsert(db, record, decision)

            if action == DedupAction.INSERT:
                inserted += 1
            elif action == DedupAction.UPDATE:
                updated += 1
            else:
                skipped += 1

        # Only advance the high-water mark when the fetch actually reached the
        # source. `fetch()` is contractually forbidden from raising, so an empty
        # generator alone cannot distinguish "no new records upstream" from
        # "credentials rejected / network down". Advancing on failure would mark
        # the un-fetched window as done and skip those records permanently.
        if getattr(fetcher, "failed", False):
            log.warning(
                "ti.ingest.watermark_held",
                source=source_name,
                since=last_fetch_ts,
                reason="fetch failed — high-water mark left unchanged so the "
                       "next run retries this window",
            )
        else:
            r.set(fetcher_class.last_fetch_key, run_start, ex=86400 * 7)

        summary = {
            "status": "partial" if getattr(fetcher, "failed", False) else "success",
            "source": source_name,
            "inserted": inserted,
            "updated": updated,
            "skipped": skipped,
            "quarantined": quarantined,
            "normalise_errors": normalise_error,
        }
        log.info("ti.ingest.done", **summary)
        return summary

    except Exception as exc:  # noqa: BLE001
        log.error("ti.ingest.failed", source=source_name, error=str(exc))
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            log.error("ti.ingest.max_retries_exceeded", source=source_name)
            return {
                "status": "failed",
                "source": source_name,
                "error": str(exc),
            }

    finally:
        try:
            lock.release()
        except Exception:  # noqa: BLE001
            pass


@celery_app.task(
    name="app.workers.tasks.ti_ingestion_task.ingest_mitre_attack",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    acks_late=True,
    queue="static_queue",
)
def ingest_mitre_attack(self) -> dict[str, Any]:
    """Ingest MITRE ATT&CK for Mobile techniques into the ttps table."""
    return _execute_ingestion(
        self,
        fetcher_class=MitreAttackFetcher,
        normalizer_class=MitreAttackNormalizer,
        lock_key="ti:lock:mitre_attack",
        source_name="mitre_attack",
    )


@celery_app.task(
    name="app.workers.tasks.ti_ingestion_task.ingest_malwarebazaar",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    acks_late=True,
    queue="static_queue",
)
def ingest_malwarebazaar(self) -> dict[str, Any]:
    """Ingest MalwareBazaar Android malware family threat feeds into the ttps table."""
    return _execute_ingestion(
        self,
        fetcher_class=MalwareBazaarFetcher,
        normalizer_class=MalwareBazaarNormalizer,
        lock_key="ti:lock:malwarebazaar",
        source_name="malwarebazaar",
    )


@celery_app.task(
    name="app.workers.tasks.ti_ingestion_task.ingest_otx",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    acks_late=True,
    queue="static_queue",
)
def ingest_otx(self) -> dict[str, Any]:
    """Ingest AlienVault OTX Android pulses into the ttps table."""
    return _execute_ingestion(
        self,
        fetcher_class=AlienVaultOtxFetcher,
        normalizer_class=AlienVaultOtxNormalizer,
        lock_key="ti:lock:otx",
        source_name="otx",
    )
