"""Deduplicator: decide whether to INSERT, UPDATE, or SKIP a normalised record.

The deduplication strategy uses **two sequential queries** (not an OR clause)
to avoid index suppression and non-deterministic multi-row returns when a
``external_id`` match and a ``name`` collision happen to resolve to different
rows.

Decision matrix
---------------
1. Query by ``external_id`` (partial unique index — fast, indexed).
   - Match → candidate for UPDATE (check version / hash to decide SKIP).
2. If no ``external_id`` match, query by ``(name, source)`` collision.
   - Match → candidate for UPDATE.
3. No match → INSERT.

The deduplicator does NOT write to the database.  It returns a
``DedupDecision`` that the Upsert layer acts on.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.threat_intelligence import TTP
from app.ti_ingestion.models import NormalizedTTPRecord

log = get_logger(__name__)


class DedupAction(str, Enum):
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    SKIP = "SKIP"


@dataclass
class DedupDecision:
    action: DedupAction
    existing_id: Optional[str] = None   # set when action = UPDATE
    existing_version: int = 0


def deduplicate(db: Session, record: NormalizedTTPRecord) -> DedupDecision:
    """Determine whether to INSERT, UPDATE, or SKIP the normalised record.

    No database writes are performed here.
    """
    existing: Optional[TTP] = None

    # ── Step 1: exact external_id match (indexed, fast path) ─────────────
    if record.external_id:
        existing = db.execute(
            select(TTP).where(TTP.external_id == record.external_id)
        ).scalar_one_or_none()

        if existing:
            log.debug(
                "dedup.external_id_match",
                external_id=record.external_id,
                existing_id=existing.id,
            )

    # ── Step 2: name + source collision (only if Step 1 found nothing) ───
    if existing is None:
        existing = db.execute(
            select(TTP).where(
                TTP.name == record.name,
                TTP.source == record.source,
            )
        ).scalar_one_or_none()

        if existing:
            log.debug(
                "dedup.name_collision",
                name=record.name,
                source=record.source,
                existing_id=existing.id,
            )

    # ── Step 3: decide action ─────────────────────────────────────────────
    if existing is None:
        return DedupDecision(action=DedupAction.INSERT)

    # Record already exists — check if the content has actually changed.
    # A lightweight comparison using description + indicator presence avoids
    # unnecessary UPDATE churn when the feed re-publishes unchanged data.
    has_new_indicators = any(ind not in (existing.indicators or []) for ind in record.indicators)
    content_changed = (
        existing.description != record.description
        or has_new_indicators
        or getattr(existing, "mitre_technique_id", None) != record.mitre_technique_id
        or getattr(existing, "mitre_tactic", None) != record.mitre_tactic
        or getattr(existing, "confidence_score", 0.85) != record.confidence_score
    )

    if not content_changed:
        log.debug("dedup.skip_unchanged", db_id=existing.id)
        return DedupDecision(action=DedupAction.SKIP, existing_id=existing.id,
                             existing_version=existing.version)

    return DedupDecision(action=DedupAction.UPDATE, existing_id=existing.id,
                         existing_version=existing.version)
